defmodule Exauth.Endpoints do

  alias Exauth.{User, Client, Views, Token, AuthCode, Middleware}
  import Plug.Conn

  @doc """
  Take a token map and decorate it according to specs
  http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-5.1
    """
  def decorate_token(token) do
    if token do
      %{access_token: token.token, token_type: "bearer"}
    end
  end

  @doc "Create a ring response for a token response"
  def token_response(%Plug.Conn{} = conn, token) do
    decorated_token = decorate_token(token) |> Poison.encode!
    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(200, decorated_token)
  end

  @doc "Create a ring response for a oauth error"
  def error_response(%Plug.Conn{} = conn, error) do
    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(400, %{error: error} |> Poison.encode!)
  end

  @doc """
  Create a new token and respond with json. If using built in token system it takes client and subject (user).
  You can also pass a function to it and the client and subject.
  """
  def respond_with_new_token(conn, %{:token_creator => token_creator, :params => params} = attrs) do
    token = Map.merge(
      select_keys(params, ["scope"]),
      select_keys(attrs, ["client", "subject", "scope"]))
    created_token = token_creator.(token)
    token_response(conn, created_token)
  end
  def respond_with_new_token(conn, attrs),
    do: respond_with_new_token(conn, Map.put_new(attrs, :params, %{}))

  def respond_with_new_token(conn, client, subject) do
    respond_with_new_token conn, &Token.create_token/1, client, subject
  end
  def respond_with_new_token(conn, token_creator, client, subject) do
    respond_with_new_token(conn, %{client: client, subject: subject, token_creator: token_creator})
  end

  @doc """
  Decode basic authentication credentials.

  If it exists it returns a vector of username and password.
  If not nil.
  """
  def basic_authentication_credentials(conn) do
    auth_string = get_req_header(conn, "authorization")
    auth_string = if auth_string == [], do: nil, else: hd(auth_string)
    if auth_string do
      basic_token = Regex.named_captures(~r/^Basic (?<basic>.*)$/, auth_string)["basic"]
      if basic_token do
        case Base.decode64(basic_token) do
          {:ok, credentials} -> String.split(credentials, ":")
          _ -> nil
        end
      end
    end
  end

  @doc """
  Check that request is authenticated by client either using Basic
  authentication or url form encoded parameters.

  The client_id and client_secret are checked against the authenticate-client
  function.

  If authenticate-client returns a client map it runs success function with
  the request and the client.
  """
  def client_authenticated_request(conn, authenticator, success) do
    basic = basic_authentication_credentials(conn)
    client_id = if basic, do: hd(basic), else: conn.params["client_id"]
    client_secret = if basic, do: List.last(basic), else: conn.params["client_secret"]
    client = authenticator.(client_id, client_secret)
    if client do
      success.(conn, client)
    else
      error_response(conn, "invalid_client")
    end
  end

  @doc "extract grant type from request"
  def grant_type(conn) do
    conn.params["grant_type"]
  end

  def token_request_handler(conn, config) do
    case grant_type(conn) do
      "client_credentials" -> token_request_handler("client_credentials", conn, config)
      "authorization_code" -> token_request_handler("authorization_code", conn, config)
      "password" -> token_request_handler("password", conn, config)
      _ -> error_response(conn, "unsupported_grant_type")
    end
  end

  def token_request_handler("client_credentials",
        conn,
        %{client_authenticator: client_authenticator, token_creator: token_creator}) do
    client_authenticated_request conn, client_authenticator, fn(conn, client) ->
      respond_with_new_token(conn, %{token_creator: token_creator,
                                     client: client,
                                     subject: client,
                                     params: conn.params})
    end
  end

  def token_request_handler("authorization_code",
        conn,
        %{client_authenticator: client_authenticator,
          token_creator: token_creator,
          auth_code_lookup: auth_code_lookup,
          auth_code_revoker: auth_code_revoker}) do

    client_authenticated_request conn, client_authenticator, fn (conn, client) ->
      code = auth_code_lookup.( conn.params["code"] )
      if code do
        if client.client_id == code.client.client_id and code.redirect_uri == conn.params["redirect_uri"] do
          auth_code_revoker.(code)
          respond_with_new_token conn, Map.merge(code, %{token_creator: token_creator, client: client})
        else
          error_response conn, "invalid_grant"
        end
      else
        error_response conn, "invalid_grant"
      end
    end
  end

  def token_request_handler("password",
        conn,
        %{client_authenticator: client_authenticator,
          token_creator: token_creator,
          user_authenticator: user_authenticator}) do
    client_authenticated_request conn, client_authenticator, fn (conn, client) ->
      user = user_authenticator.(conn.params["username"], conn.params["password"])
      if user do
        respond_with_new_token conn, token_creator, client, user
      else
        error_response conn, "invalid_grant"
      end
    end
  end

  @doc """
  Ring handler that issues oauth tokens.
  Configure it by passing an optional map containing:
    :client-authenticator a function that returns a client record when passed a
                          correct client_id and client secret combo
    :user-authenticator   a function that returns a user when passwed a correct
                          username and password combo
    :auth-code-lookup     a function which returns a auth code record when passed
                          it's code string
    :token-creator        a function that creates a new token when passed a client
                          and a user
    :auth-code-revoker    a function that revokes a auth-code when passed an
                          auth-code record
  """
  def token_handler() do
    token_handler %{}
  end
  def token_handler(client_authenticator, user_authenticator) do
    token_handler %{client_authenticator: client_authenticator,
                          user_authenticator: user_authenticator}
  end
  def token_handler(config) do
    fn conn ->
      token_request_handler conn, Map.merge(
        %{client_authenticator: &Client.authenticate_client/2,
          user_authenticator: &User.authenticate_user/2,
          token_creator: &Token.create_token/1,
          auth_code_revoker: &AuthCode.revoke_auth_code!/1,
          auth_code_lookup: &AuthCode.fetch_auth_code/1
        }, config)
    end
  end

  @doc "Return to value of :return-to key session or the contents of default-destination (by default '/')"
  def return_to_handler(conn) do
    return_to_handler conn, "/"
  end
  def return_to_handler(conn, default_destination) do
    destination = get_session(conn, :return_to) || default_destination
    conn
    |> delete_session(:return_to)
    |> put_resp_header("location", destination)
    |> send_resp(302, "")
  end

  @doc """
     Present a login form to user and log them in by adding an access token to
     the session.
     Configure it by passing the following to a map:
     Required value
       :client the site's own client application record
     Optional entries to customize functionality:
       :login-destination Where to redirect the user to after login (default '/')
       :login-form a ring handler to display a login form
       :user-authenticator a function that returns a user when passwed a correct
        username and password combo
       :token-creator a function that creates a new token when passed a client and
        a user
  """
  def login_handler(config) do
    config = Map.merge(%{login_destination: "/",
                         login_form: &Views.login_form_handler/1,
                         user_authenticator: &User.authenticate_user/2,
                         token_creator: &Token.create_token/1
                        }, config)
    %{client: client, login_form: login_form, user_authenticator: user_authenticator,
      token_creator: token_creator, login_destination: login_destination} = config
    Middleware.csrf_protect! fn conn ->
      request_method = conn.method
      params = conn.params
      if request_method == "GET" do
        login_form.(conn)
      else
        user = user_authenticator.(params["username"], params["password"])
        if user do
          conn
          |> put_session(:access_token, token_creator.(Token.oauth_token(client, user)).token)
          |> return_to_handler(login_destination)
        else
          login_form.(conn)
        end
      end
    end
  end

  @doc "logout user"
  def logout_handler(conn) do
    conn
    |> put_session(:access_token, "")
    |> put_resp_header("location", "/")
    |> send_resp(302, "")
  end

  @doc "returns true if request is logged in"
  def logged_in?(conn) do
    conn.assigns[:access_token] != nil
  end

  @doc "returns current user associated with request"
  def current_user(conn) do
    if logged_in?(conn) do
      conn.assigns[:access_token][:subject]
    end
  end

  @doc "Create a proper redirection response depending on response_type"
  def authorization_response(conn, response_params) do
    params = conn.params
    redirect_uri = params["redirect_uri"]
    join_with = if params["response_type"] == "token", do: "#", else: "?"

    state_map =
      Enum.filter(select_keys(params, ["state"]), fn {_ ,v} -> v != nil end)
      |> Enum.into(%{})

    resp_params = URI.encode_query(Map.merge(response_params, state_map))
    redirect_to = redirect_uri <> join_with <> resp_params
    conn
    |> put_resp_header("location", redirect_to)
    |> send_resp(302, "")
  end

  @doc "redirect to client with error code"
  def authorization_error_response(conn, error) do
    if conn.params["redirect_uri"] do
      authorization_response conn, %{"error" => error}
    else
      Views.error_page conn, error
    end
  end

  @doc "extract grant type from request"
  def response_type(conn) do
    conn.params["response_type"]
  end

  def authorization_request_handler(conn, config) do
    authorization_request_handler(response_type(conn), conn, config)
  end
  def authorization_request_handler("token", conn,
        %{token_lookup: token_lookup,
          token_creator: token_creator}) do
    session_token = Middleware.conn_to_token(conn, token_lookup)
    token = token_creator.(
      Map.merge(
        %{client: conn.assigns[:client],
          subject: session_token[:subject]},
        select_keys(conn.params, ["state", "scope"])))
    authorization_response conn, %{access_token: token.token,
                                   token_type: "bearer"}
  end
  def authorization_request_handler("code", conn,
        %{token_lookup: token_lookup,
          auth_code_creator: auth_code_creator}) do
    session_token = Middleware.conn_to_token(conn, token_lookup)
    code = auth_code_creator.(
      Map.merge(
        %{client: conn.assigns[:client], subject: session_token.subject},
        select_keys(conn.params, ["state", "scope"]))
      |> Map.merge(%{redirect_uri: conn.params["redirect_uri"]})
    )
    authorization_response(conn, %{code: code.code})
  end
  def authorization_request_handler(_, conn, _) do
    authorization_error_response conn, "unsupported_grant_type"
  end

  @doc """
   present a login form to user and log them in by adding an access token to
   the session
   Configure it by passing an optional map containing:
     :authorization-form a ring handler to display a authorization form
     :client-lookup a function which returns a client when passed its client_id
     :token-lookup  a function which returns a token record when passed it's
      token string
     :token-creator a function that creates a new token when passed a client and
      a user
     :auth-code-creator a function that creates an authorization code record when
      passed a client, user and redirect uri
     :allowed-response-types Defaults to code and token. You can add custome ones here or remove less secure ones such as 'token'
     :auto-approver a function for auto approving authorizations. By default no auto approval is provided. The auto approval functions is passed the request and decides based on your own business rules if the client should be authorized automatically for your user.
   """
  def authorization_handler do
    authorization_handler %{}
  end
  def authorization_handler(config) do
    # TODO: Gross. I'm sure we can do better
    config = Map.merge(%{authorization_form: &Views.authorization_form_handler/1,
                         client_lookup: &Client.fetch_client/1,
                         token_lookup: &Token.find_valid_token/1,
                         token_creator: &Token.create_token/1,
                         auth_code_creator: &AuthCode.create_auth_code/1,
                         allowed_response_types: ["code", "token"],
                         auto_approver: fn(_) -> false end}, config)
    authorization_form = config.authorization_form
    auto_approver = config.auto_approver
    client_lookup = config.client_lookup
    Middleware.require_user_session!(
      Middleware.csrf_protect!(
        fn %{params: params} = conn ->
          if params["response_type"] != nil && params["client_id"] != nil do
            client = client_lookup.(params["client_id"])
            if client do
              conn = conn |> Plug.Conn.assign(:client, client)
              if Enum.any?(config.allowed_response_types, &(&1 == params["response_type"])) do
                if conn.method == "GET" do
                  if auto_approver.(conn) do
                    authorization_request_handler conn, config
                  else
                    authorization_form.(conn)
                  end
                else
                  authorization_request_handler conn, config
                end
              else
                authorization_error_response conn, "unsupported_response_type"
              end
            else
              authorization_error_response conn, "unauthorized_client"
            end
          else
            authorization_error_response conn, "invalid_request"
          end
        end
      ),
      config.token_lookup
    )
  end

  #######################

  defp select_keys(map, keys) do
    selector = fn({k,_}) -> Enum.member? keys, k end
    map |> Enum.filter(selector) |> Enum.into(%{})
  end
end
