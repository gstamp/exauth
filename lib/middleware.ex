defmodule Exauth.Middleware do
  import Plug.Conn

  # %Plug.Conn
  # def hello_world_plug(conn, _opts) do .. end


  def requested_uri(conn) do
    path = if conn.request_path != "", do: conn.request_path, else: "/"
    if conn.query_string != "" do
      path <> "?" <> conn.query_string
    else
      path
    end
  end

  @doc "Add session variable"
  def assoc_session(conn, attr, value) do
    put_session fetch_session(conn), attr, value
  end

  @doc "Return the token string from a session"
  def conn_to_session_token_string(conn) do
    get_session(conn, :access_token)
  end
  def conn_to_token_string(conn) do
    auth_header = get_req_header(conn, "authorization")
    auth_header = if auth_header == [], do: nil, else: hd(auth_header)
    if auth_header do
      bearer = Regex.named_captures(~r/^Bearer (?<bearer>.*)/, auth_header)["bearer"]
      if bearer, do: bearer
    else
      params = fetch_query_params(conn).params
      case params do
        %{:access_token => access_token}  -> access_token
        %{"access_token" => access_token} -> access_token
        _ ->
          if conn_to_session_token_string(conn) do
            conn_to_session_token_string(conn)
          else
            case fetch_cookies(conn).cookies do
              %{"access_token" => access_token} -> access_token
              _ -> nil
            end
          end
      end
    end
  end

  def conn_to_token(conn) do
    conn_to_token(conn, &Token.find_valid_token/1)
  end
  def conn_to_token(conn, finder) do
    token = conn_to_token_string(conn)
    if token, do: finder.(token)
  end

  @doc """
  Wrap request with a OAuth2 bearer token as defined in
   http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08.
   A find-token function is passed the token and returns a map
   describing the subject of the token.
   It supports the following ways of setting the token.
     * [Authorization header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1)
     * [Form encoded body parameter](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2)
     * [URI query field](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3)
     * Non standard http cookie ('access_token') for use in interactive applications
   The subject is added to the :access-token key of the request.
  """
  def wrap_bearer_token(app) do
    wrap_bearer_token(app, &Token.find_valid_token/1)
  end
  def wrap_bearer_token(app, find_token) do
    fn (conn) ->
      access_token = conn_to_token(conn, find_token)
      if access_token do
        app.(assign(conn, :access_token, access_token))
      else
        app.(conn)
      end
    end
  end

  @doc """
  Wrap request with a OAuth2 token stored in the session. Use this for
  optional authentication where no API access is wished.
  A find-token function is passed the token and returns a clojure map
  describing the subject of the token.
  It supports the following ways of setting the token.
  The subject is added to the :access-token key of the request.
  """
  def wrap_user_session(app) do
    wrap_user_session app, &Token.find_valid_token/1
  end
  def wrap_user_session(app, find_token) do
    fn(conn) ->
      token = conn_to_session_token_string(conn)
      access_token = find_token.(token)
      if access_token do
        app.(assign(conn, :access_token, access_token))
      else
        app.(conn)
      end
    end
  end

  @doc "returns true if request has text/html in the accept header"
  def is_html?(conn) do
    accept = get_req_header(conn, "accept")
    accept = if Enum.count(accept) == 0, do: nil, else: hd(accept)
    if accept do
      Regex.match?(~r"(text/html|application/xhtml\+xml)", accept)
    end
  end

  @doc "returns true if request has form in the accept header"
  def is_form?(conn) do

    access_token = conn.assigns[:access_token]
    session_access_token = get_session(conn, :access_token)
    if access_token == nil or (access_token != nil and session_access_token) do
      content_type = get_req_header(conn, "content-type")

      content_type = if Enum.count(content_type) == 0, do: nil, else: hd(content_type)
      if content_type do
        content_types = ["application/x-www-form-urlencoded", "multipart/form-data"]
        if !Enum.empty?(Enum.filter(content_types, &(&1 == content_type))) do
          true
        end
      end
    end
  end

  @doc "if request is for a html page it runs the first handler if not the second"
  defmacro if_html(conn, do: html, else: api) do
    quote do
      if(is_html?(unquote(conn)), do: unquote(html), else: unquote(api))
    end
  end

  @doc "if request is url form encoded it runs the first handler if not the second"
  defmacro if_form(conn, do: html, else: api) do
    quote do
      if(is_form?(unquote(conn)), do: unquote(html), else: unquote(api))
    end
  end

  @doc "extract csrf token from request"
  def csrf_token(conn) do
    token = conn.assigns[:csrf_token]
    if token do
      token
    else
      get_session(conn, :csrf_token)
    end
  end

  @doc "add a csrf token to request"
  def with_csrf_token(conn) do
    if csrf_token(conn) do
      conn
    else
      token = Base.encode32 :crypto.strong_rand_bytes(20), padding: false
      assign(conn, :csrf_token, token)
    end
  end

  @doc "add a csrf token to session and reject a post request without it"
  def csrf_protect!(app) do
    fn(conn) ->
      request_method = conn.method
      if request_method == "GET" and is_html?(conn) do
        conn = with_csrf_token(conn)
        token = conn.assigns[:csrf_token]
        if token do
          app.(conn |> put_session(:csrf_token, token))
        else
          app.(conn)
        end
      else
        if_form conn do
          token = csrf_token(conn)
          if token != nil and conn.params[:csrf_token] != nil and token == conn.params[:csrf_token] do
            app.(conn)
          else
            send_resp(conn, 403, "csrf token does not match")
          end
        else
          app.(conn)
        end
      end
    end
  end

  @doc "Return HTTP 401 Response"
  def authentication_required_response(conn) do
    if_html conn do
      conn
      |> put_session(:return_to, requested_uri(conn))
      |> put_resp_header("location", "/login")
      |> send_resp(302, "")
    else
      conn
      |> put_resp_header("content-type", "text/plain")
      |> put_resp_header("www-authenticate", "Bearer realm=\"OAuth required\"")
      |> send_resp(401, "access denied")
    end
  end

  @doc """
     Require request with a OAuth2 bearer token as defined in
     http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08.
     A find-token function is passed the token and returns a clojure map
     describing the token.
     It supports the following ways of setting the token.
     * [Authorization header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1)
     * [Form encoded body parameter](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2)
     * [URI query field](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3)
     * Non standard http cookie ('access_token') for use in interactive applications
     The token is added to the :access-token key of the request.
     will return a [HTTP 401 header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.4) if no valid token is present.
  """
  def require_bearer_token!(app) do
    require_bearer_token!(app, &Token.find_valid_token/1)
  end
  def require_bearer_token!(app, find_token) do
    wrap_bearer_token(fn conn ->
      if conn.assigns[:access_token] do
        app.(conn)
      else
        authentication_required_response conn
      end
    end, find_token)
  end

  @doc "Return HTTP 403 Response or redirects to login"
  def user_session_required_response(conn) do
    if_html conn do
      conn
      |> put_session(:return_to, requested_uri(conn))
      |> put_resp_header("location", "/login")
      |> send_resp(302, '')
    else
      conn
      |> put_resp_header("content-type", "text/plain")
      send_resp(conn, 403, "Forbidden")
    end
  end

  @doc """
     Require that user is authenticated via an access_token stored in the session.
     Use this to protect parts of your application that web services should not
     have access to.
     A find-token function is passed the token and returns a clojure map
     describing the token.
     The token is added to the :access-token key of the request.
     Will redirect user to login url if not authenticated and issue a 403 to
     other requests.
  """
  def require_user_session!(app) do
    require_user_session!(app, &Token.find_valid_token/1)
  end
  def require_user_session!(app, find_token) do
    wrap_user_session(fn conn ->
      if conn.assigns[:access_token] do
        app.(conn)
      else
        user_session_required_response conn
      end
    end, find_token)
  end
end
