defmodule EndpointsTest do
  use PowerAssert
  use Plug.Test

  doctest Exauth.Endpoints

  alias Plug.ProcessStore
  alias Exauth.{Endpoints, Token, Client, Store, User, AuthCode}

  defp setup_conn(conn \\ %Plug.Conn{}) do

    session_config = Plug.Session.init store: ProcessStore, key: "foobar"
    parser_config = Plug.Parsers.init parsers: [Plug.Parsers.URLENCODED, Plug.Parsers.MULTIPART]
    conn
    |> Plug.Conn.fetch_cookies
    |> Plug.Session.call(session_config)
    |> Map.put(:secret_key_base, String.duplicate("abcdefgh", 8))
    |> Plug.Conn.fetch_session
    |> Plug.Parsers.call(parser_config)
    |> Map.put(:query_string, URI.encode_query(conn.params))

  end

  test "token decoration" do
    assert Endpoints.decorate_token( %{token: "SECRET", unimportant: "forget this"} ) ==
      %{access_token: "SECRET", token_type: "bearer"}
  end

  test "token response" do
    conn = conn(:get, "/")
    |> Endpoints.token_response( %{token: "SECRET", unimportant: "forget this"} )

    assert conn.status == 200
    assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json"]
    assert conn.resp_body == "{\"token_type\":\"bearer\",\"access_token\":\"SECRET\"}"
  end

  test "error response" do
    conn = conn(:get, "/")
    |> Endpoints.error_response(:invalid_request)

    assert conn.status == 400
    assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json"]
    assert conn.resp_body == "{\"error\":\"invalid_request\"}"
  end

  test "extract basic authenticated credentials" do
    [user, password] = conn(:get, "/")
    |> put_req_header("authorization", "Basic dXNlcjpwYXNzd29yZA==")
    |> Endpoints.basic_authentication_credentials

    assert "user" == user
    assert "password" == password
  end

  test "requesting client owner token" do

    Store.start_link %{}

    reset_stores
    handler = Endpoints.token_handler()
    client = Client.register_client
    resp_conn = conn(:get, "/", %{"grant_type" => "client_credentials", "client_id" => client.client_id, "client_secret" => client.client_secret})
    |> setup_conn
    |> handler.()

    # url form encoded client credentials
    assert resp_conn.status == 200
    assert Plug.Conn.get_resp_header(resp_conn, "content-type") == ["application/json"]
    assert Poison.decode!(resp_conn.resp_body) == %{"access_token" => hd(Token.tokens).token,
                                                   "token_type" => "bearer"}

    reset_stores
    handler = Endpoints.token_handler()
    client = Client.register_client
    auth_string = "Basic " <> Base.encode64("#{client.client_id}:#{client.client_secret}")
    resp_conn = conn(:get, "/", %{"grant_type" => "client_credentials"})
    |> setup_conn
    |> Plug.Conn.put_req_header("authorization", auth_string)
    |> handler.()

    # Basic authenticated client credentials
    assert resp_conn.status == 200
    assert Plug.Conn.get_resp_header(resp_conn, "content-type") == ["application/json"]
    assert Poison.decode!(resp_conn.resp_body) == %{"access_token" => hd(Token.tokens).token,
                                                    "token_type" => "bearer"}


    reset_stores
    handler = Endpoints.token_handler()
    client = Client.register_client
    resp_conn = conn(:get, "/", %{"grant_type" => "client_credentials", "client_id" => "bad", "client_secret" => "client"})
    |> setup_conn
    |> handler.()

    # should fial on bad client authentication
    assert resp_conn.status == 400
    assert Plug.Conn.get_resp_header(resp_conn, "content-type") == ["application/json"]
    assert Poison.decode!(resp_conn.resp_body) == %{"error" => "invalid_client"}

    reset_stores
    handler = Endpoints.token_handler()
    client = Client.register_client
    resp_conn = conn(:get, "/", %{"grant_type" => "client_credentials"})
    |> setup_conn
    |> handler.()

    # should fial on bad client authentication
    assert resp_conn.status == 400
    assert Plug.Conn.get_resp_header(resp_conn, "content-type") == ["application/json"]
    assert Poison.decode!(resp_conn.resp_body) == %{"error" => "invalid_client"}

  end

  test "requesting resource owner password credentials token" do

    Store.start_link %{}

    # url from encoded client credientials
    reset_stores
    handler = Endpoints.token_handler()
    client = Client.register_client
    user = User.register_user "john@example.com", "password"
    resp_conn = conn(:get, "/", %{"grant_type" => "password",
                                  "username" => "john@example.com",
                                  "password" => "password",
                                  "client_id" => client.client_id,
                                  "client_secret" => client.client_secret})
    |> setup_conn
    |> handler.()
    assert resp_conn.status == 200
    assert Plug.Conn.get_resp_header(resp_conn, "content-type") == ["application/json"]
    assert Poison.decode!(resp_conn.resp_body) == %{"access_token" => hd(Token.tokens).token,
                                                    "token_type" => "bearer"}


    # basic authenticated client credentials
    reset_stores
    handler = Endpoints.token_handler()
    client = Client.register_client
    user = User.register_user "john@example.com", "password"
    auth_str = "Basic " <> Base.encode64(client.client_id <> ":" <> client.client_secret)
    resp_conn = conn(:get, "/", %{"grant_type" => "password",
                                  "username" => "john@example.com",
                                  "password" => "password"})
    |> put_req_header("authorization", auth_str)
    |> setup_conn
    |> handler.()
    assert resp_conn.status == 200
    assert Plug.Conn.get_resp_header(resp_conn, "content-type") == ["application/json"]
    assert Poison.decode!(resp_conn.resp_body) == %{"access_token" => hd(Token.tokens).token,
                                                    "token_type" => "bearer"}

    # should fail on bad user password
    reset_stores
    handler = Endpoints.token_handler()
    client = Client.register_client
    user = User.register_user "john@example.com", "password"
    resp_conn = conn(:get, "/", %{"grant_type" => "password",
                                  "username" => "john@example.com",
                                  "password" => "not my password",
                                  "client_id" => client.client_id,
                                  "client_secret" => client.client_secret})
    |> setup_conn
    |> handler.()
    assert resp_conn.status == 400
    assert Plug.Conn.get_resp_header(resp_conn, "content-type") == ["application/json"]
    assert Poison.decode!(resp_conn.resp_body) == %{"error" => "invalid_grant"}

    # should fail with missing user authentication
    reset_stores
    handler = Endpoints.token_handler()
    client = Client.register_client
    user = User.register_user "john@example.com", "password"
    resp_conn = conn(:get, "/", %{"grant_type" => "password",
                                  "client_id" => client.client_id,
                                  "client_secret" => client.client_secret})
    |> setup_conn
    |> handler.()
    assert resp_conn.status == 400
    assert Plug.Conn.get_resp_header(resp_conn, "content-type") == ["application/json"]
    assert Poison.decode!(resp_conn.resp_body) == %{"error" => "invalid_grant"}

    # should fail on bad client authentication
    reset_stores
    handler = Endpoints.token_handler()
    client = Client.register_client
    user = User.register_user "john@example.com", "password"
    resp_conn = conn(:get, "/", %{"grant_type" => "password",
                                  "username" => "john@example.com",
                                  "password" => "password",
                                  "client_id" => "bad",
                                  "client_secret" => "client"})
    |> setup_conn
    |> handler.()
    assert resp_conn.status == 400
    assert Plug.Conn.get_resp_header(resp_conn, "content-type") == ["application/json"]
    assert Poison.decode!(resp_conn.resp_body) == %{"error" => "invalid_client"}

    # should fail with missing client authentication
    reset_stores
    handler = Endpoints.token_handler()
    client = Client.register_client
    user = User.register_user "john@example.com", "password"
    resp_conn = conn(:get, "/", %{"grant_type" => "password"})
    |> setup_conn
    |> handler.()
    assert resp_conn.status == 400
    assert Plug.Conn.get_resp_header(resp_conn, "content-type") == ["application/json"]
    assert Poison.decode!(resp_conn.resp_body) == %{"error" => "invalid_client"}

  end

  defp reset_stores do
    AuthCode.reset_auth_code_store!
    Token.reset_token_store!
    Client.reset_client_store!
    User.reset_user_store!
  end

  describe "requested authorization code token" do
    setup do
      Store.start_link %{}
      reset_stores

      context = %{
        handler: Endpoints.token_handler,
        client: Client.register_client,
        user: User.register_user("john@example.com", "password"),
        scope: "calendar",
        redirect_uri: "http://test.com/redirect_uri",
        object: %{id: "stuff"}
      }
      context = Map.put(context, :code, AuthCode.create_auth_code(context.client, context.user, context.redirect_uri, context.scope, context.object))
      context = Map.put(context, :auth_str, "Basic " <> Base.encode64(context.client.client_id <> ":" <> context.client.client_secret))

      {:ok, context}
    end

    test "returns valid access_token", context do
      conn = conn(:get, "/", %{"grant_type"    => "authorization_code",
                               "code"          => context.code.code,
                               "redirect_uri"  => context.redirect_uri,
                               "client_id"     => context.client.client_id,
                               "client_secret" => context.client.client_secret})
      |> setup_conn
      |> context.handler.()
      assert conn.status == 200
      assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json"]
      assert Poison.decode!(conn.resp_body) == %{"access_token" => hd(Token.tokens).token,
                                                 "token_type"  => "bearer"}
    end

    test "basic authenticated client credentials", context do
      conn = conn(:get, "/", %{"grant_type"   => "authorization_code",
                               "redirect_uri" => context.redirect_uri,
                               "code"         => context.code.code})
      |> put_req_header("authorization", context.auth_str)
      |> setup_conn
      |> context.handler.()

      assert conn.status == 200
      assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json"]
      assert Poison.decode!(conn.resp_body) == %{"access_token" => hd(Token.tokens).token,
                                                 "token_type"   => "bearer"}
    end

    test "bad client secret", context do
      conn = conn(:get, "/", %{"grant_type"    => "authorization_code",
                               "code"          => context.code.code,
                               "redirect_uri"  => context.redirect_uri,
                               "client_id"     => context.client.client_id,
                               "client_secret" => "bad"})
      |> setup_conn
      |> context.handler.()

      assert conn.status == 400
      assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json"]
      assert Poison.decode!(conn.resp_body) == %{"error" => "invalid_client"}

    end

    test "another clients details", context do
      other = Client.register_client
      conn = conn(:get, "/", %{"grant_type" => "authorization_code",
                               "code" => context.code.code,
                               "redirect_uri" => context.redirect_uri,
                               "client_id" => other.client_id,
                               "client_secret" => other.client_secret})
      |> setup_conn
      |> context.handler.()

      assert conn.status == 400
      assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json"]
      assert Poison.decode!(conn.resp_body) == %{"error" => "invalid_grant"}

    end

    test "missing redirect_uri", context do
      conn = resp_conn = conn(:get, "/", %{"grant_type" => "authorization_code",
                                           "code" => context.code.code,
                                           "client_id" => context.client.client_id,
                                           "client_secret" => context.client.client_secret})
      |> setup_conn
      |> context.handler.()

      assert conn.status == 400
      assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json"]
      assert Poison.decode!(conn.resp_body) == %{"error" => "invalid_grant"}
    end

    test "wrong redirect_uri", context do
      conn = conn(:get, "/", %{"grant_type" => "authorization_code",
                               "code" => context.code.code,
                               "redirect_uri" => "http://badsite.com",
                               "client_id" => context.client.client_id,
                               "client_secret" => context.client.client_secret})
      |> setup_conn
      |> context.handler.()

      assert conn.status == 400
      assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json"]
      assert Poison.decode!(conn.resp_body) == %{"error" => "invalid_grant"}
    end

    test "missing code", context do
      conn = conn(:get, "/", %{"grant_type" => "authorization_code",
                               "redirect_uri" => context.redirect_uri,
                               "client_id" => context.client.client_id,
                               "client_secret" => context.client.client_secret})
      |> setup_conn
      |> context.handler.()

      assert conn.status == 400
      assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json"]
      assert Poison.decode!(conn.resp_body) == %{"error" => "invalid_grant"}
    end

    test "bad client authentication", context do
      conn = conn(:get, "/", %{"grant_type"    => "authorization_code",
                               "code"          => context.code.code,
                               "redirect_uri"  => context.redirect_uri,
                               "client_id"     => "bad",
                               "client_secret" => context.client.client_secret})
      |> setup_conn
      |> context.handler.()

      assert conn.status == 400
      assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json"]
      assert Poison.decode!(conn.resp_body) == %{"error" => "invalid_client"}
    end

    test "missing client authentication", context do
      conn = conn(:get, "/", %{"grant_type" => "authorization_code",
                               "redirect_uri" => context.redirect_uri,
                               "code" => context.code.code})
      |> setup_conn
      |> context.handler.()

      assert conn.status == 400
      assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json"]
      assert Poison.decode!(conn.resp_body) == %{"error" => "invalid_client"}
    end
  end

  describe "requested authorization code" do
    setup do
      Store.start_link %{}
      reset_stores
      context = %{
        handler: Endpoints.authorization_handler,
        client: Client.register_client,
        user: User.register_user("john@example.com", "password"),
        redirect_uri: "http://test.com",
        uri: "/authorize"
      }

      params = %{response_type: "code",
                 client_id: context.client.client_id,
                 redirect_uri: context.redirect_uri,
                 state: "abcde",
                 scope: "calendar"}

      { :ok,
        context
        |> Dict.put(:params, params)
        |> Dict.put(:query_string, URI.encode_query(params))
      }
    end

    test "valid auth code with logged in session", context do
      session_token = Token.create_token(context.client, context.user)
      conn = conn(:get, "/authorize", context.params)
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> context.handler.()

      assert conn.status == 200
    end

    test "no logged in", context do
      conn = conn(:get, "/authorize", context.params)
      |> setup_conn
      |> put_req_header("accept", "text/html")
      |> context.handler.()

      assert conn.status == 302
      assert get_session(conn, :return_to) == context.uri <> "?" <> conn.query_string
      assert get_resp_header(conn, "location") == ["/login"]
    end

    test "auto approval on", context do
      session_token = Token.create_token(context.client, context.user)
      handler = Endpoints.authorization_handler(%{auto_approver: fn(_) -> true end})
      conn = conn(:get, "/authorize", context.params)
      |> setup_conn
      |> put_req_header("accept", "text/html")
      |> put_session(:access_token, session_token.token)
      |> handler.()

      post_auth_redirect_uri = get_resp_header(conn, "location") |> hd
      query = URI.parse(post_auth_redirect_uri).query
      code_string = URI.decode_query(query)["code"]
      auth_code = AuthCode.fetch_auth_code(code_string)

      # should redirect with propper format
      assert conn.status == 302
      assert post_auth_redirect_uri == "http://test.com?code=#{code_string}&state=abcde"

      # should properly save redirect_uri
      assert auth_code.client == context.client
      assert auth_code.subject == context.user
      assert auth_code.redirect_uri == context.redirect_uri
    end

    test "missing parameters", context do
      session_token = Token.create_token(context.client, context.user)
      params = context.params |> Map.delete(:response_type)
      conn = conn(:get, "/authorize", params )
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> context.handler.()

      assert conn.status == 302
      assert get_resp_header(conn, "location") == ["http://test.com?error=invalid_request&state=abcde"]
    end

    test "missing client id", context do
      session_token = Token.create_token(context.client, context.user)
      params = context.params |> Map.delete(:client_id)
      conn = conn(:get, "/authorize", params )
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> context.handler.()

      assert conn.status == 302
      assert get_resp_header(conn, "location") == ["http://test.com?error=invalid_request&state=abcde"]
    end

    test "missing client_id and state", context do
      session_token = Token.create_token(context.client, context.user)
      params = context.params |> Map.delete(:state) |> Map.delete(:client_id)
      conn = conn(:get, "/authorize", params )
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> context.handler.()

      assert conn.status == 302
      assert get_resp_header(conn, "location") == ["http://test.com?error=invalid_request"]
    end

    test "unsupported response type", context do
      session_token = Token.create_token(context.client, context.user)
      params = context.params |> put_in([:response_type], "unsupported")
      conn = conn(:get, "/authorize", params)
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> context.handler.()

      assert conn.status == 302
      assert get_resp_header(conn, "location") == ["http://test.com?error=unsupported_response_type&state=abcde"]
    end

    test "only allowed response type", context do
      handler = Endpoints.authorization_handler %{allowed_response_types: ["code"]}
      session_token = Token.create_token(context.client, context.user)
      params = context.params |> put_in([:response_type], "token")
      conn = conn(:get, "/authorize", params)
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> handler.()

      assert conn.status == 302
      assert get_resp_header(conn, "location") == ["http://test.com#error=unsupported_response_type&state=abcde"]
    end

    test "fully authorized", context do
      session_token = Token.create_token(context.client, context.user)
      params = context.params |> put_in([:csrf_token], "csrftoken")
      conn = conn(:post, "/authorize", params)
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> put_session(:csrf_token, "csrftoken")
      |> context.handler.()
      post_auth_redirect_uri = get_resp_header(conn, "location") |> hd
      query = URI.parse(post_auth_redirect_uri).query
      code_string = URI.decode_query(query)["code"]
      auth_code = AuthCode.fetch_auth_code code_string

      assert conn.status == 302
      assert post_auth_redirect_uri == "http://test.com?code=#{code_string}&state=abcde"
    end

  end

  describe "requesting implicit authorization" do
    setup do
      Store.start_link %{}
      reset_stores
      context = %{
        handler:      Endpoints.authorization_handler,
        client:       Client.register_client,
        user:         User.register_user("john@example.com", "password"),
        redirect_uri: "http://test.com",
        uri:          "/authorize"
      }

      params = %{response_type: "token",
                 client_id:     context.client.client_id,
                 redirect_uri:  context.redirect_uri,
                 state:         "abcde",
                 scope:         "calendar"}

      { :ok,
        context
        |> Dict.put(:params, params)
        |> Dict.put(:query_string, URI.encode_query(params))
      }
    end

    test "valid token string matches session", context do
      session_token = Token.create_token(context.client, context.user)
      conn = conn(:get, context.uri, context.params)
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> context.handler.()

      assert conn.status == 200
    end

    test "redirects to login with no session", context do
      conn = conn(:get, context.uri, context.params)
      |> setup_conn
      |> put_req_header("accept", "text/html")
      |> context.handler.()

      assert conn.status == 302
      assert get_session(conn, :return_to) == context.uri <> "?" <> context.query_string
      assert hd(get_resp_header(conn, "location")) == "/login"
    end

    test "missing response_type", context do
      session_token = Token.create_token(context.client, context.user)
      conn = conn(:get, context.uri, context.params |> Map.delete(:response_type))
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> context.handler.()

      assert conn.status == 302
      assert hd(get_resp_header(conn, "location")) == "http://test.com?error=invalid_request&state=abcde"
    end

    test "missing client_id", context do
      session_token = Token.create_token(context.client, context.user)
      conn = conn(:get, context.uri, context.params |> Map.delete(:client_id))
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> context.handler.()

      assert conn.status == 302
      assert hd(get_resp_header(conn, "location")) == "http://test.com#error=invalid_request&state=abcde"
    end

    test "missing client_id and state", context do
      session_token = Token.create_token(context.client, context.user)
      conn = conn(:get, context.uri, context.params |> Map.delete(:client_id) |> Map.delete(:state))
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> context.handler.()

      assert conn.status == 302
      assert hd(get_resp_header(conn, "location")) == "http://test.com#error=invalid_request"
    end

    test "unsupported response type", context do
      session_token = Token.create_token(context.client, context.user)
      conn = conn(:get, context.uri, context.params |> Map.put(:response_type, "unsupported"))
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> context.handler.()

      assert conn.status == 302
      assert hd(get_resp_header(conn, "location")) == "http://test.com?error=unsupported_response_type&state=abcde"

    end

    test "posting with correct csrftoken", context do
      session_token = Token.create_token(context.client, context.user)
      conn = conn( :post, context.uri, context.params |> Map.put(:csrf_token, "csrftoken") )
      |> setup_conn
      |> put_session(:access_token, session_token.token)
      |> put_session(:csrf_token, "csrftoken")
      |> context.handler.()
      redirect_uri = get_resp_header(conn, "location") |> hd
      token_string = Regex.named_captures(~r/access_token=(?<token>[^&]+)/, redirect_uri)["token"]
      token = Token.fetch_token(token_string)

      assert conn.status == 302
      assert redirect_uri == "http://test.com#access_token=" <>
        token_string <> "&token_type=bearer&state=abcde"
    end

  end

  test "requesting unsupported grant" do
    reset_stores
    handler = Endpoints.token_handler
    client = Client.register_client

    conn = handler.(conn(:get, "/", %{grant_type: "telepathy"}))
    assert conn.status == 400
    assert hd(get_resp_header(conn, "content-type")) == "application/json"
    assert conn.resp_body == "{\"error\":\"unsupported_grant_type\"}"

    conn = handler.(conn(:get, "/", %{}))
    assert conn.status == 400
    assert hd(get_resp_header(conn, "content-type")) == "application/json"
    assert conn.resp_body == "{\"error\":\"unsupported_grant_type\"}"

  end

  describe "interactive login session" do

    setup do
      Store.start_link %{}
      reset_stores
      context = %{
        client: Client.register_client,
        user: User.register_user("john@example.com", "password")
      }
      {:ok, context}
    end

    test "login form", context do
      handler = Endpoints.login_handler %{
        login_form: fn(_) -> %{body: "login form"} end,
        client: context.client }
      user = User.register_user "john@example.com", "password"
      conn = conn( :post, "/", %{ username: "john@example.com",
                                  password: "password",
                                  csrf_token: "csrftoken" } )
      |> setup_conn
      |> put_session(:csrf_token, "csrftoken")
      |> handler.()

      token_string = get_session(conn, :access_token)
      token = Token.fetch_token(token_string)
      assert conn.status == 302
      assert hd(get_resp_header(conn, "location")) == "/"
      assert token.subject == user
      assert token.client == context.client

      conn = conn( :post, "/", %{ username: "john@example.com",
                                  password: "password",
                                  csrf_token: "csrftoken" } )
      |> setup_conn
      |> put_session(:csrf_token, "csrftoken")
      |> put_session(:return_to, "/authorization")
      |> handler.()

      token_string = get_session(conn, :access_token)
      token = Token.fetch_token(token_string)
      assert conn.status == 302
      assert hd(get_resp_header(conn, "location")) == "/authorization"
      assert get_session(conn, :return_to) == nil
      assert token.subject == user
      assert token.client == context.client

      conn = conn( :get, "/", %{} ) |> setup_conn |> handler.()
      assert conn.body == "login form"

      conn = conn( :post, "/", %{ username: "john@example.com",
                                  password: "wrong",
                                  csrf_token: "csrftoken" } )
                                  |> setup_conn
                                  |> put_session(:csrf_token, "csrftoken")
                                  |> handler.()
      assert conn.body == "login form"
    end
  end

  test "login helpers" do
    conn = conn( :get, "/", %{} ) |> setup_conn
    assert !Endpoints.logged_in?(conn)
    assert Endpoints.current_user(conn) == nil

    client = Client.register_client
    user = User.register_user("john@example.com", "password")
    session_token = Token.create_token(client, user)
    conn = conn |> Plug.Conn.assign(:access_token, session_token)
    assert Endpoints.logged_in?(conn)
    assert Endpoints.current_user(conn) == user
  end

end
