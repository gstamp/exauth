defmodule MiddlewareTest do
  use ExUnit.Case
  use Timex
  use Plug.Test
  alias Plug.ProcessStore
  import Exauth.Middleware
  doctest Exauth.AuthCode

  defp setup_conn(conn \\ %Plug.Conn{}) do

    session_config = Plug.Session.init(store: ProcessStore, key: "foobar")
    parser_config = Plug.Parsers.init parsers: [:urlencoded]
    conn
    |> Plug.Conn.fetch_cookies
    |> Plug.Session.call(session_config)
    |> Map.put(:secret_key_base, String.duplicate("abcdefgh", 8))
    |> Plug.Conn.fetch_session
    |> Plug.Parsers.call(parser_config)

  end

  defp match_secret_token(t) do
    if t == "secrettoken", do: t
  end

  test "extract requested uri" do
    assert requested_uri(%Plug.Conn{}) == "/"
    assert requested_uri(%Plug.Conn{request_path: "/hello"}) == "/hello"
    assert requested_uri(%Plug.Conn{request_path: "/hello", query_string: "one=1&two=2"}) == "/hello?one=1&two=2"
  end

  test "assoc session value" do
    config = Plug.Session.init store: :cookie, key: "test", signing_salt: "Jk7pxAMf"
    conn = Plug.Session.call(%Plug.Conn{}, config)

    conn = assoc_session(conn, :hello, 1)
    assert conn.private.plug_session == %{"hello" => 1}
    conn = assoc_session(conn, :old, 2)
    assert conn.private.plug_session == %{"hello" => 1, "old" => 2}
    conn = assoc_session(conn, :old, 3)
    assert conn.private.plug_session == %{"hello" => 1, "old" => 3}
  end

  test "bearer token from header" do

    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    conn = app.(Plug.Conn.put_req_header(setup_conn, "authorization", "Bearer secrettoken"))
    assert conn.assigns[:access_token] == "secrettoken"

    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    conn = app.(Plug.Conn.put_req_header(setup_conn, "authorization", "Bearer wrongtoken"))
    assert conn.assigns[:access_token] == nil

    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    conn = app.(conn(:get, "/") |> setup_conn)
    assert conn.assigns[:access_token] == nil
  end

  test "bearer token from params" do

    conn = setup_conn %Plug.Conn{ query_string: "access_token=secrettoken" }
    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    assert app.(conn).assigns[:access_token] == "secrettoken"

    conn = setup_conn %Plug.Conn{ query_string: "access_token=bad" }
    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    assert app.(conn).assigns[:access_token] == nil

    conn = setup_conn %Plug.Conn{}
    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    assert app.(conn).assigns[:access_token] == nil

  end

  test "bearer token from cookies" do

    # authorization success adds oauth-token on request map
    conn = setup_conn %Plug.Conn{}
    conn = Plug.Conn.put_resp_cookie conn, "access_token", "secrettoken"
    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    assert app.(conn).assigns[:access_token] == "secrettoken"

    # should only return matching token
    conn = setup_conn %Plug.Conn{}
    conn = Plug.Conn.put_resp_cookie conn, "access_token", "bad"
    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    assert app.(conn).assigns[:access_token] == nil

    # should not set if no token present
    conn = setup_conn %Plug.Conn{}
    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    assert app.(conn).assigns[:access_token] == nil

  end

  test "bearer token from session" do

    # authorization success adds oauth-token on request map
    conn = setup_conn conn(:get, "/")
    conn = Plug.Conn.put_session conn, "access_token", "secrettoken"
    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    assert app.(conn).assigns[:access_token] == "secrettoken"

    # should only return matching token
    conn = setup_conn %Plug.Conn{}
    conn = Plug.Conn.put_session conn, "access_token", "bad"
    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    assert app.(conn).assigns[:access_token] == nil

    # should not set if no token present
    conn = setup_conn %Plug.Conn{}
    app = wrap_bearer_token(fn conn -> conn end, &match_secret_token/1)
    assert app.(conn).assigns[:access_token] == nil

  end

  test "require token" do

    # find matching token
    app = fn conn -> Plug.Conn.send_resp(conn, 200, "") end
    app = require_bearer_token!( app, &match_secret_token/1 )
    conn = conn(:get, "/") |> setup_conn |> Plug.Conn.put_req_header( "authorization", "Bearer secrettoken" )
    assert app.(conn).status == 200

    app = fn conn -> Plug.Conn.send_resp(conn, 200, "") end
    app = require_bearer_token!( app, &match_secret_token/1 )
    conn = conn(:get, "/protected", "test=123")
    |> setup_conn
    |> Plug.Conn.put_req_header( "accept", "text/html" )
    resp_conn = app.(conn)
    assert resp_conn.status == 302
    assert hd(get_resp_header(resp_conn, "location")) == "/login"
    assert "/protected?test=123", get_session(resp_conn, :return_to)

    # bad token
    app = fn conn -> Plug.Conn.send_resp(conn, 200, "") end
    app = require_bearer_token!( app, &match_secret_token/1 )
    conn = conn(:get, "/") |> setup_conn |> Plug.Conn.put_req_header( "authorization", "Bearer bad" )
    assert app.(conn).status == 401

    # no token
    app = fn conn -> Plug.Conn.send_resp(conn, 200, "") end
    app = require_bearer_token!( app, &match_secret_token/1 )
    conn = conn(:get, "/") |> setup_conn
    assert app.(conn).status == 401

  end

  test "require user session" do

    # find matching token
    ok_app = fn conn -> Plug.Conn.send_resp(conn, 200, "") end
    app = require_user_session!( ok_app, &match_secret_token/1 )
    conn = conn(:get, "/") |> setup_conn |> Plug.Conn.put_session(:access_token, "secrettoken")
    assert app.(conn).status == 200

    app = require_user_session!( ok_app, &match_secret_token/1 )
    conn = conn(:get, "/protected", "test=123")
    |> setup_conn
    |> Plug.Conn.put_req_header( "accept", "text/html" )
    resp_conn = app.(conn)
    assert resp_conn.status == 302
    assert hd(get_resp_header(resp_conn, "location")) == "/login"
    assert "/protected?test=123", get_session(resp_conn, :return_to)

    # disallow from auth header
    app = require_user_session!( ok_app, &match_secret_token/1 )
    conn = conn(:get, "/") |> setup_conn |> Plug.Conn.put_req_header( "authorization", "Bearer secrettoken" )
    assert app.(conn).status == 403

    # disallow from cookies
    app = require_user_session!( ok_app, &match_secret_token/1 )
    conn = conn(:get, "/") |> setup_conn |> Plug.Conn.put_resp_cookie( "access_token", "secrettoken" )
    assert app.(conn).status == 403

    # disallow from params
    app = require_user_session!( ok_app, &match_secret_token/1 )
    conn = conn(:get, "/", "access_token=secrettoken") |> setup_conn
    assert app.(conn).status == 403

  end

  test "request is html" do

    refute is_html?(%Plug.Conn{})
    refute is_html?(%Plug.Conn{} |> put_req_header("accept", "*/*"))
    refute is_html?(%Plug.Conn{} |> put_req_header("accept", "application/json"))

    assert is_html?(%Plug.Conn{} |> put_req_header("accept", "text/html"))
    assert is_html?(%Plug.Conn{} |> put_req_header("accept", "application/xhtml+xml"))
    assert is_html?(%Plug.Conn{} |> put_req_header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"))

  end

  test "request is form" do

    refute is_form?( setup_conn )
    refute is_form?( setup_conn |> put_req_header("content-type", "application/json") |> assign(:access_token, "acde") |> put_session(:access_token, "abcde") )
    refute is_form?( setup_conn |> put_req_header("content-type", "application/xml") |> assign(:access_token, "acde") |> put_session(:access_token, "abcde") )
    assert is_form?( setup_conn |> put_req_header("content-type", "application/x-www-form-urlencoded") |> assign(:access_token, "acde") |> put_session(:access_token, "abcde") )
    assert is_form?( setup_conn |> put_req_header("content-type", "multipart/form-data") )
    refute is_form?( setup_conn |> put_req_header("content-type", "application/json") )
    refute is_form?( setup_conn |> put_req_header("content-type", "application/xml") )
    assert is_form?( setup_conn |> put_req_header("content-type", "application/x-www-form-urlencoded") )
    assert is_form?( setup_conn |> put_req_header("content-type", "multipart/form-data") )
    refute is_form?( setup_conn |> put_req_header("content-type", "application/json") |> assign(:access_token, "acde") )
    refute is_form?( setup_conn |> put_req_header("content-type", "application/xml") |> assign(:access_token, "acde") )
    refute is_form?( setup_conn |> put_req_header("content-type", "application/x-www-form-urlencoded") |> assign(:access_token, "acde") )
    refute is_form?( setup_conn |> put_req_header("content-type", "multipart/form-data") |> assign(:access_token, "acde") )

  end

  test "request if html" do

    refute if_html setup_conn, do: true, else: false
    refute if_html setup_conn |> put_req_header("accept", "*/*"), do: true, else: false
    refute if_html setup_conn |> put_req_header("accept", "application/json"), do: true, else: false
    assert if_html setup_conn |> put_req_header("accept", "text/html"), do: true, else: false
    assert if_html setup_conn |> put_req_header("accept", "application/xhtml+xml"), do: true, else: false
    assert if_html setup_conn |> put_req_header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"), do: true, else: false

  end

  test "request if form" do

    refute if_form setup_conn, do: true, else: false
    refute if_form setup_conn |> put_req_header("content-type", "application/json"), do: true, else: false
    refute if_form setup_conn |> put_req_header("content-type", "application/xml"), do: true, else: false
    assert if_form setup_conn |> put_req_header("content-type", "application/x-www-form-urlencoded") |> assign(:access_token, "acde") |> put_session(:access_token, "abcde"), do: true, else: false
    assert if_form setup_conn |> put_req_header("content-type", "multipart/form-data") |> assign(:access_token, "acde") |> put_session(:access_token, "abcde"), do: true, else: false

  end

  test "csrf token extraction" do

    refute csrf_token(setup_conn)
    assert csrf_token(setup_conn |> put_session(:csrf_token, "token")) == "token"
    assert csrf_token(setup_conn |> assign(:csrf_token, "token")) == "token"

  end

  test "csrf is added to session" do
    # Should add a csrf-token entry to request if none is in session
    assert with_csrf_token(setup_conn).assigns[:csrf_token] != nil

    # should not add to request if one is already in request
    refute with_csrf_token(setup_conn |> put_session(:csrf_token, "existing")).assigns[:csrf_token]
  end

  test "protects against csrf" do

    handler = csrf_protect! fn(conn) -> conn end
    conn = conn(:get, "/")
    |> setup_conn
    |> put_req_header("accept", "text/html")
    |> assign(:access_token, "abcde")
    |> put_session(:access_token, "abcde")
    assert handler.(conn) |> get_session(:csrf_token)

    conn = conn(:get, "/")
    |> setup_conn
    |> put_session(:csrf_token, "existing")
    assert handler.(conn) |> get_session(:csrf_token) == "existing"

    # should fail for html post without token
    handler = csrf_protect! fn(conn) -> Plug.Conn.send_resp(conn, 200, "") end
    conn = conn(:post, "/")
    |> setup_conn
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> assign(:access_token, "abcde")
    |> put_session(:access_token, "abcde")
    assert handler.(conn).status == 403

    # should allow non html
    conn = conn(:post, "/")
    |> setup_conn
    |> put_req_header("content-type", "application/json")
    |> assign(:access_token, "abcde")
    |> put_session(:access_token, "abcde")
    assert handler.(conn).status == 200

    conn = conn(:post, "/")
    |> setup_conn
    |> put_req_header("content-type", "text/html")
    |> assign(:access_token, "abcde")
    |> put_session(:access_token, "abcde")
    assert handler.(conn).status == 200

    conn = conn(:get, "/")
    |> setup_conn
    |> put_req_header("accept", "text/html")
    assert handler.(conn) |> get_session(:csrf_token)

    # TODO: Not sure how to check if session was not set
    # conn = conn(:get, "/")
    # |> setup_conn
    # |> put_req_header("accept", "text/html")
    # |> put_session(:csrf_token, "existing")
    # refute handler.(conn) |> get_session(:csrf_token)

    conn = conn(:post, "/")
    |> setup_conn
    |> Map.put(:params, %{"csrf_token" => "secrettoken"})
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> assign(:access_token, "abcde")
    |> put_session(:csrf_token, "secrettoken")
    |> put_session(:access_token, "abcde")
    assert handler.(conn).status == 200

    conn = conn(:post, "/", %{"csrf_token" => "badtoken"})
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> setup_conn
    |> assign(:access_token, "abcde")
    |> put_session(:csrf_token, "secrettoken")
    |> put_session(:access_token, "abcde")
    assert handler.(conn).status == 403

    conn = conn(:post, "/")
    |> setup_conn
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> assign(:access_token, "abcde")
    |> put_session(:csrf_token, "secrettoken")
    |> put_session(:access_token, "abcde")
    assert handler.(conn).status == 403

  end


end
