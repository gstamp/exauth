defmodule Exauth.Views do
  use Eml.Language.HTML
  import Plug.Conn
  alias Exauth.{Middleware, Client}

  @doc "hidden form field containing csrf-token"
  def csrf_field(conn) do
    hidden_field "csrf_token", Middleware.csrf_token(conn)
  end

  defp hidden_field(name, val) do
    input type: "hidden", name: name, value: val
  end

  defp text_field(%{name: name, value: value}) do
    input name: name, value: value
  end

  @doc "Include certain parameters as hidden fields if present"
  def include_hidden_params(%{params: params}, fields) do
    select_keys(params, fields)
    |> Enum.filter( fn {_name, val} -> val end )
    |> Enum.map( fn {key,val} -> hidden_field(key,val) end )
  end

  def login_form(conn) do
    login_form(conn, conn.request_path, conn.params["username"], conn.params["password"] )
  end
  def login_form(conn, uri, username, password) do
    form method: "POST", action: uri do
      csrf_field(conn)
      label name: :username, value: "User name:"
      text_field name: :username, value: username
      label name: :password, value: "Password:"
      text_field name: :password, value: password
      div class: "form-actions" do
        button type: "submit", class: "btn btn-primary", do: "Login"
      end
    end |> Eml.render
  end

  @doc "Login form handler"
  def login_form_handler(conn) do
    conn
    |> put_resp_header( "content-type", "text/html" )
    |> send_resp( 200, login_form(conn) )
  end

  def authorization_form(conn) do
    client = Client.fetch_client(conn.params["client_id"])
    form method: "POST", action: conn.request_path do
      csrf_field conn
      include_hidden_params conn, [:client_id, :response_type, :redirect_uri, :scope, :state]
      h2 "#{client.name} requested authorization"
      div class: "form-actions" do
        button type: "submit", class: "btn btn-primary" do
          "Authorize"
        end
        a class: "btn", href: conn.params[:redirect_uri] || "/" do
          "Cancel"
        end
      end
    end |> Eml.render
  end

  @doc "Login form ring handler"
  def authorization_form_handler(conn) do
    conn
    |> put_resp_header( "content-type", "text/html" )
    |> send_resp( 200, authorization_form(conn) )
  end

  @doc "returns a simple error page"
  def error_page(conn, error) do
    response = Eml.render(h1 do
                           error
    end)
    conn
    |> send_resp( 200, response )
  end

  def hello_word(conn) do
    user = conn.assigns[:access_token].subject
    response = Eml.render(h1 do
                           user.login
    end)
    conn |> send_resp( 200, response )
  end

  # TODO: This is duplicated
  defp select_keys(map, keys) do
    selector = fn({k,_v}) -> Enum.member? keys, k end
    map |> Enum.filter(selector) |> Enum.into(%{})
  end


end
