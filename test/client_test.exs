defmodule ClientTest do
  use ExUnit.Case
  use Timex
  doctest Exauth.Token

  alias Exauth.{Client, Store}

  test "client registration" do

    Store.start_link %{}

    Client.reset_client_store!
    record = Client.register_client("Super company inc", "http://example.com")
    client_id = record.client_id
    client_secret = record.client_secret
    assert record.name == "Super company inc" # should add extra attributes to the client
    assert client_id != nil # should include client_id field
    assert client_secret != nil # should include client secret field
    assert Enum.count(Client.clients) == 1  # added one
    assert hd(Client.clients) == record # added one
    assert Client.authenticate_client(client_id, client_secret) == record # should authenticate client
    assert Client.authenticate_client(client_id, "bad") == nil # should not authenticate clients with wrong password
    assert Client.authenticate_client("idontexist", "bad") == nil # should not authenticate client with wrong id
  end

  test "client store implementation" do

    Store.start_link %{}

    Client.reset_client_store!
    assert Enum.count(Client.clients) == 0
    record = Client.client_app
    assert Client.fetch_client(record.client_id) == nil
    Client.store_client record
    assert Client.fetch_client(record.client_id) == record
    assert Enum.count(Client.clients) == 1

  end


end
