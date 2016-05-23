defmodule TokenTest do
  use ExUnit.Case
  use Timex
  doctest Exauth.Token

  alias Exauth.{Token, Store}

  test "token records" do
    record = Token.oauth_token "my-client", "user"
    assert record.client == "my-client"
    assert record.subject == "user"
    assert record.token != nil
    assert Expirable.is_valid?(record) == true # should be valid by default.
  end

  test "token creation" do

    Store.start_link %{}

    Token.reset_token_store!

    assert Enum.count(Token.tokens) == 0 # starts out empty
    record = Token.create_token "my-client", "my-user"
    assert record.client == "my-client"
    assert record.subject == "my-user"
    assert record.token != nil # should include token field
    assert Enum.count(Token.tokens) == 1 # added one
    assert Token.find_valid_token(record.token) == record
  end

  test "token store implementation" do

    Store.start_link %{}

    Token.reset_token_store!
    assert Enum.count(Token.tokens) == 0 # starts out empty
    record = Token.oauth_token "my-client", "my-user"
    assert Token.fetch_token(record.token) == nil

    Token.store_token record
    assert Token.fetch_token(record.token) == record
    assert Enum.count(Token.tokens) == 1

    Token.revoke_token record
    assert Token.fetch_token(record.token) == nil
    assert Enum.count(Token.tokens) == 0
  end

  test "find matching tokens in store" do

    Store.start_link %{}

    Token.reset_token_store!

    assert Enum.empty?(Token.find_tokens_for(%{client: "my-client", subject: "my-user"}))
    record = Token.create_token %{client: "my-client", subject: "my-user"}
    assert Token.find_tokens_for(%{client: "my-client", subject: "my-user"}) == [record]
    assert Enum.empty?(Token.find_tokens_for(%{client: "my-client", subject: "other-user"}))
    assert Enum.empty?(Token.find_tokens_for(%{client: "other-client", subject: "my-user"}))

  end

end
