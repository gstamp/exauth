defmodule AuthCodeTest do
  use ExUnit.Case
  use Timex
  doctest Exauth.AuthCode

  alias Exauth.{AuthCode, Store}

  test "Auth code records" do
    record = AuthCode.oauth_code "my-client", "user", "http://test.com/redirect"

    assert record.client == "my-client", "should have client"
    assert record.subject == "user", "should have subject"
    assert record.redirect_uri == "http://test.com/redirect", "should have redirect_uri"
    assert record.code, "should include code field"
    assert Expirable.is_valid?(record), "should be valid by default"

  end

  test "Auth code creation" do
    Store.start_link(%{})

    assert Enum.count(AuthCode.auth_codes) == 0, "starts out empty"

    record = AuthCode.create_auth_code "my-client", "my-user", "http://test.com/redirect"
    assert record.client == "my-client" # should have client
    assert record.subject == "my-user"  # should have subject
    assert record.redirect_uri == "http://test.com/redirect" # should have redirect_uri
    assert !(record.code == nil) # should include auth-code field
    assert Enum.count(AuthCode.auth_codes) == 1 # added one
    assert record == AuthCode.find_valid_auth_code(record.code)

    record = AuthCode.create_auth_code %{client: "my-client", subject: "my-user", redirect_uri: "http://test.com/redirect"}

    assert record.client == "my-client" # should have client
    assert record.subject == "my-user" # should have subject
    assert record.redirect_uri == "http://test.com/redirect" # should have redirect_uri
    assert !(record.code == nil) # should include auth-code field
    assert Enum.count(AuthCode.auth_codes) == 2 # added one
    assert record == AuthCode.find_valid_auth_code(record.code)
  end

  # Move the expirable tests into another test module
  test "auth code validity" do
    assert Expirable.is_valid? %{} # by default it's valid
    assert !Expirable.is_valid? nil # nil is always false
    assert Expirable.is_valid? %{expires: Timex.shift(DateTime.today, days: 1)} # valid if expiry date is in the future
  end

  test "auth code store implemetation" do
    Store.start_link(%{})

    AuthCode.reset_auth_code_store!
    assert Enum.count(AuthCode.auth_codes) == 0 # starts out empty
    record = AuthCode.oauth_code "my-client", "my-user", "http://test.com/redirect"
    assert AuthCode.fetch_auth_code(record.code) == nil

    AuthCode.store_auth_code record
    assert record == AuthCode.fetch_auth_code(record.code)
    assert Enum.count(AuthCode.auth_codes) == 1 # added one
  end
end


