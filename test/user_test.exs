defmodule UserTest do
  use ExUnit.Case
  use Timex
  doctest Exauth.User

  alias Exauth.{User, Store}

  test "user registration" do

    Store.start_link %{}

    User.reset_user_store!
    record = User.register_user "john@example.com", "password", "John Doe", "http://example.com"
    assert record.name == "John Doe"
    assert Enum.count(User.users) == 1 # added one
    assert hd(User.users) == record # added one
    # should authenticate user
    assert User.authenticate_user("john@example.com", "password") == record
    # should not authenticate user with bad password
    assert User.authenticate_user("john@example.com", "bad") == nil
    # should not authenicate user that does not exist
    assert User.authenticate_user("idontexist", "bad") == nil

  end

  test "user store implementation" do

    Store.start_link %{}

    User.reset_user_store!
    assert Enum.count(User.users) == 0 # starts out empty
    record = User.new_user "john@example.com", "password"
    assert User.fetch_user("john@example.com") == nil
    User.store_user record
    assert User.fetch_user("john@example.com") == record
    assert Enum.count(User.users) == 1 # added one

  end

end
