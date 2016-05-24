defmodule Exauth.User do

  @store "user"

  alias Exauth.{Store}
  import Comeonin.Bcrypt

  def bcrypt(password) do
    hashpwsalt(password)
  end

  @doc "Verify that candidate password matches the hashed bcrypted password"
  def valid_password?(candidate, hashed) do
    checkpw(candidate, hashed)
  end

  @doc "Create new user record"
  def new_user(attrs) do
    if attrs do
      if Map.get(attrs, :encrypt_password) do
        Map.put(Map.delete(attrs, :encrypt_password),
          :password,
          bcrypt(attrs.encrypt_password))
      else
        attrs
      end
    end
  end
  def new_user(login, password), do: new_user(login, password, nil, nil)
  def new_user(login, password, name, url) do
    new_user(%{login: login, encrypt_password: password, name: name, url: url})
  end

  @doc "mainly for used in testing. Clears out all users."
  def reset_user_store! do
    Store.reset_store! @store
  end

  @doc "Find user based on login"
  def fetch_user(t) do
    new_user Store.fetch(@store, t)
  end

  @doc "Store the given User and return it."
  def store_user(t) do
    Store.store! @store, :login, t
    t
  end

  @doc "Sequence of users"
  def users do
    Store.entries @store
  end

  @doc "create a unique user and store it in the user store"
  def register_user(attrs) do
    attrs |> new_user |> store_user
  end
  def register_user(login, password) do
    register_user(login, password, nil, nil)
  end
  def register_user(login, password, name, url) do
    new_user(login, password, name, url)
    |> register_user
  end

  @doc "authenticate user application using login and password"
  def authenticate_user(login, password) do
    user = fetch_user(login)
    if user do
      if valid_password?(password, user.password), do: user
    end
  end

end
