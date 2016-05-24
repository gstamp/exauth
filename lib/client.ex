defmodule Exauth.Client do
  alias Exauth.{Store, Token}

  @store :client

  @doc "Create new client-application record"
  def client_app(attrs) do
    if attrs do
      Map.merge(attrs,
        %{client_id: Map.get(attrs, :client_id, Token.generate_token),
          client_secret: Map.get(attrs, :client_secret, Token.generate_token)})
    end
  end
  def client_app, do: client_app(nil, nil)
  def client_app(name, url) do
    client_app %{name: name, url: url}
  end

  @doc "mainly for used in testing. Clears out all clients."
  def reset_client_store! do
    :ok = Store.reset_store!(@store)
  end

  @doc "Find OAuth token based on the id string"
  def fetch_client(t) do
    client_app(Store.fetch(@store, t))
  end

  @doc "Store the given ClientApplication and return it."
  def store_client(t) do
    :ok = Store.store!(@store, :client_id, t)
  end

  @doc "Sequence of clients"
  def clients do
    Store.entries @store
  end

  @doc "create a unique client and store it in the client store"
  def register_client, do: register_client nil, nil
  def register_client(name, url) do
    client = client_app name, url
    store_client client
    client
  end

  @doc "authenticate client application using client_id and client_secret"
  def authenticate_client(client_id, client_secret) do
    client = fetch_client(client_id)
    if client do
      if client_secret == Map.get(client, :client_secret), do: client
    end

  end
end
