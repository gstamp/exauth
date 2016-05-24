defmodule Exauth.Token do

  alias Exauth.Store

  @store :token

  @doc "generate a unique token"
  def generate_token do
    Base.encode32 :crypto.strong_rand_bytes(20), padding: false
  end

  @doc """
  The oauth-token defines supports various functions to verify the validity

     The following keys are defined:

     * token - a unique token identifying it
     * client - a map/record of the client app who was issued the token
     * subject - the subject who authorized the token - eg. user
     * expires - Optional time of expiry
     * scope   - An optional vector of scopes authorized
     * object  - An optional object authorized. Eg. account, photo"
  """
  def oauth_token(attrs) do
    if attrs do
      if Map.get attrs, :token do
        attrs
      else
        Map.put(attrs, :token, generate_token)
      end
    end
  end
  def oauth_token(client, subject) do
    oauth_token(client, subject, nil, nil, nil)
  end
  def oauth_token(client, subject, expires, scope, object) do
    oauth_token(generate_token, client, subject, expires, scope, object)
  end
  def oauth_token(token, client, subject, expires, scope, object) do
    oauth_token(%{
          token: token, client: client, subject: subject, expires: expires,
          score: scope, object: object
                })
  end

  def create_token(client, subject), do: create_token(oauth_token(client, subject))
  def create_token(client, subject, scope, object), do: create_token(oauth_token(client, subject, nil, scope, object))
  def create_token(client, subject, expires, scope, object), do: create_token(oauth_token(client, subject, expires, scope, object))
  def create_token(token) do
    token = oauth_token(token)
    store_token(token)
    token
  end

  @doc "return a token from the store if it is valid."
  def find_valid_token(t) do
    token = fetch_token(t)
    if Expirable.is_valid?(token) do
      token
    end
  end

  @doc "return tokens matching a given criteria"
  def find_tokens_for(criteria) do
    Enum.filter tokens(), &( criteria == Map.take(&1, Map.keys(criteria)) )
  end

  @doc "mainly used in testing. Clears out all auth-codes."
  def reset_token_store!, do: :ok = Store.reset_store!(@store)

  @doc "Find OAuth token based on the token string"
  def fetch_token(t) do
    token = Store.fetch(@store, t)
    oauth_token(token)
  end

  @doc "Store the given OAuthToken and return it."
  def store_token(t), do: :ok = Store.store! @store, :token, t

  @doc "Revoke the given OAuth token, given either a token string or object."
  def revoke_token(t) when is_binary(t) do
    :ok = Store.revoke! @store, t.token
  end
  def revoke_token(t), do: :ok = Store.revoke! @store, t.token

  @doc "Sequence of tokens"
  def tokens do
    Enum.map Store.entries(@store), &oauth_token/1
  end

end


