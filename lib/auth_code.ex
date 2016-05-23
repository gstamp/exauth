defmodule Exauth.AuthCode do
  use Timex

  alias Exauth.{Token, Store}

  @doc """
  The oauth-code defines supports various functions to verify the validity
  The following keys are defined:
     * auth-code - a unique auth-code identifying it
     * client - a map/record of the client app who was issued the auth-code
     * subject - the subject who authorized the auth-code - eg. user
     * redirect-uri - the redirect-uri passed during authorization
     * expires - Optional time of expiry
     * scope   - An optional vector of scopes authorized
     * object  - An optional object authorized. Eg. account, photo
  """
  def oauth_code(attrs) do
    if attrs do
      attrs = if Map.has_key? attrs, :code do
        attrs
      else
        Map.put(attrs, :code, Token.generate_token)
      end
      if Map.get(attrs, :expires) do
        attrs
      else
        Map.put(attrs, :expires, Timex.shift(DateTime.today, days: 1))
      end
    end
  end

  def oauth_code(client, subject, redirect_uri) do
    oauth_code client, subject, redirect_uri, nil, nil
  end

  def oauth_code(client, subject, redirect_uri, scope, object) do
    oauth_code Token.generate_token, client, subject, redirect_uri, scope, object
  end

  def oauth_code(code, client, subject, redirect_uri, scope, object) do
    oauth_code %{
      code: code, client: client, subject: subject, redirect_uri: redirect_uri,
      scope: scope, object: object
    }
  end

  @doc "create a unique auth-code and store it in the auth-code store"
  def create_auth_code(client, subject, redirect_uri) do
    create_auth_code oauth_code(client, subject, redirect_uri)
  end
  def create_auth_code(client, subject, redirect_uri, scope, object) do
    create_auth_code oauth_code(client, subject, redirect_uri, scope, object)
  end
  def create_auth_code(oauth_code) do
    code = oauth_code(oauth_code)
    store_auth_code code
    code
  end

  @doc "return a auth-code from the store if it is valid."
  def find_valid_auth_code(t) do
    oauth_code = fetch_auth_code(t)
    if oauth_code do
      if Expirable.is_valid?(oauth_code), do: oauth_code
    end
  end

  @doc "mainly used in testing. Clears out all auth-codes."
  def reset_auth_code_store!, do: :ok = Store.reset_store!

  @doc "Find OAuth auth-code based on the auth-code string"
  def fetch_auth_code(t) do
    Store.fetch(t) |> oauth_code()
  end

  @doc "Revoke the auth code so it can no longer be used"
  def revoke_auth_code!(code), do: :ok = Store.revoke(code.code)

  @doc "Store the given OAuthCode and return it."
  def store_auth_code(t), do: :ok = Store.store!(:code, t)

  @doc "Sequence of auth-codes"
  def auth_codes do
    Enum.map Store.entries, &oauth_code/1
  end


end
