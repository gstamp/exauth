defprotocol KeyStore do
  @doc "Find the item based on a key."
  def fetch(e, type, k)

  @doc "Invalidate or remove the item based on a key"
  def revoke!(e, type, k)

  @doc "KeyStore the given map using the value of the kw key_param and return it."
  def store!(e, type, key_param, item)

  @doc "sequence of entries"
  def entries(e, type)

  @doc "clear all entries"
  def reset_store!(e, type)
end

defimpl KeyStore, for: Map do
  def fetch(map, type, k) do
    Map.get(map, type, %{}) |> Map.get(k)
  end
  def revoke!(map, type, k) do
    submap = map |> Map.get(type, %{}) |> Map.delete(k)
    map |> Map.put(type, submap)
  end
  def store!(map, type, key_param, item) do
    map = unless Map.has_key?(map, type), do: Map.put(map, type, %{}), else: map
    put_in(map, [type, key_param], item)
  end
  def entries(map, type) do
    Map.get(map, type, %{}) |> Map.values
  end
  def reset_store!(map, type) do
    put_in(map, [type], %{})
  end
end
