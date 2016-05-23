defprotocol KeyStore do
  @doc "Find the item based on a key."
  def fetch(e, k)

  @doc "Invalidate or remove the item based on a key"
  def revoke!(e, k)

  @doc "KeyStore the given map using the value of the kw key_param and return it."
  def store!(e, key_param, item)

  @doc "sequence of entries"
  def entries(e)

  @doc "clear all entries"
  def reset_store!(e)
end

defimpl KeyStore, for: Map do
  def fetch(map, k), do: Map.get(map, k)
  def revoke!(map, k), do: Map.delete(map, k)
  def store!(map, key_param, item), do: Map.put(map, key_param, item)
  def entries(map), do: Map.values(map)
  def reset_store!(_), do: %{}
end
