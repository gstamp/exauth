alias Timex.DateTime

defprotocol Expirable do
  @doc "Is the object still valid?"
  def is_valid?(t)
end

defimpl Expirable, for: Map do
  def is_valid?(t) do
    expiry = Map.get t, :expires
    if expiry do
      Timex.after? expiry, DateTime.today
    else
      true
    end
  end
end

defimpl Expirable, for: Atom do
  def is_valid?(nil) do
    false
  end
end
