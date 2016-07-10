defmodule Exauth.Store do
  use ExActor.GenServer, export: :store

  defstart start_link(store_impl), do: initial_state(store_impl)

  @doc "Find the item based on a key."
  defcall fetch(type, k), state: store_impl do
    reply KeyStore.fetch(store_impl, type, k)
  end

  @doc "Invalidate or remove the item based on a key"
  defcast revoke!(type, k), state: store_impl do
    new_state KeyStore.revoke!(store_impl, type, k)
  end

  @doc "KeyStore the given map using the value of the kw key_param and return it."
  defcast store!(type, key_param, item), state: store_impl do
    new_state KeyStore.store!(store_impl, type, get_in(item, [key_param]), item)
  end

  @doc "sequence of entries"
  defcall entries(type), state: store_impl do
    reply KeyStore.entries(store_impl, type)
  end

  @doc "clear all entries"
  defcast reset_store!(type), state: store_impl do
    KeyStore.reset_store!(store_impl, type)
    |> new_state
  end

end
