defmodule Sync.Rbsr do
  @moduledoc """
  RBSR server-side reconcile, delegated to the shared `roam-rbsr` Rust core via a
  Rustler NIF. `items` is a concatenated binary of 32-byte ids; `msg` is a raw
  negentropy protocol frame. Returns the reply frame.
  """
  use Rustler, otp_app: :sync, crate: :roam_rbsr_nif

  @doc "Fold a client message over `items`, returning the negentropy reply."
  @spec reconcile_server(binary(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def reconcile_server(_items, _msg), do: :erlang.nif_error(:nif_not_loaded)
end
