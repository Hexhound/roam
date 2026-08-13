defmodule SyncWeb.CachingBodyReader do
  @moduledoc """
  A `Plug.Parsers` body reader that caches the raw request-body chunks into
  `conn.assigns[:raw_body]` as it reads them.

  BE3: `Plug.Parsers` runs on every request. Without this, a client that PUTs
  opaque ciphertext under `Content-Type: application/json` (or a form type) has
  its body consumed by the parser, leaving the raw-bytes controller's own
  `read_body/2` with `""` — silently poisoning the content-addressed id for
  every peer (the zero-knowledge backend cannot re-verify `id == hash(body)`).

  Controllers recover the untouched bytes via `cached_body/1`.
  """

  @doc "Reader passed to `Plug.Parsers`; forwards to `Plug.Conn.read_body/2` and caches each chunk."
  def read_body(conn, opts) do
    case Plug.Conn.read_body(conn, opts) do
      {:ok, body, conn} -> {:ok, body, cache(conn, body)}
      {:more, body, conn} -> {:more, body, cache(conn, body)}
      {:error, _} = error -> error
    end
  end

  @doc """
  Returns `{:ok, body}` with the full raw body if `Plug.Parsers` already read it,
  otherwise `:none` (the parser passed the body through untouched — the caller
  should read it itself).
  """
  def cached_body(conn) do
    case conn.assigns[:raw_body] do
      nil -> :none
      chunks -> {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}
    end
  end

  defp cache(conn, body) do
    update_in(conn.assigns[:raw_body], fn chunks -> [body | chunks || []] end)
  end
end
