defmodule SyncWeb.RendezvousController do
  @moduledoc """
  The pairing mailbox over HTTP. Six write-once slots per session; see
  `Sync.Backend.Mailbox` for what the relay does and does not learn.

  Unauthenticated, like every other route here — the relay authenticates nobody
  and holds nothing it can read. What bounds abuse is that a rendezvous id is 32
  unguessable bytes, so these routes cannot be found by enumeration, plus the
  per-rendezvous session cap and the body cap below.
  """
  use SyncWeb, :controller

  alias Sync.Backend.Mailbox

  def sessions(conn, %{"rendezvous" => rendezvous}) do
    if Mailbox.valid_id?(rendezvous) do
      json(conn, %{sessions: Mailbox.sessions(rendezvous)})
    else
      send_resp(conn, 400, "bad rendezvous id")
    end
  end

  def get_slot(conn, %{"rendezvous" => rendezvous, "session" => session, "slot" => slot}) do
    with :ok <- guard(rendezvous, session, slot) do
      case Mailbox.get(rendezvous, session, slot) do
        nil ->
          # Absence is the normal case while a device polls for the other side's
          # next message, not an error.
          send_resp(conn, 404, "")

        bytes ->
          conn |> put_resp_content_type("application/octet-stream") |> send_resp(200, bytes)
      end
    else
      {:error, reason} -> send_resp(conn, 400, reason)
    end
  end

  def put_slot(conn, %{"rendezvous" => rendezvous, "session" => session, "slot" => slot}) do
    with :ok <- guard(rendezvous, session, slot),
         {:ok, body, conn} <- read_raw_body(conn, length: Mailbox.max_body_bytes()) do
      case Mailbox.put(rendezvous, session, slot, body) do
        :created ->
          send_resp(conn, 201, "")

        # The write-once refusal. A client MUST treat this as "this session is
        # not mine to finish" and abandon it — see the module note on squatting.
        :exists ->
          send_resp(conn, 409, "")

        :too_many_sessions ->
          send_resp(conn, 429, "too many pairing sessions at this rendezvous")
      end
    else
      {:error, reason} -> send_resp(conn, 400, reason)
      # Over the cap — fail closed rather than crashing into a 500.
      {:more, _partial, conn} -> send_resp(conn, 413, "payload too large")
    end
  end

  # Reject bad ids BEFORE touching the filesystem (path traversal defense), and
  # reject any slot name outside the six the handshake defines — this is a
  # pairing mailbox, not a general object store.
  defp guard(rendezvous, session, slot) do
    cond do
      not Mailbox.valid_id?(rendezvous) -> {:error, "bad rendezvous id"}
      not Mailbox.valid_id?(session) -> {:error, "bad session id"}
      not Mailbox.valid_slot?(slot) -> {:error, "unknown slot"}
      true -> :ok
    end
  end

  # Same reasoning as SyncController: if Plug.Parsers already consumed the body,
  # recover the untouched raw bytes from the caching reader rather than reading
  # an emptied stream.
  defp read_raw_body(conn, opts) do
    case SyncWeb.CachingBodyReader.cached_body(conn) do
      {:ok, body} -> {:ok, body, conn}
      :none -> read_body(conn, opts)
    end
  end
end
