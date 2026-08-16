defmodule Sync.Backend.Mailbox do
  @moduledoc """
  Write-once slots for device pairing, and nothing more.

  Two devices that want to join the same vault may have no way to reach each
  other — a browser tab cannot open a UDP socket, so it can never be an iroh
  peer. The relay already stands between them, so it can carry the handshake.
  This is the smallest shape that lets it, while keeping the relay exactly as
  ignorant as it is for everything else it stores.

  ## Layout

      <root>/<rendezvous>/<session>/<slot>

  A **rendezvous** is named by 32 unguessable bytes the host mints. A **session**
  is named by 32 bytes a joiner mints; a rendezvous holds several because a
  joiner that spoils one (or an attacker that squats one) must be able to start
  a clean one. A session holds at most the six named slots of the handshake.

  ## What the relay knows

  Nothing. Every slot body is either a SPAKE2 message — which by construction
  reveals nothing testable about the pairing code — or a ciphertext sealed under
  a key derived from that code. The rendezvous id is not derived from the bucket
  id and does not appear anywhere else, so the relay cannot tell which of the
  buckets it stores a pairing belongs to, or whether it stores it at all.

  ## Write-once, and why the relay has to enforce it

  A slot that already holds bytes is never overwritten; the second writer gets
  `:exists` and the stored body is untouched. That is not about tamper-detection
  — the handshake's own confirmations are MACs over the full transcript, so
  rewriting a message fails whatever the relay does. It is about *squatting*:
  anyone who knows the rendezvous can take the slot the host was about to write,
  and a host that shrugged and carried on would verify a confirmation against a
  transcript it never wrote, spending one of its three attempts. Three of those
  retire a pairing code without the squatter guessing a digit. Refusing the write
  is what makes the host able to notice and bail out for free.

  ## Separate root, deliberately

  Mailboxes live in a sibling directory of the bucket store, not inside it. Two
  reasons, both load-bearing: `Sync.Backend.Sweeper` treats every directory under
  the bucket root as a bucket to run snapshot retention over, and bucket names
  are client-controlled — a client could PUT to a bucket named like whatever
  reserved subdirectory we picked, and reach these files through the wrong routes.
  """

  alias Sync.Backend.Store

  # The six slots of `roam_pairing::mailbox::Slot`, and the only names accepted.
  # An allowlist rather than a charset check: this is a pairing mailbox, not a
  # general-purpose object store, and it should be impossible to use it as one.
  @slots ~w(msg1 msg2 confirm-joiner confirm-host request accept)

  # Rendezvous and session ids are always 32 bytes of base64url. Requiring the
  # exact length (rather than Store.valid_id?'s "<= 128 chars") bounds directory
  # names and rejects anything that could not have come from the protocol.
  @id_length 43

  # One accept carries the host's transitive roster and key log, which grow with
  # the number of devices and role changes. Generous enough not to cap a real
  # vault, bounded so an unauthenticated writer cannot fill a disk with one PUT.
  @max_body_bytes 4_000_000

  # Enough for a joiner to retry, and for a few squatters, without letting anyone
  # create directories under one rendezvous without limit.
  @max_sessions 64

  # A pairing window is five minutes; anything untouched for this long is dead.
  @default_ttl_ms 30 * 60 * 1000

  @doc "The slot names this mailbox accepts."
  def slots, do: @slots

  @doc "Maximum body size for one slot, in bytes."
  def max_body_bytes, do: @max_body_bytes

  @doc "Maximum concurrent sessions under one rendezvous."
  def max_sessions, do: @max_sessions

  @doc """
  Absolute mailbox root — a *sibling* of the bucket store, never inside it. See
  the module note on why that separation matters.
  """
  def data_root do
    Application.get_env(:sync, :mailbox_data_root) || Store.data_root() <> "-rendezvous"
  end

  @doc "Whether `id` could be a rendezvous or session id."
  @spec valid_id?(String.t()) :: boolean()
  def valid_id?(id),
    do: is_binary(id) and byte_size(id) == @id_length and Store.valid_id?(id)

  @doc "Whether `slot` is one of the six handshake slots."
  @spec valid_slot?(String.t()) :: boolean()
  def valid_slot?(slot), do: slot in @slots

  @doc """
  Write a slot.

  `:created` on the first write, `:exists` if it was already taken (the stored
  body is left alone), `:too_many_sessions` if this would open a new session past
  the cap.
  """
  @spec put(String.t(), String.t(), String.t(), binary()) ::
          :created | :exists | :too_many_sessions
  def put(rendezvous, session, slot, bytes) do
    session_dir = Path.join([data_root(), rendezvous, session])
    path = Path.join(session_dir, slot)

    cond do
      File.exists?(path) ->
        :exists

      not File.dir?(session_dir) and session_count(rendezvous) >= @max_sessions ->
        :too_many_sessions

      true ->
        File.mkdir_p!(session_dir)
        # Write to a temporary name first, so a reader never observes a
        # half-written slot.
        tmp = path <> ".tmp." <> Integer.to_string(System.unique_integer([:positive]))
        File.write!(tmp, bytes)

        # THIS is what enforces write-once, not the `File.exists?` above — that
        # one is only a fast path that avoids a pointless write for a repeat
        # writer, and two concurrent requests can both sail past it. `File.ln`
        # fails if the target exists, atomically, which is exactly the semantics
        # a write-once slot needs; `File.rename` would silently clobber.
        #
        # Mutation-checked, and worth recording because the result was not what
        # it looks like: removing EITHER guard alone breaks nothing, because
        # sequentially they cover for each other. Only removing both fails
        # `a taken slot refuses the second write`, and only a concurrent test
        # (`two simultaneous writers`) distinguishes the link from the rename.
        case File.ln(tmp, path) do
          :ok ->
            File.rm(tmp)
            :created

          {:error, _already_there_or_unsupported} ->
            File.rm(tmp)
            if File.exists?(path), do: :exists, else: slow_path_write(tmp, path, bytes)
        end
    end
  end

  # Filesystems without hard links (rare, but not worth crashing on) fall back to
  # rename. The race window reopens there; on such a filesystem two simultaneous
  # writers to one slot can let the second win. Stated rather than pretended
  # away — every deployment target has links.
  defp slow_path_write(tmp, path, bytes) do
    File.write!(tmp, bytes)
    File.rename!(tmp, path)
    :created
  end

  @doc "The bytes in a slot, or nil."
  @spec get(String.t(), String.t(), String.t()) :: binary() | nil
  def get(rendezvous, session, slot) do
    case File.read(Path.join([data_root(), rendezvous, session, slot])) do
      {:ok, bytes} -> bytes
      {:error, _} -> nil
    end
  end

  @doc "Session ids present under `rendezvous`."
  @spec sessions(String.t()) :: [String.t()]
  def sessions(rendezvous) do
    dir = Path.join(data_root(), rendezvous)

    case File.ls(dir) do
      {:ok, names} -> names |> Enum.filter(&valid_id?/1) |> Enum.sort()
      {:error, _} -> []
    end
  end

  defp session_count(rendezvous), do: length(sessions(rendezvous))

  @doc """
  Delete every rendezvous untouched for longer than the TTL.

  Pairing is an interactive, user-present action measured in minutes, so there is
  nothing here worth keeping. Returns the ids removed.
  """
  @spec sweep(keyword()) :: [String.t()]
  def sweep(opts \\ []) do
    root = Keyword.get(opts, :data_root, data_root())
    ttl = Keyword.get(opts, :ttl_ms, Application.get_env(:sync, :mailbox_ttl_ms, @default_ttl_ms))
    now = Keyword.get(opts, :now_ms, System.system_time(:millisecond))

    case File.ls(root) do
      {:ok, names} ->
        for name <- names,
            path = Path.join(root, name),
            File.dir?(path),
            stale?(path, now, ttl) do
          File.rm_rf(path)
          name
        end

      {:error, _} ->
        []
    end
  end

  # A rendezvous directory's mtime moves every time a session is created under
  # it, so this is "no new session for a while". Slots written inside an existing
  # session do not touch it — which is fine, since the TTL is six times the
  # longest pairing window.
  defp stale?(path, now, ttl) do
    case File.stat(path, time: :posix) do
      {:ok, %{mtime: mtime}} -> now - mtime * 1000 >= ttl
      _ -> false
    end
  end
end
