defmodule Sync.Backend.Store do
  @moduledoc """
  Filesystem-backed zero-knowledge store. Ciphertext is opaque; the id is the
  filename. File existence = dedup. Ported from roam-backend/server.exs.
  """

  @id_re ~r/^[A-Za-z0-9_-]+$/
  # Ids are 43-char base64url; buckets are similar. Cap length so an absurdly long
  # (but charset-valid) id can't reach File.* and raise ENAMETOOLONG → 500.
  @max_id_len 128

  @spec valid_id?(String.t()) :: boolean()
  def valid_id?(id),
    do: is_binary(id) and byte_size(id) <= @max_id_len and Regex.match?(@id_re, id)

  @doc "Absolute data root; from :sync config or ROAM_BACKEND_DATA env."
  def data_root do
    Application.get_env(:sync, :backend_data_root) ||
      System.get_env("ROAM_BACKEND_DATA") ||
      Path.join(System.tmp_dir!(), "roam-backend-data")
  end

  @doc "`:created` on first write of `id`, `:exists` if already present."
  @spec put(String.t(), String.t(), String.t(), binary()) :: :created | :exists
  def put(bucket, kind, id, bytes) do
    dir = Path.join([data_root(), bucket, kind])
    File.mkdir_p!(dir)
    path = Path.join(dir, id)

    if File.exists?(path) do
      :exists
    else
      tmp = path <> ".tmp." <> Integer.to_string(System.unique_integer([:positive]))
      File.write!(tmp, bytes)
      File.rename!(tmp, path)
      :created
    end
  end

  @doc "The ciphertext for `id`, or nil if absent."
  @spec get(String.t(), String.t(), String.t()) :: binary() | nil
  def get(bucket, kind, id) do
    path = Path.join([data_root(), bucket, kind, id])

    case File.read(path) do
      {:ok, bytes} -> bytes
      {:error, _} -> nil
    end
  end

  @doc "All ids present for `kind` in `bucket` (excludes leftover temp files)."
  @spec list(String.t(), String.t()) :: [String.t()]
  def list(bucket, kind) do
    dir = Path.join([data_root(), bucket, kind])

    case File.ls(dir) do
      {:ok, names} -> Enum.reject(names, &String.contains?(&1, ".tmp"))
      {:error, _} -> []
    end
  end

  @doc "Total bytes stored for `kind` in `bucket` (excludes leftover temp files)."
  @spec kind_bytes(String.t(), String.t()) :: non_neg_integer()
  def kind_bytes(bucket, kind) do
    dir = Path.join([data_root(), bucket, kind])

    case File.ls(dir) do
      {:ok, names} ->
        names
        |> Enum.reject(&String.contains?(&1, ".tmp"))
        |> Enum.reduce(0, fn n, acc -> acc + file_size(Path.join(dir, n)) end)

      {:error, _} ->
        0
    end
  end

  defp file_size(path) do
    case File.stat(path) do
      {:ok, %{size: s}} -> s
      _ -> 0
    end
  end

  @doc """
  Whether the backend should ask an Admin client to snapshot: the entry tail has
  grown past `threshold_bytes`. The backend can't build a snapshot itself
  (zero-knowledge) — it can only signal demand.
  """
  @spec snapshot_wanted?(String.t(), non_neg_integer()) :: boolean()
  def snapshot_wanted?(bucket, threshold_bytes),
    do: kind_bytes(bucket, "entries") > threshold_bytes

  @doc "Concatenated 32-byte ids for the NIF: decode each base64url filename."
  @spec id_bytes(String.t(), String.t()) :: binary()
  def id_bytes(bucket, kind) do
    list(bucket, kind)
    |> Enum.map(&decode_id/1)
    |> Enum.reject(&is_nil/1)
    |> IO.iodata_to_binary()
  end

  # base64url no-pad -> 32 bytes, else nil (ids are 43-char base64url of a 32-byte hash).
  defp decode_id(id) do
    case Base.url_decode64(id, padding: false) do
      {:ok, <<bytes::binary-size(32)>>} -> bytes
      _ -> nil
    end
  end
end
