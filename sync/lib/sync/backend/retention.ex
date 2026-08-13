defmodule Sync.Backend.Retention do
  @moduledoc """
  Pure retention/GC planners plus a filesystem sweep for backend snapshots.

  Zero-knowledge throughout: the sweep reads only the PLAINTEXT manifest prefix of
  each framed snapshot object and file mtimes. It never touches the sealed
  ciphertext body.

  A snapshot object on disk is framed as
  `u32-LE manifest_len ‖ manifest_json ‖ sealed_ciphertext` (see the Rust
  `roam_backend_client::snapshot_msg::frame`). The manifest JSON carries opaque id
  lists: `subsumed_entry_ids` (entries the snapshot replaces) and `blob_ref_ids`
  (blobs it keeps alive).
  """

  alias Sync.Backend.Store

  @default_keep 3
  @default_grace_ms 7 * 24 * 60 * 60 * 1000

  @doc "Snapshot ids to drop: keep the newest `n` by ts, drop the rest."
  def snapshots_to_drop(snapshots, n) do
    snapshots
    |> Enum.sort_by(& &1.ts, :desc)
    |> Enum.drop(n)
    |> Enum.map(& &1.id)
  end

  @doc """
  Subsumed entry ids past `grace` (by arrival age) that a retained snapshot
  covers. An entry not subsumed by any retained snapshot is never returned.
  """
  def entries_to_delete(retained_subsumed, entry_ages, now, grace) do
    retained_subsumed
    |> Enum.filter(fn id ->
      case Map.get(entry_ages, id) do
        nil -> false
        born -> now - born >= grace
      end
    end)
    |> Enum.sort()
  end

  @doc """
  Blob ids safe to delete: referenced by a DROPPED snapshot but NOT by any
  retained snapshot, past `grace`.

  BE2: the zero-knowledge backend cannot see an encrypted entry's blob refs, so a
  blob newer than every snapshot appears in NO manifest — and a live, non-subsumed
  entry may still reference it. Requiring membership in `dropped_blob_refs`
  (evidence the blob was in the snapshot lineage and is now superseded) mirrors
  `entries_to_delete` deleting only `subsumed` entries, and never reaps a blob the
  backend has no evidence is dead.
  """
  def blobs_to_delete(retained_blob_refs, dropped_blob_refs, blob_ages, now, grace) do
    blob_ages
    |> Enum.filter(fn {id, born} ->
      MapSet.member?(dropped_blob_refs, id) and
        not MapSet.member?(retained_blob_refs, id) and
        now - born >= grace
    end)
    |> Enum.map(&elem(&1, 0))
    |> Enum.sort()
  end

  @doc """
  Sweep one bucket: drop snapshots past the newest `:keep` (default #{@default_keep}),
  then delete subsumed entries and orphaned blobs older than `:grace_ms`
  (default 7 days). Always keeps >= 1 snapshot (generational floor).

  Opts: `:keep`, `:grace_ms`, `:now_ms` (inject for tests), `:data_root`.
  Returns `%{snapshots: [ids], entries: [ids], blobs: [ids]}` of what was deleted.
  """
  def sweep(bucket, opts \\ []) do
    keep = max(Keyword.get(opts, :keep, @default_keep), 1)
    grace = Keyword.get(opts, :grace_ms, @default_grace_ms)
    now = Keyword.get(opts, :now_ms, System.system_time(:millisecond))
    root = Keyword.get(opts, :data_root, Store.data_root())

    snaps = load_snapshots(root, bucket)
    dropped_ids = snapshots_to_drop(snaps, keep)
    dropped_set = MapSet.new(dropped_ids)
    {dropped, retained} = Enum.split_with(snaps, &MapSet.member?(dropped_set, &1.id))

    # Delete the dropped snapshot files.
    Enum.each(dropped_ids, &rm(root, bucket, "snapshots", &1))

    retained_subsumed =
      retained |> Enum.flat_map(& &1.subsumed) |> MapSet.new()

    retained_blob_refs =
      retained |> Enum.flat_map(& &1.blob_refs) |> MapSet.new()

    # BE2: only blobs the DROPPED snapshots referenced are GC candidates — a blob
    # in no manifest (newer than every snapshot) may still back a live entry.
    dropped_blob_refs =
      dropped |> Enum.flat_map(& &1.blob_refs) |> MapSet.new()

    entry_ages = file_ages(root, bucket, "entries")
    del_entries = entries_to_delete(retained_subsumed, entry_ages, now, grace)
    Enum.each(del_entries, &rm(root, bucket, "entries", &1))

    blob_ages = file_ages(root, bucket, "blobs")
    del_blobs = blobs_to_delete(retained_blob_refs, dropped_blob_refs, blob_ages, now, grace)
    Enum.each(del_blobs, &rm(root, bucket, "blobs", &1))

    %{snapshots: dropped_ids, entries: del_entries, blobs: del_blobs}
  end

  # --- internals ---

  defp load_snapshots(root, bucket) do
    dir = Path.join([root, bucket, "snapshots"])

    case File.ls(dir) do
      {:ok, names} ->
        names
        |> Enum.reject(&String.contains?(&1, ".tmp"))
        |> Enum.flat_map(fn id ->
          path = Path.join(dir, id)

          with {:ok, json} <- read_manifest_json(path),
               {:ok, manifest} <- decode_manifest(json) do
            [
              %{
                id: id,
                ts: mtime_ms(path),
                subsumed: Map.get(manifest, "subsumed_entry_ids", []),
                blob_refs: Map.get(manifest, "blob_ref_ids", [])
              }
            ]
          else
            # A file that doesn't parse as a frame is not a valid snapshot object;
            # skip it rather than crash the sweep (fail-safe: never delete on doubt).
            _ -> []
          end
        end)

      {:error, _} ->
        []
    end
  end

  # Frame: u32-LE manifest_len ‖ manifest_json ‖ sealed_ct.
  #
  # Read ONLY the length prefix and the manifest, never the sealed ciphertext body
  # that follows. The body can be up to the PUT cap (tens of MB), and the sweep
  # loads EVERY snapshot object in the bucket on EVERY pass — slurping the whole
  # file (`File.read`) meant a bucket full of large snapshots transiently pulled
  # hundreds of MB into the BEAM per sweep, a cross-tenant memory-pressure DoS.
  # Sequential `:file.read` in `:raw` mode stops after the manifest, so the body is
  # never touched.
  defp read_manifest_json(path) do
    case :file.open(path, [:read, :binary, :raw]) do
      {:ok, io} ->
        result =
          with {:ok, <<len::little-32>>} <- :file.read(io, 4),
               true <- len > 0,
               {:ok, json} when byte_size(json) == len <- :file.read(io, len) do
            {:ok, json}
          else
            _ -> :error
          end

        :file.close(io)
        result

      {:error, _} ->
        :error
    end
  end

  # M-A: the manifest is attacker-supplied plaintext. Accept it only when it is a
  # map whose id fields are lists of strings; anything else (a non-map, or a field
  # of the wrong type) is treated like an unparseable frame and SKIPPED. Without
  # this, a shape-poisoned-but-valid-JSON manifest raises (`Map.get/3` on a
  # non-map, or `flat_map` over a non-list) on EVERY sweep of that bucket —
  # BE4's per-bucket rescue then turns the crash into permanent retention
  # starvation (unbounded disk growth for that bucket).
  defp decode_manifest(json) do
    case Jason.decode(json) do
      {:ok, manifest} when is_map(manifest) ->
        if id_list?(Map.get(manifest, "subsumed_entry_ids", [])) and
             id_list?(Map.get(manifest, "blob_ref_ids", [])) do
          {:ok, manifest}
        else
          :error
        end

      _ ->
        :error
    end
  end

  # A manifest id field must be a list of opaque string ids — reject any other
  # shape so downstream `flat_map`/`rm` never raise on attacker-crafted types.
  defp id_list?(value), do: is_list(value) and Enum.all?(value, &is_binary/1)

  defp file_ages(root, bucket, kind) do
    dir = Path.join([root, bucket, kind])

    case File.ls(dir) do
      {:ok, names} ->
        names
        |> Enum.reject(&String.contains?(&1, ".tmp"))
        |> Map.new(fn id -> {id, mtime_ms(Path.join(dir, id))} end)

      {:error, _} ->
        %{}
    end
  end

  defp mtime_ms(path) do
    case File.stat(path, time: :posix) do
      {:ok, %{mtime: secs}} -> secs * 1000
      _ -> 0
    end
  end

  defp rm(root, bucket, kind, id) do
    File.rm(Path.join([root, bucket, kind, id]))
  end
end
