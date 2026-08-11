defmodule Sync.Backend.SnapshotCycleTest do
  @moduledoc """
  Full backend snapshot lifecycle through the HTTP surface: uploads trip the
  size signal, a framed snapshot lands, then the sweep prunes subsumed entries +
  orphan blobs while retaining the snapshot and in-reference blobs.
  """
  use SyncWeb.ConnCase, async: false

  alias Sync.Backend.Sweeper

  @bucket String.duplicate("Z", 43)

  setup do
    root = Path.join(System.tmp_dir!(), "roam-cycle-#{System.unique_integer([:positive])}")
    Application.put_env(:sync, :backend_data_root, root)
    Application.put_env(:sync, :snapshot_threshold_bytes, 100)

    on_exit(fn ->
      File.rm_rf(root)
      Application.delete_env(:sync, :snapshot_threshold_bytes)
    end)

    :ok
  end

  defp raw(conn), do: put_req_header(conn, "content-type", "application/octet-stream")

  defp id(seed), do: seed |> then(&:crypto.hash(:sha256, &1)) |> Base.url_encode64(padding: false)

  defp snapshot_frame(subsumed, blob_refs) do
    json = Jason.encode!(%{"subsumed_entry_ids" => subsumed, "blob_ref_ids" => blob_refs})
    <<byte_size(json)::little-32>> <> json <> "sealed-ciphertext"
  end

  test "upload → threshold → snapshot → sweep prunes subsumed + orphans, keeps referenced", %{
    conn: conn
  } do
    esub = id("subsumed-entry")
    bkeep = id("kept-blob")
    borphan = id("orphan-blob")

    # Upload a >100-byte entry so the tail crosses the snapshot threshold.
    assert put(raw(conn), "/b/#{@bucket}/entries/#{esub}", :binary.copy(<<0>>, 200)).status == 201
    assert put(raw(build_conn()), "/b/#{@bucket}/blobs/#{bkeep}", "x").status == 201
    assert put(raw(build_conn()), "/b/#{@bucket}/blobs/#{borphan}", "x").status == 201

    # The backend now asks for a snapshot.
    manifest = json_response(get(build_conn(), "/b/#{@bucket}/manifest"), 200)
    assert manifest["snapshot_wanted"] == true

    # A client uploads a framed snapshot subsuming the entry and referencing bkeep.
    sid = id("snapshot-1")
    frame = snapshot_frame([esub], [bkeep])
    assert put(raw(build_conn()), "/b/#{@bucket}/snapshots/#{sid}", frame).status == 201

    # Sweep with grace 0: subsumed entry + orphan blob purged; snapshot + bkeep stay.
    result = Sweeper.sweep_all(keep: 3, grace_ms: 0, now_ms: 9_000_000_000_000)

    assert result[@bucket].entries == [esub]
    assert result[@bucket].blobs == [borphan]

    assert Sync.Backend.Store.list(@bucket, "snapshots") == [sid]
    assert Sync.Backend.Store.list(@bucket, "entries") == []
    assert Sync.Backend.Store.list(@bucket, "blobs") == [bkeep]

    # After pruning the tail, the threshold is no longer crossed.
    manifest2 = json_response(get(build_conn(), "/b/#{@bucket}/manifest"), 200)
    assert manifest2["snapshot_wanted"] == false
  end
end
