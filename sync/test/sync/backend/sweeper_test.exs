defmodule Sync.Backend.SweeperTest do
  use ExUnit.Case, async: false

  alias Sync.Backend.{Store, Sweeper}

  setup do
    root = Path.join(System.tmp_dir!(), "roam-sweeper-#{System.unique_integer([:positive])}")
    Application.put_env(:sync, :backend_data_root, root)
    on_exit(fn -> File.rm_rf(root) end)
    {:ok, root: root}
  end

  defp snapshot_frame(subsumed, blob_refs) do
    json =
      Jason.encode!(%{"subsumed_entry_ids" => subsumed, "blob_ref_ids" => blob_refs})

    <<byte_size(json)::little-32>> <> json <> "sealed"
  end

  test "sweep_all compacts every over-limit bucket under the data root" do
    b1 = String.duplicate("A", 43)
    b2 = String.duplicate("B", 43)

    for bucket <- [b1, b2] do
      frame = snapshot_frame(["esub"], ["bkeep"])
      for id <- ["s1", "s2", "s3", "s4"], do: Store.put(bucket, "snapshots", id, frame)
      Store.put(bucket, "entries", "esub", "x")
      Store.put(bucket, "blobs", "borphan", "x")
    end

    results = Sweeper.sweep_all(keep: 3, grace_ms: 0, now_ms: 9_000_000_000_000)

    assert Map.has_key?(results, b1)
    assert Map.has_key?(results, b2)

    for bucket <- [b1, b2] do
      # One snapshot dropped, subsumed entry purged. BE2: "borphan" is in no
      # manifest, so the backend has no evidence it's dead — it is kept.
      assert length(Store.list(bucket, "snapshots")) == 3
      assert Store.list(bucket, "entries") == []
      assert Store.list(bucket, "blobs") == ["borphan"]
    end
  end

  test "sweep_all on an empty data root is a no-op" do
    assert Sweeper.sweep_all(keep: 3) == %{}
  end

  test "sweep_all tolerates a shape-poisoned bucket and still sweeps the healthy buckets" do
    # BE4 + M-A: buckets are client-controlled. A snapshot manifest that parses as
    # JSON but carries a non-list `subsumed_entry_ids` is now SKIPPED at parse time
    # (M-A) rather than raising, so the poisoned bucket sweeps cleanly instead of
    # crash-looping. Either way, one poisoned bucket must never abort the whole
    # periodic sweep and starve every other bucket of retention (BE4's per-bucket
    # isolation remains as defense-in-depth for any other unforeseen raise).
    good = String.duplicate("A", 43)
    bad = String.duplicate("B", 43)

    frame = snapshot_frame(["esub"], [])
    for id <- ["s1", "s2", "s3", "s4"], do: Store.put(good, "snapshots", id, frame)
    Store.put(good, "entries", "esub", "x")

    # subsumed_entry_ids is a bare string, not a list -> M-A skips this snapshot.
    Store.put(bad, "snapshots", "s1", snapshot_frame("boom", []))

    results = Sweeper.sweep_all(keep: 3, grace_ms: 0, now_ms: 9_000_000_000_000)

    # The healthy bucket is still compacted despite the poisoned neighbour.
    assert length(Store.list(good, "snapshots")) == 3
    # The poisoned bucket is handled gracefully (its bad snapshot skipped), never a
    # crash that killed the run.
    assert Map.has_key?(results, bad)
    assert is_map(results[bad])
    # The poison object parses to no valid snapshot, so nothing is dropped there.
    assert results[bad] == %{snapshots: [], entries: [], blobs: []}
  end
end
