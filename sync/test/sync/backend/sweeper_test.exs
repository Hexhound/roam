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
      # One snapshot dropped, subsumed entry + orphan blob purged.
      assert length(Store.list(bucket, "snapshots")) == 3
      assert Store.list(bucket, "entries") == []
      assert Store.list(bucket, "blobs") == []
    end
  end

  test "sweep_all on an empty data root is a no-op" do
    assert Sweeper.sweep_all(keep: 3) == %{}
  end
end
