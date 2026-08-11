defmodule Sync.Backend.RetentionTest do
  use ExUnit.Case, async: false

  alias Sync.Backend.Retention
  alias Sync.Backend.Store

  describe "pure planners" do
    test "keep the newest N snapshots; older ones are dropped" do
      snaps = [%{id: "s1", ts: 1}, %{id: "s2", ts: 2}, %{id: "s3", ts: 3}, %{id: "s4", ts: 4}]
      assert Retention.snapshots_to_drop(snaps, 3) == ["s1"]
      assert Retention.snapshots_to_drop(snaps, 4) == []
      assert Enum.sort(Retention.snapshots_to_drop(snaps, 2)) == ["s1", "s2"]
    end

    test "a subsumed entry past grace is deletable; within grace is kept" do
      now = 1000
      retained_subsumed = MapSet.new(["e1", "e2"])
      entry_ages = %{"e1" => now - 10_000, "e2" => now - 1}
      assert Retention.entries_to_delete(retained_subsumed, entry_ages, now, 5000) == ["e1"]
    end

    test "an entry not subsumed by any retained snapshot is never deleted" do
      assert Retention.entries_to_delete(MapSet.new(), %{"e1" => 0}, 1000, 0) == []
    end

    test "a blob referenced by no retained snapshot, past grace, is deletable" do
      now = 10_000
      retained = MapSet.new(["b_keep"])
      blob_ages = %{"b_keep" => 0, "b_orphan" => 0}
      assert Retention.blobs_to_delete(retained, blob_ages, now, 5000) == ["b_orphan"]
    end

    test "a blob still referenced by a retained snapshot survives even past grace" do
      assert Retention.blobs_to_delete(MapSet.new(["b"]), %{"b" => 0}, 10_000, 5000) == []
    end
  end

  describe "sweep/2 on a real data root" do
    setup do
      root = Path.join(System.tmp_dir!(), "roam-sweep-#{System.unique_integer([:positive])}")
      Application.put_env(:sync, :backend_data_root, root)
      on_exit(fn -> File.rm_rf(root) end)
      {:ok, root: root, bucket: String.duplicate("Z", 43)}
    end

    # Frame a manifest the way the Rust client does: u32-LE len ‖ json ‖ sealed.
    defp snapshot_frame(subsumed, blob_refs) do
      json =
        Jason.encode!(%{
          "subsumed_entry_ids" => subsumed,
          "blob_ref_ids" => blob_refs,
          "author" => 1,
          "sig" => "x"
        })

      <<byte_size(json)::little-32>> <> json <> "sealed-ciphertext"
    end

    test "drops old snapshots, subsumed entries, orphan blobs; keeps referenced", %{bucket: b} do
      # Four snapshots. Only the retained ones' manifests count for keep-sets, so
      # to make the assertions deterministic regardless of WHICH snapshot is
      # dropped, every snapshot carries the same manifest: subsumes "eold",
      # references "bkeep". Thus "eold" is subsumed by a retained snapshot and
      # "borphan" is referenced by none.
      frame = snapshot_frame(["eold"], ["bkeep"])
      for id <- ["s1", "s2", "s3", "s4"], do: Store.put(b, "snapshots", id, frame)

      Store.put(b, "entries", "eold", "x")
      Store.put(b, "entries", "efresh", "x")
      Store.put(b, "blobs", "bkeep", "x")
      Store.put(b, "blobs", "borphan", "x")

      # grace 0 + now far in the future forces every past-grace deletion.
      result = Retention.sweep(b, keep: 3, grace_ms: 0, now_ms: 9_000_000_000_000)

      # Exactly one snapshot dropped (4 - keep 3), leaving 3.
      assert length(result.snapshots) == 1
      assert length(Store.list(b, "snapshots")) == 3

      # "eold" is subsumed by a retained snapshot and past grace -> deleted.
      assert "eold" in result.entries
      # "efresh" is not subsumed by anything -> kept.
      refute "efresh" in result.entries
      assert "efresh" in Store.list(b, "entries")

      # "borphan" referenced by no retained snapshot -> deleted; "bkeep" kept.
      assert result.blobs == ["borphan"]
      assert "bkeep" in Store.list(b, "blobs")
      refute "borphan" in Store.list(b, "blobs")
    end

    test "nothing is deleted while still within the grace window", %{bucket: b} do
      frame = snapshot_frame(["eold"], ["bkeep"])
      for id <- ["s1", "s2", "s3", "s4"], do: Store.put(b, "snapshots", id, frame)
      Store.put(b, "entries", "eold", "x")
      Store.put(b, "blobs", "borphan", "x")

      # Huge grace: snapshots still drop by count, but no entry/blob is purged yet.
      result = Retention.sweep(b, keep: 3, grace_ms: 9_000_000_000_000, now_ms: 0)

      assert length(result.snapshots) == 1
      assert result.entries == []
      assert result.blobs == []
      assert "eold" in Store.list(b, "entries")
      assert "borphan" in Store.list(b, "blobs")
    end
  end
end
