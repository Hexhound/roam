defmodule Sync.Backend.StoreTest do
  use ExUnit.Case, async: false

  alias Sync.Backend.Store

  @bucket String.duplicate("C", 43)
  @id String.duplicate("D", 43)

  setup do
    root = Path.join(System.tmp_dir!(), "roam-store-test-#{System.unique_integer([:positive])}")
    Application.put_env(:sync, :backend_data_root, root)
    on_exit(fn -> File.rm_rf(root) end)
    :ok
  end

  test "kind_bytes sums stored payloads for a kind" do
    assert Store.kind_bytes(@bucket, "entries") == 0
    Store.put(@bucket, "entries", @id, :binary.copy(<<0>>, 200))
    assert Store.kind_bytes(@bucket, "entries") == 200
  end

  test "snapshot_wanted? trips once the entry tail crosses the threshold" do
    refute Store.snapshot_wanted?(@bucket, 100)
    Store.put(@bucket, "entries", @id, :binary.copy(<<0>>, 200))
    assert Store.snapshot_wanted?(@bucket, 100)
    # A larger threshold is not yet crossed.
    refute Store.snapshot_wanted?(@bucket, 1000)
  end
end
