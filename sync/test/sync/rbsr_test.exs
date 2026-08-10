defmodule Sync.RbsrTest do
  use ExUnit.Case, async: true

  test "a malformed/short msg returns an :error tuple, never crashes the VM" do
    assert {:error, _} = Sync.Rbsr.reconcile_server(<<>>, <<0xFF, 0xFF>>)
  end

  test "items binary not a multiple of 32 is a clean error" do
    assert {:error, reason} = Sync.Rbsr.reconcile_server(<<1, 2, 3>>, <<>>)
    assert reason =~ "multiple of 32"
  end
end
