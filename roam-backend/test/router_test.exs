System.put_env("ROAM_BACKEND_NOSERVE", "1")
System.put_env("ROAM_BACKEND_ROOT", Path.join(System.tmp_dir!(), "roam-backend-test-#{:erlang.unique_integer([:positive])}"))
Code.require_file("../server.exs", __DIR__)

ExUnit.start()

defmodule Roam.Backend.RouterTest do
  use ExUnit.Case, async: false
  use Plug.Test

  @opts Roam.Backend.Router.init([])

  defp call(conn), do: Roam.Backend.Router.call(conn, @opts)

  test "put new entry returns 201, duplicate returns 409, no overwrite" do
    c = call(conn(:put, "/b/bkt/entries/e1", "first"))
    assert c.status == 201
    c2 = call(conn(:put, "/b/bkt/entries/e1", "second"))
    assert c2.status == 409
    got = call(conn(:get, "/b/bkt/entries/e1"))
    assert got.status == 200
    assert got.resp_body == "first"
  end

  test "get absent entry returns 404" do
    assert call(conn(:get, "/b/bkt/entries/nope")).status == 404
  end

  test "manifest reflects writes" do
    call(conn(:put, "/b/m/entries/e1", "x"))
    call(conn(:put, "/b/m/blobs/b1", "y"))
    got = call(conn(:get, "/b/m/manifest"))
    assert got.status == 200
    assert Jason.decode!(got.resp_body) == %{"entry_ids" => ["e1"], "blob_ids" => ["b1"]}
  end

  test "path-traversal id is rejected with 400" do
    assert call(conn(:put, "/b/bkt/entries/..%2Fescape", "x")).status == 400
  end
end
