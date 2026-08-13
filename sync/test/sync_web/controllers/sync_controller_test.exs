defmodule SyncWeb.SyncControllerTest do
  use SyncWeb.ConnCase, async: false

  @bucket "testbucket"
  @id String.duplicate("A", 43)

  setup do
    root = Path.join(System.tmp_dir!(), "roam-be-test-#{System.unique_integer([:positive])}")
    Application.put_env(:sync, :backend_data_root, root)
    on_exit(fn -> File.rm_rf(root) end)
    :ok
  end

  test "put then get an entry round-trips the bytes", %{conn: conn} do
    conn = put_req_header(conn, "content-type", "application/octet-stream")
    resp = put(conn, "/b/#{@bucket}/entries/#{@id}", "ciphertext")
    assert resp.status == 201

    got = get(build_conn(), "/b/#{@bucket}/entries/#{@id}")
    assert got.status == 200
    assert got.resp_body == "ciphertext"
  end

  test "putting the same id twice is a 409 (dedup)", %{conn: conn} do
    conn = put_req_header(conn, "content-type", "application/octet-stream")
    assert put(conn, "/b/#{@bucket}/entries/#{@id}", "x").status == 201

    assert put(
             build_conn() |> put_req_header("content-type", "application/octet-stream"),
             "/b/#{@bucket}/entries/#{@id}",
             "x"
           ).status == 409
  end

  test "missing entry is 404", %{conn: conn} do
    assert get(conn, "/b/#{@bucket}/entries/#{@id}").status == 404
  end

  test "manifest lists uploaded ids", %{conn: conn} do
    put(
      conn |> put_req_header("content-type", "application/octet-stream"),
      "/b/#{@bucket}/entries/#{@id}",
      "x"
    )

    resp = get(build_conn(), "/b/#{@bucket}/manifest")
    assert %{"entry_ids" => [@id], "blob_ids" => []} = json_response(resp, 200)
  end

  test "put then get a snapshot round-trips the bytes", %{conn: conn} do
    conn = put_req_header(conn, "content-type", "application/octet-stream")
    assert put(conn, "/b/#{@bucket}/snapshots/#{@id}", "snapct").status == 201

    got = get(build_conn(), "/b/#{@bucket}/snapshots/#{@id}")
    assert got.status == 200
    assert got.resp_body == "snapct"
  end

  test "manifest lists snapshot ids", %{conn: conn} do
    put(
      conn |> put_req_header("content-type", "application/octet-stream"),
      "/b/#{@bucket}/snapshots/#{@id}",
      "s"
    )

    resp = get(build_conn(), "/b/#{@bucket}/manifest")
    assert %{"snapshot_ids" => [@id]} = json_response(resp, 200)
  end

  test "manifest signals snapshot_wanted once the entry tail crosses the threshold", %{
    conn: conn
  } do
    Application.put_env(:sync, :snapshot_threshold_bytes, 100)
    on_exit(fn -> Application.delete_env(:sync, :snapshot_threshold_bytes) end)

    resp = get(build_conn(), "/b/#{@bucket}/manifest")
    assert %{"snapshot_wanted" => false} = json_response(resp, 200)

    put(
      conn |> put_req_header("content-type", "application/octet-stream"),
      "/b/#{@bucket}/entries/#{@id}",
      :binary.copy(<<0>>, 200)
    )

    resp = get(build_conn(), "/b/#{@bucket}/manifest")
    assert %{"snapshot_wanted" => true} = json_response(resp, 200)
  end

  test "reconcile over the snapshots kind is accepted", %{conn: conn} do
    conn = put_req_header(conn, "content-type", "application/octet-stream")
    resp = post(conn, "/b/#{@bucket}/reconcile/snapshots", <<>>)
    assert resp.status in [200, 400]
    refute resp.status == 500
  end

  test "path-traversal id is rejected 400", %{conn: conn} do
    assert get(conn, "/b/#{@bucket}/entries/..%2f..%2fetc").status == 400
  end

  test "reconcile endpoint returns octet-stream bytes or fails closed for a client frame", %{
    conn: conn
  } do
    # Empty body: reconcile_server must fail closed -> 400, not crash -> 500.
    conn = put_req_header(conn, "content-type", "application/octet-stream")
    resp = post(conn, "/b/#{@bucket}/reconcile/entries", <<>>)
    assert resp.status in [200, 400]
    refute resp.status == 500
  end

  test "reconcile rejects an unknown kind 400", %{conn: conn} do
    conn = put_req_header(conn, "content-type", "application/octet-stream")
    assert post(conn, "/b/#{@bucket}/reconcile/bogus", <<>>).status == 400
  end

  test "a body sent with a application/json content-type is stored raw, not eaten by Plug.Parsers",
       %{conn: conn} do
    # BE3: Plug.Parsers runs on every request. If a client (buggy or hostile)
    # PUTs opaque ciphertext under Content-Type: application/json, Parsers must
    # NOT consume the body and leave the controller's read_body with "". The
    # backend is zero-knowledge and cannot re-verify id == hash(body), so a
    # silently-emptied body would poison the content-addressed id for every peer.
    raw = ~s({"looks":"like json","but":"is ciphertext"})
    conn = put_req_header(conn, "content-type", "application/json")
    assert put(conn, "/b/#{@bucket}/entries/#{@id}", raw).status == 201

    got = get(build_conn(), "/b/#{@bucket}/entries/#{@id}")
    assert got.status == 200
    assert got.resp_body == raw
  end

  test "an oversized body fails closed (413), never 500", %{conn: conn} do
    # >8MB exceeds read_body's default limit -> {:more, ...}; the controller must
    # fail closed with 413, not raise WithClauseError -> 500.
    big = :binary.copy(<<0>>, 8_000_001)
    conn = put_req_header(conn, "content-type", "application/octet-stream")
    resp = post(conn, "/b/#{@bucket}/reconcile/entries", big)
    assert resp.status == 413
  end
end
