defmodule SyncWeb.RendezvousControllerTest do
  use SyncWeb.ConnCase, async: false

  alias Sync.Backend.Mailbox

  @rendezvous String.duplicate("R", 43)
  @session String.duplicate("S", 43)

  setup do
    root = Path.join(System.tmp_dir!(), "roam-rv-test-#{System.unique_integer([:positive])}")
    Application.put_env(:sync, :backend_data_root, root)
    Application.delete_env(:sync, :mailbox_data_root)

    on_exit(fn ->
      File.rm_rf(root)
      File.rm_rf(root <> "-rendezvous")
      Application.delete_env(:sync, :backend_data_root)
    end)

    :ok
  end

  defp raw(conn), do: put_req_header(conn, "content-type", "application/octet-stream")

  defp put_slot(session, slot, body) do
    put(raw(build_conn()), "/rendezvous/#{@rendezvous}/#{session}/#{slot}", body)
  end

  test "a slot round-trips through the relay" do
    assert put_slot(@session, "msg1", "spake").status == 201

    got = get(build_conn(), "/rendezvous/#{@rendezvous}/#{@session}/msg1")
    assert got.status == 200
    assert got.resp_body == "spake"
  end

  test "an unwritten slot is 404, which is the normal polling case" do
    assert get(build_conn(), "/rendezvous/#{@rendezvous}/#{@session}/msg2").status == 404
  end

  test "writing a taken slot is 409 and leaves the body alone" do
    # The client contract: a 409 means this session is not mine to finish. A
    # host that ignored it would verify a confirmation against a transcript it
    # never wrote, and spend one of its three attempts for free.
    assert put_slot(@session, "msg1", "first").status == 201
    assert put_slot(@session, "msg1", "second").status == 409

    assert get(build_conn(), "/rendezvous/#{@rendezvous}/#{@session}/msg1").resp_body ==
             "first"
  end

  test "sessions under a rendezvous are listed" do
    other = String.duplicate("B", 43)
    put_slot(@session, "msg1", "x")
    put_slot(other, "msg1", "x")

    resp = get(build_conn(), "/rendezvous/#{@rendezvous}/sessions")
    assert %{"sessions" => sessions} = json_response(resp, 200)
    assert sessions == Enum.sort([@session, other])
  end

  test "a slot name outside the six is refused" do
    assert put_slot(@session, "msg3", "x").status == 400
    assert get(build_conn(), "/rendezvous/#{@rendezvous}/#{@session}/msg3").status == 400
  end

  test "a malformed id is refused before the filesystem is touched" do
    short = String.duplicate("A", 10)
    assert put_slot(short, "msg1", "x").status == 400

    assert put(
             raw(build_conn()),
             "/rendezvous/#{short}/#{@session}/msg1",
             "x"
           ).status == 400

    assert get(build_conn(), "/rendezvous/#{short}/sessions").status == 400
  end

  test "a body over the cap fails closed rather than crashing" do
    oversized = :binary.copy("a", Mailbox.max_body_bytes() + 1)
    assert put_slot(@session, "msg1", oversized).status == 413
  end

  test "past the session cap a new session is refused" do
    for index <- 1..Mailbox.max_sessions() do
      assert put_slot(String.pad_leading("#{index}", 43, "0"), "msg1", "x").status == 201
    end

    assert put_slot(String.duplicate("X", 43), "msg1", "x").status == 429
  end

  describe "CORS" do
    # Without these headers a browser client cannot reach ANY of these routes:
    # a cross-origin fetch is blocked before the request is made, which presents
    # as an opaque network error with nothing in it to debug. Everything else
    # built for the browser depends on this working.

    test "a pairing response carries the allow-origin header" do
      resp = get(build_conn(), "/rendezvous/#{@rendezvous}/sessions")
      assert get_resp_header(resp, "access-control-allow-origin") == ["*"]
    end

    test "a sync bucket response carries it too" do
      # The mailbox alone is not enough — a browser that paired but could not
      # then reach /b/:bucket would hold a vault it cannot sync.
      resp = get(build_conn(), "/b/#{String.duplicate("C", 43)}/manifest")
      assert get_resp_header(resp, "access-control-allow-origin") == ["*"]
    end

    test "the preflight for a raw PUT succeeds and advertises the method" do
      # A PUT of octet-stream is not a simple request, so a browser sends this
      # first and refuses the real request unless it succeeds. An unrouted
      # OPTIONS would 404 with no CORS headers at all.
      resp = options(build_conn(), "/rendezvous/#{@rendezvous}/#{@session}/msg1")

      assert resp.status == 204
      assert get_resp_header(resp, "access-control-allow-origin") == ["*"]
      assert ["" <> methods] = get_resp_header(resp, "access-control-allow-methods")
      assert methods =~ "PUT"
      assert ["content-type"] = get_resp_header(resp, "access-control-allow-headers")
    end

    test "the bucket routes answer a preflight as well" do
      resp = options(build_conn(), "/b/#{String.duplicate("C", 43)}/entries/#{@session}")
      assert resp.status == 204
      assert get_resp_header(resp, "access-control-allow-origin") == ["*"]
    end

    test "credentials are never allowed" do
      # `*` and credentials are illegal together, and there are no credentials
      # to send: leaving this unset is what keeps a browser from attaching
      # cookies, so none of these routes can become a CSRF surface.
      resp = get(build_conn(), "/rendezvous/#{@rendezvous}/sessions")
      assert get_resp_header(resp, "access-control-allow-credentials") == []
    end
  end
end
