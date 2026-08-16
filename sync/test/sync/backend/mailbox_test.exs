defmodule Sync.Backend.MailboxTest do
  use ExUnit.Case, async: false

  alias Sync.Backend.{Mailbox, Store}

  @rendezvous String.duplicate("R", 43)
  @session String.duplicate("S", 43)

  setup do
    root = Path.join(System.tmp_dir!(), "roam-mailbox-test-#{System.unique_integer([:positive])}")
    Application.put_env(:sync, :backend_data_root, root)
    Application.delete_env(:sync, :mailbox_data_root)

    on_exit(fn ->
      File.rm_rf(root)
      File.rm_rf(root <> "-rendezvous")
      Application.delete_env(:sync, :backend_data_root)
    end)

    :ok
  end

  test "a slot round-trips its bytes" do
    assert Mailbox.put(@rendezvous, @session, "msg1", "spake bytes") == :created
    assert Mailbox.get(@rendezvous, @session, "msg1") == "spake bytes"
  end

  test "an absent slot reads as nil rather than raising" do
    # Polling for a slot the other side has not written yet is the normal case,
    # not an error — a raise here would make every poll a 500.
    assert Mailbox.get(@rendezvous, @session, "msg2") == nil
  end

  test "a taken slot refuses the second write and keeps the first body" do
    # Refusing is only half of it. If the second write landed anyway, a squatter
    # could replace a message the other side had already read.
    assert Mailbox.put(@rendezvous, @session, "msg1", "first") == :created
    assert Mailbox.put(@rendezvous, @session, "msg1", "second") == :exists
    assert Mailbox.get(@rendezvous, @session, "msg1") == "first"
  end

  test "two simultaneous writers to one slot: exactly one wins" do
    # The case the `File.exists?` fast path structurally cannot handle — both
    # requests see an absent file, and one of them must still lose. Only the
    # atomic link does that; a rename would let both report success and the
    # second body would silently replace the first.
    #
    # A relay serves concurrent requests, so this is the real shape of a
    # squatter racing the host, not a contrived one.
    slot = "msg2"

    outcomes =
      1..24
      |> Task.async_stream(
        fn index -> Mailbox.put(@rendezvous, @session, slot, "writer-#{index}") end,
        max_concurrency: 24,
        ordered: false
      )
      |> Enum.map(fn {:ok, outcome} -> outcome end)

    assert Enum.count(outcomes, &(&1 == :created)) == 1,
           "exactly one writer may create the slot, got #{inspect(outcomes)}"

    # And the body that survived is a whole one from a single writer, not a
    # blend of two interleaved writes.
    assert Mailbox.get(@rendezvous, @session, slot) =~ ~r/^writer-\d+$/
  end

  test "sessions are listed and do not bleed across rendezvous" do
    other = String.duplicate("T", 43)
    session_b = String.duplicate("B", 43)

    Mailbox.put(@rendezvous, @session, "msg1", "x")
    Mailbox.put(@rendezvous, session_b, "msg1", "x")
    Mailbox.put(other, String.duplicate("C", 43), "msg1", "x")

    assert Mailbox.sessions(@rendezvous) == Enum.sort([@session, session_b])
    assert Mailbox.sessions(other) == [String.duplicate("C", 43)]
    assert Mailbox.sessions(String.duplicate("Z", 43)) == []
  end

  test "a rendezvous stops accepting new sessions at the cap" do
    # An unauthenticated writer must not be able to create directories under one
    # rendezvous without limit.
    for index <- 1..Mailbox.max_sessions() do
      session = String.pad_leading("#{index}", 43, "0")
      assert Mailbox.put(@rendezvous, session, "msg1", "x") == :created
    end

    assert Mailbox.put(@rendezvous, String.duplicate("X", 43), "msg1", "x") ==
             :too_many_sessions

    # An EXISTING session must still be usable — the cap bounds new directories,
    # it must not break a handshake already in flight.
    assert Mailbox.put(@rendezvous, String.pad_leading("1", 43, "0"), "msg2", "y") ==
             :created
  end

  test "only the six handshake slot names are accepted" do
    # This is a pairing mailbox, not a general object store, and it should be
    # impossible to use it as one.
    for slot <- ~w(msg1 msg2 confirm-joiner confirm-host request accept) do
      assert Mailbox.valid_slot?(slot), "#{slot} must be accepted"
    end

    for slot <- ~w(msg3 MSG1 accept2 .. ../../etc/passwd), do: refute(Mailbox.valid_slot?(slot))
  end

  test "ids must be exactly a 32-byte base64url id" do
    assert Mailbox.valid_id?(@rendezvous)
    refute Mailbox.valid_id?(String.duplicate("A", 42)), "too short"
    refute Mailbox.valid_id?(String.duplicate("A", 44)), "too long"
    refute Mailbox.valid_id?("../" <> String.duplicate("A", 40)), "path traversal"
    refute Mailbox.valid_id?(nil)
  end

  test "the mailbox root is not inside the bucket root" do
    # Load-bearing, and easy to undo by accident. `Sweeper` treats every
    # directory under the bucket root as a bucket to run snapshot retention
    # over, and bucket names are client-controlled — so a mailbox subtree living
    # inside it would both be swept as if it were a vault and be reachable
    # through the `/b/:bucket` routes.
    bucket_root = Path.expand(Store.data_root())
    mailbox_root = Path.expand(Mailbox.data_root())

    refute String.starts_with?(mailbox_root <> "/", bucket_root <> "/"),
           "the mailbox root #{mailbox_root} is inside the bucket root #{bucket_root}"
  end

  describe "sweep" do
    test "removes a rendezvous untouched for longer than the ttl" do
      Mailbox.put(@rendezvous, @session, "msg1", "x")

      # Nothing deletes a mailbox when a handshake ends — both sides just stop
      # polling — so without the sweep these accumulate one per pairing attempt.
      swept = Mailbox.sweep(ttl_ms: 0, now_ms: System.system_time(:millisecond) + 60_000)

      assert swept == [@rendezvous]
      assert Mailbox.sessions(@rendezvous) == []
      assert Mailbox.get(@rendezvous, @session, "msg1") == nil
    end

    test "leaves a rendezvous that is still inside its window" do
      # A sweep that took the live one too would break pairing rather than tidy
      # up after it.
      Mailbox.put(@rendezvous, @session, "msg1", "x")

      assert Mailbox.sweep(ttl_ms: 60_000) == []
      assert Mailbox.get(@rendezvous, @session, "msg1") == "x"
    end

    test "an absent root is not an error" do
      assert Mailbox.sweep(data_root: "/nonexistent/roam-mailbox-root") == []
    end
  end
end
