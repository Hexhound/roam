defmodule Sync.Backend.Sweeper do
  @moduledoc """
  Periodically runs the snapshot retention sweep across every bucket so the
  backend reclaims space without unbounded growth. The heavy lifting is in
  `Sync.Backend.Retention`; this is just the timer + bucket enumeration.

  Enabled by default; set `config :sync, :enable_sweeper, false` (test env) to
  keep it out of the supervision tree and drive `sweep_all/1` directly.
  """
  use GenServer
  require Logger

  alias Sync.Backend.{Mailbox, Retention, Store}

  @default_interval_ms 6 * 60 * 60 * 1000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    interval = Keyword.get(opts, :interval_ms, config_interval())
    schedule(interval)
    {:ok, %{interval: interval}}
  end

  @impl true
  def handle_info(:sweep, state) do
    sweep_all([])
    schedule(state.interval)
    {:noreply, state}
  end

  @doc """
  Sweep every bucket under the data root. Returns a map of `bucket => result`.
  `opts` are forwarded to `Retention.sweep/2` (e.g. `:keep`, `:grace_ms`,
  `:now_ms`, `:data_root`) — handy for tests.
  """
  def sweep_all(opts \\ []) do
    root = Keyword.get(opts, :data_root, Store.data_root())
    sweep_mailboxes(opts)

    for bucket <- buckets(root), into: %{} do
      {bucket, sweep_one(bucket, opts)}
    end
  end

  # Pairing mailboxes are short-lived by nature — a pairing window is five
  # minutes — but nothing deletes them at the end of a successful handshake:
  # both sides simply stop polling, and a failed one leaves its slots behind
  # too. Without this they accumulate forever, one directory per pairing
  # attempt. Isolated like the bucket sweep, so a mailbox root that cannot be
  # read never starves snapshot retention.
  defp sweep_mailboxes(opts) do
    Mailbox.sweep(Keyword.take(opts, [:ttl_ms, :now_ms]))
  rescue
    error ->
      Logger.error("pairing mailbox sweep failed: #{inspect(error)}")
      []
  end

  # BE4: buckets are client-controlled, so a single poisoned bucket (e.g. a
  # snapshot manifest with a non-list field) can make Retention.sweep raise.
  # Isolate each bucket: one failure is logged and reported, never aborting the
  # periodic sweep and starving every other bucket of retention.
  defp sweep_one(bucket, opts) do
    Retention.sweep(bucket, opts)
  rescue
    error ->
      Logger.error("retention sweep failed for bucket #{inspect(bucket)}: #{inspect(error)}")
      {:error, error}
  end

  defp buckets(root) do
    case File.ls(root) do
      {:ok, names} ->
        Enum.filter(names, fn n -> File.dir?(Path.join(root, n)) end)

      {:error, _} ->
        []
    end
  end

  defp schedule(interval), do: Process.send_after(self(), :sweep, interval)

  defp config_interval,
    do: Application.get_env(:sync, :snapshot_sweep_interval_ms, @default_interval_ms)
end
