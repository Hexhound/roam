defmodule Sync.Backend.Sweeper do
  @moduledoc """
  Periodically runs the snapshot retention sweep across every bucket so the
  backend reclaims space without unbounded growth. The heavy lifting is in
  `Sync.Backend.Retention`; this is just the timer + bucket enumeration.

  Enabled by default; set `config :sync, :enable_sweeper, false` (test env) to
  keep it out of the supervision tree and drive `sweep_all/1` directly.
  """
  use GenServer

  alias Sync.Backend.{Retention, Store}

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

    for bucket <- buckets(root), into: %{} do
      {bucket, Retention.sweep(bucket, opts)}
    end
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
