defmodule Sync.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      SyncWeb.Telemetry,
      Sync.Repo,
      {DNSCluster, query: Application.get_env(:sync, :dns_cluster_query) || :ignore},
      {Oban,
       AshOban.config(
         Application.fetch_env!(:sync, :ash_domains),
         Application.fetch_env!(:sync, Oban)
       )},
      {Phoenix.PubSub, name: Sync.PubSub},
      # Start a worker by calling: Sync.Worker.start_link(arg)
      # {Sync.Worker, arg},
      # Start to serve requests, typically the last entry
      SyncWeb.Endpoint,
      {AshAuthentication.Supervisor, [otp_app: :sync]}
    ]

    # The retention sweeper is opt-out (off in test env, where sweep_all/1 is
    # driven directly).
    children =
      if Application.get_env(:sync, :enable_sweeper, true) do
        children ++ [Sync.Backend.Sweeper]
      else
        children
      end

    # See https://elixir.hexdocs.pm/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Sync.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    SyncWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
