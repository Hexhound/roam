import Config
config :sync, Oban, testing: :manual
config :sync, token_signing_secret: "GJoJa2Y8HdowxVjNkrRMmMKcTD/lSWC+"
config :bcrypt_elixir, log_rounds: 1
config :ash, policies: [show_policy_breakdowns?: true], disable_async?: true

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
# Credentials read the standard PG* variables before falling back to the
# conventional postgres/postgres — see the longer note in `dev.exs`. devenv's
# Postgres has no `postgres` role at all, and the failure surfaces as
# "The database for Sync.Repo couldn't be created: killed", which names neither
# the role nor the cause.
config :sync, Sync.Repo,
  username: System.get_env("PGUSER") || "postgres",
  password: System.get_env("PGPASSWORD") || "postgres",
  hostname: System.get_env("PGHOST") || "localhost",
  port: String.to_integer(System.get_env("PGPORT") || "5432"),
  database: "sync_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :sync, SyncWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "LHgPrltv2ItHSFhNvqMVCZprxoaWgKVrn662rO5b3L6f+NRSYR/Hq742I8gnPOZt",
  server: false

# In test we don't send emails
config :sync, Sync.Mailer, adapter: Swoosh.Adapters.Test

# Disable swoosh api client as it is only required for production adapters
config :swoosh, :api_client, false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true

# Keep the retention sweeper out of the supervision tree in tests; sweep_all/1 is
# driven directly where needed.
config :sync, :enable_sweeper, false
