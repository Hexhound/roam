defmodule SyncWeb.Router do
  use SyncWeb, :router

  import Oban.Web.Router
  use AshAuthentication.Phoenix.Router

  import AshAuthentication.Plug.Helpers

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {SyncWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :load_from_session
  end

  pipeline :api do
    plug :accepts, ["json"]

    plug AshAuthentication.Strategy.ApiKey.Plug,
      resource: Sync.Accounts.User,
      # if you want to require an api key to be supplied, set `required?` to true
      required?: false

    plug :load_from_bearer
    plug :set_actor, :user
  end

  pipeline :raw do
    plug :accepts, ["*/*"]
    plug :reject_multipart_body
    plug :allow_any_origin
  end

  # CORS, and why `*` is the honest answer here rather than a lazy one.
  #
  # A browser client cannot reach ANY of these routes without it — not the sync
  # bucket, not the pairing mailbox — because a cross-origin `fetch` to a
  # different host is blocked before the request is even made. That made a web
  # client impossible regardless of everything else that had been built for it.
  #
  # `*` is correct because there is nothing here for an origin to be trusted
  # with. These routes carry opaque ciphertext, they authenticate nobody, and
  # possession of the URL is already the whole of the access control: an
  # attacker who knows a bucket or rendezvous id can read it with `curl` and does
  # not need a browser to do it for them. Restricting the header would inconvenience
  # honest clients and stop no attacker.
  #
  # What is NOT set, deliberately:
  #
  #   * `Access-Control-Allow-Credentials` — with `*` the two are illegal
  #     together, and more to the point there are no credentials. Leaving it off
  #     means a browser attaches no cookies to these requests, so nothing here
  #     can ever become a CSRF surface.
  #   * `Access-Control-Allow-Headers: *` for anything beyond content-type. A
  #     client sends opaque bytes and nothing else.
  #
  # This applies only to the `:raw` pipeline. The `:browser` pipeline — which
  # does have sessions, cookies and CSRF protection — is untouched.
  defp allow_any_origin(conn, _opts) do
    conn
    |> Plug.Conn.put_resp_header("access-control-allow-origin", "*")
    |> Plug.Conn.put_resp_header("access-control-allow-methods", "GET, PUT, POST, OPTIONS")
    |> Plug.Conn.put_resp_header("access-control-allow-headers", "content-type")
    |> Plug.Conn.put_resp_header("access-control-max-age", "86400")
  end

  # The OPTIONS preflight each scope needs is a route of its own — see
  # `SyncWeb.PreflightController` for why a plug alone could not do it.

  # H-C: the raw sync routes carry opaque octet-stream ciphertext. The MULTIPART
  # Plug.Parser reads the body via `read_part_body`, bypassing the caching
  # `body_reader`, so a multipart PUT reaches the controller with an empty body
  # and (first-write-wins, zero-knowledge) would poison the content-addressed id
  # with a 0-byte object for every peer. A legitimate client never uses multipart
  # here, so refuse it outright. (json/urlencoded are safe — they read through the
  # CachingBodyReader and the controller recovers the raw bytes.)
  defp reject_multipart_body(conn, _opts) do
    # Match the media type the SAME way Plug.Parsers picks its parser —
    # `content_type/1` downcases the type and trims params — so a header like
    # `Multipart/form-data` or ` MULTIPART/mixed` cannot slip past a naive
    # case-sensitive `starts_with?` while still triggering the multipart parser.
    case Plug.Conn.get_req_header(conn, "content-type") do
      [content_type | _] ->
        case Plug.Conn.Utils.content_type(content_type) do
          {:ok, "multipart", _subtype, _params} ->
            conn
            |> Plug.Conn.send_resp(415, "unsupported media type")
            |> Plug.Conn.halt()

          _ ->
            conn
        end

      _ ->
        conn
    end
  end

  # Device pairing through the relay: write-once slots so two devices that cannot
  # reach each other directly can run a handshake. Opaque here exactly like every
  # other kind — every body is a SPAKE2 message or a ciphertext sealed under a
  # key derived from a code the relay never sees. See `Sync.Backend.Mailbox`.
  scope "/rendezvous/:rendezvous", SyncWeb do
    pipe_through :raw

    match :options, "/*path", PreflightController, :preflight
    get "/sessions", RendezvousController, :sessions
    get "/:session/:slot", RendezvousController, :get_slot
    put "/:session/:slot", RendezvousController, :put_slot
  end

  scope "/b/:bucket", SyncWeb do
    pipe_through :raw

    match :options, "/*path", PreflightController, :preflight
    get "/manifest", SyncController, :manifest
    get "/entries/:id", SyncController, :get_entry
    put "/entries/:id", SyncController, :put_entry
    get "/blobs/:id", SyncController, :get_blob
    put "/blobs/:id", SyncController, :put_blob
    get "/snapshots/:id", SyncController, :get_snapshot
    put "/snapshots/:id", SyncController, :put_snapshot
    get "/trust/:id", SyncController, :get_trust
    put "/trust/:id", SyncController, :put_trust
    post "/reconcile/:kind", SyncController, :reconcile
  end

  scope "/", SyncWeb do
    pipe_through :browser

    ash_authentication_live_session :authenticated_routes do
      # in each liveview, add one of the following at the top of the module:
      #
      # If an authenticated user must be present:
      # on_mount {SyncWeb.LiveUserAuth, :live_user_required}
      #
      # If an authenticated user *may* be present:
      # on_mount {SyncWeb.LiveUserAuth, :live_user_optional}
      #
      # If an authenticated user must *not* be present:
      # on_mount {SyncWeb.LiveUserAuth, :live_no_user}
    end
  end

  scope "/", SyncWeb do
    pipe_through :browser

    get "/", PageController, :home
    auth_routes AuthController, Sync.Accounts.User, path: "/auth"
    sign_out_route AuthController

    # Remove these if you'd like to use your own authentication views
    sign_in_route register_path: "/register",
                  reset_path: "/reset",
                  auth_routes_prefix: "/auth",
                  on_mount: [{SyncWeb.LiveUserAuth, :live_no_user}],
                  overrides: [
                    SyncWeb.AuthOverrides,
                    Elixir.AshAuthentication.Phoenix.Overrides.Default
                  ]

    # Remove this if you do not want to use the reset password feature
    reset_route auth_routes_prefix: "/auth",
                overrides: [
                  SyncWeb.AuthOverrides,
                  Elixir.AshAuthentication.Phoenix.Overrides.Default
                ]

    # Remove this if you do not use the confirmation strategy
    confirm_route Sync.Accounts.User, :confirm_new_user,
      auth_routes_prefix: "/auth",
      overrides: [SyncWeb.AuthOverrides, Elixir.AshAuthentication.Phoenix.Overrides.Default]

    # Remove this if you do not use the magic link strategy.
    magic_sign_in_route(Sync.Accounts.User, :magic_link,
      auth_routes_prefix: "/auth",
      overrides: [SyncWeb.AuthOverrides, Elixir.AshAuthentication.Phoenix.Overrides.Default]
    )
  end

  # Other scopes may use custom stacks.
  # scope "/api", SyncWeb do
  #   pipe_through :api
  # end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:sync, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: SyncWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end

    scope "/" do
      pipe_through :browser

      oban_dashboard("/oban")
    end
  end
end
