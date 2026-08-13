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
  end

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

  scope "/b/:bucket", SyncWeb do
    pipe_through :raw

    get "/manifest", SyncController, :manifest
    get "/entries/:id", SyncController, :get_entry
    put "/entries/:id", SyncController, :put_entry
    get "/blobs/:id", SyncController, :get_blob
    put "/blobs/:id", SyncController, :put_blob
    get "/snapshots/:id", SyncController, :get_snapshot
    put "/snapshots/:id", SyncController, :put_snapshot
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
