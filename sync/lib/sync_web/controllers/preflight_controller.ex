defmodule SyncWeb.PreflightController do
  @moduledoc """
  Answers the CORS preflight for the raw sync and pairing routes.

  A `PUT` of `application/octet-stream` is not a "simple request", so a browser
  sends an `OPTIONS` request first and refuses to make the real one unless it
  succeeds. That preflight has to be *routed*: a plug in the pipeline is never
  reached, because Phoenix matches a route before it runs the pipeline, and an
  unmatched `OPTIONS` is a 404 with no CORS headers at all — which a browser
  reports as an opaque network failure with nothing in it to debug.

  So it is a real route with a real action. The headers themselves come from the
  `:raw` pipeline, which this shares, so there is one place they are defined.
  """
  use SyncWeb, :controller

  def preflight(conn, _params), do: send_resp(conn, 204, "")
end
