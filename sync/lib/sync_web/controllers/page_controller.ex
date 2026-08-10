defmodule SyncWeb.PageController do
  use SyncWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
