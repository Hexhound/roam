defmodule SyncWeb.SyncController do
  use SyncWeb, :controller
  alias Sync.Backend.Store

  # Reject bad bucket/id BEFORE touching the filesystem (path traversal defense).
  defp guard(conn, ids) do
    if Enum.all?(ids, &Store.valid_id?/1), do: :ok, else: {:halt, send_resp(conn, 400, "bad id")}
  end

  def get_entry(conn, %{"bucket" => b, "id" => id}), do: do_get(conn, b, "entries", id)
  def put_entry(conn, %{"bucket" => b, "id" => id}), do: do_put(conn, b, "entries", id)
  def get_blob(conn, %{"bucket" => b, "id" => id}), do: do_get(conn, b, "blobs", id)
  def put_blob(conn, %{"bucket" => b, "id" => id}), do: do_put(conn, b, "blobs", id)

  @kinds %{"entries" => "entries", "blobs" => "blobs"}

  def reconcile(conn, %{"bucket" => bucket, "kind" => kind}) do
    with :ok <- guard(conn, [bucket]),
         {:ok, kind_dir} <- fetch_kind(kind),
         {:ok, body, conn} <- read_body(conn) do
      items = Store.id_bytes(bucket, kind_dir)

      case Sync.Rbsr.reconcile_server(items, body) do
        {:ok, reply} ->
          conn |> put_resp_content_type("application/octet-stream") |> send_resp(200, reply)

        {:error, _reason} ->
          send_resp(conn, 400, "bad reconcile message")
      end
    else
      {:halt, conn} -> conn
      :error -> send_resp(conn, 400, "unknown kind")
    end
  end

  defp fetch_kind(kind) do
    case Map.fetch(@kinds, kind) do
      {:ok, dir} -> {:ok, dir}
      :error -> :error
    end
  end

  def manifest(conn, %{"bucket" => b}) do
    with :ok <- guard(conn, [b]) do
      json(conn, %{entry_ids: Store.list(b, "entries"), blob_ids: Store.list(b, "blobs")})
    else
      {:halt, conn} -> conn
    end
  end

  defp do_get(conn, bucket, kind, id) do
    with :ok <- guard(conn, [bucket, id]) do
      case Store.get(bucket, kind, id) do
        nil ->
          send_resp(conn, 404, "")

        bytes ->
          conn |> put_resp_content_type("application/octet-stream") |> send_resp(200, bytes)
      end
    else
      {:halt, conn} -> conn
    end
  end

  defp do_put(conn, bucket, kind, id) do
    with :ok <- guard(conn, [bucket, id]),
         {:ok, body, conn} <- read_body(conn, length: 64_000_000) do
      case Store.put(bucket, kind, id, body) do
        :created -> send_resp(conn, 201, "")
        :exists -> send_resp(conn, 409, "")
      end
    else
      {:halt, conn} -> conn
    end
  end
end
