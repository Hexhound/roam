Mix.install([
  {:plug, "~> 1.16"},
  {:bandit, "~> 1.5"},
  {:jason, "~> 1.4"}
])

defmodule Roam.Backend.Store do
  @moduledoc "Filesystem-backed opaque ciphertext store. Existence = dedup."

  @id ~r/^[A-Za-z0-9_-]+$/

  def valid_id?(id), do: is_binary(id) and Regex.match?(@id, id)

  def root, do: System.get_env("ROAM_BACKEND_ROOT", "./roam-backend-data")

  defp dir(bucket, kind), do: Path.join([root(), "b", bucket, kind])

  @doc "Write ciphertext iff absent. :created | :exists."
  def put(bucket, kind, id, body) do
    dir = dir(bucket, kind)
    File.mkdir_p!(dir)
    path = Path.join(dir, id)

    if File.exists?(path) do
      :exists
    else
      # Unique temp name per writer so two concurrent first-writers for the same
      # id never share (and corrupt) one `.tmp` file. rename is atomic; the last
      # rename wins and both writers wrote identical ciphertext bytes anyway.
      tmp = path <> ".tmp." <> Integer.to_string(:erlang.unique_integer([:positive]))
      File.write!(tmp, body)
      File.rename!(tmp, path)
      :created
    end
  end

  @doc "Read ciphertext. {:ok, bytes} | :not_found."
  def get(bucket, kind, id) do
    path = Path.join(dir(bucket, kind), id)
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, :enoent} -> :not_found
      {:error, reason} -> raise "read failed: #{inspect(reason)}"
    end
  end

  @doc "List ids present for a bucket/kind."
  def list(bucket, kind) do
    case File.ls(dir(bucket, kind)) do
      {:ok, names} -> Enum.reject(names, &String.contains?(&1, ".tmp"))
      {:error, :enoent} -> []
    end
  end
end

defmodule Roam.Backend.Router do
  use Plug.Router

  plug :match
  plug :dispatch

  alias Roam.Backend.Store

  get "/b/:bucket/manifest" do
    if Store.valid_id?(bucket) do
      body = Jason.encode!(%{entry_ids: Store.list(bucket, "entries"), blob_ids: Store.list(bucket, "blobs")})
      conn |> put_resp_content_type("application/json") |> send_resp(200, body)
    else
      send_resp(conn, 400, "bad bucket id")
    end
  end

  get "/b/:bucket/entries/:id", do: do_get(conn, bucket, "entries", id)
  get "/b/:bucket/blobs/:id", do: do_get(conn, bucket, "blobs", id)
  put "/b/:bucket/entries/:id", do: do_put(conn, bucket, "entries", id)
  put "/b/:bucket/blobs/:id", do: do_put(conn, bucket, "blobs", id)

  match _ do
    send_resp(conn, 404, "not found")
  end

  defp do_get(conn, bucket, kind, id) do
    cond do
      not (Store.valid_id?(bucket) and Store.valid_id?(id)) ->
        send_resp(conn, 400, "bad id")

      true ->
        case Store.get(bucket, kind, id) do
          {:ok, bytes} -> conn |> put_resp_content_type("application/octet-stream") |> send_resp(200, bytes)
          :not_found -> send_resp(conn, 404, "not found")
        end
    end
  end

  defp do_put(conn, bucket, kind, id) do
    cond do
      not (Store.valid_id?(bucket) and Store.valid_id?(id)) ->
        send_resp(conn, 400, "bad id")

      true ->
        {:ok, body, conn} = read_body(conn, length: 64_000_000)
        case Store.put(bucket, kind, id, body) do
          :created -> send_resp(conn, 201, "")
          :exists -> send_resp(conn, 409, "")
        end
    end
  end
end

if System.get_env("ROAM_BACKEND_NOSERVE") == nil do
  port = String.to_integer(System.get_env("PORT", "4000"))
  IO.puts("roam-backend listening on :#{port} (root=#{Roam.Backend.Store.root()})")
  {:ok, _} = Bandit.start_link(plug: Roam.Backend.Router, port: port)
  Process.sleep(:infinity)
end
