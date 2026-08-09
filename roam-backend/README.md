# roam-backend

Zero-knowledge encrypted fallback store for roam. Stores opaque ciphertext by
opaque id; never sees plaintext, vault identity, authorship, or ordering.

## Run

    ROAM_BACKEND_ROOT=/var/lib/roam-backend PORT=4000 elixir server.exs

## Test

    elixir test/router_test.exs

No DB, no auth (this slice). Auth arrives later via AshAuthentication.
