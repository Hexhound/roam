defmodule Sync.Accounts do
  use Ash.Domain,
    otp_app: :sync

  resources do
    resource Sync.Accounts.Token
    resource Sync.Accounts.User
    resource Sync.Accounts.ApiKey
  end
end
