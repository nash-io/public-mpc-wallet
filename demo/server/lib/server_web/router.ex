defmodule ServerWeb.Router do
  use ServerWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
    plug :fetch_session
    plug CORSPlug, origin: ["http://localhost:4000", "http://localhost:8080"]

  end

  scope "/api/v1", ServerWeb do
    pipe_through :api

    post "/get_paillier_keypair_and_proof", MPCController, :get_paillier_keypair_and_proof
    options "/get_paillier_keypair_and_proof", MPCController, :nothing # for cors_plug

    post "/dh_rpool", MPCController, :dh_rpool
    options "/dh_rpool", MPCController, :nothing # for cors_plug

    post "/complete_sig", MPCController, :complete_sig
    options "/complete_sig", MPCController, :nothing # for cors_plug
  end

  scope "/", ServerWeb do
    pipe_through :browser

    get "/", PageController, :index
  end

  # Other scopes may use custom stacks.
  # scope "/api", ServerWeb do
  #   pipe_through :api
  # end
end
