defmodule Server.MPCwallet do
  @moduledoc """
  Library for the server part of the MPC-based API keys.

  Glossary of terms:
      - MPC: Multi-party computation. A method to have multiple parties compute a function while keeping their inputs private. For our case, the function is creating a digital signature and the (private) inputs are secret shares.
      - DH: Diffie-Hellman key exchange. A method to derive a shared secret key over an insecure channel.
      - Paillier: A public-key, additive homomorphic cryptosystem. Allows the client to conduct operations on the ciphertext.
      - r: Random value shared between client and server (derived via DH), from which the r value of the ECDSA signature is derived.
      - k: Server part of the nonce used in the signature. This should be handled like a secret key, i.e., store securely, delete/zeroize after use, ..
      - curve: Elliptic curve to be used in an ECDSA signature. Currently we support secp256k1 (for BTC and ETH) and secp256r1 (for NEO).
      - presig: A presignature generated on the client that can be finalized to a conventional signature by the server.
      - rpool: Pool of random values shared between client and server that allows to generate signatures with a single message.
      - r, s: a conventional ECDSA signature.
      - recovery_id: 2 bits that help recovering the public key from a signature, used in Ethereum to save space.
      - correct_key_proof: ZK proof that the Paillier public key was generated correctly.
  """
  use Rustler, otp_app: :server, crate: "mpc_wallet_elixir"

  @doc ~S"""
  Generate Paillier keypair with safe primes and proof that the keypair was generated correctly.

  ## Parameters

      - none

  ## Returns

      - Paillier secret key
      - Paillier public key
      - correct_key_proof: proof
  """
  def generate_paillier_keypair_and_proof(), do: :erlang.nif_error(:nif_not_loaded)


  @doc ~S"""
  Compute rpool values via Diffie-Hellman.

  ## Parameters

      - client_dh_publics: list of DH public keys received from the client
      - curve: Secp256k1 or Secp256r1 curve

  ## Returns

      - rpool_new: map of rpool values to be added to the local pool
      - server_dh_publics: list of public keys (to be sent to the client)

  """
  def dh_rpool(_client_dh_publics, _curve), do: :erlang.nif_error(:nif_not_loaded)


  @doc ~S"""
  Complete presignature to conventional ECDSA signature.

  ## Parameters

      - paillier_sk: Paillier secret key
      - presig: presignature received from client
      - r: random value shared between server and client
      - k: server part of the nonce used in the signature
      - curve: Secp256k1 or Secp256r1 curve

  ## Returns

      - r: r part of a conventional ECDSA signature
      - s: s part of a conventional ECDSA signature
      - recovery_id: 2 bits that help recovering the public key from a signature

  """
  def complete_sig(_paillier_sk, _presig, _r, _k, _curve), do: :erlang.nif_error(:nif_not_loaded)


  @doc ~S"""
  Verify conventional ECDSA signature.

  ## Parameters

      - r: r part of a conventional ECDSA signature
      - s: s part of a conventional ECDSA signature
      - pubkey: ECDSA public key
      - msg_hash: hash of the message
      - curve: Secp256k1 or Secp256r1 curve

  ## Returns

      - ok | error: boolean indicating success

  """
  def verify(_r, _s, _pubkey, _msg_hash, _curve), do: :erlang.nif_error(:nif_not_loaded)


  @doc ~S"""
  Generate key pairs for Diffie-Hellman.

  ## Parameters

      - n: number of key pairs to generate
      - curve: Secp256k1 or Secp256r1 curve

  ## Returns

      - dh_secrets: list of (n) secret keys
      - dh_publics: list of (n) public keys

      First public key corresponds to first secret key, ..
  """
  def dh_init(_n, _curve), do: :erlang.nif_error(:nif_not_loaded)


  @doc ~S"""
  Compute presignature of a message.

  ## Parameters

      - apikey: API key struct
      - msg_hash: hash of the message to be signed
      - curve: Secp256k1 or Secp256r1 curve

  ## Returns

      - presig: presignature that is to be completed by the server
      - r: message-independent part of the signature that was used to compute the presignature

  """
  def compute_presig(_apikey, _msg_hash, _curve), do: :erlang.nif_error(:nif_not_loaded)


  @doc ~S"""
  (re-)Fill pool of r-values from dh secret and public values.

  ## Parameters

      - client_dh_secrets: list of client DH secret keys
      - server_dh_publics: list of DH public keys received from the server
      - curve: Secp256k1 or Secp256r1 curve
      - paillier_pk: Paillier public key

  ## Returns

      - ok | error: boolean indicating success

  """
  def fill_rpool(_client_dh_secrets, _server_dh_publics, _curve, _paillier_pk), do: :erlang.nif_error(:nif_not_loaded)


  @doc ~S"""
  Initialize API childkey creation by setting the full secret key.

  ## Parameters

      - secret_key: full secret key

  ## Returns

      - api_childkey_creator: API childkey creation struct

  """
  def init_api_childkey_creator(_secret_key), do: :erlang.nif_error(:nif_not_loaded)


  @doc ~S"""
  Initialize API childkey creation by setting the full secret key and the paillier public key, assuming that the paillier public key has been verified before.

  ## Parameters

      - secret_key: full secret key
      - paillier_pk: Paillier public key

  ## Returns

      - api_childkey_creator: API childkey creation struct

  """
  def init_api_childkey_creator_with_verified_paillier(_secret_key, _paillier_pk), do: :erlang.nif_error(:nif_not_loaded)


  @doc ~S"""
  Verify that the Paillier public key was generated correctly.

  ## Parameters

      - api_childkeyc_reator: API childkey creation struct
      - paillier_pk: Paillier public key
      - correct_key_proof: ZK proof that the Paillier public key was generated correctly

  ## Returns

      - api_childkey_creator: API key creation struct

  """
  def verify_paillier(_api_childkey_creator, _paillier_pk, _correct_key_proof), do: :erlang.nif_error(:nif_not_loaded)


  @doc ~S"""
  Create API childkey.

  ## Parameters

      - api_childkey_creator: API childkey creation struct
      - curve: Secp256k1 or Secp256r1 curve

  ## Returns

      - api_childkey: API childkey struct

  """
  def create_api_childkey(_api_childkey_creator, _curve), do: :erlang.nif_error(:nif_not_loaded)


  @doc ~S"""
  Derive public key from given secret key.

  ## Parameters

      - secret_key: (full) secret key)
      - curve: Secp256k1 or Secp256r1 curve

  ## Returns

      - public_key: corresponding public key

  """
  def publickey_from_secretkey(_secret_key, _curve), do: :erlang.nif_error(:nif_not_loaded)
end
