# Example Authorization Token via SSH Agent


## Introduction

Example of a candidate approach for API keys. This approach:

1. Uses ssh keys (via the ssh-agent) on clients to provide identity. The ssh-agent is tasked with ssh key operations - this code never touches the client's private ssh key.

2. Does not centralize any private client key. Users can make their own ssh keys and submit the public key only for identification / usage.

3. Issues a signed JWT token with issue and expirataion times, and as the ip network that the key is valid for.

    - end-users can have a shorter validity and a single address network.

    - internal users can have a longer validty and the internal subnet.

4. Implementation uses standard python SSH / JOSE / JWT / JWK constructs and packages.

5. Verification requires only the issuer public key and a token provided (and signed) by the issuer. The issuer is not required to be available in order to verify an issued token.

5. Auth exchange is based on OAUTH, with client_id and PCKE, but with only two counterparties - the client and the issuer.


## Requirements

1. SSH Agent running on the client, with the required key added.
2. Issuer routes availabe to the client

## Token Issue

```python
tc = TokenClient(logger=logger)
if tc.use('SHA256:<HASH>'):
    token = tc.access_token
```

### Token Issue Internals

1. Client GETs a nonce from the issuer, also providing the client_id (the public ssh key hash), and also a state + PCKE challenge as part of the request.

2. Issuer responses with a nonce (16 bytes of random data) and the state provided by the client, all signed with the Issuer's private key.

3. Client verifies the signed response from the Issue via the Issuer's public key.

3. Client uses ssh agent to sign the nonce.

4. Client POSTS the signed nonce data, the state + PCKE verifier.

5. Issuer verifies the PCKE verifier and the signature on the signed data.

6. Issuer generates claim for the client (a dictionary) with timestamps and network, signs this with the Issuer's private key, and issues the result as a token to the client.

7. Client uses the provided token in the `Authorization` http header.


## Token Usage

### Client:
```python
if token.valid:
    headers={'Authorization': f"Bearer {token!s}"
```

### Server:

```python
if TokenVerifier.verify_token(token, client_ip, issuer_public_key):
```


## Discussion

### Issuer

1. Provides four routes:

 - GET `/nonce`

    initial nonce generation and private storage of the nonce, PCKE challenge, and client_id

 - POST `/nonce`

    verification of client's data (signature, PCKE, etc). token issue

 - GET `/jwks`

    covenience function to provide Issuers public key, useful if it isn't stored on the client (or server).

 - GET `/verify`

    convenience function for a client to check if their token is valid. a simple wrapper around `TokenVerifier.verify_token` where the client provides the token via the `Authorization` header.

2. Issuer private key can be generated at run-time (means all tokens are invalidated asof when a Server read the updated public key via the `/jwks` route). Or stored in an Issuer config.

3. Client public key fingerprints can be stored in a configuration.

4. Issuer public key can be requested from the Issuer or stored in a configuration.

5. Issuer can produce a token outside of the client verification with:
    ```python
    network_access_token = await issuer.generate_access_token(datetime.timedelta(days=7), ipaddress.ip_network("10.0.0.0/16"))
    ```
