<p align="center">
  <img src="docs/source/_static/logo.png" alt="py-oidc-auth-client logo" width="560">
</p>
<p align="center">
<em>Typed client library for the authentication routes exposed by py-oidc-auth.</em>
</p>

py-oidc-auth-client is the counterpart of the server-side library **py-oidc-auth**.

While **py-oidc-auth** helps you add OpenID Connect login, token, and device endpoints to web frameworks,
**py-oidc-auth-client** consumes those routes and gives you ready-to-use bearer tokens for calling protected APIs.

## Features

* One high level helper: `authenticate()`
* Device flow for headless sessions
* Authorization code flow for interactive logins
* Token caching and refresh token support via a token file
* Fully typed public API

## Install

```console
python -m pip install py-oidc-auth-client
```

Import name is `py_oidc_auth_client`:

```python
from py_oidc_auth_client import authenticate
```

## Relationship to py-oidc-auth

A typical **py-oidc-auth** server exposes endpoints similar to:

* `GET  /auth/v2/login`
* `GET  /auth/v2/callback`
* `POST /auth/v2/token`
* `POST /auth/v2/device`
* `GET  /auth/v2/logout`
* `GET  /auth/v2/userinfo`

This client calls the relevant routes (token and device, and possibly login/callback) and returns a `Token`
object that contains a ready-made `Authorization` header.

## Quick start

```python
from py_oidc_auth_client import authenticate

token = authenticate(host="https://auth.example.org")

# Use with any HTTP client
headers = token["headers"]
print(headers["Authorization"])
```

### Use with httpx

```python
import httpx
from py_oidc_auth_client import authenticate

token = authenticate(host="https://auth.example.org")

with httpx.Client() as client:
    r = client.get("https://service.example.org/protected", headers=token["headers"])
    r.raise_for_status()
    print(r.json())
```

## Token persistence

By default, the client stores tokens in a cache file so you do not have to re-authenticate on every run.
You can control where tokens are stored with `token_file`:

```python
from py_oidc_auth_client import authenticate

token = authenticate(
    host="https://auth.example.org",
    token_file="~/.cache/py-oidc-auth-client/token.json",
)
```

You can also point to a token file via environment variable:

* `OIDC_TOKEN_FILE`

## Interactive and non-interactive environments

The client tries to select a suitable strategy:

1. Use a valid cached access token.
2. Refresh using the refresh token.
3. If interactive authentication is possible, fall back to an interactive login.
4. If running in a non-interactive session without a usable token, raise an error telling you how to provide a token file.

For headless sessions, the device flow is the recommended approach.

## Advanced usage

If you need more control than `authenticate()`, use the flow helpers from `py_oidc_auth_client.auth`.

### Device flow

```python
import asyncio
from py_oidc_auth_client.auth import DeviceFlowResponse
from py_oidc_auth_client.utils import Config

async def main() -> None:
    cfg = Config(host="https://auth.example.org")
    flow = DeviceFlowResponse(config=cfg, token=None, timeout=600)

    device = await flow.get_device_code()
    print("Open:", device.uri)
    print("Code:", device.user_code)

    await flow.poll_for_token(device.device_code, int(device.interval))
    print(flow.token["headers"])

asyncio.run(main())
```

### Authorization code flow

```python
import asyncio
from py_oidc_auth_client.auth import CodeFlowResponse
from py_oidc_auth_client.utils import Config

async def main() -> None:
    cfg = Config(host="https://auth.example.org")
    flow = CodeFlowResponse(config=cfg, token=None, timeout=120)
    await flow.login()
    print(flow.token["headers"])

asyncio.run(main())
```

## Documentation

This repository ships a Sphinx documentation tree under `docs/`.

If you build documentation without installing all runtime dependencies, you can configure Sphinx to mock
imports via `autodoc_mock_imports` in `conf.py`.

## License

Choose a license that matches your project goals. For most Python libraries, MIT or Apache-2.0 are common choices.

## Contributing

Contributions are welcome. Please open an issue to discuss larger changes before submitting a pull request.
