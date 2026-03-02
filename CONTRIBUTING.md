# Contributing

Thanks for considering a contribution to py-oidc-auth.

This project aims to keep a small core that is framework independent, with thin
framework adapters that provide a consistent user experience.

## Development prerequisites

You will need:

* Python 3.11 or newer
* tox
* container engine for the development identity provider (Docker or Podman)

Install tox with:

```console
python -m pip install tox
```

## Development identity provider

The development setup uses a Keycloak server as a local OpenID Provider.

To spin up Keycloak, use docker-compose or podman-compose:

```console
podman-compose -f dev-env/docker-compose.yaml up -d
```

If you use Docker:

```console
docker compose -f dev-env/docker-compose.yaml up -d
```

Wait until the OIDC service is ready:

```console
python dev-env/dev_utils.py oidc
```

## Development servers

Pick your framework extra, then start a simple test server using the
`dev_utils.py` script.

Example (FastAPI):

```console
python -m pip install -e .[fastapi]
python dev-env/dev_utils.py fastapi-server
```

The utility shows all available commands:

```console
python dev-env/dev_utils.py --help
usage: dev_utils.py [-h] {fastapi-server,flask-server,quart-server,tornado-server,litestar-server,django-server,gen-certs,oidc} ...

Various utilities for development purpose.

positional arguments:
  {fastapi-server,flask-server,quart-server,tornado-server,litestar-server,django-server,gen-certs,oidc}
    fastapi-server      Run a simple fastapi test server.
    flask-server        Run a simple flask test server.
    quart-server        Run a simple quart test server.
    tornado-server      Run a simple tornado test server.
    litestar-server     Run a simple litestar test server.
    django-server       Run a simple django test server.
    gen-certs           Generate a random pair of public and private certificates.
    oidc                Wait for the oidc service to start up.
```

## Testing, linting, and type checks

Automated testing, linting, and type checking is managed with tox.

Run unit tests:

```console
tox -e test
```

Run linting:

```console
tox -e lint
```

Run mypy:

```console
tox -e types
```

Build documentation:

```console
tox -e docs
```

List all environments:

```console
tox list
```

Typical environments include:

* docs
* lint
* types
* test
* release

## Documentation expectations

Public functions and classes should have docstrings that render well in Sphinx.

When you add or change user visible behavior:

* Update the RST docs under `docs/`
* Add or update examples for the relevant framework adapter
* Keep request examples minimal and copyable

## Adding or changing framework adapters

Adapters should:

* keep the core behavior in `OIDCAuth`
* expose auth endpoints using the framework's standard routing mechanism
* provide `required()` and `optional()` helpers that feel natural in the framework
* stay thin and avoid importing heavy framework internals at module import time

If your adapter needs optional dependencies, keep them behind an extra and
ensure the docs build without those dependencies using `autodoc_mock_imports`.

## Pull requests

Please include:

* a clear description of the change and motivation
* tests for fixes and new features where reasonable
* typing updates if the public API changes
* documentation updates if user behavior changes

If you are unsure about the design direction, open an issue first and propose
an approach before implementing a larger change.

## Security

If you believe you have found a security issue, please do not open a public
issue. Instead, contact the maintainer privately with details and a minimal
reproduction.
