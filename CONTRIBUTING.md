# Contributing

Thanks for considering a contribution to py-oidc-auth.

This project aims to keep a small core that is framework independent, with thin
framework adapters that provide a consistent user experience.

## Development prerequisites

You will need:

* [just](https://just.systems)
* Docker with compose, or Podman with podman-compose

Python itself is not needed on your machine: everything except `just release`
runs in containers, one image per Python version, with the dependencies
installed into the image's own Python (no virtualenv). Your checkout is
mounted into the container, so edits apply without a rebuild. A change to
`pyproject.toml` gets a fresh image on the next run.

Run `just` to see all recipes. Two environment variables pick the setup:

* `PY` sets the Python version (default 3.13): `PY=3.11 just test`
* `COMPOSE` sets the compose tool (default `docker compose`):
  `COMPOSE=podman-compose just dev`

## Development servers

`just dev` starts Keycloak and a test app for the framework of your choice
on <http://localhost:7777>, reloading when you edit the code:

```console
just dev                              # fastapi
just dev litestar                     # any of: fastapi flask quart tornado litestar django
just dev django --no-broker-mode      # extra arguments go to dev-env/dev_utils.py
PY=3.11 just dev flask
```

Ctrl-C stops the server; Keycloak keeps running until `just down`.

The test app serves the auth routes under `/api/test/auth/v2/` and these
endpoints:

- `/protected`: requires a token
- `/optional`: accepts requests with or without a token
- `/admin`: requires a token with the admin claim

To log in with a browser, open
<http://localhost:7777/api/test/auth/v2/login?redirect_uri=http://localhost:7777/api/test/auth/v2/callback>.

## Development identity provider (IDP)

Keycloak runs on <http://localhost:8080> (admin console: `keycloak` /
`secret`) with the `freva` realm from `dev-env/keycloak/import`. `just up`
starts it on its own, and the `dev` and `test` recipes start it as needed.
Inside the dev container Keycloak is `localhost:8080` too, so tokens have
the same issuer everywhere.

The realm is imported when the Keycloak container is created. After
changing `realm-export.json`, run `just down` so the next start imports it
again.

### IDP accounts
The development IDP server ships with pre-defined mock accounts those are

- uid: ``<YOUR-USER>``, password: ``secret``
- uid: ``johndoe``, password: ``johndoe123``
- uid: ``janedoe``, password: ``janedoe123``
- uid: ``alicebrown``, password: ``alicebrown123``
- uid: ``bobsmith``, password: ``bobsmith123``
- uid: ``lisajones``, password: ``lisajones123``

`<YOUR-USER>` is the user name that started Keycloak.

## Testing, linting, and type checks

```console
just test                    # the whole suite with coverage
just test -k pkce -x         # or any pytest arguments
PY=3.11 just test            # on another Python version
just test-all                # on every supported version, then a summary
just lint                    # black, isort, flake8, codespell, pydocstyle, bandit
just fmt                     # apply black and isort
just types                   # mypy
just docs                    # build the docs into docs/build/html
just check                   # lint, types and test
```

`just shell` opens a shell in the dev container, with Keycloak at
`localhost:8080`.

## Git hooks

`just setup` (realm, dev image, hooks) and `just dev` turn on the hooks in
`.githooks`:

* **pre-commit** runs `lint` and `types` (a few seconds), only for commits
  that touch `src/`, `tests/` or `pyproject.toml`. It checks the working tree,
  unstaged edits included. If it fails on formatting, `just fmt` fixes it.
* **pre-push** runs what CI runs: `lint`, `types` and `docs`, then the tests
  on `$PY`. That starts Keycloak if it is not running and leaves it up for the
  next push. `PREPUSH_ALL=1 git push` tests every Python version.

Both need docker or podman running. Skip them once with `--no-verify`, for a
whole shell with `SKIP_HOOKS=1`, or turn them off with `just hooks-off`.

The recipes that run inside the container live in `dev-env/container.just`.
CI runs those same recipes on the runner, after `pip install -e .[dev]`, so
you can do that too if you prefer working without containers:

```console
python -m pip install -e .[dev]
docker compose -f dev-env/docker-compose.yaml up -d     # Keycloak only
just -f dev-env/container.just -d . test
```

## Housekeeping

* `just ps` and `just logs [service]` show what is running
* `just down` stops Keycloak and anything else still running
* `just build` / `just rebuild` build the dev image for `$PY`
* `just clean` stops everything and removes all dev images

With Docker, the container runs with your user and group id, so files it
writes into the checkout (coverage reports, `docs/build`) belong to you.
Rootless Podman does that by itself. On rootless Docker, set
`DEV_AS_USER=0`.

## Releases

`just release` tags a new version. It runs on your machine, because it uses
your git credentials, and needs `python3` and `git`.

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
