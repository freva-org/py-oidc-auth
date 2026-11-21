# py-oidc-auth development.
#
#   just dev [framework] [args]   Keycloak plus a dev server on :7777
#   just test [pytest args]       the tests, in a container on Python $PY
#   just check                    lint, types and tests
#
# Everything but `release` runs in containers, one image per Python version
# with the dependencies installed into the image's own Python (no virtualenv).
# The checkout is mounted, so edits apply without a rebuild; a change to
# pyproject.toml gets a fresh image on the next run.
#
#   PY=3.11 just test                 another Python version
#   COMPOSE=podman-compose just dev   podman instead of docker
#
# The recipes that run inside the container live in dev-env/container.just;
# the ones here drive compose from outside.

set shell := ["bash", "-euo", "pipefail", "-c"]
# Pass recipe arguments on as "$@", so quoting survives: just test -k "a and b"
set positional-arguments

compose := env("COMPOSE", "docker compose")
export PY := env("PY", "3.13")
export DEPS_HASH := `sha256sum pyproject.toml | cut -c1-12`
versions := "3.10 3.11 3.12 3.13 3.14 3.15"
dc := compose + " -f dev-env/docker-compose.yaml"
engine := if compose =~ "podman" { "podman" } else { "docker" }

# Files the container writes into the checkout (coverage, reports, docs)
# should belong to you. Rootless podman maps container root to you anyway;
# docker needs to be told. DEV_AS_USER=0 turns it off (rootless docker).
as_user := env("DEV_AS_USER", if compose =~ "podman" { "0" } else { "1" })
run := dc + " run --rm" + if as_user == "1" { " --user " + `id -u` + ":" + `id -g` } else { "" }

[private]
default:
    @just --justfile {{ justfile() }} --list
    @echo
    @echo "  dev server  http://localhost:7777  (just dev [framework])"
    @echo "  keycloak    http://localhost:8080  (admin: keycloak / secret, you: ${USER:-$(id -un)} / secret)"
    @echo "  python      {{ PY }}  (PY=3.11 just ...)"

# --- the stack --------------------------------------------------------------

# Keycloak plus a dev server, reloading on edits: just dev litestar --no-broker-mode
[group('stack')]
dev framework="fastapi" *args: up
    #!/usr/bin/env bash
    set -euo pipefail
    # A fixed name, removed before and after: a server left over from an
    # interrupted run would otherwise keep port 7777.
    name=py-oidc-auth-dev-server
    {{ engine }} rm -f "$name" >/dev/null 2>&1 || true
    trap '{{ engine }} rm -f "$name" >/dev/null 2>&1 || true' EXIT
    {{ run }} --name "$name" dev just serve "$@"

# Start Keycloak (and create your user) in the background
[group('stack')]
up:
    {{ dc }} up -d keycloak keycloak-bootstrap

# Stop everything
[group('stack')]
down:
    {{ dc }} --profile dev down

# Show what is running
[group('stack')]
ps:
    {{ dc }} --profile dev ps

# Follow logs, of everything or of some services: just logs keycloak
[group('stack')]
logs *services:
    {{ dc }} logs -f "$@"

# Open a shell in the dev image (with Keycloak at localhost:8080)
[group('stack')]
shell: up
    {{ run }} dev bash

# --- quality ----------------------------------------------------------------

# Run the tests on $PY: all with coverage, or `pytest ARGS`: just test -k pkce
[group('quality')]
test *args: up
    {{ run }} dev just test "$@"

# Run the tests on every supported Python version, then list what failed
[group('quality')]
test-all *args: up
    #!/usr/bin/env bash
    set -uo pipefail
    failed=()
    for v in {{ versions }}; do
      echo "=== Python $v"
      PY=$v {{ just_executable() }} --justfile {{ justfile() }} test "$@" || failed+=("$v")
    done
    if [ ${#failed[@]} -gt 0 ]; then
      echo "failed on Python: ${failed[*]}" >&2
      exit 1
    fi
    echo "passed on Python: {{ versions }}"

# Check formatting, import order, style, spelling, docstrings and security
[group('quality')]
lint:
    {{ run }} tools just lint

# Format the code with black and isort
[group('quality')]
fmt:
    {{ run }} tools just fmt

# Static type checking
[group('quality')]
types:
    {{ run }} tools just types

# Build the docs into docs/build/html
[group('quality')]
docs:
    {{ run }} tools just docs

# Lint, types and tests, as CI runs them
[group('quality')]
check: lint types test

# --- images -----------------------------------------------------------------

# Build the dev image for $PY (happens on first use anyway)
[group('images')]
build:
    {{ dc }} --profile dev build dev

# Rebuild the dev image for $PY from scratch, pulling the base image
[group('images')]
rebuild:
    {{ dc }} --profile dev build --pull --no-cache dev

# Stop everything and remove all dev images, for every Python version
[group('images')]
clean: down
    #!/usr/bin/env bash
    set -euo pipefail
    images=$({{ engine }} images --format '{{{{.Repository}}:{{{{.Tag}}' | grep '^localhost/py-oidc-auth-dev:' || true)
    [ -z "$images" ] || {{ engine }} rmi $images
    echo "dev images removed; 'just dev' or 'just test' builds them again."

# --- release ----------------------------------------------------------------

# Tag a release (runs on the host, needs python3 and git)
[group('release')]
release:
    #!/usr/bin/env bash
    set -euo pipefail
    python3 -m pip install git-python requests packaging tomli
    curl -H 'Cache-Control: no-cache' -Ls -o bump.py \
      https://raw.githubusercontent.com/freva-org/freva-admin/main/release.py
    trap 'rm -f bump.py' EXIT
    python3 bump.py tag py_oidc_auth
