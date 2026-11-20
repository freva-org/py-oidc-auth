# Recipes that run INSIDE the dev container.
#
# The dev image sets JUST_JUSTFILE to this file and JUST_WORKING_DIRECTORY
# to the mounted checkout, so plain `just <recipe>` works in it. CI runs the
# same recipes straight on the runner, after `pip install -e .[dev]`:
#
#   just -f dev-env/container.just -d . test
#
# The host-side counterpart is the justfile in the repository root.

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

discovery := env("OIDC_DISCOVERY_URL", "http://localhost:8080/realms/freva/.well-known/openid-configuration")
frameworks := "fastapi flask quart tornado litestar django"

[private]
default:
    @just --justfile {{ justfile() }} --list

# --- services ---------------------------------------------------------------

# Serve the test app for a framework on :7777, reloading on edits
[group('services')]
serve framework="fastapi" *args: wait-oidc
    #!/usr/bin/env bash
    set -euo pipefail
    framework=$1; shift
    cmd=(python dev-env/dev_utils.py "$framework-server" --port 7777 --discovery-url "{{ discovery }}" "$@")
    echo "$framework on http://localhost:7777 (API docs for fastapi: /api/test/help)"
    case "$framework" in
      # These reload by themselves.
      fastapi|flask|quart) exec "${cmd[@]}" ;;
      tornado|litestar|django)
        exec watchfiles --filter python --target-type command "${cmd[*]}" src dev-env ;;
      *) echo "unknown framework '$framework', pick one of: {{ frameworks }}" >&2; exit 2 ;;
    esac

# Wait until Keycloak serves the freva realm
[group('services')]
wait-oidc timeout="300":
    python dev-env/dev_utils.py oidc "{{ discovery }}" --timeout "$1" --time-increment 3

# --- quality ----------------------------------------------------------------

# Run the tests: all of them with coverage, or `pytest ARGS` if given
[group('quality')]
test *args: wait-oidc
    #!/usr/bin/env bash
    set -euo pipefail
    if [ $# -gt 0 ]; then
      exec python -m pytest "$@"
    fi
    python -m pytest -vv --cov=py_oidc_auth --cov-report=html:coverage_report \
      --cov-report xml --junitxml report.xml tests/
    python -m coverage report --fail-under=98.5 --precision=2

# Check formatting, import order, style, spelling, docstrings and security
[group('quality')]
lint:
    python -m black --check src
    python -m isort --check --profile black -t py312 -l 79 src
    python -m flake8 src --count --max-complexity=10 --ignore=F405,F403,E704,W503,C901 --max-line-length=100 --statistics --show-source
    python -m codespell_lib --quiet-level=2 src/
    python -m pydocstyle src/py_oidc_auth
    python -m bandit -r src/py_oidc_auth --severity-level medium --confidence-level high

# Format the code (what lint checks for black and isort)
[group('quality')]
fmt:
    python -m isort --profile black -t py312 -l 79 src
    python -m black src

# Static type checking
[group('quality')]
types:
    python -m mypy

# Spell-check and build the docs into docs/build/html
[group('quality')]
docs:
    python -m codespell_lib --quiet-level=2 docs/source
    rm -rf docs/build
    python -m sphinx -M html docs/source docs/build
