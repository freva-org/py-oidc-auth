"""Pluggable token broker storage backends.

The :class:`BrokerStore` abstract base class defines the storage interface
required by :class:`~py_oidc_auth.broker.issuer.TokenBroker`. Choose a
backend that matches your deployment:

===================  ========================================================
URL prefix           Backend
===================  ========================================================
``memory://``        :class:`InMemoryBrokerStore` — testing only
``mongodb://``       :class:`MongoDBBrokerStore` — requires ``pymongo``
``sqlite+...``       :class:`SQLAlchemyBrokerStore` — requires ``sqlalchemy``
``postgresql+...``   :class:`SQLAlchemyBrokerStore` — requires ``sqlalchemy``
``mysql+...``        :class:`SQLAlchemyBrokerStore` — requires ``sqlalchemy``
===================  ========================================================

Use :func:`create_broker_store` to instantiate the right backend from a URL::

    store = create_broker_store("mongodb://localhost/py_oidc_auth")
    store = create_broker_store("postgresql+asyncpg://user:pw@host/db")
    store = create_broker_store("sqlite+aiosqlite:///~/.local/share/py-oidc-auth/broker.sqlite")
    store = create_broker_store("memory://")   # testing

**Multi-worker key generation:**

All backends handle the signing-key creation race safely:

* **MongoDB** uses ``$setOnInsert`` with ``upsert=True`` so only one document
  is ever written even if two workers race.
* **SQL backends** catch ``IntegrityError`` from a UNIQUE constraint violation
  and re-read the winning worker's key.
* **SQLite** additionally sets ``PRAGMA journal_mode=WAL`` so concurrent
  readers do not block the single writer.

**Session expiry:**

* **MongoDB** uses a native TTL index on the ``expires_at`` datetime field.
  No application-level cleanup is needed.
* **SQL backends** perform a best-effort ``DELETE`` of expired rows on
  :meth:`BrokerStore.setup` and verify expiry on every :meth:`get_session`
  call.  For long-running processes you may additionally schedule periodic
  calls to :meth:`SQLAlchemyBrokerStore.purge_expired`.
"""

from __future__ import annotations

import abc
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import platformdirs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from sqlalchemy import (
    Column,
    DateTime,
    Index,
    MetaData,
    String,
    Table,
    Text,
    event,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine
from typing_extensions import TypedDict

if TYPE_CHECKING:
    from pymongo.asynchronous.database import AsyncDatabase
    from sqlalchemy.ext.asyncio import AsyncEngine

# ---------------------------------------------------------------------------
# Shared types
# ---------------------------------------------------------------------------


class JWKDict(TypedDict, total=False):
    """Typed alias for a single JWK entry (kty, n, e, kid, use, alg)."""

    kty: str
    n: str
    e: str
    kid: str
    use: str
    alg: str


class JWKSDict(TypedDict):
    """Typed alias for a JWKS document ``{"keys": [...]}``."""

    keys: list[JWKDict]


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class BrokerStore(abc.ABC):
    """Abstract storage backend for the token broker.

    All methods are ``async``.  Implementations must be safe to call from
    multiple workers — see :mod:`py_oidc_auth.broker.store` for details on
    how each backend handles concurrent startup.

    :meth:`setup` is idempotent: calling it on an already-initialised store
    is a no-op.  It is invoked automatically on the first broker operation so
    you do not have to call it in a lifespan handler, though doing so is
    recommended to surface errors eagerly.
    """

    # -------------------------------------------------------------------
    # Default Store
    # -------------------------------------------------------------------
    @staticmethod
    def get_default_broker_store(appname: str = "py-oidc-auth") -> str:
        """Define the SQLite default broker path."""
        try:
            app_dir = platformdirs.site_data_path(appname=appname, ensure_exists=True)
        except (OSError, PermissionError):
            app_dir = platformdirs.user_data_path(appname=appname, ensure_exists=True)
        return "sqlite+aiosqlite:///" + str(app_dir / "broker.sqlite")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def setup(self) -> None:
        """Initialise schema / indexes.

        Safe to call concurrently from multiple worker processes.
        Implementations must be idempotent.
        """

    # ------------------------------------------------------------------
    # Signing key
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def load_or_create_signing_key(self) -> str:
        """Return the PEM-encoded RSA private key, creating it if absent.

        :returns: PEM-encoded RSA-2048 private key as a string.
        """

    # ------------------------------------------------------------------
    # Sessions (jti → IDP refresh token)
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def save_session(
        self,
        jti: str,
        sub: str,
        refresh_token: str,
        expires_at: int,
    ) -> None:
        """Persist or replace an IDP refresh-token session.

        :param jti: JWT ID claim from the minted freva JWT.
        :param sub: Subject identifier.
        :param refresh_token: IDP refresh token to store.
        :param expires_at: Expiry as a Unix timestamp.
        """

    @abc.abstractmethod
    async def get_session(self, jti: str) -> Optional[tuple[str, str]]:
        """Return ``(sub, refresh_token)`` or ``None`` if absent or expired.

        :param jti: JWT ID to look up.
        """

    @abc.abstractmethod
    async def delete_session(self, jti: str) -> None:
        """Remove a session (token rotation or logout).

        :param jti: JWT ID to remove.
        """

    # ------------------------------------------------------------------
    # Peer JWKS (federation)
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def save_peer_jwks(self, issuer_url: str, jwks: JWKSDict) -> None:
        """Persist peer public keys for cross-instance federation.

        :param issuer_url: Canonical URL of the peer instance.
        :param jwks: JWKS document from the peer.
        """

    @abc.abstractmethod
    async def load_all_peer_jwks(self) -> list[tuple[str, JWKSDict]]:
        """Return all stored peer JWKS documents.

        :returns: List of ``(issuer_url, jwks)`` tuples.
        """

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_rsa_pem() -> str:
        """Generate a 2048-bit RSA private key and return it as a PEM string."""
        key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()


# ---------------------------------------------------------------------------
# In-memory backend (testing)
# ---------------------------------------------------------------------------


class _SessionEntry:
    __slots__ = ("sub", "refresh_token", "expires_at")

    def __init__(self, sub: str, refresh_token: str, expires_at: int) -> None:
        self.sub = sub
        self.refresh_token = refresh_token
        self.expires_at = expires_at


class InMemoryBrokerStore(BrokerStore):
    """Ephemeral in-memory store.

    Suitable for unit tests.  **Not safe for multiple processes** — each
    process gets its own isolated store.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, _SessionEntry] = {}
        self._signing_key: Optional[str] = None
        self._peer_jwks: dict[str, JWKSDict] = {}
        self._lock = asyncio.Lock()
        self._ready = False

    async def setup(self) -> None:
        """Perform in-memory setup."""
        self._ready = True

    async def load_or_create_signing_key(self) -> str:
        """Return the PEM-encoded RSA private key, creating it if absent."""
        async with self._lock:
            if self._signing_key is None:
                self._signing_key = self._generate_rsa_pem()
            return self._signing_key

    async def save_session(
        self,
        jti: str,
        sub: str,
        refresh_token: str,
        expires_at: int,
    ) -> None:
        """Persist or replace an IDP refresh-token session.

        :param jti: JWT ID claim from the minted freva JWT.
        :param sub: Subject identifier.
        :param refresh_token: IDP refresh token to store.
        :param expires_at: Expiry as a Unix timestamp.
        """
        self._sessions[jti] = _SessionEntry(sub, refresh_token, expires_at)

    async def get_session(self, jti: str) -> Optional[tuple[str, str]]:
        """Return ``(sub, refresh_token)`` or ``None`` if absent or expired.

        :param jti: JWT ID to look up.
        """
        entry = self._sessions.get(jti)
        if entry is None:
            return None
        now = int(datetime.now(timezone.utc).timestamp())
        if entry.expires_at < now:
            del self._sessions[jti]
            return None
        return entry.sub, entry.refresh_token

    async def delete_session(self, jti: str) -> None:
        """Remove a session (token rotation or logout).

        :param jti: JWT ID to remove.
        """
        self._sessions.pop(jti, None)

    async def save_peer_jwks(self, issuer_url: str, jwks: JWKSDict) -> None:
        """Persist peer public keys for cross-instance federation.

        :param issuer_url: Canonical URL of the peer instance.
        :param jwks: JWKS document from the peer.
        """
        self._peer_jwks[issuer_url] = jwks

    async def load_all_peer_jwks(self) -> list[tuple[str, JWKSDict]]:
        """Return all stored peer JWKS documents.

        :returns: List of ``(issuer_url, jwks)`` tuples.
        """
        return list(self._peer_jwks.items())


# ---------------------------------------------------------------------------
# MongoDB backend
# ---------------------------------------------------------------------------


class MongoDBBrokerStore(BrokerStore):
    """MongoDB-backed store using async pymongo.

    :param url: MongoDB connection URL including database name, e.g.
                ``mongodb://user:pass@host/mydb``.  The database is resolved via
                ``get_default_database()`` so the name must be present in the URL.
    :param db: A pre-existing :class:`~pymongo.asynchronous.database.AsyncDatabase`
               instance.  Use this to share an existing client.  Takes precedence
               over ``url``.


    Requires ``pymongo``:

    .. code-block:: shell

        pip install pymongo
    """

    _SIGNING_KEY_ID = "broker-signing-key"
    _PEER_PREFIX = "peer-jwks:"

    def __init__(
        self,
        url: Optional[str] = None,
        db: Optional["AsyncDatabase[dict[str, object]]"] = None,
    ) -> None:
        try:
            from pymongo import AsyncMongoClient
        except ImportError as exc:
            raise ImportError("MongoDBBrokerStore requires 'pymongo'.") from exc
        if db is not None:
            self._db = db
        elif url is not None:
            self._db = AsyncMongoClient(url).get_default_database()
        else:
            raise ValueError("Either url or db must be provided.")
        self._setup_done = False

    @property
    def _sessions(self) -> object:
        return self._db["broker_sessions"]

    @property
    def _keys(self) -> object:
        return self._db["broker_keys"]

    async def setup(self) -> None:
        """Create mongoDB indexes."""
        if self._setup_done:
            return
        await self._sessions.create_index(  # type: ignore[attr-defined]
            [("expires_at", 1)],
            expireAfterSeconds=0,
            name="sessions_ttl",
        )
        self._setup_done = True

    async def load_or_create_signing_key(self) -> str:
        """Return the PEM-encoded RSA private key, creating it if absent."""
        doc = await self._keys.find_one({"_id": self._SIGNING_KEY_ID})  # type: ignore[attr-defined]
        if doc:
            return str(doc["pem"])

        pem = self._generate_rsa_pem()
        await self._keys.update_one(  # type: ignore[attr-defined]
            {"_id": self._SIGNING_KEY_ID},
            {"$setOnInsert": {"pem": pem}},
            upsert=True,
        )
        doc = await self._keys.find_one({"_id": self._SIGNING_KEY_ID})  # type: ignore[attr-defined]
        return str(doc["pem"]) if doc else pem

    async def save_session(
        self,
        jti: str,
        sub: str,
        refresh_token: str,
        expires_at: int,
    ) -> None:
        """Persist or replace an IDP refresh-token session.

        :param jti: JWT ID claim from the minted freva JWT.
        :param sub: Subject identifier.
        :param refresh_token: IDP refresh token to store.
        :param expires_at: Expiry as a Unix timestamp.
        """
        await self._sessions.replace_one(  # type: ignore[attr-defined]
            {"_id": jti},
            {
                "_id": jti,
                "sub": sub,
                "refresh_token": refresh_token,
                "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc),
            },
            upsert=True,
        )

    async def get_session(self, jti: str) -> Optional[tuple[str, str]]:
        """Return ``(sub, refresh_token)`` or ``None`` if absent or expired.

        :param jti: JWT ID to look up.
        """
        doc = await self._sessions.find_one({"_id": jti})  # type: ignore[attr-defined]
        if doc is None:
            return None
        return str(doc["sub"]), str(doc["refresh_token"])

    async def delete_session(self, jti: str) -> None:
        """Remove a session (token rotation or logout).

        :param jti: JWT ID to remove.
        """
        await self._sessions.delete_one({"_id": jti})  # type: ignore[attr-defined]

    async def save_peer_jwks(self, issuer_url: str, jwks: JWKSDict) -> None:
        """Persist peer public keys for cross-instance federation.

        :param issuer_url: Canonical URL of the peer instance.
        :param jwks: JWKS document from the peer.
        """
        doc_id = f"{self._PEER_PREFIX}{issuer_url}"
        await self._keys.replace_one(  # type: ignore[attr-defined]
            {"_id": doc_id},
            {
                "_id": doc_id,
                "issuer_url": issuer_url,
                "jwks": jwks,
                "fetched_at": datetime.now(tz=timezone.utc),
            },
            upsert=True,
        )

    async def load_all_peer_jwks(self) -> list[tuple[str, JWKSDict]]:
        """Return all stored peer JWKS documents.

        :returns: List of ``(issuer_url, jwks)`` tuples.
        """
        result: list[tuple[str, JWKSDict]] = []
        async for doc in self._keys.find(  # type: ignore[attr-defined]
            {"_id": {"$regex": f"^{self._PEER_PREFIX}"}}
        ):
            result.append((str(doc["issuer_url"]), doc["jwks"]))
        return result


# ---------------------------------------------------------------------------
# SQLAlchemy backend (PostgreSQL, MySQL, SQLite)
# ---------------------------------------------------------------------------


class SQLAlchemyBrokerStore(BrokerStore):
    """Async SQLAlchemy store supporting PostgreSQL, MySQL and SQLite.

    :param url: SQLAlchemy async connection URL.
    :param db: A pre-existing :class:`sqlalchemy.engine`
               instance.  Use this to share an existing client.  Takes precedence
               over ``url``.
    Requires an ``sqlalchemy`` async driver:

    .. code-block:: shell

        pip install asyncpg         # PostgreSQL
        pip install aiomysql        # MySQL

    **SQLite specifics:**

    * ``PRAGMA journal_mode=WAL`` is set on every connection for safe
      concurrent access within a single process.
    * SQLite does **not** support multiple writer processes safely even in
      WAL mode.  For multi-process deployments use PostgreSQL or MySQL.

    **Session expiry**

    Expired rows are deleted on :meth:`setup` and on every :meth:`get_session`
    call.  Call :meth:`purge_expired` from a background task for long-running
    processes.
    """

    _SIGNING_KEY_ID = "signing_key"

    def __init__(
        self, url: Optional[str] = None, db: Optional["AsyncEngine"] = None
    ) -> None:

        if db is not None:
            self._engine = db
        elif url is not None:
            self._engine = create_async_engine(
                url,
                pool_pre_ping=True,
            )
        else:
            raise ValueError("Either url or db must be provided.")

        metadata = MetaData()
        self._is_sqlite = self._engine.dialect.name == "sqlite"

        self._sessions_table = Table(
            "broker_sessions",
            metadata,
            Column("jti", String(36), primary_key=True),
            Column("sub", String(255), nullable=False),
            Column("refresh_token", Text, nullable=False),
            Column(
                "expires_at",
                DateTime(timezone=True),
                nullable=False,
            ),
            Index("ix_broker_sessions_expires_at", "expires_at"),
        )

        self._keys_table = Table(
            "broker_keys",
            metadata,
            Column("key_id", String(255), primary_key=True),
            Column("value", Text, nullable=False),
        )

        self._peer_jwks_table = Table(
            "broker_peer_jwks",
            metadata,
            Column("issuer_url", String(512), primary_key=True),
            Column("jwks_json", Text, nullable=False),
            Column(
                "fetched_at",
                DateTime(timezone=True),
                nullable=False,
            ),
        )

        self._metadata = metadata
        self._setup_done = False
        self._setup_lock = asyncio.Lock()

    async def setup(self) -> None:
        """Create tables if absent and delete expired sessions."""
        async with self._setup_lock:
            if self._setup_done:
                return

            if self._is_sqlite:
                event.listen(
                    self._engine.sync_engine,
                    "connect",
                    lambda conn, _: conn.execute("PRAGMA journal_mode=WAL"),
                )

            async with self._engine.begin() as conn:
                await conn.run_sync(self._metadata.create_all)
                # Purge any rows that already expired
                now = datetime.now(timezone.utc)
                await conn.execute(
                    self._sessions_table.delete().where(
                        self._sessions_table.c.expires_at < now
                    )
                )

            self._setup_done = True

    async def purge_expired(self) -> int:
        """Delete expired session rows.

        :returns: Number of rows removed.

        Call this from a background task for long-running processes.
        """
        now = datetime.now(timezone.utc)
        async with self._engine.begin() as conn:
            result = await conn.execute(
                self._sessions_table.delete().where(
                    self._sessions_table.c.expires_at < now
                )
            )
            return int(result.rowcount)

    async def load_or_create_signing_key(self) -> str:
        """Return the signing key PEM, creating it if absent.

        Race-safe: concurrent workers that both attempt insertion will get an
        ``IntegrityError`` from the UNIQUE primary key constraint; the loser
        re-reads the winner's key.
        """
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(self._keys_table.c.value).where(
                        self._keys_table.c.key_id == self._SIGNING_KEY_ID
                    )
                )
            ).first()
            if row:
                return str(row[0])

        pem = self._generate_rsa_pem()

        async with self._engine.begin() as conn:
            try:
                await conn.execute(
                    self._keys_table.insert().values(
                        key_id=self._SIGNING_KEY_ID, value=pem
                    )
                )
            except IntegrityError:
                pass  # another worker won the race

            row = (
                await conn.execute(
                    select(self._keys_table.c.value).where(
                        self._keys_table.c.key_id == self._SIGNING_KEY_ID
                    )
                )
            ).first()
            return str(row[0]) if row else pem

    async def save_session(
        self,
        jti: str,
        sub: str,
        refresh_token: str,
        expires_at: int,
    ) -> None:
        """Persist or replace an IDP refresh-token session.

        :param jti: JWT ID claim from the minted freva JWT.
        :param sub: Subject identifier.
        :param refresh_token: IDP refresh token to store.
        :param expires_at: Expiry as a Unix timestamp.
        """
        expires_dt = datetime.fromtimestamp(expires_at, tz=timezone.utc)
        async with self._engine.begin() as conn:
            try:
                await conn.execute(
                    self._sessions_table.insert().values(
                        jti=jti,
                        sub=sub,
                        refresh_token=refresh_token,
                        expires_at=expires_dt,
                    )
                )
            except IntegrityError:
                # Row exists — update it
                await conn.execute(
                    self._sessions_table.update()
                    .where(self._sessions_table.c.jti == jti)
                    .values(
                        sub=sub,
                        refresh_token=refresh_token,
                        expires_at=expires_dt,
                    )
                )

    async def get_session(self, jti: str) -> Optional[tuple[str, str]]:
        """Return ``(sub, refresh_token)`` or ``None`` if absent or expired.

        :param jti: JWT ID to look up.
        """
        now = datetime.now(timezone.utc)
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        self._sessions_table.c.sub,
                        self._sessions_table.c.refresh_token,
                        self._sessions_table.c.expires_at,
                    ).where(self._sessions_table.c.jti == jti)
                )
            ).first()

        if row is None:
            return None
        expires_at = (
            row[2].replace(tzinfo=timezone.utc) if row[2].tzinfo is None else row[2]
        )
        if expires_at < now:
            await self.delete_session(jti)
            return None
        return str(row[0]), str(row[1])

    async def delete_session(self, jti: str) -> None:
        """Remove a session (token rotation or logout).

        :param jti: JWT ID to remove.
        """
        async with self._engine.begin() as conn:
            await conn.execute(
                self._sessions_table.delete().where(self._sessions_table.c.jti == jti)
            )

    async def save_peer_jwks(self, issuer_url: str, jwks: JWKSDict) -> None:
        """Persist peer public keys for cross-instance federation.

        :param issuer_url: Canonical URL of the peer instance.
        :param jwks: JWKS document from the peer.
        """
        jwks_json = json.dumps(jwks)
        now = datetime.now(timezone.utc)
        async with self._engine.begin() as conn:
            try:
                await conn.execute(
                    self._peer_jwks_table.insert().values(
                        issuer_url=issuer_url,
                        jwks_json=jwks_json,
                        fetched_at=now,
                    )
                )
            except IntegrityError:
                await conn.execute(
                    self._peer_jwks_table.update()
                    .where(self._peer_jwks_table.c.issuer_url == issuer_url)
                    .values(jwks_json=jwks_json, fetched_at=now)
                )

    async def load_all_peer_jwks(self) -> list[tuple[str, JWKSDict]]:
        """Return all stored peer JWKS documents.

        :returns: List of ``(issuer_url, jwks)`` tuples.
        """
        result: list[tuple[str, JWKSDict]] = []
        async with self._engine.connect() as conn:
            rows = await conn.execute(
                select(
                    self._peer_jwks_table.c.issuer_url,
                    self._peer_jwks_table.c.jwks_json,
                )
            )
            for row in rows:
                pay_load: JWKSDict = json.loads(str(row[1]))
                result.append((str(row[0]), pay_load))
        return result


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_broker_store(
    url: Optional[str], app_name: str = "py-oidc-auth"
) -> BrokerStore:
    """Create the appropriate :class:`BrokerStore` from a connection URL.

    :param url: Connection URL — see module docstring for supported schemes.
    :returns: Configured :class:`BrokerStore` instance.
    :raises ValueError: For unrecognised URL schemes.

    Example
    -------
    .. code-block:: python

        store = create_broker_store("memory://")
        store = create_broker_store("mongodb://localhost/py_oidc_auth")
        store = create_broker_store(
            "postgresql+asyncpg://user:pw@host/db"
        )
        store = create_broker_store(
            "sqlite+aiosqlite:///~/.local/share/py-oidc-auth/broker.sqlite"
        )

    """
    url = url or BrokerStore.get_default_broker_store(app_name)
    if url.startswith("memory://"):
        return InMemoryBrokerStore()
    if url.startswith("mongodb"):
        return MongoDBBrokerStore(url)
    if url.startswith(("sqlite", "postgresql", "mysql")):
        # Normalise bare sqlite:// → sqlite+aiosqlite://
        if url.startswith("sqlite://") and "+aiosqlite" not in url:
            url = url.replace("sqlite://", "sqlite+aiosqlite://", 1)
        # Expand ~ in SQLite paths
        if url.startswith("sqlite+aiosqlite:///~"):
            url = url.replace(
                "sqlite+aiosqlite:///~", f"sqlite+aiosqlite:///{Path.home()}", 1
            )
        return SQLAlchemyBrokerStore(url)
    raise ValueError(
        f"Unsupported broker store URL scheme: {url!r}. "
        "Supported: memory://, mongodb://, sqlite:///, "
        "postgresql+asyncpg://, mysql+aiomysql://"
    )
