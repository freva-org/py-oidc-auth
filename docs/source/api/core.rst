Core API
========

The core is framework independent and can be used directly.

.. automodule:: py_oidc_auth.auth_base
   :members:
   :member-order: bysource

.. automodule:: py_oidc_auth.schema
   :members:
   :member-order: bysource

.. automodule:: py_oidc_auth.token_validation
   :members:
   :member-order: bysource

.. automodule:: py_oidc_auth.exceptions
   :members:
   :member-order: bysource

.. automodule:: py_oidc_auth.utils
   :members:
   :member-order: bysource

Token minting and federation
============================

.. automodule:: py_oidc_auth.broker.issuer
   :members: TokenBroker
   :member-order: bysource

.. automodule:: py_oidc_auth.broker.store
   :members: InMemoryBrokerStore, MongoDBBrokerStore, SQLAlchemyBrokerStore
   :member-order: bysource
