"""Login broker: logs into whitelisted sites as a separate uid, hands out session bundles.

See ``PLAN_login-broker.md`` at the repo root. The package is deployed root-owned
under ``/usr/local/libexec/login-broker/current`` and runs as ``_loginbroker``;
the agent side is the client in ``bin/browser.py``.
"""
