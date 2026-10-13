"""Connector plugin registry.

Third-party connectors register themselves under the ``vigil.connectors``
entry-point group:

    [project.entry-points."vigil.connectors"]
    myconn = "myplugin.connector:MyConnector"
"""

from __future__ import annotations

from importlib.metadata import entry_points

from vigil.ingest.base import Connector


def discover_connectors() -> dict[str, Connector]:
    """Instantiate every registered connector (best-effort)."""
    found: dict[str, Connector] = {}
    try:
        eps = entry_points(group="vigil.connectors")
    except TypeError:  # pragma: no cover - older Python
        eps = entry_points().select(group="vigil.connectors")
    for ep in eps:
        try:
            obj = ep.load()
            found[ep.name] = obj() if isinstance(obj, type) else obj
        except Exception as exc:  # noqa: BLE001 - a broken plugin must not kill startup
            print(f"[vigil] connector plugin {ep.name!r} failed to load: {exc}")
    return found
