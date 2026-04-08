from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Snapshot:
    root: Path
    tenant: dict[str, Any]
    users: list[dict[str, Any]]
    groups: list[dict[str, Any]]
    directory_roles: list[dict[str, Any]]
    directory_role_memberships: list[dict[str, Any]]
    applications: list[dict[str, Any]]
    service_principals: list[dict[str, Any]]
    owners: list[dict[str, Any]]
    azure_role_assignments: list[dict[str, Any]]
    subscriptions: list[dict[str, Any]]
    directory_audits: list[dict[str, Any]]
    sign_ins: list[dict[str, Any]]


def load_snapshot(root: str | Path) -> Snapshot:
    base = Path(root).resolve()
    return Snapshot(
        root=base,
        tenant=_load_json(base / "tenant.json"),
        users=_load_json(base / "users.json"),
        groups=_load_json(base / "groups.json"),
        directory_roles=_load_json(base / "directory_roles.json"),
        directory_role_memberships=_load_json(base / "directory_role_memberships.json"),
        applications=_load_json(base / "applications.json"),
        service_principals=_load_json(base / "service_principals.json"),
        owners=_load_json(base / "owners.json"),
        azure_role_assignments=_load_json(base / "azure_role_assignments.json"),
        subscriptions=_load_json(base / "subscriptions.json"),
        directory_audits=_load_json_optional(base / "directory_audits.json"),
        sign_ins=_load_json_optional(base / "sign_ins.json"),
    )


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_json_optional(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        return data
    return []
