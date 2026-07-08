"""
Cyphora-S1 Auth — User and Token Models

BUG 2 FIX: Provides the core identity primitives for authentication.
"""
from __future__ import annotations
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime, timezone


class Role(str, Enum):
    READONLY       = "readonly"
    ANALYST        = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    SOC_MANAGER    = "soc_manager"
    ADMIN          = "admin"


# Actions each role is permitted to approve
ROLE_PERMISSIONS: dict = {
    Role.READONLY:       [],
    Role.ANALYST:        ["notify_soc", "create_threat_alert", "generate_incident_report",
                          "snapshot_memory", "quarantine_file"],
    Role.SENIOR_ANALYST: ["notify_soc", "create_threat_alert", "generate_incident_report",
                          "snapshot_memory", "quarantine_file", "kill_process",
                          "block_ip", "revoke_token"],
    Role.SOC_MANAGER:    ["notify_soc", "create_threat_alert", "generate_incident_report",
                          "snapshot_memory", "quarantine_file", "kill_process",
                          "block_ip", "revoke_token", "isolate_host", "disable_account"],
    Role.ADMIN:          ["*"],   # all actions
}


@dataclass
class CyphoraUser:
    user_id:   str
    email:     str
    tenant_id: str
    role:      Role
    display_name: str = ""
    created_at:   str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())

    def can_execute(self, action: str) -> bool:
        permitted = ROLE_PERMISSIONS.get(self.role, [])
        return "*" in permitted or action in permitted

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id, "email": self.email,
            "tenant_id": self.tenant_id, "role": self.role.value,
            "display_name": self.display_name,
        }


@dataclass
class TokenPayload:
    user_id:   str
    email:     str
    tenant_id: str
    role:      str
    exp:       float   # UNIX epoch expiry
    iat:       float   # UNIX epoch issued-at
    jti:       str     # JWT ID (for revocation)
