"""Central config: write-class flags + audit sink, parsed from the environment.

Connection settings (MALCOLM_URL/USERNAME/PASSWORD/SSL_VERIFY/TIMEOUT) stay in
MalcolmClient.from_env(); this module owns only the write-layer knobs so the
gate has a single source of truth.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _flag(name: str) -> bool:
    return os.environ.get(name, "false").strip().lower() == "true"


def _onoff(value: bool) -> str:
    return "on" if value else "off"


@dataclass(frozen=True)
class WriteConfig:
    """Immutable snapshot of which write classes are enabled + audit sink."""

    alerting: bool
    arkime_tags: bool
    hunt_jobs: bool
    pcap_upload: bool
    arkime_views: bool
    audit_file: str | None
    upload_dir: str | None

    @classmethod
    def from_env(cls) -> WriteConfig:
        audit = os.environ.get("MALCOLM_MCP_AUDIT_FILE", "").strip()
        upload_dir = os.environ.get("MALCOLM_MCP_UPLOAD_DIR", "").strip()
        return cls(
            alerting=_flag("MALCOLM_MCP_ENABLE_ALERTING"),
            arkime_tags=_flag("MALCOLM_MCP_ENABLE_ARKIME_TAGS"),
            hunt_jobs=_flag("MALCOLM_MCP_ENABLE_HUNT_JOBS"),
            pcap_upload=_flag("MALCOLM_MCP_ENABLE_PCAP_UPLOAD"),
            arkime_views=_flag("MALCOLM_MCP_ENABLE_ARKIME_VIEWS"),
            audit_file=audit or None,
            upload_dir=upload_dir or None,
        )

    def any_enabled(self) -> bool:
        return any(
            (self.alerting, self.arkime_tags, self.hunt_jobs, self.pcap_upload, self.arkime_views)
        )

    def enabled_summary(self) -> str:
        return (
            f"alerting={_onoff(self.alerting)} "
            f"arkime-tag={_onoff(self.arkime_tags)} "
            f"hunt-job={_onoff(self.hunt_jobs)} "
            f"pcap-upload={_onoff(self.pcap_upload)} "
            f"arkime-view={_onoff(self.arkime_views)}"
        )
