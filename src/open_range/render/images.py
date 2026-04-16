"""Central runtime image policy for rendered OpenRange components.

Keep third-party image choices here so dependency review happens in one place.
"""

from __future__ import annotations

from typing import Final

DEFAULT_SERVICE_IMAGE: Final[str] = "ubuntu:22.04"

SERVICE_IMAGE_BY_KIND: Final[dict[str, str]] = {
    "web_app": "php:8.1-apache",
    "email": "namshi/smtp:latest",
    "idp": "osixia/openldap:1.5.0",
    "fileshare": "dperson/samba:latest",
    "db": "mysql:8.0",
    "siem": "busybox:1.36",
}

# Reused for red/blue sandboxes and the DB mTLS helper so there is a single
# review point for this third-party troubleshooting image.
SANDBOX_MULTITOOL_IMAGE: Final[str] = "wbitt/network-multitool:alpine-extra"

SANDBOX_IMAGE_BY_ROLE: Final[dict[str, str]] = {
    "red": SANDBOX_MULTITOOL_IMAGE,
    "blue": SANDBOX_MULTITOOL_IMAGE,
    "green": "busybox:1.36",
}

DB_MTLS_HELPER_IMAGE: Final[str] = SANDBOX_MULTITOOL_IMAGE


def service_image_for_kind(kind: str) -> str:
    return SERVICE_IMAGE_BY_KIND.get(kind, DEFAULT_SERVICE_IMAGE)


def sandbox_image_for_role(role: str) -> str:
    return SANDBOX_IMAGE_BY_ROLE.get(role, DEFAULT_SERVICE_IMAGE)
