"""DHCP provider protocol and backend detection for OPNsense."""

import logging
from collections.abc import Callable, Coroutine
from typing import Any, Protocol, runtime_checkable

from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider
from opnsense_mcp.utils.dhcp_providers.isc import ISCProvider
from opnsense_mcp.utils.dhcp_providers.kea import KeaProvider

logger = logging.getLogger(__name__)

MakeRequestFn = Callable[..., Coroutine[Any, Any, dict[str, Any] | list[Any]]]
"""Signature: async (method, endpoint, **kwargs) -> dict | list."""


@runtime_checkable
class DHCPProvider(Protocol):
    """Contract that every DHCP backend provider must satisfy."""

    name: str

    async def get_v4_leases(self) -> list[dict[str, Any]]:
        """Return all DHCPv4 leases."""

    async def get_v6_leases(self) -> list[dict[str, Any]]:
        """Return all DHCPv6 leases."""

    async def search_v4_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv4 leases by hostname, IP, or MAC."""

    async def search_v6_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv6 leases by hostname, IP, or MAC."""

    async def delete_v4_lease(self, ip: str) -> dict[str, Any]:
        """Delete a DHCPv4 lease by IP address."""

    async def delete_v6_lease(self, ip: str) -> dict[str, Any]:
        """Delete a DHCPv6 lease by IP address."""


def provider_supports_subnet_dns(provider: DHCPProvider) -> bool:
    """Return True when the detected provider supports subnet DNS tools."""
    return bool(getattr(provider, "SUBNET_DNS_SUPPORTED", False))


def require_subnet_dns_provider(provider: DHCPProvider) -> Any:
    """Return provider when subnet DNS is supported, else raise ValueError."""
    if not provider_supports_subnet_dns(provider):
        backend = getattr(provider, "name", provider.__class__.__name__)
        msg = (
            f"Subnet DNS configuration is not supported for DHCP backend {backend!r}"
        )
        raise ValueError(msg)
    return provider


_BACKEND_PROBES: list[tuple[str, type[DHCPProvider]]] = [
    (KeaProvider.SERVICE_STATUS_ENDPOINT, KeaProvider),
    (DnsmasqProvider.SERVICE_STATUS_ENDPOINT, DnsmasqProvider),
    (ISCProvider.SERVICE_STATUS_ENDPOINT_V4, ISCProvider),
]


def _is_active_probe_response(response: dict[str, Any] | list[Any]) -> bool:
    """Return True when a probe response indicates an active backend."""
    if isinstance(response, dict):
        status = str(response.get("status", "")).strip().lower()
        if status:
            return status in {"running", "ok", "enabled", "active"}
    # If no explicit status is available, treat successful response as active.
    return True


async def detect_dhcp_backend(make_request: MakeRequestFn) -> DHCPProvider:
    """Probe OPNsense API and return the detected DHCP backend provider."""
    for probe_endpoint, provider_cls in _BACKEND_PROBES:
        try:
            response = await make_request("GET", probe_endpoint)
            if not _is_active_probe_response(response):
                logger.debug(
                    "DHCP probe endpoint %s returned inactive status for %s",
                    probe_endpoint,
                    provider_cls.name,
                )
                continue
            provider = provider_cls(make_request)
            logger.info("Detected DHCP backend: %s", provider.name)
            return provider
        except Exception:
            logger.debug(
                "DHCP probe failed for %s endpoint: %s",
                provider_cls.name,
                probe_endpoint,
            )

    logger.warning("All DHCP backend probes failed; falling back to ISC provider")
    return ISCProvider(make_request)
