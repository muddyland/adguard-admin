"""Async client for the on-box agent (docs/design/agent-api.md, section 2).

Every call is mutual TLS: the context trusts only our CA and presents our client
certificate. Errors surface as AgentError with the HTTP status (None for
transport failures) so callers can tell "the agent refused" from "the host is
down".
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from .adguard_client import describe_transport_error
from .config import settings
from .pki import Pki, client_ssl_context, get_pki

logger = logging.getLogger("adguard_admin.agent_client")

SERVICES = ("adguard", "dnsdist", "keepalived", "agent")


class AgentError(Exception):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class AgentClient:
    def __init__(self, base_url: str, *, pki: Pki | None = None, timeout: float | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout if timeout is not None else settings.agent_timeout_seconds
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            verify=client_ssl_context(pki or get_pki()),
            follow_redirects=False,
        )

    async def __aenter__(self) -> "AgentClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs) -> Any:
        try:
            resp = await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise AgentError(
                f"{method} {path} failed: {describe_transport_error(exc, self.timeout)}"
            ) from exc
        if resp.status_code >= 400:
            detail = ""
            try:
                detail = resp.json().get("error") or ""
            except Exception:  # noqa: BLE001 - non-JSON error body
                detail = (resp.text or "")[:200]
            raise AgentError(
                f"{method} {path} -> HTTP {resp.status_code}{': ' + detail if detail else ''}",
                status_code=resp.status_code,
            )
        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise AgentError(f"{method} {path} returned a non-JSON body") from exc

    # ---- host ------------------------------------------------------------ #
    async def info(self) -> dict:
        return await self._request("GET", "/v1/info")

    async def health(self) -> dict:
        return await self._request("GET", "/v1/health")

    # ---- roles ----------------------------------------------------------- #
    async def put_role(self, role: str, spec: dict) -> dict:
        return await self._request("PUT", f"/v1/{role}", json=spec)

    async def get_role(self, role: str) -> dict:
        return await self._request("GET", f"/v1/{role}")

    async def adguard_update(self) -> dict:
        return await self._request("POST", "/v1/adguard/update")

    async def drain(self, backend: str, *, undrain: bool = False, role: str = "dnsdist") -> dict:
        """Take a backend out of rotation on dnsdist or on the IPVS table (keepalived)."""
        action = "undrain" if undrain else "drain"
        return await self._request("POST", f"/v1/{role}/backends/{backend}/{action}")

    # ---- services -------------------------------------------------------- #
    async def restart(self, service: str) -> dict:
        return await self._request("POST", f"/v1/services/{service}/restart")

    async def logs(self, service: str, lines: int = 200) -> list[str]:
        data = await self._request("GET", "/v1/logs", params={"service": service, "lines": lines})
        return list((data or {}).get("lines") or [])

    # ---- certificate ----------------------------------------------------- #
    async def renew_csr(self) -> str:
        data = await self._request("POST", "/v1/cert/renew")
        csr = (data or {}).get("csr_pem")
        if not csr:
            raise AgentError("agent returned no CSR")
        return csr

    async def install_cert(self, cert_pem: str, ca_pem: Optional[str] = None) -> dict:
        body = {"cert_pem": cert_pem}
        if ca_pem:
            body["ca_pem"] = ca_pem
        return await self._request("PUT", "/v1/cert", json=body)
