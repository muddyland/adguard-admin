"""Thin async client for the AdGuard Home control API.

We only touch the pieces we need to manage custom DNS records, which AdGuard
calls "DNS rewrites" (a domain -> answer mapping). Docs/endpoints:
    GET  /control/status            -> instance health + version
    GET  /control/rewrite/list      -> [{"domain": ..., "answer": ...}]
    POST /control/rewrite/add       -> {"domain": ..., "answer": ...}
    POST /control/rewrite/delete    -> {"domain": ..., "answer": ...}
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass(frozen=True)
class Rewrite:
    domain: str
    answer: str

    def key(self) -> tuple[str, str]:
        return (self.domain.strip().lower(), self.answer.strip())


class AdGuardError(Exception):
    pass


class AdGuardClient:
    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 10.0,
        verify=True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        auth = (username, password) if username else None
        # `verify` may be True/False or an ssl.SSLContext pinned to a server cert.
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            auth=auth,
            timeout=timeout,
            follow_redirects=True,
            verify=verify,
        )

    async def __aenter__(self) -> "AdGuardClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def status(self) -> dict:
        try:
            resp = await self._client.get("/control/status")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise AdGuardError(f"status check failed: {exc}") from exc

    async def stats(self) -> dict:
        """GET /control/stats — query counts, blocked counts, top lists, timings."""
        try:
            resp = await self._client.get("/control/stats")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise AdGuardError(f"stats failed: {exc}") from exc

    async def version_check(self, recheck: bool = False) -> dict:
        """POST /control/version.json — returns {new_version, announcement, ...}.
        Uses AdGuard's cached result unless recheck is True."""
        try:
            resp = await self._client.post("/control/version.json", json={"recheck_now": recheck})
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise AdGuardError(f"version check failed: {exc}") from exc

    async def dns_info(self) -> dict:
        """GET /control/dns_info — current DNS config (upstreams, bootstrap, etc.)."""
        try:
            resp = await self._client.get("/control/dns_info")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise AdGuardError(f"dns_info failed: {exc}") from exc

    async def set_dns_config(self, config: dict) -> None:
        """Partial update of DNS config (only the keys provided), e.g.
        upstream_dns / bootstrap_dns / fallback_dns / local_ptr_upstreams."""
        try:
            resp = await self._client.post("/control/dns_config", json=config)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise AdGuardError(f"set dns config failed: {exc}") from exc

    async def list_rewrites(self) -> list[Rewrite]:
        try:
            resp = await self._client.get("/control/rewrite/list")
            resp.raise_for_status()
            data = resp.json() or []
            return [Rewrite(domain=r["domain"], answer=r["answer"]) for r in data]
        except httpx.HTTPError as exc:
            raise AdGuardError(f"list rewrites failed: {exc}") from exc
        except (KeyError, TypeError) as exc:
            raise AdGuardError(f"unexpected rewrite payload: {exc}") from exc

    async def add_rewrite(self, rewrite: Rewrite) -> None:
        try:
            resp = await self._client.post(
                "/control/rewrite/add",
                json={"domain": rewrite.domain, "answer": rewrite.answer},
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise AdGuardError(f"add rewrite {rewrite.domain} failed: {exc}") from exc

    async def delete_rewrite(self, rewrite: Rewrite) -> None:
        try:
            resp = await self._client.post(
                "/control/rewrite/delete",
                json={"domain": rewrite.domain, "answer": rewrite.answer},
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise AdGuardError(f"delete rewrite {rewrite.domain} failed: {exc}") from exc
