"""Thin async client for the AdGuard Home control API.

We touch the pieces needed to manage DNS rewrites, upstream config, stats and
the query log. Errors are surfaced as AdGuardError carrying the HTTP status code
and (for 429s) a retry-after hint, so the reconcile loop can back off instead of
hammering a server — AdGuard has brute-force protection that blocks auth after
repeated failures.
"""
from __future__ import annotations

import re
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
    def __init__(self, message: str, status_code: int | None = None, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


def _retry_after(resp: httpx.Response) -> int | None:
    ra = resp.headers.get("retry-after")
    if ra:
        try:
            return int(float(ra))
        except ValueError:
            pass
    # AdGuard's lockout message looks like: "auth: blocked for 13m47.96s"
    try:
        m = re.search(r"blocked for\s+(?:(\d+)m)?([\d.]+)s", resp.text or "")
    except Exception:
        m = None
    if m:
        return int(int(m.group(1) or 0) * 60 + float(m.group(2) or 0)) + 1
    return None


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

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        try:
            resp = await self._client.request(method, path, **kwargs)
            resp.raise_for_status()
            return resp
        except httpx.HTTPStatusError as exc:
            r = exc.response
            raise AdGuardError(
                f"{method} {path} -> HTTP {r.status_code}",
                status_code=r.status_code,
                retry_after=_retry_after(r),
            ) from exc
        except httpx.HTTPError as exc:
            raise AdGuardError(f"{method} {path} failed: {exc}") from exc

    async def status(self) -> dict:
        return (await self._request("GET", "/control/status")).json()

    async def stats(self) -> dict:
        """GET /control/stats — query counts, blocked counts, top lists, timings."""
        return (await self._request("GET", "/control/stats")).json()

    async def version_check(self, recheck: bool = False) -> dict:
        """POST /control/version.json — returns {new_version, announcement, ...}."""
        return (await self._request("POST", "/control/version.json", json={"recheck_now": recheck})).json()

    async def query_log(self, params: dict) -> dict:
        """GET /control/querylog — recent DNS queries. Supports limit/search/response_status."""
        return (await self._request("GET", "/control/querylog", params=params)).json()

    async def dns_info(self) -> dict:
        """GET /control/dns_info — current DNS config (upstreams, bootstrap, etc.)."""
        return (await self._request("GET", "/control/dns_info")).json()

    async def set_dns_config(self, config: dict) -> None:
        """Partial update of DNS config (only the keys provided)."""
        await self._request("POST", "/control/dns_config", json=config)

    async def list_rewrites(self) -> list[Rewrite]:
        data = (await self._request("GET", "/control/rewrite/list")).json() or []
        try:
            return [Rewrite(domain=r["domain"], answer=r["answer"]) for r in data]
        except (KeyError, TypeError) as exc:
            raise AdGuardError(f"unexpected rewrite payload: {exc}") from exc

    async def add_rewrite(self, rewrite: Rewrite) -> None:
        await self._request("POST", "/control/rewrite/add",
                            json={"domain": rewrite.domain, "answer": rewrite.answer})

    async def delete_rewrite(self, rewrite: Rewrite) -> None:
        await self._request("POST", "/control/rewrite/delete",
                            json={"domain": rewrite.domain, "answer": rewrite.answer})
