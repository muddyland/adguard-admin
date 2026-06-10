"""Reverse-proxy a server's AdGuard Home UI for same-origin iframe embedding.

AdGuard's UI assumes it's hosted at the web root (absolute /control, /assets
paths) and sends X-Frame-Options, so it can't normally be iframed cross-origin.
We proxy it under /api/servers/{id}/ui/ and:
  - inject the stored Basic-auth credentials (auto-login),
  - strip framing headers (X-Frame-Options / CSP) and terminate TLS our side,
  - rewrite absolute paths in the served HTML, and
  - inject a JS shim that rewrites runtime fetch/XHR calls to the prefix.

Iframe sub-requests can't carry our JWT header, so access is authorized by a
short-lived, path-scoped cookie minted by /ui-session (editor-only).
"""
from __future__ import annotations

import re

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from ..certs import verify_for
from ..config import settings
from ..deps import RequireEditor, SessionDep
from ..models import Server
from ..security import create_proxy_token, decode_proxy_token, decrypt_secret

router = APIRouter(prefix="/api/servers", tags=["proxy"])

_PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
_HOP_BY_HOP = {
    "host", "cookie", "authorization", "accept-encoding", "content-length",
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}
_STRIP_RESP = {
    "x-frame-options", "content-security-policy", "content-security-policy-report-only",
    "content-encoding", "content-length", "transfer-encoding", "connection",
    "strict-transport-security", "set-cookie",
}

# Runtime shim: rewrite absolute URLs (/control, /assets, …) to the proxy prefix
# so the AdGuard SPA's fetch/XHR calls resolve through us. P is injected per server.
_SHIM_BODY = """
function fix(u){try{
  if(typeof u!=="string")return u;
  if(u.indexOf(P+"/")===0||u===P)return u;
  if(u.indexOf("http")===0){var a=document.createElement("a");a.href=u;
    if(a.origin===location.origin&&a.pathname.indexOf(P+"/")!==0)return P+a.pathname+a.search+a.hash;
    return u;}
  if(u.charAt(0)==="/"&&u.charAt(1)!=="/")return P+u;
  return u;
}catch(e){return u;}}
var of=window.fetch;
window.fetch=function(i,init){if(typeof i==="string")i=fix(i);else if(i&&i.url){try{i=new Request(fix(i.url),i)}catch(e){}}return of.call(this,i,init);};
var oo=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){try{arguments[1]=fix(u)}catch(e){}return oo.apply(this,arguments);};
"""


def _shim(prefix: str) -> str:
    return "<script>(function(){var P=" + _to_js_str(prefix) + ";" + _SHIM_BODY + "})();</script>"


def _to_js_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _rewrite_html(html: str, prefix: str) -> str:
    head = re.search(r"<head[^>]*>", html, re.IGNORECASE)
    shim = _shim(prefix)
    html = html[: head.end()] + shim + html[head.end():] if head else shim + html
    # Rewrite absolute attribute paths: src/href/action="/x" -> "/prefix/x"
    return re.sub(r'(\s(?:src|href|action)=["\'])/(?!/)', r"\1" + prefix + "/", html)


def _rewrite_location(loc: str, server_url: str, prefix: str) -> str:
    base = server_url.rstrip("/")
    if loc.startswith(base):
        loc = loc[len(base):] or "/"
    if loc.startswith("/") and not loc.startswith("//") and not loc.startswith(prefix):
        return prefix + loc
    return loc


@router.post("/{server_id}/ui-session")
def ui_session(server_id: int, user: RequireEditor, session: SessionDep, response: Response):
    """Mint a path-scoped cookie that authorizes embedding this server's UI."""
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    prefix = f"/api/servers/{server_id}/ui"
    response.set_cookie(
        key=f"aghproxy_{server_id}",
        value=create_proxy_token(server_id, user.id),
        path=prefix,
        httponly=True,
        samesite="lax",
        secure=settings.public_base_url.startswith("https"),
        max_age=3600,
    )
    return {"ok": True, "src": prefix + "/"}


@router.api_route("/{server_id}/ui/{path:path}", methods=_PROXY_METHODS, include_in_schema=False)
async def proxy_ui(server_id: int, path: str, request: Request, session: SessionDep):
    token = request.cookies.get(f"aghproxy_{server_id}")
    if not token or not decode_proxy_token(token, server_id):
        raise HTTPException(status_code=401, detail="UI session expired — reopen the server UI")
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    prefix = f"/api/servers/{server_id}/ui"
    target = server.url.rstrip("/") + "/" + path
    if request.url.query:
        target += "?" + request.url.query

    fwd = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}
    fwd["accept-encoding"] = "identity"
    creds = (server.username, decrypt_secret(server.password_enc)) if server.username else None
    body = await request.body()

    try:
        async with httpx.AsyncClient(verify=verify_for(server.tls_cert), auth=creds,
                                     follow_redirects=False, timeout=30.0) as client:
            up = await client.request(request.method, target, headers=fwd, content=body)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream error: {exc}")

    ct = up.headers.get("content-type", "")
    out_headers = {}
    for k, v in up.headers.items():
        kl = k.lower()
        if kl in _STRIP_RESP:
            continue
        if kl == "location":
            v = _rewrite_location(v, server.url, prefix)
        out_headers[k] = v

    content = up.content
    if "text/html" in ct.lower():
        content = _rewrite_html(content.decode("utf-8", "replace"), prefix).encode("utf-8")

    return Response(content=content, status_code=up.status_code, headers=out_headers, media_type=ct or None)
