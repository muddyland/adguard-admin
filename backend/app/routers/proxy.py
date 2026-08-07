"""Reverse-proxy a server's AdGuard Home UI for embedding in the admin SPA.

AdGuard's UI assumes it's hosted at the web root (absolute /control, /assets
paths) and sends X-Frame-Options, so it can't normally be iframed cross-origin.
We proxy it under /api/servers/{id}/ui/ and:
  - inject the stored Basic-auth credentials (auto-login),
  - strip framing headers (X-Frame-Options / CSP) and terminate TLS our side,
  - rewrite absolute paths in the served HTML, and
  - inject a JS shim that rewrites runtime fetch/XHR calls to the prefix.

Trust boundary
--------------
The proxied bytes are written by the remote AdGuard instance, not by us. If they
were rendered in this app's origin, a compromised or hostile managed server
could read the admin session token straight out of localStorage. So the SPA
embeds the iframe with `sandbox` and *without* `allow-same-origin`, which puts
the proxied document in an opaque origin: it cannot reach the parent's DOM or
storage. That in turn makes its own fetch/XHR calls cross-origin (Origin: null),
so we emit permissive CORS headers on *this* prefix only — the rest of /api
stays unreachable to it. The admin API authenticates with a Bearer header rather
than an ambient cookie, so the sandboxed frame also has nothing to replay.

Iframe sub-requests can't carry our JWT header, so access is authorized by a
short-lived, path-scoped cookie minted by /ui-session (editor-only). The cookie
carries the user id and is re-checked against the database on every request —
a disabled, deleted or demoted user loses access immediately rather than at
token expiry.
"""
from __future__ import annotations

import re

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from ..certs import verify_for
from ..config import settings
from ..deps import RequireEditor, SessionDep, user_has_role
from ..models import Role, Server, User
from ..security import create_proxy_token, decode_proxy_token, decrypt_secret

router = APIRouter(prefix="/api/servers", tags=["proxy"])

# Shared with main.py so the security-header and preflight middleware can tell
# proxy traffic apart from the rest of the API.
UI_PROXY_PATH_RE = re.compile(r"^/api/servers/\d+/ui(/|$)")

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
    # We re-issue our own below; never let the upstream dictate them.
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-methods", "access-control-allow-headers",
}

# Responses larger than this are streamed straight through rather than buffered.
# Only HTML needs rewriting, and AdGuard's HTML is a small shell.
_MAX_REWRITE_BYTES = 8 * 1024 * 1024

# Runtime shim: rewrite absolute URLs (/control, /assets, …) to the proxy prefix
# so the AdGuard SPA's fetch/XHR calls resolve through us. P is injected per server.
# credentials:"include" is required because the sandboxed frame is cross-origin
# to us and would otherwise omit the path-scoped auth cookie.
_SHIM_BODY = """
function fix(u){try{
  if(typeof u!=="string")return u;
  if(u.indexOf(P+"/")===0||u===P)return u;
  if(u.indexOf("http")===0){var a=document.createElement("a");a.href=u;
    if(a.origin===B&&a.pathname.indexOf(P+"/")!==0)return B+P+a.pathname+a.search+a.hash;
    return u;}
  if(u.charAt(0)==="/"&&u.charAt(1)!=="/")return B+P+u;
  return u;
}catch(e){return u;}}
var of=window.fetch;
window.fetch=function(i,init){init=init||{};if(!init.credentials)init.credentials="include";
  if(typeof i==="string")i=fix(i);else if(i&&i.url){try{i=new Request(fix(i.url),i)}catch(e){}}
  return of.call(this,i,init);};
var oo=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){try{arguments[1]=fix(u)}catch(e){}
  var r=oo.apply(this,arguments);try{this.withCredentials=true}catch(e){}return r;};
"""


def _to_js_str(s: str) -> str:
    # Also escape < so the payload can never terminate the enclosing <script>.
    return (
        '"'
        + s.replace("\\", "\\\\").replace('"', '\\"').replace("<", "\\x3c")
        + '"'
    )


def _shim(prefix: str) -> str:
    base = settings.public_base_url.rstrip("/")
    return (
        "<script>(function(){var P="
        + _to_js_str(prefix)
        + ";var B="
        + _to_js_str(base)
        + ";"
        + _SHIM_BODY
        + "})();</script>"
    )


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


def is_ui_proxy_preflight(request: Request) -> bool:
    """True for a CORS preflight aimed at this router."""
    return (
        request.method == "OPTIONS"
        and "access-control-request-method" in request.headers
        and UI_PROXY_PATH_RE.match(request.url.path) is not None
    )


def preflight_response(request: Request) -> Response:
    """Answer a preflight from the sandboxed iframe.

    This runs above the app-wide CORSMiddleware, which would otherwise reject
    `Origin: null` with a 400 before routing ever happens. Scoping it here keeps
    the rest of /api unreachable from the opaque origin.
    """
    headers = _cors_headers(request)
    if not headers:
        return Response(status_code=403)
    return Response(status_code=204, headers={**headers, "access-control-max-age": "600"})


def _cors_headers(request: Request) -> dict[str, str]:
    """Allow the sandboxed (opaque-origin) iframe to read its own responses.

    Scoped to this router's responses only. `Origin: null` is exactly what a
    sandboxed frame sends; we echo it back rather than using "*" because the
    requests are credentialed.
    """
    origin = request.headers.get("origin")
    if not origin:
        return {}
    allowed = {"null", settings.public_base_url.rstrip("/")}
    if origin not in allowed:
        return {}
    return {
        "access-control-allow-origin": origin,
        "access-control-allow-credentials": "true",
        "access-control-allow-methods": ", ".join(_PROXY_METHODS),
        "access-control-allow-headers": request.headers.get(
            "access-control-request-headers", "content-type"
        ),
        "vary": "Origin",
    }


def _authorize(request: Request, server_id: int, session: SessionDep) -> Server:
    """Validate the proxy cookie *and* the current standing of its user."""
    if not settings.ui_proxy_enabled:
        raise HTTPException(status_code=404, detail="Embedded UI proxy is disabled")

    token = request.cookies.get(f"aghproxy_{server_id}")
    user_id = decode_proxy_token(token, server_id) if token else None
    if user_id is None:
        raise HTTPException(status_code=401, detail="UI session expired — reopen the server UI")

    # A valid signature is not proof of current authorization: re-check the user.
    user = session.get(User, user_id)
    if user is None or not user.is_active or not user_has_role(user, Role.editor):
        raise HTTPException(status_code=403, detail="Not authorized for this server UI")

    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return server


@router.post("/{server_id}/ui-session")
def ui_session(server_id: int, user: RequireEditor, session: SessionDep, response: Response):
    """Mint a path-scoped cookie that authorizes embedding this server's UI."""
    if not settings.ui_proxy_enabled:
        raise HTTPException(status_code=404, detail="Embedded UI proxy is disabled")
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    prefix = f"/api/servers/{server_id}/ui"
    response.set_cookie(
        key=f"aghproxy_{server_id}",
        value=create_proxy_token(server_id, user.id),
        path=prefix,
        httponly=True,
        # The sandboxed iframe is an opaque origin, so its sub-requests are
        # cross-site as far as the cookie is concerned; Lax would drop them.
        # Confidentiality still holds: HttpOnly keeps it out of reach of script,
        # and the value is a signed, server-scoped, short-lived token.
        samesite="none" if settings.secure_cookies else "lax",
        secure=settings.secure_cookies,
        max_age=settings.proxy_token_ttl_minutes * 60,
    )
    return {
        "ok": True,
        "src": prefix + "/",
        "sandbox": _sandbox_attr(),
    }


def _sandbox_attr() -> str:
    """The iframe sandbox the SPA must apply to the proxied UI."""
    tokens = ["allow-scripts", "allow-forms", "allow-popups", "allow-downloads"]
    if settings.ui_proxy_allow_same_origin:
        # Escape hatch for AdGuard builds that hard-require localStorage. This
        # hands the proxied instance same-origin access to this app; startup
        # refuses to run with it set unless ALLOW_INSECURE_CONFIG is on.
        tokens.append("allow-same-origin")
    return " ".join(tokens)


@router.api_route("/{server_id}/ui/{path:path}", methods=_PROXY_METHODS, include_in_schema=False)
async def proxy_ui(server_id: int, path: str, request: Request, session: SessionDep):
    cors = _cors_headers(request)

    if is_ui_proxy_preflight(request):
        # Normally handled by the middleware above CORSMiddleware; kept here so
        # the route is still correct if called directly.
        return preflight_response(request)

    server = _authorize(request, server_id, session)

    prefix = f"/api/servers/{server_id}/ui"
    target = server.url.rstrip("/") + "/" + path
    if request.url.query:
        target += "?" + request.url.query

    fwd = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}
    fwd["accept-encoding"] = "identity"
    creds = (server.username, decrypt_secret(server.password_enc)) if server.username else None

    client = httpx.AsyncClient(
        verify=verify_for(server.tls_cert),
        auth=creds,
        follow_redirects=False,
        timeout=httpx.Timeout(30.0, read=300.0),
    )
    try:
        # Stream the request body upstream instead of materialising it: the
        # AdGuard UI uploads filter lists and config backups through here.
        upstream_req = client.build_request(
            request.method, target, headers=fwd, content=request.stream()
        )
        up = await client.send(upstream_req, stream=True)
    except httpx.HTTPError as exc:
        await client.aclose()
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
    out_headers.update(cors)

    # HTML is the only thing we rewrite, so it's the only thing we buffer.
    if "text/html" in ct.lower():
        try:
            raw = await up.aread()
        finally:
            await up.aclose()
            await client.aclose()
        if len(raw) <= _MAX_REWRITE_BYTES:
            content = _rewrite_html(raw.decode("utf-8", "replace"), prefix).encode("utf-8")
        else:
            content = raw
        return Response(
            content=content, status_code=up.status_code,
            headers=out_headers, media_type=ct or None,
        )

    async def _body():
        try:
            async for chunk in up.aiter_raw():
                yield chunk
        finally:
            await up.aclose()
            await client.aclose()

    return StreamingResponse(
        _body(), status_code=up.status_code, headers=out_headers, media_type=ct or None,
    )
