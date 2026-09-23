# Users & SSO

## Roles

AdGuard Admin has three roles, enforced on every API call:

| Role | Can do |
|---|---|
| **admin** | Everything, including managing users |
| **editor** | Manage zones, servers, records, DNS settings; trigger sync and provisioning |
| **viewer** | Read-only — dashboards, query log, and configuration, but no changes |

Manage accounts from the **Users** page (admins only).

![Users](images/users.png)

Each user shows their **role**, **type** (Local or OIDC), **status**, and creation date.
You can edit a user's role/email, deactivate them, or reset a local user's password. The
account you're signed in as is marked **(you)** and can't delete itself.

## Local accounts

The first time the app starts with an empty database, a **bootstrap admin** is created
from `ADMIN_USERNAME` / `ADMIN_PASSWORD`. Log in, then:

- change its password immediately, **or**
- create your own admin and deactivate the bootstrap account.

Passwords are hashed; login issues a signed JWT (`SECRET_KEY`) whose algorithm is pinned
on decode to prevent algorithm-confusion attacks.

Every request re-reads the user from the database, so deactivating an account or
changing its role takes effect on the next request — you do not have to wait for
the token to expire.

Failed logins are rate-limited per client IP and per username; too many in a row
returns `429` with a `Retry-After` header. Tune it with `LOGIN_MAX_ATTEMPTS`,
`LOGIN_WINDOW_SECONDS` and `LOGIN_LOCKOUT_SECONDS`.

## OIDC single sign-on

AdGuard Admin supports OpenID Connect single sign-on **alongside** local
accounts. Nothing in the client is provider-specific: past the issuer and the
client credentials, every endpoint and key comes from the provider's discovery
document. Tested with [Kanidm](https://kanidm.com/) and
[Authentik](https://goauthentik.io/).

### 1. Create the client in your IdP

- **Redirect URI**: `<public-base-url>/api/auth/oidc/callback`
  (e.g. `http://localhost:8080/api/auth/oidc/callback`)
- **Scopes**: `openid email profile`, plus `groups` if you want group→role
  mapping and your provider gates the claim behind that scope (Kanidm does;
  Authentik puts groups in `profile`).
- **PKCE**: leave it required. The app sends an S256 challenge by default.

<details>
<summary>Kanidm recipe</summary>

```sh
kanidm system oauth2 create adguard-admin "AdGuard Admin" https://adguard.example.com
kanidm system oauth2 add-redirect-url adguard-admin \
    https://adguard.example.com/api/auth/oidc/callback
# Map the group you want to read as "admin" into the groups claim.
kanidm system oauth2 update-scope-map adguard-admin adguard-admins \
    openid email profile groups
# Optional: hand out "alice" instead of the full SPN "alice@idm.example.com"
# as preferred_username, which is what becomes the local account name.
kanidm system oauth2 prefer-short-username adguard-admin
kanidm system oauth2 show-basic-secret adguard-admin
```

The issuer is `https://idm.example.com/oauth2/openid/adguard-admin`.

</details>

### 2. Configure the app

In `.env`:

```ini
OIDC_ENABLED=true
OIDC_ISSUER=https://idm.example.com/oauth2/openid/adguard-admin
OIDC_CLIENT_ID=adguard-admin
OIDC_CLIENT_SECRET=...
OIDC_DISPLAY_NAME=Kanidm            # login button reads "Sign in with Kanidm"
OIDC_SCOPES=openid email profile groups
OIDC_REDIRECT_URI=https://adguard.example.com/api/auth/oidc/callback
OIDC_ADMIN_GROUP=adguard-admins     # optional: members become admins
OIDC_DEFAULT_ROLE=viewer            # role for first-time SSO users
```

On startup the app logs the issuer, client id, PKCE mode, scopes and button
label in one line — read it first when sign-in breaks after a provider change.

### 3. Sign in

The login screen gains a **Sign in with `OIDC_DISPLAY_NAME`** button (default:
"Sign in with SSO"). First-time SSO users are provisioned automatically with
`OIDC_DEFAULT_ROLE` (or **admin** if they're in `OIDC_ADMIN_GROUP`). After
authenticating, the token is handed to the SPA via the URL fragment so it never
lands in server logs.

### Group → role mapping

`OIDC_ADMIN_GROUP` is matched against the `groups` claim exactly, entry by
entry — never as a substring, so `admins` does not match `not-admins`. Kanidm
names groups by SPN, so both forms work:

| `OIDC_ADMIN_GROUP` | Matches |
|---|---|
| `adguard-admins` | `adguard-admins`, `adguard-admins@idm.example.com` |
| `adguard-admins@idm.example.com` | that SPN only — not the same name in another domain |

Membership only ever **promotes**: a user in the admin group becomes an admin on
login, but leaving the group does not demote them automatically. Change the role
in **Users** instead.

If nobody is being promoted, the usual cause is a missing `groups` scope — the
app logs a warning at startup when `OIDC_ADMIN_GROUP` is set without it.

### Usernames

The local account name comes from `preferred_username`, falling back to a
verified email and then to `sub`. Kanidm sends the full SPN
(`alice@idm.example.com`) unless the client has `prefer-short-username` set, so
decide which you want *before* the first sign-in: changing it later produces a
second account, since accounts are keyed on `sub`, not on the name.

### Linking SSO to existing accounts

An SSO identity is matched on the provider's stable `sub` claim. It is **not**
matched on username by default: many IdPs let users choose their own
`preferred_username`, so username matching would let someone claim an existing
account — including `admin` — just by renaming themselves.

If your IdP controls usernames centrally you can opt in with
`OIDC_ALLOW_USERNAME_LINKING=true`. Even then, an account that has a local
password is never adopted, and an account already bound to a different `sub` is
never taken over. If an SSO login would collide with an existing local username,
it is refused with a `409` and an administrator must link the accounts.

Only an email the provider marked `email_verified` is trusted; an unverified
address is self-asserted and gets ignored.

See the [configuration reference](configuration.md#oidc-single-sign-on) for every
OIDC setting.
