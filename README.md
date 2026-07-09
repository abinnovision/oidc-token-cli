# oidc-token-cli

A small CLI that fetches an OIDC token and prints it as a bare string —
built as a drop-in `exec` credential provider for `frpc`, `kubectl`,
`curl`, or CI pipelines.

Nothing is hardcoded to a specific issuer or client: every endpoint is
resolved at runtime from `/.well-known/openid-configuration`, and the
interactive grant (`authcode+PKCE` or `device-code`) is auto-selected based
on what the issuer supports and what the environment can do (browser vs.
attended terminal). Tokens are cached per `(issuer, client_id)` and
silently refreshed; a browser or device-code prompt is only shown when the
cache is cold.

## Contract

- **Success:** exactly the token bytes on stdout (no trailing newline), exit 0.
- **Failure:** non-zero exit, message on stderr, empty stdout — never a
  partial or placeholder token.
- Public client by default (PKCE, no secret). Confidential clients are
  opt-in via `--client-auth-method` — see
  [Confidential clients](#confidential-clients). mTLS client
  authentication (`tls_client_auth`) is not supported.

## Install

Download a release binary (darwin/linux, amd64/arm64) from the
[releases page](https://github.com/abinnovision/oidc-token-cli/releases).

## Usage

```sh
oidc-token \
  --issuer https://id.example.com/ \
  --client-id my-public-client \
  [--scope "openid offline_access"] \
  [--audience my-api] \
  [--grant-type auto|authcode|device-code|token-exchange] \
  [--token-type access_token|id_token] \
  [--cache-dir DIR] \
  [--token-store auto|keychain|file] \
  [--redirect PORT] \
  [--non-interactive] \
  [--all] \
  [--logout] \
  [--config FILE] \
  [--client-auth-method client_secret_basic|client_secret_post|private_key_jwt] \
  [--client-secret SECRET | --client-secret-file FILE] \
  [--private-key-file FILE] [--private-key-id KID] [--private-key-alg ALG] \
  [--client-assertion-audience AUD] \
  [--subject-token TOKEN | --subject-token-file FILE] [--subject-token-type TYPE] \
  [--requested-token-type TYPE] [--resource URI ...]
```

| Flag | Default | Description |
|---|---|---|
| `--issuer` | *(required)* | OIDC issuer URL (HTTPS, except loopback in tests). Discovery's `issuer` field must match exactly. |
| `--client-id` | *(required)* | OAuth2/OIDC client ID. |
| `--scope` | `openid offline_access` | Space-separated scopes. |
| `--audience` | *(empty)* | Expected `aud` claim — required if the relying party checks audience (e.g. frp's `auth.oidc.audience`). |
| `--grant-type` | `auto` | `auto`, `authcode`, `device-code`, or `token-exchange`. See [Grant selection](#grant-selection) and [Token exchange](#token-exchange-rfc-8693). |
| `--token-type` | `access_token` | Which field bare mode prints. |
| `--cache-dir` | `$XDG_CACHE_HOME/oidc-token` | Override the token cache directory (used by the `file` backend and, in `auto` mode, as the fallback store). |
| `--token-store` | `auto` | `auto`, `keychain`, or `file`. See [Cache](#cache). |
| `--redirect` | `0` (ephemeral) | Fixed loopback port for the authcode callback, if your IdP requires an exact redirect URI. |
| `--non-interactive` | `false` | Never emit a device-code prompt; authcode+browser is still allowed if a display is available. |
| `--all` | `false` | Print a JSON document instead of a bare token. |
| `--logout` | `false` | Clear the cached entry for `--issuer`/`--client-id` and exit; no login or refresh is attempted. |
| `--config` | *(none)* | Optional JSON config file. |
| `--client-auth-method` | *(none, public client)* | `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. See [Confidential clients](#confidential-clients). |
| `--client-secret` / `--client-secret-file` | *(none)* | Client secret for `client_secret_basic`/`client_secret_post`. Prefer `--client-secret-file` or `$OIDC_TOKEN_CLIENT_SECRET` over the bare flag; `--client-secret-file` wins if both are set. |
| `--private-key-file` | *(none)* | PEM file (PKCS#1/PKCS#8/EC) used to sign the `private_key_jwt` client assertion. |
| `--private-key-id` | *(none)* | Optional `kid` header on the client assertion. |
| `--private-key-alg` | `RS256` | JWS signing algorithm: `RS256`/`RS384`/`RS512`/`PS256`/`PS384`/`PS512`/`ES256`/`ES384`/`ES512`. |
| `--client-assertion-audience` | *(the discovered token endpoint)* | Override the assertion's `aud` claim, for issuers that expect the issuer URL or something else instead. |
| `--subject-token` / `--subject-token-file` | *(none)* | RFC 8693 `subject_token` for `--grant-type=token-exchange`. Prefer `--subject-token-file` or `$OIDC_TOKEN_SUBJECT_TOKEN` over the bare flag; `--subject-token-file` wins if both are set. |
| `--subject-token-type` | `urn:ietf:params:oauth:token-type:access_token` | RFC 8693 `subject_token_type`. |
| `--requested-token-type` | *(none)* | RFC 8693 `requested_token_type`; omitted from the request entirely when unset. |
| `--resource` | *(none)* | RFC 8693 `resource` target URI; repeatable for multiple resource params. |

Every flag except `--config`/`--client-secret-file`/`--subject-token-file`/
`--resource` also has an env var: `OIDC_TOKEN_ISSUER`,
`OIDC_TOKEN_CLIENT_ID`, `OIDC_TOKEN_SCOPE`, `OIDC_TOKEN_AUDIENCE`,
`OIDC_TOKEN_GRANT_TYPE`, `OIDC_TOKEN_TOKEN_TYPE`, `OIDC_TOKEN_CACHE_DIR`,
`OIDC_TOKEN_STORE`, `OIDC_TOKEN_NON_INTERACTIVE`, `OIDC_TOKEN_LOGOUT`,
`OIDC_TOKEN_CLIENT_AUTH_METHOD`, `OIDC_TOKEN_CLIENT_SECRET`,
`OIDC_TOKEN_PRIVATE_KEY_FILE`, `OIDC_TOKEN_PRIVATE_KEY_ID`,
`OIDC_TOKEN_PRIVATE_KEY_ALG`, `OIDC_TOKEN_CLIENT_ASSERTION_AUDIENCE`,
`OIDC_TOKEN_SUBJECT_TOKEN`, `OIDC_TOKEN_SUBJECT_TOKEN_TYPE`.
`OIDC_TOKEN_CLIENT_SECRET` (or `--client-secret-file`) is the recommended
way to pass a secret — avoid `--client-secret` on the command line where it
can land in shell history or process listings. Precedence: defaults < env <
`--config` file < explicit flags.

### Grant selection

`auto` picks the best viable grant based on what the issuer advertises and
what the environment supports:

| Grant | Advertised when | Viable when |
|---|---|---|
| `authorization_code` | default per OIDC Discovery, or explicitly listed | a browser can be launched |
| `device-code` | issuer has a `device_authorization_endpoint` | a TTY is attached and `--non-interactive` was not passed |

Authcode is tried first when both are viable. If the client is rejected
for the grant it tried (`unauthorized_client`/`invalid_grant` at the
authorization endpoint), it falls back to the other viable grant once —
capped at 2 attempts total, no cycling back. `--grant-type=authcode` or
`=device-code` forces one grant and fails fast if it isn't viable, with a
diagnostic describing what the IdP offers and why browser/terminal
viability failed.

### Confidential clients

By default `oidc-token` is a public client: no secret, no client
authentication on token requests. Setting `--client-auth-method` switches
it to a confidential client for all three grants (authcode, device-code,
refresh):

- **`client_secret_basic`** / **`client_secret_post`** — send
  `--client-secret` (or, preferably, `--client-secret-file`/
  `$OIDC_TOKEN_CLIENT_SECRET`) as HTTP Basic auth or a POST body param,
  respectively.
- **`private_key_jwt`** (RFC 7523) — sign a fresh, short-lived JWT
  assertion per token request with `--private-key-file` (PEM,
  PKCS#1/PKCS#8/EC). `--private-key-id` sets an optional `kid` header for
  issuers that select the verification key from a registered JWKS.
  `--client-assertion-audience` overrides the assertion's `aud` claim if
  your issuer expects something other than the discovered token endpoint
  (conventions vary between IdPs — check yours if authentication fails
  with an audience-related error).

Not supported: mTLS client authentication (`tls_client_auth`).

### Token exchange (RFC 8693)

`--grant-type=token-exchange` exchanges an existing `--subject-token` (e.g.
minted by another system or CI job) for a new token, instead of performing
an interactive login. It requires `--subject-token` (or, preferably,
`--subject-token-file`/`$OIDC_TOKEN_SUBJECT_TOKEN`) and reuses
`--audience`/`--scope` and, for confidential clients, the same
`--client-auth-method` machinery as the other grants.

Unlike every other grant, **token exchange is never cached**: each
invocation hits the token endpoint fresh. The cache's `(issuer, client_id)`
key can't distinguish between exchanges for different `--audience`/
`--resource` targets, and reusing it would risk serving a token minted for
the wrong one.

- `--subject-token-type` defaults to
  `urn:ietf:params:oauth:token-type:access_token`; override it per RFC 8693
  §3 (e.g. `...:id_token`, `...:jwt`) to match what `--subject-token`
  actually is.
- `--requested-token-type` is optional and omitted from the request
  entirely when unset.
- `--resource` may be repeated to send multiple RFC 8693 `resource` params
  in a single request.
- With `--all`, the response's `issued_token_type` (RFC 8693 §2.2.1) is
  included in the JSON document.

### Cache

Tokens are cached per `(issuer, client_id)` profile, addressed by a
SHA-256 hash of the pair so those values don't leak into keys/filenames.
`--token-store` selects where:

| `--token-store` | Behavior |
|---|---|
| `auto` (default) | Try the OS keychain (macOS Keychain, Linux Secret Service over D-Bus) first; fall back to the plaintext file store only when the keychain backend is unavailable (no daemon reachable) — not on a plain cache miss. Logs a one-line notice to stderr the first time it falls back. |
| `keychain` | OS keychain only, no fallback. Fails fast at startup if no keychain backend is reachable. |
| `file` | Plaintext JSON file only — this CLI's original behavior, no cgo, works anywhere. |

The file store lives at `--cache-dir` (default `$XDG_CACHE_HOME/oidc-token`
or `~/.cache/oidc-token`); files are `0600`, written atomically, and
refreshes run under an advisory `flock` so concurrent invocations converge
on one winner instead of each re-authenticating. `auto` mode reuses that
same `flock` for cross-process coordination even when the token payload
lives in the keychain; `keychain`-enforce mode has no cross-process lock
(OS keychains expose no such primitive), so concurrent invocations against
the same profile aren't fully serialized in that mode.

There's no migration between backends: switching an existing profile from
`file` to `auto`/`keychain` on a machine with a working keychain triggers
one fresh login, since a keychain miss isn't treated as "check the file
next." Use `--logout` to explicitly clear a cached entry (keychain items
can't be removed with `rm` the way file entries can).

No cgo dependency either way — the keychain backend shells out to
`security` on macOS and speaks D-Bus directly on Linux.

### Bootstrap model

First run (cache empty) opens a browser or prints a device code and
blocks until login completes. Every run after that is served from cache
or silently refreshed. If the cache is cold *and* no grant is viable
(headless CI with `--non-interactive`), it fails fast — it will never
print a device-code prompt nobody can see. Warm the cache once,
interactively, before wiring `oidc-token` into a non-interactive job.

## Recipes

### `frpc` (`auth.oidc.tokenSource.exec`)

frp's client sends the OAuth2 **`access_token`** (not `id_token`) and
trims all whitespace from the exec output, so use `--token-type
access_token`:

```toml
# frpc.toml
[auth]
method = "oidc"

[auth.oidc.tokenSource.exec]
command = "oidc-token"
args = [
  "--issuer", "https://id.example.com/",
  "--client-id", "frpc-client",
  "--token-type", "access_token",
  "--audience", "frps",        # match frps's auth.oidc.audience exactly
  "--non-interactive",
]
```

`--non-interactive` here just suppresses the device-code prompt in
frpc's log — a cold cache still opens a browser, since frpc's `exec`
still has a display available even without a TTY. Bootstrap once before
first use to avoid that popup coming from inside frpc's process tree:

```sh
oidc-token --issuer https://id.example.com/ --client-id frpc-client \
  --token-type access_token --audience frps
```

### kubectl `ExecCredential`-style (`--all`)

```yaml
# ~/.kube/config (users[].user.exec)
exec:
  apiVersion: client.authentication.k8s.io/v1
  command: oidc-token
  args:
    - --issuer=https://id.example.com/
    - --client-id=my-k8s-client
    - --token-type=id_token
    - --all
```

`--all`'s JSON has `access_token`/`id_token`/`refresh_token`/`expiry` but
no `apiVersion`/`kind`/`status` envelope — wrap it if your consumer needs
the literal k8s schema.

### CI (`--non-interactive`)

```sh
# One-time, interactive, with a TTY:
oidc-token --issuer https://id.example.com/ --client-id ci-client

# In the actual CI job, against the warmed cache:
export OIDC_TOKEN_ISSUER=https://id.example.com/
export OIDC_TOKEN_CLIENT_ID=ci-client
oidc-token --non-interactive
```

Reuse the same `--cache-dir` between the bootstrap step and later
non-interactive runs — an ephemeral runner has no warm cache and will
fail fast by design.

## Build & release

```sh
go build ./...
go vet ./...
go test ./...
```

Every push to `main` runs CI; if it's green, [svu](https://github.com/caarlos0/svu)
derives the next semver from conventional commits and, on a version bump,
`goreleaser release --clean` builds darwin/linux × amd64/arm64 archives
plus a GitHub release.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
