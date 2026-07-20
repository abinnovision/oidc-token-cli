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

```sh
brew install abinnovision/tap/oidc-token
```

Or download a release binary (darwin/linux, amd64/arm64) from the
[releases page](https://github.com/abinnovision/oidc-token-cli/releases).

## Quick start

```sh
# First run: opens a browser (or prints a device code), then caches the token.
oidc-token --issuer https://id.example.com/ --client-id my-public-client

# Every run after: served from cache, silently refreshed.
oidc-token --issuer https://id.example.com/ --client-id my-public-client
```

## Usage

```sh
oidc-token \
  --issuer https://id.example.com/ \
  --client-id my-public-client \
  [--scope "openid offline_access"] \
  [--audience my-api] \
  [--grant-type auto|authcode|device-code|token-exchange] \
  [--token-type access_token|id_token] \
  [--token-store-dir DIR] \
  [--token-store auto|keychain|file|none] \
  [--redirect PORT] \
  [--non-interactive] \
  [--format token|json|exec-credential] \
  [--all] \
  [--logout] \
  [--config FILE] \
  [--client-auth-method client_secret_basic|client_secret_post|private_key_jwt] \
  [--client-secret SECRET | --client-secret-file FILE] \
  [--private-key-file FILE] [--private-key-id KID] [--private-key-alg ALG] \
  [--client-assertion-audience AUD] \
  [--subject-token TOKEN | --subject-token-file FILE] [--subject-token-type TYPE] \
  [--subject-token-source github-actions] \
  [--requested-token-type TYPE] [--resource URI ...] \
  [--extra key=value ...]
```

#### Core flags

| Flag | Default | Description |
|---|---|---|
| `--issuer` | *(required)* | OIDC issuer URL (HTTPS, except loopback in tests). Discovery's `issuer` field must match exactly. |
| `--client-id` | *(required)* | OAuth2/OIDC client ID. |
| `--scope` | `openid offline_access` | Space-separated scopes. |
| `--audience` | *(empty)* | Expected `aud` claim — required if the relying party checks audience (e.g. frp's `auth.oidc.audience`). |
| `--grant-type` | `auto` | `auto`, `authcode`, `device-code`, or `token-exchange`. See [Grant selection](#grant-selection) and [Token exchange](#token-exchange-rfc-8693). |
| `--token-type` | `access_token` | Which field bare mode prints. |

#### Cache and storage

| Flag | Default | Description |
|---|---|---|
| `--token-store` | `auto` | `auto`, `keychain`, `file`, or `none`. See [Token store](#token-store). |
| `--token-store-dir` | `$XDG_CACHE_HOME/oidc-token` | Override the token store directory (used by the `file` backend and, in `auto` mode, as the fallback store). Ignored when `--token-store=none`. |

#### Behavior

| Flag | Default | Description |
|---|---|---|
| `--redirect` | `0` (ephemeral) | Fixed loopback port for the authcode callback, if your IdP requires an exact redirect URI. |
| `--non-interactive` | `false` | Never emit a device-code prompt; authcode+browser is still allowed if a display is available. |
| `--format` | `token` | `token`, `json`, or `exec-credential`. See [kubectl ExecCredential](#kubectl-execcredential---format-exec-credential). |
| `--all` | `false` | Deprecated: alias for `--format=json`. Print a JSON document instead of a bare token. Ignored when `--format` is set explicitly. |
| `--logout` | `false` | Clear the cached entry for `--issuer`/`--client-id` and exit; no login or refresh is attempted. |
| `--config` | *(none)* | Optional JSON config file. |
| `--extra` | *(none)* | Repeatable `key=value` pair forwarded to the token endpoint. In a config file, set as an `"extra"` object. |

#### Confidential client flags

| Flag | Default | Description |
|---|---|---|
| `--client-auth-method` | *(none, public client)* | `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. See [Confidential clients](#confidential-clients). |
| `--client-secret` / `--client-secret-file` | *(none)* | Client secret for `client_secret_basic`/`client_secret_post`. Prefer `--client-secret-file` or `$OIDC_TOKEN_CLIENT_SECRET` over the bare flag; `--client-secret-file` wins if both are set. |
| `--private-key-file` | *(none)* | PEM file (PKCS#1/PKCS#8/EC) used to sign the `private_key_jwt` client assertion. |
| `--private-key-id` | *(none)* | Optional `kid` header on the client assertion. |
| `--private-key-alg` | `RS256` | JWS signing algorithm: `RS256`/`RS384`/`RS512`/`PS256`/`PS384`/`PS512`/`ES256`/`ES384`/`ES512`. |
| `--client-assertion-audience` | *(the discovered token endpoint)* | Override the assertion's `aud` claim, for issuers that expect the issuer URL or something else instead. |

#### Token exchange flags

| Flag | Default | Description |
|---|---|---|
| `--subject-token` / `--subject-token-file` | *(none)* | RFC 8693 `subject_token` for `--grant-type=token-exchange`. Prefer `--subject-token-file` or `$OIDC_TOKEN_SUBJECT_TOKEN` over the bare flag; `--subject-token-file` wins if both are set. |
| `--subject-token-source` | *(empty, manual)* | `github-actions`: auto-fetch `--subject-token` from GitHub Actions' native OIDC provider instead of supplying it manually. Mutually exclusive with `--subject-token`/`--subject-token-file`/`$OIDC_TOKEN_SUBJECT_TOKEN`; requires `--grant-type=token-exchange`. See [Subject token sources](#subject-token-sources). |
| `--subject-token-type` | `urn:ietf:params:oauth:token-type:access_token` (or `…:id_token` when `--subject-token-source=github-actions`) | RFC 8693 `subject_token_type`. |
| `--requested-token-type` | *(none)* | RFC 8693 `requested_token_type`; omitted from the request entirely when unset. |
| `--resource` | *(none)* | RFC 8693 `resource` target URI; repeatable for multiple resource params. |

Every flag except `--config`, `--client-secret-file`, `--subject-token-file`,
`--resource`, `--all`, `--redirect`, `--requested-token-type`, and `--extra`
has an `OIDC_TOKEN_*` env var (e.g. `--issuer` becomes `OIDC_TOKEN_ISSUER`).
Prefer `OIDC_TOKEN_CLIENT_SECRET` or `--client-secret-file` over
`--client-secret` on the command line -- the bare flag can leak into shell
history or process listings.

Precedence: defaults < env < `--config` file < explicit flags.

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
capped at 2 attempts total, no cycling back.

`--grant-type=authcode` or `=device-code` forces one grant and fails fast
if it isn't viable, with a diagnostic describing what the IdP offers and
why browser/terminal viability failed.

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
  `urn:ietf:params:oauth:token-type:access_token`, or to `...:id_token` when
  `--subject-token-source=github-actions` (that endpoint issues an ID token).
  Override it per RFC 8693 §3 (e.g. `...:id_token`, `...:jwt`) to match what
  `--subject-token` actually is.
- `--requested-token-type` is optional and omitted from the request
  entirely when unset.
- `--resource` may be repeated to send multiple RFC 8693 `resource` params
  in a single request.
- With `--all`, the response's `issued_token_type` (RFC 8693 §2.2.1) is
  included in the JSON document.

#### Subject token sources

By default `--subject-token` must be supplied manually. Setting
`--subject-token-source=github-actions` instead fetches it automatically
from GitHub Actions' native OIDC provider — the same
`ACTIONS_ID_TOKEN_REQUEST_URL`/`ACTIONS_ID_TOKEN_REQUEST_TOKEN` mechanism
GitHub injects into any job with `permissions: id-token: write`. This is
mutually exclusive with `--subject-token`/`--subject-token-file`/
`$OIDC_TOKEN_SUBJECT_TOKEN` and only valid with
`--grant-type=token-exchange`.

```sh
oidc-token \
  --issuer https://id.example.com/ \
  --client-id my-token-exchange-client \
  --grant-type token-exchange \
  --subject-token-source github-actions \
  --audience gtb-abinnovision
```

Because this source fetches an ID token, `--subject-token-type` defaults to
`urn:ietf:params:oauth:token-type:id_token` here (rather than the usual
`...:access_token`), so it doesn't need to be set explicitly.

`--audience` doubles as the GitHub Actions `audience` query parameter for
the fetched ID token.

This flag only supplies the *subject token*; the receiving IdP/broker must
still implement RFC 8693 §2.1 token exchange for the full flow to work.

### Token store

Tokens are cached per `(issuer, client_id)` profile, addressed by a
SHA-256 hash of the pair so those values don't leak into keys/filenames.
`--token-store` selects where:

| `--token-store` | Behavior |
|---|---|
| `auto` (default) | Try the OS keychain (macOS Keychain, Linux Secret Service over D-Bus) first; fall back to the plaintext file store only when the keychain backend is unavailable (no daemon reachable) — not on a plain cache miss. Logs a one-line notice to stderr the first time it falls back. |
| `keychain` | OS keychain only, no fallback. Fails fast at startup if no keychain backend is reachable. |
| `file` | Plaintext JSON file only — this CLI's original behavior, no cgo, works anywhere. |
| `none` | Disables persistence entirely: nothing is read from or written to disk or the keychain, and every run performs a fresh login/exchange. `--token-store-dir` is ignored. |

The file store lives at `--token-store-dir` (default `$XDG_CACHE_HOME/oidc-token`
or `~/.cache/oidc-token`); files are `0600`, written atomically, and
refreshes run under an advisory `flock` so concurrent invocations converge
on one winner instead of each re-authenticating. `auto` mode reuses that
lock even when the payload lives in the keychain; `keychain`-only mode has
no cross-process lock.

There's no migration between backends: switching an existing profile from
`file` to `auto`/`keychain` on a machine with a working keychain triggers
one fresh login, since a keychain miss isn't treated as "check the file
next." Use `--logout` to explicitly clear a cached entry (keychain items
can't be removed with `rm` the way file entries can).

No cgo dependency either way.

### Bootstrap model

First run (cache empty) opens a browser or prints a device code and
blocks until login completes. Every run after that is served from cache
or silently refreshed.

If the cache is cold *and* no grant is viable (headless CI with
`--non-interactive`), it fails fast — it will never print a device-code
prompt nobody can see. Warm the cache once, interactively, before wiring
`oidc-token` into a non-interactive job.

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

### kubectl `ExecCredential` (`--format exec-credential`)

```yaml
# ~/.kube/config (users[].user.exec)
exec:
  apiVersion: client.authentication.k8s.io/v1
  command: oidc-token
  args:
    - --issuer=https://id.example.com/
    - --client-id=my-k8s-client
    - --token-type=id_token
    - --format=exec-credential
```

`--format=exec-credential` emits a genuine Kubernetes `ExecCredential`
envelope: `apiVersion`, `kind: ExecCredential`, and a `status.token` field
(plus `status.expirationTimestamp` when the token has a known expiry) —
exactly what `kubectl`'s exec plugin protocol expects, no wrapping needed.
The `apiVersion` echoes the one `kubectl` passes via `$KUBERNETES_EXEC_INFO`,
falling back to `client.authentication.k8s.io/v1` when that env var is
absent or unparsable.

### CI (`--non-interactive`)

```sh
# One-time, interactive, with a TTY:
oidc-token --issuer https://id.example.com/ --client-id ci-client

# In the actual CI job, against the warmed cache:
export OIDC_TOKEN_ISSUER=https://id.example.com/
export OIDC_TOKEN_CLIENT_ID=ci-client
oidc-token --non-interactive
```

Reuse the same `--token-store-dir` between the bootstrap step and later
non-interactive runs — an ephemeral runner has no warm cache and will
fail fast by design.

## Build & release

```sh
go build ./...
go vet ./...
go test ./...
golangci-lint run
```

Every push to `main` runs CI. [release-please](https://github.com/googleapis/release-please)
opens a release PR tracking conventional commits; merging it creates a
draft GitHub Release with the next semver tag. GoReleaser then adopts
that draft (`mode: append`, `use_existing_draft: true`), builds
darwin/linux x amd64/arm64 archives, attaches them plus checksums, and
publishes the release. The Homebrew cask is pushed to
[`abinnovision/homebrew-tap`](https://github.com/abinnovision/homebrew-tap)
using a short-lived token minted per-release via `oidc-token-cli` itself
against gh-token-broker's token-exchange endpoint (not a stored PAT).

`.goreleaser.yaml` uses the `homebrew_casks` key with a post-install hook
that strips the macOS quarantine xattr (`com.apple.quarantine`) from the
unsigned binary.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
