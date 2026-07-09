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
- Public client + PKCE only — no client secret handling.

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
  [--grant-type auto|authcode|device-code] \
  [--token-type access_token|id_token] \
  [--cache-dir DIR] \
  [--redirect PORT] \
  [--non-interactive] \
  [--all] \
  [--config FILE]
```

| Flag | Default | Description |
|---|---|---|
| `--issuer` | *(required)* | OIDC issuer URL (HTTPS, except loopback in tests). Discovery's `issuer` field must match exactly. |
| `--client-id` | *(required)* | OAuth2/OIDC public client ID. |
| `--scope` | `openid offline_access` | Space-separated scopes. |
| `--audience` | *(empty)* | Expected `aud` claim — required if the relying party checks audience (e.g. frp's `auth.oidc.audience`). |
| `--grant-type` | `auto` | `auto`, `authcode`, or `device-code`. See [Grant selection](#grant-selection). |
| `--token-type` | `access_token` | Which field bare mode prints. |
| `--cache-dir` | `$XDG_CACHE_HOME/oidc-token` | Override the token cache directory. |
| `--redirect` | `0` (ephemeral) | Fixed loopback port for the authcode callback, if your IdP requires an exact redirect URI. |
| `--non-interactive` | `false` | Never emit a device-code prompt; authcode+browser is still allowed if a display is available. |
| `--all` | `false` | Print a JSON document instead of a bare token. |
| `--config` | *(none)* | Optional JSON config file. |

Every flag except `--config` also has an env var: `OIDC_TOKEN_ISSUER`,
`OIDC_TOKEN_CLIENT_ID`, `OIDC_TOKEN_SCOPE`, `OIDC_TOKEN_AUDIENCE`,
`OIDC_TOKEN_GRANT_TYPE`, `OIDC_TOKEN_TOKEN_TYPE`, `OIDC_TOKEN_CACHE_DIR`,
`OIDC_TOKEN_NON_INTERACTIVE`. Precedence: defaults < env < `--config` file
< explicit flags.

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

### Cache

Tokens are cached at `--cache-dir` (default `$XDG_CACHE_HOME/oidc-token`
or `~/.cache/oidc-token`), keyed by a SHA-256 hash of `(issuer,
client_id)` so those values don't leak into filenames. Files are `0600`,
written atomically. Refreshes run under an advisory `flock` so concurrent
invocations converge on one winner instead of each re-authenticating.

Plain JSON file, not an OS keychain — matches `kubelogin`'s model and
avoids a cgo dependency. Revisit if this ever runs on a shared/multi-user
host.

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
