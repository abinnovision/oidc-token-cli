//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// dexImage is pinned exactly; bump deliberately and re-check
// e2e/testdata/dex-config.yaml.tmpl and dex_login.go's form-scraping regex
// against the new tag's config schema and web/templates/password.html.
const dexImage = "dexidp/dex:v2.42.0"

// dexClientID is the public (no client_secret) client registered in every
// rendered dex config.
const dexClientID = "oidc-token-cli-e2e"

// dexConfidentialClientID is the confidential (client_secret_basic/post)
// client registered alongside dexClientID in every rendered dex config.
const dexConfidentialClientID = "oidc-token-cli-e2e-confidential"

// dexConfidentialClientSecret is the fixture secret dex is configured to
// expect from dexConfidentialClientID; not a real secret, since dex only
// ever runs inside an ephemeral test container.
const dexConfidentialClientSecret = "dex-e2e-test-client-secret"

const dexUsername = "e2e@example.com"

// dexPassword is the fixture password whose bcrypt hash is baked into
// dex-config.yaml.tmpl; not a real secret, since dex only ever runs inside
// an ephemeral test container.
const dexPassword = "dex-e2e-test-password"

// dexPasswordHash is bcrypt("dex-e2e-test-password", cost=10), precomputed
// offline so the harness doesn't need golang.org/x/crypto/bcrypt as a
// runtime dependency just to hash a static fixture.
const dexPasswordHash = "$2a$10$Ct.NVXKFV0w9gqKgD3ULwulcsXO32W9kg4ceKWX4Z6IYgEfAzHMx."

// maxStartDexAttempts bounds retries against the small, unavoidable TOCTOU
// race between mustFreePort's probe and dex's/Docker's own bind of the same
// port.
const maxStartDexAttempts = 3

// DexInstance describes a running dex container and the fixture clients it
// was configured with.
type DexInstance struct {
	IssuerURL    string
	ClientID     string
	Username     string
	Password     string
	RedirectURI  string
	RedirectPort int

	// ConfidentialClientID/ConfidentialClientSecret identify the second,
	// non-public static client registered alongside ClientID, for
	// client_secret_basic/client_secret_post e2e coverage.
	ConfidentialClientID     string
	ConfidentialClientSecret string

	container testcontainers.Container
}

var dexConfigTmpl = template.Must(template.ParseFiles(filepath.Join("testdata", "dex-config.yaml.tmpl")))

type dexConfigData struct {
	DexPort                  int
	ClientID                 string
	ConfidentialClientID     string
	ConfidentialClientSecret string
	RedirectURI              string
	Username                 string
	PasswordHash             string
}

// StartDex renders a dex config with ports pre-allocated on the host for
// both dex itself and the CLI's authcode loopback callback, starts a
// dexidp/dex container bound to those exact host ports, waits for
// discovery to become reachable, and registers t.Cleanup to terminate it.
func StartDex(t *testing.T) *DexInstance {
	t.Helper()
	if testing.Short() {
		t.Skip("e2e: skipping dex container in -short mode")
	}

	var lastErr error
	for attempt := 0; attempt < maxStartDexAttempts; attempt++ {
		inst, err := startDexOnce(t)
		if err == nil {
			return inst
		}
		lastErr = err
		t.Logf("StartDex attempt %d/%d failed, retrying with fresh ports: %v", attempt+1, maxStartDexAttempts, err)
	}
	t.Fatalf("StartDex: giving up after %d attempts: %v", maxStartDexAttempts, lastErr)
	return nil
}

func startDexOnce(t *testing.T) (*DexInstance, error) {
	t.Helper()
	ctx := context.Background()

	dexPort := mustFreePort(t)
	cbPort := mustFreePort(t)
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", cbPort)

	configPath := renderDexConfig(t, dexConfigData{
		DexPort:                  dexPort,
		ClientID:                 dexClientID,
		ConfidentialClientID:     dexConfidentialClientID,
		ConfidentialClientSecret: dexConfidentialClientSecret,
		RedirectURI:              redirectURI,
		Username:                 dexUsername,
		PasswordHash:             dexPasswordHash,
	})

	dexContainerPort := network.MustParsePort("5556/tcp")
	hostIP := netip.MustParseAddr("127.0.0.1")

	req := testcontainers.ContainerRequest{
		Image:        dexImage,
		ExposedPorts: []string{"5556/tcp"},
		Cmd:          []string{"dex", "serve", "/etc/dex/config.yaml"},
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      configPath,
			ContainerFilePath: "/etc/dex/config.yaml",
			FileMode:          0o644,
		}},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.PortBindings = network.PortMap{
				dexContainerPort: []network.PortBinding{{HostIP: hostIP, HostPort: fmt.Sprintf("%d", dexPort)}},
			}
		},
		WaitingFor: wait.ForHTTP("/.well-known/openid-configuration").
			WithPort("5556/tcp").
			WithStatusCodeMatcher(func(status int) bool { return status == 200 }).
			WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("start dex container: %w", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("terminate dex container: %v", err)
		}
	})

	return &DexInstance{
		IssuerURL:                fmt.Sprintf("http://127.0.0.1:%d", dexPort),
		ClientID:                 dexClientID,
		Username:                 dexUsername,
		Password:                 dexPassword,
		RedirectURI:              redirectURI,
		RedirectPort:             cbPort,
		ConfidentialClientID:     dexConfidentialClientID,
		ConfidentialClientSecret: dexConfidentialClientSecret,
		container:                container,
	}, nil
}

func renderDexConfig(t *testing.T, data dexConfigData) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "dex-config.yaml")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create rendered dex config: %v", err)
	}
	defer f.Close()
	if err := dexConfigTmpl.Execute(f, data); err != nil {
		t.Fatalf("render dex config template: %v", err)
	}
	return path
}
