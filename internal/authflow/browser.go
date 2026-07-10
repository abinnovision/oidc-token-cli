package authflow

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

// OpenBrowser launches the platform's default browser at rawURL. It is a
// best-effort convenience: AuthCodeLogin always prints the URL as text too,
// so a failure here never blocks login.
//
// rawURL is validated as an http/https URL before it ever reaches exec, so a
// compromised discovery response can't smuggle arbitrary content into the
// OS's URL-open command.
func OpenBrowser(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("authflow: refusing to open browser: invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("authflow: refusing to open browser: URL scheme %q is not http/https", u.Scheme)
	}

	// OpenBrowser is a fire-and-forget, best-effort launch (Start, not Wait)
	// with no caller-supplied context to thread through.
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL) //nolint:noctx
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL) //nolint:noctx
	default:
		cmd = exec.Command("xdg-open", rawURL) //nolint:noctx
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("authflow: open browser: %w", err)
	}
	return nil
}
