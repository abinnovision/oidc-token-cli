//go:build e2e

package e2e

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"testing"
	"time"
)

// maxLoginFormSteps bounds the form-walking loop: the authcode/refresh
// flows need one step (the login form), the device flow needs two (the
// user_code confirmation form, then the login form). A generous ceiling
// guards against an unexpected extra step turning into an infinite loop.
const maxLoginFormSteps = 5

// formRe extracts a <form method="post" ...> tag's action attribute and
// its raw inner HTML (to enumerate <input> fields) from dex's server-
// rendered pages (web/templates/*.html). This couples to those templates
// staying stable across dexImage's pinned tag; re-check on any version
// bump. HTML attribute order in a tag with a duplicated attribute (dex's
// device.html has a stray extra `method="get"`) resolves to the first
// occurrence per the HTML parsing spec, so matching "method=\"post\""
// first is correct.
var (
	formRe  = regexp.MustCompile(`(?is)<form[^>]*method="post"[^>]*action="([^"]+)"[^>]*>(.*?)</form>`)
	inputRe = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	attrRe  = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

// dexLoginWalker returns an authflow.Source.OpenBrowser-shaped func
// (func(string) error) that drives dex's real server-rendered forms with a
// plain net/http.Client (cookie jar, default redirect-following) instead
// of a headless browser: it walks up to maxLoginFormSteps <form> pages,
// re-submitting every field dex pre-filled (e.g. the device flow's
// user_code) and overriding "login"/"password" with the given credentials
// whenever those fields are present, until a page with no <form> is
// reached (dex's success page, or — for the authcode/refresh flows — the
// CLI's own loopback callback response).
func dexLoginWalker(t *testing.T, username, password string) func(startURL string) error {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	return func(startURL string) error {
		resp, err := client.Get(startURL)
		if err != nil {
			return fmt.Errorf("dex login: GET %s: %w", startURL, err)
		}

		for step := 0; ; step++ {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return fmt.Errorf("dex login: read page at %s: %w", resp.Request.URL, err)
			}

			m := formRe.FindSubmatch(body)
			if m == nil {
				// No more forms: either dex's terminal success page, or the
				// CLI's own loopback callback response.
				return nil
			}
			if step >= maxLoginFormSteps {
				return fmt.Errorf("dex login: exceeded %d form-submission steps starting at %s", maxLoginFormSteps, startURL)
			}

			action, err := resp.Request.URL.Parse(html.UnescapeString(string(m[1])))
			if err != nil {
				return fmt.Errorf("dex login: parse form action %q: %w", m[1], err)
			}

			values := url.Values{}
			for _, input := range inputRe.FindAllSubmatch(m[2], -1) {
				attrs := map[string]string{}
				for _, a := range attrRe.FindAllSubmatch(input[1], -1) {
					attrs[string(a[1])] = html.UnescapeString(string(a[2]))
				}
				name := attrs["name"]
				if name == "" {
					continue
				}
				values.Set(name, attrs["value"])
			}
			if _, ok := values["login"]; ok {
				values.Set("login", username)
			}
			if _, ok := values["password"]; ok {
				values.Set("password", password)
			}

			resp, err = client.PostForm(action.String(), values)
			if err != nil {
				return fmt.Errorf("dex login: POST form at %s: %w", action, err)
			}
		}
	}
}
