package authflow

import (
	"os"
	"runtime"

	"golang.org/x/term"
)

// Environment captures the runtime signals grant selection uses to decide
// which interactive grants are viable. The two capabilities are
// independent: a browser can be available with nobody at the terminal
// (e.g. a desktop session driving frpc's `exec` credential provider, which
// has a display but no TTY), and a terminal can be attended with no
// browser at all (a bare SSH session).
type Environment struct {
	// TTY reports whether stdin is an interactive terminal.
	TTY bool
	// Display reports whether a GUI/browser is likely available.
	Display bool
}

// BrowserAvailable reports whether a browser can plausibly be launched —
// the precondition for the authcode+PKCE grant, which never reads stdin
// and only needs somewhere to pop a window and a loopback port to catch
// the callback.
func (e Environment) BrowserAvailable() bool {
	return e.Display
}

// TerminalAttended reports whether a human is plausibly at the terminal —
// the precondition for the device-code grant, whose user_code prompt is
// meaningless if nobody is there to read it off stderr.
func (e Environment) TerminalAttended() bool {
	return e.TTY
}

// DetectEnvironment inspects the real process environment: stdin's
// terminal-ness and (on non-macOS/Windows platforms) $DISPLAY/
// $WAYLAND_DISPLAY, since a GUI is otherwise assumed present on
// darwin/windows.
func DetectEnvironment() Environment {
	return Environment{
		TTY:     term.IsTerminal(int(os.Stdin.Fd())),
		Display: hasDisplay(runtime.GOOS, os.Getenv),
	}
}

// hasDisplay reports whether a GUI/browser is likely available: on
// darwin/windows a GUI is assumed present; elsewhere (linux/bsd) an X11 or
// Wayland display must be advertised via the environment.
func hasDisplay(goos string, getenv func(string) string) bool {
	switch goos {
	case "darwin", "windows":
		return true
	default:
		return getenv("DISPLAY") != "" || getenv("WAYLAND_DISPLAY") != ""
	}
}
