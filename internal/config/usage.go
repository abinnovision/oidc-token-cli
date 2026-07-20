package config

import (
	"flag"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// flagGroup describes one section of the grouped --help output: a title and
// the ordered flag names it contains.
type flagGroup struct {
	Title string
	Flags []string
}

// groups defines the order and membership of --help sections. Any flag not
// listed here falls back to an "Other:" section, so newly added flags never
// silently disappear from --help.
var groups = []flagGroup{
	{Title: "Common", Flags: []string{"issuer", "client-id", "scope", "audience", "grant-type", "token-type", "config"}},
	{Title: "Output", Flags: []string{"format", "all", "logout", "non-interactive"}},
	{Title: "Token Storage", Flags: []string{"token-store", "token-store-dir"}},
	{Title: "Advanced - Client Authentication", Flags: []string{"client-auth-method", "client-secret", "client-secret-file", "private-key-file", "private-key-id", "private-key-alg", "client-assertion-audience"}},
	{Title: "Advanced - Token Exchange (--grant-type=token-exchange)", Flags: []string{"subject-token", "subject-token-file", "subject-token-type", "subject-token-source", "requested-token-type", "resource"}},
	{Title: "Advanced - Other", Flags: []string{"redirect", "extra"}},
}

// printGroupedUsage prints fs's registered flags organized into groups, in
// the order defined by groups. Flags not listed in any group are printed
// under a trailing "Other:" section, so the output never silently omits a
// flag just because it wasn't added to groups.
func printGroupedUsage(w io.Writer, fs *flag.FlagSet) {
	seen := map[string]bool{}

	for i, g := range groups {
		var present []*flag.Flag
		for _, name := range g.Flags {
			if f := fs.Lookup(name); f != nil {
				present = append(present, f)
				seen[name] = true
			}
		}
		if len(present) == 0 {
			continue
		}
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "  %s:\n", g.Title)
		for _, f := range present {
			printFlag(w, f)
		}
	}

	var other []*flag.Flag
	fs.VisitAll(func(f *flag.Flag) {
		if !seen[f.Name] {
			other = append(other, f)
		}
	})
	if len(other) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  Other:\n")
		for _, f := range other {
			printFlag(w, f)
		}
	}
}

// printFlag formats a single flag, matching the style of stdlib
// flag.PrintDefaults but indented one level deeper to sit under a group
// header: the flag name gets a 4-space indent, and its usage text (and any
// "(default ...)" suffix) gets a 6-space-plus-tab indent.
func printFlag(w io.Writer, f *flag.Flag) {
	var b strings.Builder
	fmt.Fprintf(&b, "    -%s", f.Name)
	name, usage := flag.UnquoteUsage(f)
	if len(name) > 0 {
		b.WriteString(" ")
		b.WriteString(name)
	}
	b.WriteString("\n      \t")
	b.WriteString(strings.ReplaceAll(usage, "\n", "\n      \t"))

	if !isZeroValue(f, f.DefValue) {
		if isStringFlag(f) {
			// put quotes on the value, matching stdlib's stringValue case.
			fmt.Fprintf(&b, " (default %q)", f.DefValue)
		} else {
			fmt.Fprintf(&b, " (default %v)", f.DefValue)
		}
	}
	fmt.Fprint(w, b.String(), "\n")
}

// isStringFlag reports whether f's underlying flag.Value wraps a string
// (as fs.String does), so its default should be quoted. flag.stringValue is
// unexported, so this is determined via reflection on the Value's
// underlying kind rather than a type assertion.
func isStringFlag(f *flag.Flag) bool {
	typ := reflect.TypeOf(f.Value)
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ.Kind() == reflect.String
}

// isZeroValue reports whether value is the zero value for f's flag.Value
// type, replicating the logic flag.PrintDefaults uses internally to decide
// whether to print a "(default ...)" suffix at all.
func isZeroValue(f *flag.Flag, value string) bool {
	typ := reflect.TypeOf(f.Value)
	var z reflect.Value
	if typ.Kind() == reflect.Pointer {
		z = reflect.New(typ.Elem())
	} else {
		z = reflect.New(typ).Elem()
	}
	zv, ok := z.Interface().(flag.Value)
	if !ok {
		return false
	}
	return value == zv.String()
}
