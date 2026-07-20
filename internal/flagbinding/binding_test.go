package flagbinding

import (
	"flag"
	"testing"
)

func TestUsageWithEnv(t *testing.T) {
	tests := []struct {
		usage, key, want string
	}{
		{"OIDC issuer URL", "OIDC_TOKEN_ISSUER", "OIDC issuer URL [$OIDC_TOKEN_ISSUER]"},
		{"description", "", "description"},
	}
	for _, tt := range tests {
		if got := usageWithEnv(tt.usage, tt.key); got != tt.want {
			t.Errorf("usageWithEnv(%q, %q) = %q, want %q", tt.usage, tt.key, got, tt.want)
		}
	}
}

func TestStringField_Register_EnvSuffix(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := &StringField{FlagName: "foo", EnvKey: "FOO_BAR", Usage: "a flag"}
	f.Register(fs)

	got := fs.Lookup("foo")
	if got == nil {
		t.Fatal("flag not registered")
	}
	want := "a flag [$FOO_BAR]"
	if got.Usage != want {
		t.Errorf("Usage = %q, want %q", got.Usage, want)
	}
}

func TestStringField_Register_NoEnv(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := &StringField{FlagName: "bar", Usage: "a flag"}
	f.Register(fs)

	got := fs.Lookup("bar")
	if got == nil {
		t.Fatal("flag not registered")
	}
	if got.Usage != "a flag" {
		t.Errorf("Usage = %q, want %q", got.Usage, "a flag")
	}
}
