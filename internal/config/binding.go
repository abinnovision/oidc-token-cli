package config

import "flag"

// field describes how a single Config value is populated from the four-layer
// precedence stack: default < env < file < explicit flag.
type field interface {
	register(fs *flag.FlagSet)
	applyEnv(env func(string) string)
	applyFile(fc map[string]any)
	applyFlag(explicit map[string]bool)
}

// stringField binds a string-typed Config field to a CLI flag, an optional
// environment variable, and an optional JSON config-file key.
type stringField struct {
	target   *string
	flagName string
	envKey   string
	jsonKey  string
	usage    string
	def      string
	flagVal  *string
}

func (f *stringField) register(fs *flag.FlagSet) {
	f.flagVal = fs.String(f.flagName, f.def, f.usage)
}

func (f *stringField) applyEnv(env func(string) string) {
	if f.envKey == "" {
		return
	}
	if v := env(f.envKey); v != "" {
		*f.target = v
	}
}

func (f *stringField) applyFile(fc map[string]any) {
	if f.jsonKey == "" || fc == nil {
		return
	}
	if v, ok := fc[f.jsonKey].(string); ok {
		*f.target = v
	}
}

func (f *stringField) applyFlag(explicit map[string]bool) {
	if explicit[f.flagName] {
		*f.target = *f.flagVal
	}
}

// boolField binds a bool-typed Config field to a CLI flag, an optional
// environment variable, and an optional JSON config-file key. Environment
// values are parsed as "1" or "true" (case-sensitive), matching the
// existing behavior.
type boolField struct {
	target   *bool
	flagName string
	envKey   string
	jsonKey  string
	usage    string
	def      bool
	flagVal  *bool
}

func (f *boolField) register(fs *flag.FlagSet) {
	f.flagVal = fs.Bool(f.flagName, f.def, f.usage)
}

func (f *boolField) applyEnv(env func(string) string) {
	if f.envKey == "" {
		return
	}
	if v := env(f.envKey); v != "" {
		*f.target = v == "1" || v == "true"
	}
}

func (f *boolField) applyFile(fc map[string]any) {
	if f.jsonKey == "" || fc == nil {
		return
	}
	if v, ok := fc[f.jsonKey].(bool); ok {
		*f.target = v
	}
}

func (f *boolField) applyFlag(explicit map[string]bool) {
	if explicit[f.flagName] {
		*f.target = *f.flagVal
	}
}
