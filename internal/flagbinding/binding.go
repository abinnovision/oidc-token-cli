package flagbinding

import (
	"flag"
	"strconv"
	"strings"
)

// usageWithEnv appends " [$key]" to usage when key is non-empty.
func usageWithEnv(usage, key string) string {
	if key == "" {
		return usage
	}
	return usage + " [$" + key + "]"
}

// Field describes how a single config value is populated from the four-layer
// precedence stack: default < env < file < explicit flag.
type Field interface {
	Register(fs *flag.FlagSet)
	ApplyEnv(env func(string) string)
	ApplyFile(fc map[string]any)
	ApplyFlag(explicit map[string]bool)
}

// StringField binds a string-typed field to a CLI flag, an optional
// environment variable, and an optional JSON config-file key.
type StringField struct {
	Target   *string
	FlagName string
	EnvKey   string
	JsonKey  string
	Usage    string
	Def      string
	flagVal  *string
}

func (f *StringField) Register(fs *flag.FlagSet) {
	f.flagVal = fs.String(f.FlagName, f.Def, usageWithEnv(f.Usage, f.EnvKey))
}

func (f *StringField) ApplyEnv(env func(string) string) {
	if f.EnvKey == "" {
		return
	}
	if v := env(f.EnvKey); v != "" {
		*f.Target = v
	}
}

func (f *StringField) ApplyFile(fc map[string]any) {
	if f.JsonKey == "" || fc == nil {
		return
	}
	if v, ok := fc[f.JsonKey].(string); ok {
		*f.Target = v
	}
}

func (f *StringField) ApplyFlag(explicit map[string]bool) {
	if explicit[f.FlagName] {
		*f.Target = *f.flagVal
	}
}

// BoolField binds a bool-typed field to a CLI flag, an optional
// environment variable, and an optional JSON config-file key.
type BoolField struct {
	Target   *bool
	FlagName string
	EnvKey   string
	JsonKey  string
	Usage    string
	Def      bool
	flagVal  *bool
}

func (f *BoolField) Register(fs *flag.FlagSet) {
	f.flagVal = fs.Bool(f.FlagName, f.Def, usageWithEnv(f.Usage, f.EnvKey))
}

func (f *BoolField) ApplyEnv(env func(string) string) {
	if f.EnvKey == "" {
		return
	}
	if v := env(f.EnvKey); v != "" {
		*f.Target = v == "1" || v == "true"
	}
}

func (f *BoolField) ApplyFile(fc map[string]any) {
	if f.JsonKey == "" || fc == nil {
		return
	}
	if v, ok := fc[f.JsonKey].(bool); ok {
		*f.Target = v
	}
}

func (f *BoolField) ApplyFlag(explicit map[string]bool) {
	if explicit[f.FlagName] {
		*f.Target = *f.flagVal
	}
}

// IntField binds an int-typed field to a CLI flag, an optional environment
// variable, and an optional JSON config-file key.
type IntField struct {
	Target   *int
	FlagName string
	EnvKey   string
	JsonKey  string
	Usage    string
	Def      int
	flagVal  *int
}

func (f *IntField) Register(fs *flag.FlagSet) {
	f.flagVal = fs.Int(f.FlagName, f.Def, usageWithEnv(f.Usage, f.EnvKey))
}

func (f *IntField) ApplyEnv(env func(string) string) {
	if f.EnvKey == "" {
		return
	}
	if v := env(f.EnvKey); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*f.Target = n
		}
	}
}

func (f *IntField) ApplyFile(fc map[string]any) {
	if f.JsonKey == "" || fc == nil {
		return
	}
	if v, ok := fc[f.JsonKey].(float64); ok {
		*f.Target = int(v)
	}
}

func (f *IntField) ApplyFlag(explicit map[string]bool) {
	if explicit[f.FlagName] {
		*f.Target = *f.flagVal
	}
}

// StringSliceField binds a string-slice field to a repeatable CLI flag and
// an optional JSON config-file key.
type StringSliceField struct {
	Target   *[]string
	FlagName string
	EnvKey   string
	JsonKey  string
	Usage    string
	flagVal  sliceValue
}

func (f *StringSliceField) Register(fs *flag.FlagSet) {
	fs.Var(&f.flagVal, f.FlagName, usageWithEnv(f.Usage, f.EnvKey))
}

func (f *StringSliceField) ApplyEnv(env func(string) string) {
	if f.EnvKey == "" {
		return
	}
	if v := env(f.EnvKey); v != "" {
		*f.Target = strings.Split(v, ",")
	}
}

func (f *StringSliceField) ApplyFile(fc map[string]any) {
	if f.JsonKey == "" || fc == nil {
		return
	}
	if arr, ok := fc[f.JsonKey].([]any); ok {
		res := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		if len(res) > 0 {
			*f.Target = res
		}
	}
}

func (f *StringSliceField) ApplyFlag(explicit map[string]bool) {
	if explicit[f.FlagName] {
		*f.Target = []string(f.flagVal)
	}
}

// sliceValue implements flag.Value for a repeatable string flag,
// appending on every Set call.
type sliceValue []string

func (s *sliceValue) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *sliceValue) Set(v string) error {
	*s = append(*s, v)
	return nil
}
