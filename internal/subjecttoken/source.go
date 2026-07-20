package subjecttoken

import "context"

// Source resolves an RFC 8693 subject_token from an ambient CI environment.
type Source interface {
	Name() string
	DefaultTokenType() string
	Fetch(ctx context.Context, audience string) (string, error)
}

func FindSource(sources []Source, name string) Source {
	for _, s := range sources {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

func SourceNames(sources []Source) []string {
	names := make([]string, len(sources))
	for i, s := range sources {
		names[i] = s.Name()
	}
	return names
}
