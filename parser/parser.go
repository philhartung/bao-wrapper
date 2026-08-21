// Package parser parses SECRET_* environment variables into SecretRef descriptors.
//
// Variable format: SECRET_<NAME>=<engine>://[[field][:type]@]path[?key=value&...]
//
// Defaults:
//   - type    → "env"
//   - field   → "" (return entire JSON data map)
package parser

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// SecretType describes how the secret value should be delivered to the child
// process.
type SecretType string

const (
	// TypeEnv injects the secret as an environment variable.
	TypeEnv SecretType = "env"
	// TypeFile writes the secret to a temporary file and injects the path.
	TypeFile SecretType = "file"
)

// SecretRef represents one parsed SECRET_* variable.
type SecretRef struct {
	// EnvName is the bare variable name without the "SECRET_" prefix.
	EnvName string
	// Engine is the explicitly selected secret engine.
	Engine string
	// Path is the secret path within the engine.
	Path string
	// Field is the key within the secret data (empty = return full JSON).
	Field string
	// Type controls env vs file injection.
	Type SecretType
	// Args holds optional query parameters (e.g. outfile) parsed from the URL.
	Args map[string]string
}

// ParseEnv iterates os.Environ() and returns all SecretRef entries.
// prefix is the environment variable prefix used to identify secret variables
// (e.g. "SECRET_"). Variables whose key starts with prefix are parsed as
// secret references when their values use an explicit supported engine
// scheme; the prefix is stripped to derive the bare name. Other prefixed
// variables are ignored so ambient passwords, tokens, and keys are never
// mistaken for Vault paths.
func ParseEnv(prefix string) ([]SecretRef, error) {
	return parseEnv(os.Environ(), prefix)
}

// parseEnv is the internal, testable implementation.
// Variables without an explicit supported engine scheme (e.g. ambient
// SECRET_* credentials or SECRET_SCANNING_URL values set by CI platforms) are
// silently skipped.
func parseEnv(environ []string, prefix string) ([]SecretRef, error) {
	var refs []SecretRef
	for _, e := range environ {
		idx := strings.IndexByte(e, '=')
		if idx < 0 {
			continue
		}
		key := e[:idx]
		value := e[idx+1:]

		if !strings.HasPrefix(key, prefix) {
			continue
		}
		name := strings.TrimPrefix(key, prefix)

		// Automatic discovery is deliberately opt-in at the value level. A bare
		// SECRET_* value is much more likely to be an ambient credential than a
		// Vault path, so only explicit supported schemes are references.
		scheme, _, hasScheme := strings.Cut(value, "://")
		if !hasScheme || !ValidEngine(scheme) {
			continue
		}

		ref, err := parseValue(name, value)
		if err != nil {
			return nil, fmt.Errorf("parser: %s: %w", key, err)
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// parseURL adds a "kv://" scheme when value has none, then calls url.Parse.
// It returns the parsed URL and whether an explicit scheme was present.
// A scheme is required so that url.Parse treats the first slash-delimited
// segment as the host rather than part of a relative path; host and path are
// later joined to recover the original Vault path.
func parseURL(value string) (*url.URL, bool, error) {
	hasScheme := strings.Contains(value, "://")
	raw := value
	if !hasScheme {
		raw = "kv://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Parse errors can include raw input, which may itself be a secret.
		return nil, false, fmt.Errorf("invalid secret reference")
	}
	return u, hasScheme, nil
}

// ValidEngine reports whether the given engine name is a supported engine.
// Only "kv", "legacy", and "template" are valid.
func ValidEngine(engine string) bool {
	switch engine {
	case "kv", "legacy", "template":
		return true
	default:
		return false
	}
}

// parseValue parses the value of a SECRET_* variable.
//
// The pseudo-URL format is:  [[engine]://][[field][:type]@]path[?key=value&...]
//
// The value is parsed with net/url.Parse. When no scheme is present a "kv://"
// prefix is added so that the standard parser can locate the host and path
// components. The resulting URL fields map as follows:
//   - scheme    → engine  (only when "://" was present in the original value)
//   - userinfo  → field[:type]  (username = field, password = type)
//   - host+path → Vault path  (e.g. "myapp" + "/db" → "myapp/db")
//   - query     → Args map
func parseValue(name, value string) (SecretRef, error) {
	ref := SecretRef{
		EnvName: name,
		Engine:  "kv",
		Type:    TypeEnv,
	}

	u, hasScheme, err := parseURL(value)
	if err != nil {
		return ref, err
	}

	// Engine from explicit scheme only; keep the default when no "://" was given.
	if hasScheme {
		ref.Engine = u.Scheme
	}

	// Validate engine (only kv, legacy, template are allowed).
	if !ValidEngine(ref.Engine) {
		return ref, fmt.Errorf("unknown engine (allowed: kv, legacy, template)")
	}

	// Field and type from userinfo (field[:type]@).
	if u.User != nil {
		ref.Field = u.User.Username()
		if typePart, ok := u.User.Password(); ok {
			switch SecretType(typePart) {
			case TypeEnv, TypeFile:
				ref.Type = SecretType(typePart)
			case "":
				// keep default
			default:
				return ref, fmt.Errorf("unknown secret type (allowed: env, file)")
			}
		}
	}

	// Reconstruct the Vault path from the host and path components.
	// url.Parse puts the first segment into Host, so joining them gives the
	// original path (e.g. Hostname()="myapp", Path="/db" → "myapp/db").
	ref.Path = u.Hostname() + u.Path

	// Query parameters.
	if q := u.Query(); len(q) > 0 {
		ref.Args = make(map[string]string, len(q))
		for k, vals := range q {
			ref.Args[k] = vals[0]
		}
	}

	return ref, nil
}

// KVVersionForEngine returns the KV API version to use when reading a secret
// for the given engine name.
//
// The "kv" and "template" engines use OpenBao/Vault KV v2
// (GET /v1/<mount>/data/<secret_path>). The "legacy" engine uses the generic
// read path (GET /v1/<path>) which corresponds to KV v1.
func KVVersionForEngine(engine string) int {
	switch engine {
	case "legacy":
		return 1
	default: // "kv", "template"
		return 2
	}
}

// ParseTemplateSecretURL parses the reduced URL syntax used inside templates
// (e.g. "kv://password@database/prod"). Only the engines "kv" and "legacy"
// are allowed. Type selectors (":env", ":file") and query parameters
// ("?key=val") are forbidden.
func ParseTemplateSecretURL(raw string) (SecretRef, error) {
	// Detect explicit type selectors before calling parseValue, because
	// parseValue silently keeps the TypeEnv default for ":env".
	// url.User.Password() returns ok=true whenever a colon was present in the
	// userinfo portion, so it cleanly catches both ":env" and ":file".
	u, _, err := parseURL(raw)
	if err != nil {
		return SecretRef{}, err
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			return SecretRef{}, fmt.Errorf("type selectors are not allowed in templates")
		}
	}

	ref, err := parseValue("", raw)
	if err != nil {
		return ref, err
	}

	// Reject query arguments.
	if len(ref.Args) > 0 {
		return ref, fmt.Errorf("query arguments are not allowed in templates")
	}

	// Only allow kv and legacy engines.
	switch ref.Engine {
	case "kv", "legacy":
		// ok
	default:
		return ref, fmt.Errorf("engine is not allowed in templates")
	}

	return ref, nil
}
