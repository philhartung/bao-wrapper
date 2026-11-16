package parser

import (
	"strings"
	"testing"
)

// FuzzParseEnv feeds arbitrary values through secret discovery. Declarations
// come from the environment, so parsing must never panic, must fail without
// echoing the value (it may be a credential rather than a reference), and
// must only ever produce a supported engine and delivery type.
func FuzzParseEnv(f *testing.F) {
	for _, seed := range []string{
		"kv://password:env@kv/myapp/db", "kv://kv/myapp/db", "legacy://token:file@kvv1/my/path",
		"template://tpl:file@kv/config", "kv://:file@kv/app", "kv://f:bogus@kv/app", "kv://kv/app?x=1",
		"kv://db%2Fpass@kv/my%20app", "kv://%zz@kv/app", "kv://[::1]/x", "kv://a b/c", "vault://kv/app",
		"plain-ambient-credential", "kv://", "kv:///", "kv://@", "kv://:@/", "legacy://user:file@host:1/p",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if strings.ContainsRune(value, 0) {
			t.Skip("environment values cannot contain NUL")
		}
		const key = "SECRET_FUZZ"
		refs, err := parseEnv([]string{"UNRELATED=kv://kv/other", key + "=" + value}, "SECRET_")
		if err != nil {
			if refs != nil {
				t.Fatalf("references returned together with an error: %+v", refs)
			}
			if strings.Contains(err.Error(), value) {
				t.Fatalf("error exposes the value %q: %v", value, err)
			}
			if !strings.HasPrefix(err.Error(), "parser: "+key+": ") {
				t.Fatalf("error does not name the variable: %v", err)
			}
			return
		}
		scheme, _, hasScheme := strings.Cut(value, "://")
		if !hasScheme || !ValidEngine(scheme) {
			if len(refs) != 0 {
				t.Fatalf("%q has no supported scheme but produced %+v", value, refs)
			}
			return
		}
		if len(refs) != 1 {
			t.Fatalf("%q produced %d references", value, len(refs))
		}
		ref := refs[0]
		if ref.EnvName != "FUZZ" || ref.Engine != scheme {
			t.Fatalf("%q: name %q engine %q", value, ref.EnvName, ref.Engine)
		}
		if ref.Type != TypeEnv && ref.Type != TypeFile {
			t.Fatalf("%q: unsupported type %q", value, ref.Type)
		}
		// Parsing is deterministic and independent of other variables.
		again, err := parseEnv([]string{key + "=" + value}, "SECRET_")
		if err != nil || len(again) != 1 || again[0] != ref {
			t.Fatalf("%q: second parse differs: %+v, %v", value, again, err)
		}
	})
}
