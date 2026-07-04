package fingerdsl

import (
	"strings"
	"testing"
)

func TestParseAndEvalSimple(t *testing.T) {
	cases := []struct {
		name string
		expr string
		ctx  Context
		want bool
	}{
		{
			name: "single contains hit",
			expr: `title="管理后台"`,
			ctx:  Context{"title": "某系统管理后台"},
			want: true,
		},
		{
			name: "single contains miss",
			expr: `title="管理后台"`,
			ctx:  Context{"title": "首页"},
			want: false,
		},
		{
			name: "case-insensitive contains",
			expr: `header="Server: Nginx"`,
			ctx:  Context{"header": "server: nginx"},
			want: true,
		},
		{
			name: "strict equal hit",
			expr: `title=="Login"`,
			ctx:  Context{"title": "login"}, // EqualFold should treat as same
			want: true,
		},
		{
			name: "strict equal miss",
			expr: `title=="Login"`,
			ctx:  Context{"title": "Login Portal"},
			want: false,
		},
		{
			name: "not equal hit",
			expr: `banner!="couchdb"`,
			ctx:  Context{"banner": "nginx"},
			want: true,
		},
		{
			name: "not equal miss",
			expr: `banner!="couchdb"`,
			ctx:  Context{"banner": "couchdb"},
			want: false,
		},
		{
			name: "regex hit",
			expr: `body~="(?i)error: \\d{3,5}"`,
			ctx:  Context{"body": "internal error: 12345 occurred"},
			want: true,
		},
		{
			name: "regex miss",
			expr: `body~="^\\d+$"`,
			ctx:  Context{"body": "abc"},
			want: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expr, err := Parse(c.expr)
			if err != nil {
				t.Fatalf("Parse(%q): %v", c.expr, err)
			}
			if got := expr.Eval(c.ctx); got != c.want {
				t.Errorf("Eval = %v, want %v (canon=%s)", got, c.want, expr.String())
			}
		})
	}
}

func TestLogicalCombinators(t *testing.T) {
	cases := []struct {
		expr string
		ctx  Context
		want bool
	}{
		{`title="管理" && body="login"`, Context{"title": "管理后台", "body": "user login"}, true},
		{`title="管理" && body="login"`, Context{"title": "管理后台", "body": "home"}, false},
		{`title="A" || title="B"`, Context{"title": "B"}, true},
		{`title="A" || title="B"`, Context{"title": "C"}, false},
		{`!title="forbidden"`, Context{"title": "ok"}, true},
		{`!title="forbidden"`, Context{"title": "forbidden access"}, false},
		{
			`(body="a" && body="b") || title="x"`,
			Context{"body": "contains a and b", "title": "y"},
			true,
		},
		{
			`(body="a" && body="b") || title="x"`,
			Context{"body": "only a", "title": "y"},
			false,
		},
		{
			`(body="a" && body="b") || title="x"`,
			Context{"body": "only a", "title": "x marks"},
			true,
		},
	}

	for _, c := range cases {
		t.Run(c.expr, func(t *testing.T) {
			expr, err := Parse(c.expr)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := expr.Eval(c.ctx); got != c.want {
				t.Errorf("Eval = %v, want %v", got, c.want)
			}
		})
	}
}

func TestPrecedence(t *testing.T) {
	// AND binds tighter than OR — "a OR b AND c" == "a OR (b AND c)"
	expr := MustParse(`title="A" || body="B" && header="C"`)
	got := expr.Eval(Context{"title": "A", "body": "", "header": ""})
	if !got {
		t.Errorf("title=A alone should satisfy OR-branch, got false. canon=%s", expr.String())
	}

	got = expr.Eval(Context{"title": "", "body": "B", "header": "C"})
	if !got {
		t.Errorf("body=B AND header=C should satisfy, got false")
	}

	got = expr.Eval(Context{"title": "", "body": "B", "header": ""})
	if got {
		t.Errorf("body=B alone should NOT satisfy (header missing)")
	}
}

func TestEscapesInString(t *testing.T) {
	// quote-in-string: body="id=\"server\""
	expr := MustParse(`body="id=\"server\""`)
	if !expr.Eval(Context{"body": `<div id="server">x`}) {
		t.Errorf("escape parse/eval failed: canon=%s", expr.String())
	}
}

func TestRealWorldFingerprints(t *testing.T) {
	cases := []struct {
		name string
		expr string
		ctx  Context
		want bool
	}{
		{
			name: "Hand IAM system",
			expr: `body="src='/Public/sheme/default/images/ajax-loader.gif'" && body="杭州汉领信息科技有限公司"`,
			ctx: Context{
				"body": `<img src='/Public/sheme/default/images/ajax-loader.gif'> 杭州汉领信息科技有限公司`,
			},
			want: true,
		},
		{
			name: "Synchronet BBS with exclusion",
			expr: `header="Server: Synchronet BBS " || (banner="Server: Synchronet BBS " && banner!="couchdb")`,
			ctx:  Context{"header": "", "banner": "Server: Synchronet BBS v3"},
			want: true,
		},
		{
			name: "Synchronet BBS excluded",
			expr: `header="Server: Synchronet BBS " || (banner="Server: Synchronet BBS " && banner!="couchdb")`,
			ctx:  Context{"header": "", "banner": "couchdb"},
			want: false,
		},
		{
			name: "UBNT EdgeSwitch protocol",
			expr: `protocol="snmp" && banner="EdgeSwitch"`,
			ctx:  Context{"protocol": "snmp", "banner": "Ubiquiti EdgeSwitch v6"},
			want: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expr, err := Parse(c.expr)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := expr.Eval(c.ctx); got != c.want {
				t.Errorf("Eval = %v, want %v (canon=%s)", got, c.want, expr.String())
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		`title=`,            // missing string
		`title="unclosed`,   // unterminated string
		`(title="A"`,        // unclosed paren
		`title="A" &&`,      // trailing operator
		`= "x"`,             // missing field
		`title ~ "x"`,       // wrong operator (~ alone)
		`title="A" "extra"`, // trailing token
		`title="A" |`, // dangling |
	}
	for _, b := range bad {
		t.Run(b, func(t *testing.T) {
			_, err := Parse(b)
			if err == nil {
				t.Errorf("expected error for %q", b)
			}
		})
	}
}

func TestParseLimits(t *testing.T) {
	t.Run("max expr length", func(t *testing.T) {
		big := strings.Repeat("body=\"x\" && ", maxExprLen/14+1)
		_, err := Parse(big)
		if err == nil {
			t.Fatal("expected error for over-long expression")
		}
	})
	t.Run("max string length", func(t *testing.T) {
		long := `body="` + strings.Repeat("x", maxStringLen+1) + `"`
		_, err := Parse(long)
		if err == nil {
			t.Fatal("expected error for over-long quoted string")
		}
	})
	t.Run("max nested parens", func(t *testing.T) {
		// Build an expression nested one level deeper than the limit.
		depth := maxParseDepth + 1
		prefix := strings.Repeat("(", depth)
		suffix := strings.Repeat(")", depth)
		_, err := Parse(prefix + `body="x"` + suffix)
		if err == nil {
			t.Fatal("expected error for deeply-nested parens")
		}
	})
	t.Run("exactly at max depth", func(t *testing.T) {
		depth := maxParseDepth
		prefix := strings.Repeat("(", depth)
		suffix := strings.Repeat(")", depth)
		_, err := Parse(prefix + `body="x"` + suffix)
		if err != nil {
			t.Fatalf("expected success at max depth, got: %v", err)
		}
	})
	t.Run("deep not chain is fine", func(t *testing.T) {
		// Unary NOT doesn't recurse via enter/leave, so a chain of ! should
		// parse regardless of maxParseDepth.
		expr := strings.Repeat("!", 100) + `body="x"`
		_, err := Parse(expr)
		if err != nil {
			t.Fatalf("unexpected error for deep NOT chain: %v", err)
		}
	})
}

func TestRegexCache(t *testing.T) {
	// Hit cache twice — second compile should reuse.
	exp1 := MustParse(`body~="foo[0-9]+"`)
	exp2 := MustParse(`body~="foo[0-9]+"`)
	if !exp1.Eval(Context{"body": "foo123"}) {
		t.Fatal("first eval failed")
	}
	if !exp2.Eval(Context{"body": "foo123"}) {
		t.Fatal("second eval failed")
	}
}
