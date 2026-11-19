package bashcompat

import "testing"

func TestBashGlob(t *testing.T) {
	yes := [][2]string{{"*.egg-info", "pkg.egg-info"}, {"*", ""}, {"a?c", "abc"}, {"[ab]x", "bx"}, {"[!a]x", "bx"}, {"[^a]x", "bx"}, {"[a-c]", "b"}, {"a\\*", "a*"}, {"[", "["}, {"[]a]", "]"}}
	no := [][2]string{{"*.egg-info", "egg-info"}, {"a?c", "ac"}, {"[ab]x", "cx"}, {"[!a]x", "ax"}, {"[a-c]", "d"}, {"a\\*", "ab"}, {"vendor", "vendor2"}}
	for _, c := range yes {
		if !Glob(c[0], c[1]) {
			t.Errorf("glob %q should match %q", c[0], c[1])
		}
	}
	for _, c := range no {
		if Glob(c[0], c[1]) {
			t.Errorf("glob %q should not match %q", c[0], c[1])
		}
	}
}

func TestBashQuoteQ(t *testing.T) {
	for in, want := range map[string]string{
		"": "''", "plain": "plain", "a b": `a\ b`, "~x": `\~x`, "a~b": "a~b", "a:~b": `a:\~b`, "#x": `\#x`, "a#b": "a#b",
		"it's": `it\'s`, "a\tb": `$'a\tb'`, "\x7f": `$'\177'`, "é": "é", "é\t": "$'é\\t'", "a\xc3": `$'a\303'`, "\x1b[0m": `$'\E[0m'`,
		"x,y": `x\,y`, "back\\s": `back\\s`, "\u0085": `$'\302\205'`,
	} {
		if got := QuoteQ(in); got != want {
			t.Errorf("QuoteQ(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestBashArith(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "7": 7, "010": 8, "007": 7, "99999999999999999999": 7766279631452241919, "9223372036854775808": -9223372036854775808} {
		if got, ok := Arith(in); !ok || got != want {
			t.Errorf("Arith(%s) = %d,%v want %d", in, got, ok, want)
		}
	}
	if _, ok := Arith("08"); ok {
		t.Error("08 must be an arithmetic error")
	}
}
