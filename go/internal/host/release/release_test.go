package release

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	good := map[string]Info{
		"IMAGE_VERSION=3.0.0\nCONTROL_API=1\n":                       {"3.0.0", 1},
		"# comment\n\nIMAGE_VERSION=\"3.1.0-rc.1\"\r\nCONTROL_API=2": {"3.1.0-rc.1", 2},
		"OTHER=x y\nCONTROL_API=1\nIMAGE_VERSION=3+b.1\n":            {"3+b.1", 1},
	}
	for in, want := range good {
		got, err := Parse([]byte(in))
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	bad := []string{
		"", "IMAGE_VERSION=3\n", "CONTROL_API=1\n",
		"IMAGE_VERSION=3\nCONTROL_API=01\n", "IMAGE_VERSION=3\nCONTROL_API=0\n", "IMAGE_VERSION=3\nCONTROL_API=-1\n",
		"IMAGE_VERSION=3\nCONTROL_API=1x\n", "IMAGE_VERSION=3\nCONTROL_API=99999999999999999999\n",
		"IMAGE_VERSION=3\nCONTROL_API=1\nCONTROL_API=2\n", "IMAGE_VERSION=3 4\nCONTROL_API=1\n",
		"IMAGE_VERSION=$(x)\nCONTROL_API=1\n", "IMAGE_VERSION=\nCONTROL_API=1\n", " IMAGE_VERSION=3\nCONTROL_API=1\n",
		"IMAGE_VERSION=3\nCONTROL_API=1\njunk\n", "IMAGE_VERSION=3\nCONTROL_API=\"1\\\"\"\n",
		"IMAGE_VERSION=3\nCONTROL_API=1\n" + strings.Repeat("#", MaxSize),
		"IMAGE_VERSION=" + strings.Repeat("1", 65) + "\nCONTROL_API=1\n",
	}
	for _, in := range bad {
		if got, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%q) = %+v, want an error", in, got)
		}
	}
}

func TestCheck(t *testing.T) {
	if err := Check(Info{"3.0.0", MinControlAPI}); err != nil {
		t.Fatal(err)
	}
	if err := Check(Info{"2.9", MinControlAPI - 1}); err == nil || !strings.Contains(err.Error(), "sandbox install --dev-image <newer image>") {
		t.Errorf("older image: %v", err)
	}
	if err := Check(Info{"4.0", MaxControlAPI + 1}); err == nil || !strings.Contains(err.Error(), "Use a newer sandbox binary") {
		t.Errorf("newer image: %v", err)
	}
}
