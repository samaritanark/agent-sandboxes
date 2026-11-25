package tty

import (
	"os"
	"testing"
)

func TestIs(t *testing.T) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if Is(null) {
		t.Errorf("%s is not a terminal", os.DevNull)
	}
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if Is(r) {
		t.Error("a pipe is not a terminal")
	}
}
