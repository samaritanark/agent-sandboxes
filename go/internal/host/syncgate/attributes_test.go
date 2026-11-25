package syncgate

import "testing"

func TestCheckAttributes(t *testing.T) {
	ok := func(host, vm string) {
		t.Helper()
		var h []byte
		if host != "-" {
			h = []byte(host)
		}
		if err := CheckAttributes(h, []byte(vm)); err != nil {
			t.Errorf("host %q vm %q: %v", host, vm, err)
		}
	}
	bad := func(host, vm string) {
		t.Helper()
		var h []byte
		if host != "-" {
			h = []byte(host)
		}
		if err := CheckAttributes(h, []byte(vm)); err == nil {
			t.Errorf("host %q vm %q: accepted", host, vm)
		}
	}
	ok("-", "*.png binary\n*.sh text eol=lf\n*.min.js -diff\n*.md linguist-documentation\n*.c diff\n# filter=evil\n")
	ok("-", "*.bin filter=lfs diff=lfs merge=lfs -text\n")
	ok("-", "  *.bin   merge=lfs  filter=lfs diff=lfs\n")
	bad("-", "*.bin filter=lfs diff=lfs\n")
	bad("-", "* diff=pdf\n")
	bad("-", "*.txt filter=lfs diff=lfs merge=lfs merge=union\n")
	bad("-", "*.c merge=ours\n")
	bad("-", "*.c Diff=x\n")
	bad("-", "*.c !diff=x\n")
	bad("-", "[attr]evil filter=x\n*.c evil\n")
	bad("-", "[attr]innocent text\n")
	bad("-", "\"*.c\" diff=x\n")
	bad("-", "\"unterminated diff=x\n")
	bad("-", "*.c\tdiff=x\r\n")
	// unchanged driver lines on the host pass; a changed value does not
	ok("*.ipynb diff=jupyter\n", "*.ipynb diff=jupyter\n*.md text\n")
	bad("*.ipynb diff=jupyter\n", "*.ipynb diff=other\n")
	bad("*.ipynb diff=jupyter\n", "*.ipynb diff=jupyter\n*.py diff=jupyter\n")
	ok("*.ipynb diff=jupyter\n", "") // removing drivers is not an exec vector
	ok("*.c diff=x\n", "*.c -diff\n")
	if err := CheckAttributes([]byte("x"), nil); err != nil {
		t.Error("deletion refused")
	}
}
