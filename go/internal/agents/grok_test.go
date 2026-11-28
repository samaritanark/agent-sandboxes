package agents

import (
	"strings"
	"testing"
)

// TestGrokConfig (v2's ensure_grok_privacy_config, checked at every launch in v3): no file or one
// without the settings gets v2's block; a set key is left alone, warned about unless true; a table
// of the same name is not edited (TOML forbids a second header); a pinned model key is warned about.
func TestGrokConfig(t *testing.T) {
	out, w := GrokConfig(nil)
	if string(out) != GrokPrivacyBlock || len(w) != 0 {
		t.Errorf("none: %q %q", out, w)
	}
	out, w = GrokConfig([]byte("[ui]\ntheme = \"dark\"\n\n\n"))
	if string(out) != "[ui]\ntheme = \"dark\"\n\n"+GrokPrivacyBlock || len(w) != 0 {
		t.Errorf("appended: %q %q", out, w)
	}
	if out, w = GrokConfig([]byte("[harness]\n  disable_codebase_upload = true # mine\n")); out != nil || len(w) != 0 {
		t.Errorf("set: %q %q", out, w)
	}
	if out, w = GrokConfig([]byte("[harness]\ndisable_codebase_upload = false\n")); out != nil || len(w) != 1 || !strings.Contains(w[0], "to false") {
		t.Errorf("false: %q %q", out, w)
	}
	if out, w = GrokConfig([]byte("[telemetry]\nenabled = true\n")); out != nil || len(w) != 1 || !strings.Contains(w[0], "[harness] or [telemetry]") {
		t.Errorf("table: %q %q", out, w)
	}
	out, w = GrokConfig([]byte("[model.grok-4]\napi_key = \"xai-...\"\n"))
	if out == nil || len(w) != 1 || !strings.Contains(w[0], "api_key/env_key") {
		t.Errorf("model key: %q %q", out, w)
	}
}
