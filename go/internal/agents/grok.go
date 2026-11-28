package agents

import (
	"regexp"
	"strings"
)

// Grok's privacy settings (v2's ensure_grok_privacy_config, lib/onboard.sh): grok 0.2.93 uploaded
// the whole repository to xAI's trace bucket. The hosts those uploads used are not on a Grok
// session's allowlist, but api.x.ai, which is, is not a pure inference channel, so the client-side
// veto stays. In v3 the agent's home is writable by the agent, so the check runs at every launch.

var (
	grokUploadKey = regexp.MustCompile(`(?m)^[ \t]*disable_codebase_upload[ \t]*=[ \t]*([^\s#]*)`)
	grokTables    = regexp.MustCompile(`(?m)^[ \t]*\[(harness|telemetry)\]`)
	grokCredKey   = regexp.MustCompile(`(?m)^[ \t]*(api_key|env_key)[ \t]*=`)
)

// GrokPrivacyBlock is what v2 appended to Grok's config.toml.
const GrokPrivacyBlock = `# Added by the sandbox. grok 0.2.93 uploaded the ENTIRE repository — not
# just files a prompt read — to xAI's grok-code-session-traces bucket. The session's
# allowlist already blocks the hosts those uploads used, but api.x.ai — which a session
# must reach — is not a pure inference channel, so this is the client-side veto
# (defense-in-depth). Reverse-engineered for grok 0.2.93; run 'grok inspect' to confirm
# it still loads.
[harness]
disable_codebase_upload = true

[telemetry]
trace_upload = false
enabled = false
`

// GrokConfig checks a Grok config.toml (nil: none) for a launch: it returns the file to write
// (nil when it is to stay as it is) and warnings.
func GrokConfig(cfg []byte) (out []byte, warnings []string) {
	s := string(cfg)
	if grokCredKey.MatchString(s) {
		warnings = append(warnings, "grok's config.toml pins a per-model api_key/env_key, which outranks the session's xAI login and stays in the sandbox VM; remove it (grok login --device-auth instead).")
	}
	if m := grokUploadKey.FindStringSubmatch(s); m != nil {
		if m[1] != "true" {
			warnings = append(warnings, "grok's config.toml sets disable_codebase_upload to "+m[1]+": grok may upload the whole repository. Set it to true under [harness].")
		}
		return nil, warnings
	}
	if grokTables.MatchString(s) {
		warnings = append(warnings, "grok's config.toml has a [harness] or [telemetry] table without disable_codebase_upload; add 'disable_codebase_upload = true' under [harness] (and trace_upload = false, enabled = false under [telemetry]) to keep whole-repository upload off.")
		return nil, warnings
	}
	if len(cfg) == 0 {
		return []byte(GrokPrivacyBlock), warnings
	}
	return []byte(strings.TrimRight(s, "\n") + "\n\n" + GrokPrivacyBlock), warnings
}
