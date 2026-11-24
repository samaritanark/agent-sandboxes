// genagents writes the corpus for lib/agents.sh and check_host_env_not_leaked:
// testdata/cases.tsv, one case per line, "id op agent args env" ("=" + base64 each). env holds
// NAME=VALUE entries separated by the byte 0x1e (a value may contain a newline).
//
// Usage: go run ./internal/agents/internal/genagents -base internal/agents/testdata
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func enc(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

func main() {
	base := flag.String("base", "internal/agents/testdata", "testdata directory")
	flag.Parse()
	var rows []string
	add := func(op, agent string, args []string, env ...string) {
		e := ""
		if len(env) > 0 {
			e = strings.Join(env, "\x1e")
		}
		rows = append(rows, fmt.Sprintf("a%04d\t%s\t%s\t%s\t%s", len(rows), enc(op), enc(agent), enc(strings.Join(args, "\n")), enc(e)))
	}
	agents := []string{"claude", "codex", "opencode", "copilot", "grok", "", "Claude", "gemini", "claude "}
	for _, a := range agents {
		for _, op := range []string{"validate", "endpoint", "flags", "mcp", "cred", "domains"} {
			add(op, a, nil)
		}
	}
	urls := []string{"https://api.openai.com/v1", "http://vllm.internal:8000/v1", "https://user:pw@host.example/v1",
		"https://a@b@c.example:9/x", "api.openai.com/v1", "https://", "https:///v1", "https://[::1]:8080/v1",
		"https://h.example?x=1", "https://h.example#f", "HTTPS://Up.Example/", "ftp://h", ":", "https://h:/", "//h/x"}
	for _, u := range urls {
		add("endpoint", "opencode", nil, "OPENCODE_BASE_URL="+u)
		add("domains", "opencode", nil, "OPENCODE_BASE_URL="+u)
		add("endpoint", "codex", nil, "OPENCODE_BASE_URL="+u)
	}
	add("domains", "opencode", nil, "OPENCODE_BASE_URL=")
	recs := [][]string{
		nil, {"fs|http|http://dep-fs:8080/mcp"}, {"fs|sse|http://a/sse", "git|http|http://b/mcp"},
		{"fs|http|http://a", "fs|sse|http://b"}, {"noseparator"}, {"a|b"}, {"|http|u"}, {"n|t|u|with|pipes"},
		{"", "x|http|u"}, {"q\"uote|http|http://h/\\path"}, {"ü|http|http://h/é"}, {"ctl\x01|http|u\t"},
	}
	for _, a := range []string{"claude", "codex", "bogus"} {
		for _, r := range recs {
			add("render", a, r)
		}
	}
	envSets := [][]string{
		nil,
		{"KUBECONFIG=/k", "SSH_AUTH_SOCK=/s", "GH_TOKEN=t"},
		{"KUBECONFIG="},
		{"AWS_PROFILE=p"},
		{"AWS_EMPTY="},
		{"OS_AUTH_URL=x", "GOOGLE_APPLICATION_CREDENTIALS=y", "AZURE_X=1", "TELEPORT_P=1", "TSH_H=1", "ANTHROPIC_API_KEY=k", "OPENAI_API_KEY=o"},
		{"SPOOF=harmless\nAWS_SECRET_ACCESS_KEY=fake"},
		{"OPENCODE_API_KEY=k"},
		{"XAI_API_KEY=x", "GROK_DEPLOYMENT_KEY=g", "GITHUB_COPILOT_X=1", "COPILOT_GITHUB_TOKEN=c", "GITHUB_TOKEN=gt"},
		{"DOCKER_HOST=tcp://x", "KUBERNETES_SERVICE_HOST=10.0.0.1", "KUBERNETES_SERVICE_PORT=443"},
		{"AWSX=1", "aws_lower=1", "MY_AWS_X=1"},
	}
	for _, a := range []string{"claude", "opencode"} {
		for _, e := range envSets {
			add("envcheck", a, nil, e...)
		}
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d cases\n", len(rows))
}
