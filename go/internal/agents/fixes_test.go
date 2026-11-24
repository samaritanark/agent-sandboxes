package agents

import (
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

func TestFixEnvCheckByName(t *testing.T) {
	env := []string{"SPOOF=x\nAWS_SECRET_ACCESS_KEY=fake", "AWS_EMPTY=", "AWS_PROFILE=p", "KUBECONFIG="}
	e, _ := CheckHostEnv("claude", env)
	got := strings.Join(e, "\n")
	if !strings.Contains(got, "AWS_SECRET_ACCESS_KEY") || !strings.Contains(got, "AWS_EMPTY") {
		t.Fatalf("legacy: expected the spoofed and the empty variable, got %q", got)
	}
	defer deviation.Force(deviation.EnvCheckByName)()
	e, o := CheckHostEnv("claude", env)
	got = strings.Join(e, "\n")
	if strings.Contains(got, "AWS_SECRET_ACCESS_KEY") || strings.Contains(got, "AWS_EMPTY") || !strings.Contains(got, "AWS_PROFILE") || len(e) != 1 {
		t.Errorf("fixed: %q", got)
	}
	if len(o) != 1 || !strings.Contains(o[0], "1 host env var") {
		t.Errorf("fixed summary: %q", o)
	}
}
