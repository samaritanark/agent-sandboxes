package app

// opencode's API key and model list (design 5.9.4: "Agent API key (opencode): placeholder injected
// toward the configured provider host"). v2 read OPENCODE_API_KEY and OPENCODE_BASE_URL from the
// host's environment, fetched the endpoint's model list with the key, and gave the pod the key, the
// base URL, and an opencode configuration naming those models. Here the host does the parts that
// need the key: it fetches the model list, builds the configuration (which holds no secret: its
// apiKey is "{env:OPENAI_API_KEY}"), seals the key bound to the endpoint's host, and passes the
// configuration to the run. OPENCODE_BASE_URL itself is forwarded to the VM, which decides as v2
// did (--base-url overrides it).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// OpencodeRef is opencode's API key in the broker store; OpencodeConfigEnv carries its
// configuration to the run.
const (
	OpencodeRef       = "opencode.OPENAI_API_KEY"
	OpencodeConfigEnv = "SANDBOX_OPENCODE_CONFIG"
)

// maxModels bounds the model list the endpoint may return.
const maxModels = 1 << 20

// fetchModels is GET base/models with the key as a bearer token (v2's curl -fsSL --max-time 10).
func fetchModels(ctx context.Context, base, key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("the endpoint answered %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxModels))
}

// opencodeConfig is v2's OPENCODE_CONFIG_CONTENT for the endpoint's /models answer: each model id
// with v2's limits, under one openai-compatible provider at base. n is the number of models.
func opencodeConfig(base string, models []byte) (cfg string, n int) {
	var d struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	list := map[string]any{}
	if json.Unmarshal(models, &d) == nil {
		for _, m := range d.Data {
			if m.ID != "" {
				list[m.ID] = map[string]any{"name": m.ID, "limit": map[string]int{"context": 131072, "output": 8192}}
			}
		}
	}
	c := map[string]any{
		"enabled_providers": []string{"openai-compat"},
		"provider": map[string]any{"openai-compat": map[string]any{
			"npm": "@ai-sdk/openai-compatible", "name": "OpenAI-compatible endpoint",
			"options": map[string]any{"baseURL": base, "apiKey": "{env:OPENAI_API_KEY}"},
			"models":  list,
		}},
	}
	b, _ := json.Marshal(c)
	return string(b), len(list)
}

// opencodeNamed is whether base is the base URL the operator gave: run's --base-url, or else
// OPENCODE_BASE_URL in the host's environment.
func opencodeNamed(base string, args []string, env string) bool {
	if v := optionValues(args, "--base-url"); len(v) > 0 {
		return v[len(v)-1] == base
	}
	return env != "" && env == base
}

// prepareOpencode does the host's part of an opencode launch and returns the configuration the run
// gets. It stops the launch as v2 did when the key or the model list is missing.
func (a *app) prepareOpencode(ep driver.SSHEndpoint, base string, args []string) string {
	if !opencodeNamed(base, args, a.getenv("OPENCODE_BASE_URL")) {
		a.die("the sandbox VM asked to send opencode's API key to %s, which neither --base-url nor OPENCODE_BASE_URL names.\n"+
			"  Nothing was pushed. If you did not expect this, the sandbox VM may be compromised: see 'sandbox doctor'.", base)
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		a.die("OPENCODE_BASE_URL must be a complete URL with http(s) scheme — got '%s'. Example: https://vllm-proxy.example.com/v1", base)
	}
	key := a.getenv("OPENCODE_API_KEY")
	if key == "" {
		a.die("OPENCODE_API_KEY must be set in host environment for opencode agent.")
	}
	fmt.Fprintf(a.env.Stdout, "  Fetching model list from %s...\n", base)
	fetch := a.env.FetchModels
	if fetch == nil {
		fetch = fetchModels
	}
	models, err := fetch(a.ctx, base, key)
	if err != nil {
		a.die("Could not fetch model list from %s/models:\n  %v\n  Verify the URL has scheme + path (typically https://host/v1) and\n  that OPENCODE_API_KEY is valid for the endpoint.", base, err)
	}
	cfg, n := opencodeConfig(base, models)
	if n == 0 {
		a.die("%s/models returned no usable models.\n  The endpoint responded but its model list is empty or malformed.\n  Verify the URL is the OpenAI-compatible base (typically ends in /v1)\n  and that OPENCODE_API_KEY has permission to list models.", base)
	}
	fmt.Fprintf(a.env.Stdout, "  Found %d model(s) on endpoint.\n", n)
	if a.env.BrokerKey == nil {
		a.die("opencode's API key needs the credential broker, but this host has no place to keep its key.")
	}
	k, err := a.brokerKey()
	if err != nil {
		a.die("%v", err)
	}
	defer brokerseal.Wipe(k)
	v := []byte(key)
	sealed, err := brokerseal.SealBound(k, OpencodeRef, v, brokerseal.Binding{Hosts: []string{strings.ToLower(u.Hostname())}, Inject: "bearer"})
	brokerseal.Wipe(v)
	if err != nil {
		a.die("%v", err)
	}
	if err := a.sandboxd(ep, bytes.NewReader(sealed), "broker-put", OpencodeRef); err != nil {
		a.die("could not store opencode's API key in the sandbox VM: %v", err)
	}
	return cfg
}

func (a *app) getenv(k string) string {
	if a.env.Getenv == nil {
		return ""
	}
	return a.env.Getenv(k)
}
