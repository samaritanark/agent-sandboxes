package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/brokerstore"
)

func jwtWithExp(exp int64, tag string) string {
	p, _ := json.Marshal(map[string]any{"exp": exp, "tag": tag})
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

// TestRefreshLogin: a login that stays valid long enough is left alone; one that expires sooner is
// refreshed at the agent's endpoint, its new tokens sealed into the store (the access token keeping
// its binding, the refresh token rotated); a refusal or a bad answer leaves the store as it was.
func TestRefreshLogin(t *testing.T) {
	key, _ := brokerseal.NewKey()
	st := brokerstore.Store{Dir: t.TempDir()}
	now := time.Unix(1_800_000_000, 0)
	b := &brokerseal.Binding{Hosts: []string{"chatgpt.com"}, Inject: "bearer"}
	putEntry(t, st, key, "agent.codex", jwtWithExp(now.Add(10*24*time.Hour).Unix(), "old"), b)
	putEntry(t, st, key, "agent.codex.refresh", "rt-old", &brokerseal.Binding{})
	var posts []string
	answer := func(status int, body string) func(context.Context, string, []byte) (int, []byte, error) {
		return func(_ context.Context, url string, req []byte) (int, []byte, error) {
			posts = append(posts, url+" "+string(req))
			return status, []byte(body), nil
		}
	}
	week := 7*24*time.Hour + time.Hour
	exp, err := refreshLogin(st, key, "agent.codex", week, now, answer(200, "{}"))
	if err != nil || exp != now.Add(10*24*time.Hour).Unix() || len(posts) != 0 {
		t.Fatalf("still valid: %d %v %q", exp, err, posts)
	}
	// five days on, the token has less than a week left: refreshed
	later := now.Add(5 * 24 * time.Hour)
	newAccess := jwtWithExp(later.Add(10*24*time.Hour).Unix(), "new")
	exp, err = refreshLogin(st, key, "agent.codex", week, later, answer(200, `{"access_token":"`+newAccess+`","refresh_token":"rt-new","id_token":"x"}`))
	if err != nil || exp != later.Add(10*24*time.Hour).Unix() || len(posts) != 1 {
		t.Fatalf("refresh: %d %v %q", exp, err, posts)
	}
	if want := `https://auth.openai.com/oauth/token {"client_id":"app_EMoamEEZ73f0CkXaXp7hrann","grant_type":"refresh_token","refresh_token":"rt-old","scope":"openid profile email"}`; posts[0] != want {
		t.Errorf("request %q", posts[0])
	}
	open := func(ref string) (string, brokerseal.Binding) {
		sealed, _ := st.Get(ref)
		v, bb, _, err := brokerseal.OpenBound(key, ref, sealed)
		if err != nil {
			t.Fatal(err)
		}
		return string(v), bb
	}
	if v, bb := open("agent.codex"); v != newAccess || strings.Join(bb.Hosts, ",") != "chatgpt.com" {
		t.Errorf("access %q %+v", v, bb)
	}
	if v, _ := open("agent.codex.refresh"); v != "rt-new" {
		t.Errorf("refresh %q", v)
	}
	// refused, garbled, or unreachable: an error, and the store unchanged
	muchLater := later.Add(5 * 24 * time.Hour)
	for name, post := range map[string]func(context.Context, string, []byte) (int, []byte, error){
		"refused":             answer(400, `{"error":"invalid_grant"}`),
		"refused with a body": answer(401, `{"access_token":"`+jwtWithExp(muchLater.Add(10*24*time.Hour).Unix(), "x")+`"}`),
		"garbled":             answer(200, `{"access_token":"not-a-jwt"}`),
		"empty":               answer(200, `{}`),
		"offline":             func(context.Context, string, []byte) (int, []byte, error) { return 0, nil, errors.New("no route") },
	} {
		if _, err := refreshLogin(st, key, "agent.codex", week, muchLater, post); err == nil {
			t.Errorf("%s: no error", name)
		}
		if v, _ := open("agent.codex.refresh"); v != "rt-new" {
			t.Errorf("%s: refresh token changed to %q", name, v)
		}
	}
	if _, err := refreshLogin(st, key, "agent.claude", week, now, answer(200, "{}")); err == nil {
		t.Error("a login with no token endpoint refreshed")
	}
}
