package main

// The broker's own refresh of an agent's OAuth login (design 5.9.4: the broker performs refresh).
// Before a launch, sandboxd runs a short-lived copy of itself (__broker-refresh) with the key and
// the agent's reference: when the access token in the store expires within the launch's window, the
// helper redeems the refresh token at the agent's token endpoint, seals the new access and refresh
// tokens into the store (rotation stays in the VM, 5.1.5), wipes, and prints the access token's
// expiry (not a secret), which the CLI puts into the guest's look-alike token.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/brokerstore"
)

// oauthClient is an agent's token endpoint.
type oauthClient struct {
	url, clientID, scope string
}

// oauthClients are the agents whose logins the broker refreshes, by access token reference; the
// refresh token is the reference plus ".refresh".
var oauthClients = map[string]oauthClient{
	// Codex (codex-rs/login/src/auth/manager.rs: REFRESH_TOKEN_URL, CLIENT_ID)
	"agent.codex": {url: "https://auth.openai.com/oauth/token", clientID: "app_EMoamEEZ73f0CkXaXp7hrann", scope: "openid profile email"},
}

// refreshJob is what the refresh helper reads on its stdin.
type refreshJob struct {
	Key      []byte `json:"key"`
	Store    string `json:"store"`
	Ref      string `json:"ref"`
	MinValid int64  `json:"min_valid"` // seconds the access token must still be valid for
}

func (b *brokerStore) Refresh(ctx context.Context, ref string, minValid time.Duration) (int64, error) {
	if _, ok := oauthClients[ref]; !ok {
		return 0, fmt.Errorf("the broker does not refresh %s", ref)
	}
	b.mu.Lock()
	if b.key == nil {
		b.mu.Unlock()
		return 0, errors.New("the broker key has not been pushed from the host (run 'sandbox vm start' there)")
	}
	job, err := json.Marshal(refreshJob{Key: b.key, Store: b.store.Dir, Ref: ref, MinValid: int64(minValid / time.Second)})
	b.mu.Unlock()
	if err != nil {
		return 0, err
	}
	defer brokerstore.Wipe(job)
	out, err := runHelperOut(ctx, "__broker-refresh", "refresh helper", job)
	if err != nil {
		return 0, err
	}
	var r struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(out, &r); err != nil || r.Exp == 0 {
		return 0, fmt.Errorf("the refresh helper answered %q", strings.TrimSpace(string(out)))
	}
	return r.Exp, nil
}

// brokerRefresh is the helper.
func brokerRefresh() int {
	fail := func(err error) int { fmt.Fprintln(os.Stderr, err); return 1 }
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return fail(err)
	}
	defer brokerstore.Wipe(raw)
	var job refreshJob
	if err := json.Unmarshal(raw, &job); err != nil {
		return fail(fmt.Errorf("unreadable job: %w", err))
	}
	defer brokerstore.Wipe(job.Key)
	exp, err := refreshLogin(brokerstore.Store{Dir: job.Store}, job.Key, job.Ref, time.Duration(job.MinValid)*time.Second, time.Now(), httpPost)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("{\"exp\":%d}\n", exp)
	return 0
}

// httpPost posts a JSON body and returns the status and the response body.
func httpPost(ctx context.Context, url string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, err
}

// jwtExp is a JWT's expiry (the claims are not verified: the token came from the store).
func jwtExp(tok []byte) (int64, error) {
	parts := bytes.Split(tok, []byte("."))
	if len(parts) != 3 {
		return 0, errors.New("the access token is not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(string(parts[1]), "="))
	if err != nil {
		return 0, err
	}
	var c struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(b, &c); err != nil || c.Exp == 0 {
		return 0, errors.New("the access token has no expiry")
	}
	return c.Exp, nil
}

// refreshLogin refreshes ref's login when its access token expires within minValid of now, and
// returns the access token's expiry.
func refreshLogin(st brokerstore.Store, key []byte, ref string, minValid time.Duration, now time.Time,
	post func(context.Context, string, []byte) (int, []byte, error)) (int64, error) {
	client, ok := oauthClients[ref]
	if !ok {
		return 0, fmt.Errorf("the broker does not refresh %s", ref)
	}
	open := func(r string) ([]byte, brokerseal.Binding, error) {
		sealed, err := st.Get(r)
		if err != nil {
			return nil, brokerseal.Binding{}, fmt.Errorf("credential %s is not in the broker store", r)
		}
		v, b, _, err := brokerseal.OpenBound(key, r, sealed)
		return v, b, err
	}
	access, binding, err := open(ref)
	if err != nil {
		return 0, err
	}
	exp, err := jwtExp(access)
	brokerstore.Wipe(access)
	if err != nil {
		return 0, err
	}
	if time.Unix(exp, 0).Sub(now) > minValid {
		return exp, nil
	}
	refresh, _, err := open(ref + ".refresh")
	if err != nil {
		return 0, err
	}
	body, _ := json.Marshal(map[string]string{"client_id": client.clientID, "grant_type": "refresh_token",
		"refresh_token": string(refresh), "scope": client.scope})
	brokerstore.Wipe(refresh)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	status, out, err := post(ctx, client.url, body)
	brokerstore.Wipe(body)
	defer brokerstore.Wipe(out)
	if err != nil {
		return 0, fmt.Errorf("refreshing %s: %v", ref, err)
	}
	if status != http.StatusOK {
		var e struct {
			Error any `json:"error"`
		}
		json.Unmarshal(out, &e)
		return 0, fmt.Errorf("the token endpoint answered %d (%v)", status, e.Error)
	}
	var r struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(out, &r); err != nil || r.AccessToken == "" {
		return 0, fmt.Errorf("refreshing %s: no access token in the answer", ref)
	}
	newAccess := []byte(r.AccessToken)
	defer brokerstore.Wipe(newAccess)
	newExp, err := jwtExp(newAccess)
	if err != nil {
		return 0, err
	}
	// the refresh token first: a rotated one must never be lost while its access token is kept
	if r.RefreshToken != "" {
		rt := []byte(r.RefreshToken)
		sealed, err := brokerseal.SealBound(key, ref+".refresh", rt, brokerseal.Binding{})
		brokerstore.Wipe(rt)
		if err == nil {
			err = st.Put(ref+".refresh", sealed)
		}
		if err != nil {
			return 0, err
		}
	}
	sealed, err := brokerseal.SealBound(key, ref, newAccess, binding)
	if err == nil {
		err = st.Put(ref, sealed)
	}
	if err != nil {
		return 0, err
	}
	return newExp, nil
}
