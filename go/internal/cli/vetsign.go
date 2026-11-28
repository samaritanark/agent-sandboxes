package cli

// The VM's halves of `sandbox vet --repo` (design 5.1.3, D-20; vetting.Prepare and Finish): the
// host runs them on the repository's synced copy (its host path, which the VM links to the copy),
// signs on its own side, and writes the tag into the host repository itself.

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/samaritanark/agent-sandboxes/go/internal/gate"
	"github.com/samaritanark/agent-sandboxes/go/internal/vetting"
)

// VetFinishInput is what the host sends `__vet-finish` on stdin.
type VetFinishInput struct {
	Tag string `json:"tag"` // the payload and its signature
}

// VetFinishOutput is what `__vet-finish` prints.
type VetFinishOutput struct {
	Warnings []string `json:"warnings,omitempty"`
}

func (c *cmdCtx) attester() vetting.Attester {
	v := c.vetting()
	return vetting.Attester{Ctx: v, Out: c.stdout, Err: c.stderr, Stdin: c.stdin,
		Warn: func(m string) { c.warn("%s", m) },
		Scan: func(r, accept string) []string { return gate.ScanRepoSecrets(c.env.Env, r, accept, io.Discard) }}
}

// vetRepo checks and expands a repository path as `vet` does.
func (c *cmdCtx) vetRepo(repo string) string {
	repo = c.expandHome(repo)
	if err := c.workspace().ValidateRepoPath(repo); err != nil {
		c.fail(err)
	}
	return repo
}

func runCtx(env Env, stdout, stderr io.Writer, f func(c *cmdCtx)) (status int) {
	c := &cmdCtx{env: env, stdout: stdout, stderr: stderr}
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exit); ok {
				status = int(e)
				return
			}
			panic(r)
		}
	}()
	f(c)
	return 0
}

// VetPrepare is `sandbox __vet-prepare REPO TAGGER [MESSAGE]`: the plan (vetting.Plan) as JSON.
func VetPrepare(args []string, env Env, stdout, stderr io.Writer) int {
	return runCtx(env, stdout, stderr, func(c *cmdCtx) {
		if len(args) < 2 || len(args) > 3 {
			c.die("usage: __vet-prepare REPO TAGGER [MESSAGE]")
		}
		msg := ""
		if len(args) == 3 {
			msg = args[2]
		}
		p, err := c.attester().Prepare(c.vetRepo(args[0]), msg, args[1])
		if err != nil {
			c.die("%v", err)
		}
		b, _ := json.Marshal(p)
		fmt.Fprintln(c.stdout, string(b))
	})
}

// VetFinish is `sandbox __vet-finish REPO` with VetFinishInput on stdin.
func VetFinish(args []string, env Env, stdin io.Reader, stdout, stderr io.Writer) int {
	return runCtx(env, stdout, stderr, func(c *cmdCtx) {
		if len(args) != 1 {
			c.die("usage: __vet-finish REPO")
		}
		var in VetFinishInput
		dec := json.NewDecoder(io.LimitReader(stdin, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			c.die("the host's signed tag is malformed: %v", err)
		}
		w, err := c.attester().Finish(c.vetRepo(args[0]), []byte(in.Tag))
		if err != nil {
			c.die("%v", err)
		}
		b, _ := json.Marshal(VetFinishOutput{Warnings: w})
		fmt.Fprintln(c.stdout, string(b))
	})
}
