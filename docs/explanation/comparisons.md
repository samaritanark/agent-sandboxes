# How This Compares (Apple Containers and friends)

[← Documentation](../index.md)

People sometimes look at this project next to a container runtime and
ask "isn't that the same thing?" — most recently Apple's
[`container`](https://github.com/apple/container). It's a fair question,
and the answer is no, but for a reason worth spelling out: those tools
are a *box*, and this is the *box plus a leash, a locked filing cabinet,
and a guarded exit*. A stronger box doesn't replace the leash.

The axis that matters is **containment boundary** (how hard it is to
break *out* of the sandbox) versus **policy layer** (what the thing
inside is allowed to *do* while it stays in). A container runtime gives
you the first. This sandbox is built on a boundary and then spends most
of its code on the second — egress allowlisting, credential isolation,
filesystem masking, the tier model. For an *untrusted agent*, the policy
layer is the half that does the heavy lifting: the everyday risk isn't
the agent escaping its sandbox, it's the agent inside the sandbox
exfiltrating data, phoning home, or misusing a credential — exactly what
a runtime alone does nothing about.

| Tool | What it is | Containment boundary | Default-deny egress | Credential isolation | Overlaps this tool? |
|------|------------|----------------------|---------------------|----------------------|----------------------|
| **Agent Sandbox** (this) | Policy layer over a gVisor pod | gVisor (syscall interception) | Yes — per-tier allowlist | Yes — OAuth / per-session Secrets | — |
| **Apple `container`** | macOS container runtime | Hardware VM, one per container (*stronger* than gVisor) | No | No | No — complementary |
| **Docker / Podman** | Container runtimes | Shared-kernel namespaces (weaker) | No | No | No — we *use* them to build images |
| **Dev Containers** (VS Code) | Reproducible dev environment | Same as Docker | No | No — assumes trusted code | No — different goal |
| **Hosted agent sandboxes** (E2B, Daytona, Codex cloud, etc.) | Cloud code-execution for agents | Provider microVMs (strong) | Provider-controlled | On the provider's infra | Closest in *intent*, different in *place* |

A few notes on the rows worth a sentence each:

- **Apple Containers** is genuinely interesting here, and not as a
  competitor. Its per-container hardware VM is a *stronger* containment
  boundary than gVisor's syscall interception — philosophically more
  aligned with "agents are untrusted," not less. But it's a runtime, not
  a policy engine: out of the box a `container run` has open egress,
  whatever credentials you hand it, and whatever mounts you configure.
  Swapping this tool for raw Apple Containers upgrades the boundary that
  matters less for agents and discards the policy layer that matters
  more. The compelling version isn't "instead of" — it's "underneath":
  Apple's VM as the box, this tool's controls around it. That would be an
  isolation-backend change, not a drop-in, and it's macOS-on-Apple-Silicon
  only (macOS 26+), so it's a someday, not a today.

- **Docker / Podman** aren't rivals at all — the sandbox shells out to
  whichever you have to *build* its images (see [Rebuilding
  Images](../how-to/rebuilding-images.md)). The confusion is only ever
  "can't I just `docker run` the agent?" You can, and you'd be running it
  in a box with the door open.

- **Hosted agent sandboxes** are the closest in intent — they also exist
  to run agents you don't fully trust. The difference is where the agent
  ends up and what it can reach: those run on the provider's
  infrastructure and are pointed at the provider's network, while this
  runs on your own host or cluster and is meant to let an agent reach
  *your* internal systems (Tier 3 dev clusters, infra endpoints) under a
  policy you control. Different tool for "ship code to a clean cloud
  box" versus "let an agent touch our stuff, carefully."

If your takeaway is "I like the stronger boundary Apple Containers
offers" — good instinct, and noted. The point of this section is just
that the boundary is one ingredient, and on its own it leaves the egress
and credential controls described in [PRINCIPLES.md](../../PRINCIPLES.md) on
the table.
