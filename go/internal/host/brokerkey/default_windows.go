package brokerkey

// Default is Credential Manager, with the state directory in the target name (owner decision,
// 2026-11-25, seventh round).
func Default(stateDir string) Keeper {
	return CredMan{Target: "agent-sandboxes broker key:" + stateDir}
}
