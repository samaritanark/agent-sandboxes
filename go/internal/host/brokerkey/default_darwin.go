package brokerkey

// Default is the keychain, with the state directory as the item's account.
func Default(stateDir string) Keeper { return Keychain{Account: stateDir} }
