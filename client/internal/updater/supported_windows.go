package updater

// Inherited platform installers must remain disabled until the GoreeCloud
// signing, package identity, upgrade and rollback chain is qualified.
func isAutoUpdateSupported() bool {
	return false
}
