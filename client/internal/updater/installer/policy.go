package installer

import "errors"

// ErrUpdatesDisabled identifies the Fork-to-Native update-channel restriction.
var ErrUpdatesDisabled = errors.New("automatic installation is disabled: GoreeCloud VPN has no qualified signed update channel")

// CheckUpdatePolicy blocks inherited installers until GoreeCloud owns and
// qualifies the complete signing, package identity, upgrade and rollback chain.
// This is deliberately not configurable by an environment variable, management
// directive, installer filename or development signing build tag.
func CheckUpdatePolicy() error {
	return ErrUpdatesDisabled
}
