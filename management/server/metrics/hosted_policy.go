package metrics

import "errors"

var errHostedMetricsDisabled = errors.New("hosted management statistics are disabled pending a qualified GoreeCloud collection channel")

// Inherited flags and interval settings cannot authorize a hosted recipient.
func hostedMetricsEnabled() bool {
	return false
}
