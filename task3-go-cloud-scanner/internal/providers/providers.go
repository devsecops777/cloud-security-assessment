// Package providers turns each cloud's API responses into the neutral report
// model in package scanner.
//
// Every provider follows the same contract: it never aborts the whole scan. A
// region, project or subscription that cannot be read is recorded as a
// ScanError and the remaining scopes are still scanned, because a partial
// answer is useful and a silent empty one is dangerous.
package providers

import "cloudscan/internal/scanner"

// Outcome carries the non-findings half of a provider's result: how much was
// examined (so "0 findings" can be distinguished from "0 resources seen") and
// what failed.
type Outcome struct {
	Examined int
	Errors   []scanner.ScanError
}

func (o *Outcome) fail(provider, scope string, err error) {
	o.Errors = append(o.Errors, scanner.ScanError{
		Provider: provider,
		Scope:    scope,
		Message:  err.Error(),
	})
}
