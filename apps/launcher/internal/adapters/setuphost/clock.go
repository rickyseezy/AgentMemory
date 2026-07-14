// Package setuphost supplies the native host capabilities used by the
// authenticated local setup surface.
package setuphost

import "time"

// Clock is a wall clock whose observations are always normalized to UTC.
// Setup expiry policy deliberately does not depend on the host time zone.
type Clock struct{}

// Now returns the current wall-clock observation in UTC.
func (Clock) Now() time.Time { return time.Now().UTC() }
