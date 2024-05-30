package test

import "time"

// Time represents a fixed point in time for all tests
var Time = time.Date(2021, 3, 12, 4, 23, 32, 11, time.UTC)

// Now returns a fixed point in time
func Now() time.Time { return Time }
