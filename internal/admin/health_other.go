//go:build !windows && !linux

package admin

import "time"

func processCPUTime() time.Duration { return 0 }
