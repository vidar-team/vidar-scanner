package basework

import "time"

const (
	PortStateOpen            = "open"
	PortStateClose           = "close"
	PortStateNone            = "none"
	PortStateError           = "error"
	PortStateSendError       = "send_error"
	PortStateFilteredTimeout = "filtered/timeout"
)

const (
	synScanAttempts = 3
	synScanDelay    = 200 * time.Millisecond
)

func shouldRetryPortState(state string) bool {
	switch state {
	case PortStateOpen, PortStateClose:
		return false
	default:
		return true
	}
}
