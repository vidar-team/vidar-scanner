package basework

import (
	"testing"
	"time"
)

func TestShouldRetryPortState(t *testing.T) {
	cases := []struct {
		state string
		want  bool
	}{
		{state: PortStateOpen, want: false},
		{state: PortStateClose, want: false},
		{state: PortStateFilteredTimeout, want: true},
		{state: PortStateError, want: true},
		{state: PortStateSendError, want: true},
		{state: PortStateNone, want: true},
		{state: "unexpected", want: true},
	}

	for _, tc := range cases {
		if got := shouldRetryPortState(tc.state); got != tc.want {
			t.Fatalf("state %q: got retry=%v want %v", tc.state, got, tc.want)
		}
	}
}

func TestAdaptiveLimiterCanStopAndRestart(t *testing.T) {
	InitAdaptiveLimiter(100)
	time.Sleep(10 * time.Millisecond)
	StopAdaptiveLimiter()

	InitAdaptiveLimiter(200)
	time.Sleep(10 * time.Millisecond)

	if Limiter == nil {
		t.Fatal("Limiter should be initialized")
	}

	if got := float64(Limiter.Limit()); got != 200 {
		t.Fatalf("Limiter limit = %v, want 200", got)
	}

	StopAdaptiveLimiter()
}
