package basework

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	Limiter  *rate.Limiter
	MinRps   = 20.0
	CurRps   = 50.0
	MaxRps   = 1000.0
	Stats    ControlStat
	StatLock sync.Mutex
)

type ControlStat struct {
	Total   int64
	Err     int64
	LateSum time.Duration
}

func InitAdaptiveLimiter(InitRps float64) {
	CurRps = InitRps
	Limiter = rate.NewLimiter(rate.Limit(CurRps), 1)
	go ControlLimiter()
}

func RecordResult(err error, latency time.Duration) {
	StatLock.Lock()
	defer StatLock.Unlock()

	Stats.Total++
	Stats.LateSum += latency
	if err != nil {
		Stats.Err++
	}
}

func ControlLimiter() {
	ticker := time.NewTicker(3 * time.Second)
	for range ticker.C {
		StatLock.Lock()
		s := Stats
		Stats = ControlStat{}
		StatLock.Unlock()

		if s.Total == 0 {
			fmt.Println("[DEBUG] window empty, no stats")
			continue
		}

		ErrRate := float64(s.Err) / float64(s.Total)
		AvgLatency := time.Duration(int64(s.LateSum) / s.Total)
		NewRps := CurRps

		fmt.Printf("[DEBUG] window: total=%d err=%d errRate=%.2f avgLatency=%v curRps=%.1f\n",
			s.Total, s.Err, ErrRate, AvgLatency, CurRps)

		if ErrRate < 0.1 && AvgLatency < 1500*time.Millisecond {
			NewRps *= 1.1
		} else if ErrRate > 0.4 && AvgLatency > 3*time.Second {
			NewRps *= 0.8
		}

		if NewRps < MinRps {
			NewRps = MinRps
		}
		if NewRps > MaxRps {
			NewRps = MaxRps
		}

		if NewRps != CurRps {
			CurRps = NewRps
			Limiter = rate.NewLimiter(rate.Limit(CurRps), 1)

			fmt.Printf("[auto] RPS change to %.1f ErrRate=%.2f AvgLatency=%v)\n", CurRps, ErrRate, AvgLatency)
		}
	}
}
