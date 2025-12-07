package basework

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	Limiter   *rate.Limiter
	MinRps    = 20.0
	CurRps    = 50.0
	MaxRps    = 2000.0
	Stats     ControlStat
	StatLock  sync.Mutex
	Ssthresh  = 320.0
	SlowStart = true
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
	ticker := time.NewTicker(1 * time.Second)
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

		const (
			ErrRateHigh = 0.01
			ErrRateLow  = 0.001
			RttHigh     = 1500 * time.Millisecond
		)

		if ErrRate > ErrRateHigh || AvgLatency > RttHigh {
			Ssthresh = CurRps / 2.0
			if Ssthresh < MinRps {
				Ssthresh = MinRps
			}

			NewRps = CurRps * 0.5
			if NewRps < MinRps {
				NewRps = MinRps
			}

			SlowStart = true

			fmt.Printf("[auto] CONGESTION: errRate=%.4f avgLatency=%v -> cut RPS to %.1f, ssthresh=%.1f\n",
				ErrRate, AvgLatency, NewRps, Ssthresh)
		} else {
			if SlowStart && CurRps < Ssthresh {
				NewRps = CurRps * 2

				if NewRps > Ssthresh {
					NewRps = Ssthresh
				}
				fmt.Printf("[auto] slowStart: Rps to %.1f\n", NewRps)

				if NewRps >= Ssthresh {
					SlowStart = false
				}

			} else {
				step := CurRps * 0.1
				if step < 5 {
					step = 5
				}

				NewRps = CurRps + step
				fmt.Printf("[auto] congestion-avoid: RPS to %.1f (+%.1f)\n", NewRps, step)

			}
		}

		//if ErrRate < 0.001 && AvgLatency < 1000*time.Millisecond {
		//NewRps *= 2.0
		//} else if ErrRate > 0.01 && AvgLatency > 3*time.Second {
		//NewRps *= 0.5
		//} else if ErrRate > 0.3 && AvgLatency > 3*time.Second {
		//NewRps *= 0.3
		//}

		if NewRps < MinRps {
			NewRps = MinRps
		}
		if NewRps > MaxRps {
			NewRps = MaxRps
		}

		if NewRps != CurRps {
			CurRps = NewRps
			Limiter.SetLimit(rate.Limit(CurRps))

			fmt.Printf("[auto] RPS change to %.1f ErrRate=%.2f AvgLatency=%v)\n", CurRps, ErrRate, AvgLatency)
		}
	}
}
