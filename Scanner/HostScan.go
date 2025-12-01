package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
	"vidar-scan/basework"

	"github.com/panjf2000/ants/v2"
)

// IPv4 转 uint32
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 |
		uint32(ip[1])<<16 |
		uint32(ip[2])<<8 |
		uint32(ip[3])
}

// uint32 转 IPv4
func Uint32ToIP(n uint32) net.IP {
	return net.IPv4(
		byte(n>>24),
		byte(n>>16),
		byte(n>>8),
		byte(n),
	)
}

func HostScan(StartIP string, EndIP string) {
	var wg sync.WaitGroup
	fmt.Println("-----START-----")

	concurrencylimit := 2000
	basework.InitAdaptiveLimiter(100)

	scanfunc := func(data interface{}) {
		defer wg.Done()

		ip := Uint32ToIP(data.(uint32)).String()
		task := func() bool { return basework.IsAliveTCP(ip, 1000*time.Millisecond) }

		basework.Limiter.Wait(context.Background())

		start := time.Now()
		result := basework.RetryWithBool(3, 2*time.Second, task)

		latency := time.Since(start)
		var err error

		if latency >= 2000*time.Millisecond {
			err = fmt.Errorf("too slow")
		}

		basework.RecordResult(err, latency)

		if result {
			fmt.Printf("[Alive] %s\n", ip)
		}
	}

	pool, err := ants.NewPoolWithFunc(concurrencylimit, scanfunc)

	if err != nil {
		fmt.Println("error: %v", err)
	}

	defer pool.Release()

	for ip := IPToUint32(net.ParseIP(StartIP)); ip <= IPToUint32(net.ParseIP(EndIP)); ip++ {
		//fmt.Println(Uint32ToIP(ip).string())
		wg.Add(1)

		err := pool.Invoke(ip)

		if err != nil {
			fmt.Println("error: %v", err)
			wg.Done()
		}
	}

	wg.Wait()
	fmt.Println("-----OVER-----")
}
