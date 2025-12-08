package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"
	"vidar-scan/basework"

	"github.com/panjf2000/ants/v2"
)

func PortScan(targetIp string, BeginPort int, EndPort int) []int {
	var wg sync.WaitGroup
	var mu sync.Mutex

	basework.InitAdaptiveLimiter(100)

	const srcPort = 56789

	scanner, err := basework.NewSynScanner(targetIp, srcPort)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer scanner.Close()

	concurrencylimit := 1000
	//rateLimit := 3 * time.Millisecond
	var ports []int

	workerfunc := func(data interface{}) {
		defer wg.Done()

		p := data.(int)
		basework.Limiter.Wait(context.Background())

		//time.Sleep(rateLimit)

		start := time.Now()
		//task := func() bool { return basework.TcpConnect(targetIp, p, 3*time.Second) }
		state := scanner.ScanPort(uint16(p), 1000*time.Millisecond)
		latency := time.Since(start)
		var err error

		switch state {
		case "open", "close":
			err = nil
		default:
			err = fmt.Errorf("unexpected state: %s", state)
			//fmt.Println(err)
		}

		basework.RecordResult(err, latency)

		//result := basework.RetryWithBool(3, 500*time.Millisecond, task)

		if state == "open" {
			mu.Lock()
			ports = append(ports, p)
			mu.Unlock()

			fmt.Printf("[OPEN] %d\n", p)
		}
	}

	pool, err := ants.NewPoolWithFunc(concurrencylimit, workerfunc)

	if err != nil {
		fmt.Println("error: %v", err)
	}

	fmt.Println("-----START-----")

	for port := BeginPort; port <= EndPort; port++ {
		wg.Add(1)

		err := pool.Invoke(port)
		if err != nil {
			fmt.Println("error: %v", err)
			wg.Done()
		}
	}

	wg.Wait()
	defer pool.Release()
	fmt.Println("-----OVER-----")

	return ports
}
