package scanner

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
	"vidar-scan/basework"

	"github.com/panjf2000/ants/v2"
)

func Getscan(url string, filename string) {
	finalChan, err := basework.UrlConstruct(url, filename)

	t := &http.Transport{
		//MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 500,
		//IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives: false,
	}

	client := &http.Client{
		Transport: t,
		Timeout:   10 * time.Second,
	}

	var wg sync.WaitGroup

	concurrencylimit := 4000

	basework.InitAdaptiveLimiter(30)
	//limiter := rate.NewLimiter(rate.Limit(rps), 1)
	//sleeptime := 500 * time.Millisecond

	workerfunc := func(data interface{}) {
		defer wg.Done()

		url := data.(string)

		//waitStart := time.Now()
		basework.Limiter.Wait(context.Background())
		//waitLatency := time.Since(waitStart)
		//fmt.Println("[DEBUG] wait latency:", waitLatency)

		start := time.Now()

		task := func() error {
			return basework.SendMessage(client, url)
		}

		err := basework.RetryWithError(3, 1*time.Second, task)
		latency := time.Since(start)
		basework.RecordResult(err, latency)
		//time.Sleep(sleeptime)
	}

	pool, err := ants.NewPoolWithFunc(concurrencylimit, workerfunc)
	if err != nil {
		fmt.Println("error: %v", err)
	}

	defer pool.Release()

	fmt.Println("-----START-----")
	for url := range finalChan {

		wg.Add(1)

		err := pool.Invoke(url)
		if err != nil {
			fmt.Println("error: %v", err)
			wg.Done()
		}
	}

	wg.Wait()

	fmt.Println("-----OVER-----")

}
