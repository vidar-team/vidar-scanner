package scanner

import (
	"fmt"
	"net/http"
	"sync"
	"time"
	"vidar-scan/basework"

	"github.com/panjf2000/ants/v2"
)

func Getscan(url string, filename string) {
	finalpath := basework.UrlConstruct(url, filename)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	var wg sync.WaitGroup

	concurrencylimit := 200

	sleeptime := 5000 * time.Millisecond

	workerfunc := func(data interface{}) {
		defer wg.Done()

		url := data.(string)

		basework.SendMessage(client, url)
		time.Sleep(sleeptime)
	}

	pool, err := ants.NewPoolWithFunc(concurrencylimit, workerfunc)
	if err != nil {
		fmt.Println("error: %v", err)
	}

	defer pool.Release()

	fmt.Println("-----START-----")
	for _, url = range finalpath {

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
