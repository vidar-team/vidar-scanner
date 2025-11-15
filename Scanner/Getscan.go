package scanner

import(
	"fmt"
	"vidar-scan/basework"
	"sync"
	"net/http"
	"time"
	
)

func Getscan(url string, filename string){
	finalpath := basework.UrlConstruct(url, filename)

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	var wg sync.WaitGroup

	ratelimit := 1000
	
	limitch := make(chan struct{}, ratelimit)

	fmt.Println("-----START-----")

	for _, url = range finalpath{
		limitch <- struct{}{}

		wg.Add(1)

		go func(url string){
			defer wg.Done()

			defer func(){<-limitch}()

			basework.SendMessage(client, url)

		}(url)
	}

	wg.Wait()

	fmt.Println("-----OVER-----")


}