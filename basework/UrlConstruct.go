package basework

import (
	"bufio"
	"os"
)

func UrlConstruct(urlStr string, filename string) (<-chan string, error) {
	out := make(chan string, 100) // 缓冲通道
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	//base, err := url.Parse(urlStr)
	//if err != nil{
	//	log.Printf("error:%v",err)
	//	return nil
	//}
	go func() {
		defer file.Close()
		defer close(out)
		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				out <- urlStr + line
			}
		}
	}()

	return out, nil
}
