package basework

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func SendMessage(client *http.Client, finalpath string, cookie string) error {
	//fmt.Println(finalpath)
	req, err := CGETreq(finalpath, cookie)
	var result strings.Builder

	if err != nil {
		//fmt.Printf("[error]:%v\n", err)
		return err
	}

	rep, err := client.Do(req)

	if err != nil {
		//fmt.Printf("[error]:%v\n", err)
		return err
	}

	io.Copy(&result, io.LimitReader(rep.Body, 4096))
	output, err := HTMLPreprocess(result.String())

	if err != nil {
		return err
	}

	defer rep.Body.Close()

	code := rep.StatusCode

	fmt.Println(code)
	switch {

	case code >= 200 && code < 300:
		fmt.Println("请求成功")

	case code >= 300 && code < 400:
		return nil

	case code >= 400 && code < 500:
		return nil

	case code >= 500 && code < 600:
		return nil

	default:
		return nil
	}

	if label, err := Predict404(output); err == nil && label != "__label__404" {
		fmt.Printf("[found] %-6d %s\n", rep.StatusCode, finalpath)
	}

	return nil
}
