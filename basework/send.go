package basework

import (
	"fmt"
	"io"
	"net/http"
)

func SendMessage(client *http.Client, finalpath string) error {
	req, err := CGETreq(finalpath)

	if err != nil {
		fmt.Printf("[error]:%v\n", err)
		return err
	}

	rep, err := client.Do(req)

	if err != nil {
		//fmt.Printf("[error]:%v\n", err)
		return err
	}

	io.Copy(io.Discard, rep.Body)
	defer rep.Body.Close()

	//if rep.StatusCode == 200 || rep.StatusCode == 302 {
	if rep.StatusCode != 404 {
		fmt.Printf("[found] %-6d %s\n", rep.StatusCode, finalpath)
	}
	return nil
}
