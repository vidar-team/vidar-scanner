package basework

import(
	"fmt"
	"net/http"
)

func SendMessage(client *http.Client, finalpath string){
	req, err := CGETreq(finalpath)
	
	if err != nil{
		fmt.Printf("[error]:%v\n",err)
		return
	}

	rep, err := client.Do(req)

	if err != nil{
		fmt.Printf("[error]:%v\n",err)
		return
	}

	defer rep.Body.Close()

	if rep.StatusCode != 404{
		fmt.Printf("[found] %-6d %s",rep.StatusCode, finalpath)
	}
}