package basework

import(
	"net/http"
)

func CGETreq(finalpath string)(*http.Request, error){
	req, err := http.NewRequest("GET", finalpath, nil)
	CheckErr(err)

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0")

	return req, err
}