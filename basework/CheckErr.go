package basework

import "fmt"
import "os"

func CheckErr(err error){
	if err != nil{
		fmt.Printf("error: %v\n",err)
		os.Exit(1)
	}
}