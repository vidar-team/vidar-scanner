package basework

import(
	"bufio"
	"os"
	"fmt"
)

func LoadFile2List(filename string) ([]string, error){
	file, err := os.Open(filename)
	CheckErr(err)
	file.Close()

	scanner := bufio.NewScanner(file)

	var lines []string

	for scanner.Scan(){

		line := scanner.Text()

		if line != ""{
			lines = append(lines, line)
		}

		if err := scanner.Err(); err != nil{
			return nil, fmt.Errorf("error: %v",err)
		}

	}

	return lines, nil

}