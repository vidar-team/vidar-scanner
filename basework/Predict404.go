package basework

import (
	//"fmt"

	"github.com/rai-project/go-fasttext"
)

func Predict404(text string) (string, error) {
	modelPath := "./src/model/model_404.bin"
	model := fasttext.Open(modelPath)
	defer model.Close()

	preds, err := model.Predict(text)
	if err != nil {
		return "", err
	}

	//fmt.Println(preds)

	pred1, pred2 := preds[0], preds[1]
	if pred1.Probability > pred2.Probability {
		return pred1.Label, nil
	} else {
		return pred2.Label, nil
	}
}
