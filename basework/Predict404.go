package basework

import (
	//"fmt"

	"errors"
	"fmt"
	"path/filepath"

	"github.com/rai-project/go-fasttext"
)

func Predict404(text string) (string, error) {
	relativePath := "src/model/model_404.bin"

	modelPath, err := filepath.Abs(relativePath)
	if err != nil {
		return "", fmt.Errorf("failed to load model: %v", err)
	}
	//fmt.Printf("Attempting to load model from: %s\n", modelPath)

	model := fasttext.Open(modelPath)
	defer model.Close()

	//fmt.Println(text)
	preds, err := model.Predict(text)
	if err != nil {
		return "", err
	}
	if preds == nil || len(preds) == 0 {
		return "", errors.New("no prediction")
	}
	//fmt.Println(preds)

	pred1, pred2 := preds[0], preds[1]
	if pred1.Probability > pred2.Probability {
		return pred1.Label, nil
	} else {
		return pred2.Label, nil
	}
}
