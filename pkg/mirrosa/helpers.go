package mirrosa

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

func GetJsonBytes(rule interface{}, log *slog.Logger) ([]byte, error) {
	jsonOutput, err := json.Marshal(rule)
	if err != nil && log != nil {
		log.Debug("Error mashalling SecurityGroup json", slog.String("error", fmt.Sprintf("%v", err)))
	}
	if jsonOutput == nil {
		jsonOutput = []byte{}
	}
	return jsonOutput, err
}
