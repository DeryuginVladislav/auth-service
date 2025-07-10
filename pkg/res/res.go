package res

import (
	"encoding/json"
	"net/http"
)

func MakeJson(w http.ResponseWriter, s any, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(s)
}
