package remoteconfig

import (
	"bytes"
	"encoding/json"
	"strings"
)

// uniqueConfigFields rejects ambiguous top-level member names before the
// standard decoder applies its last-value-wins field matching. EqualFold
// mirrors encoding/json's case-insensitive struct field matching.
func uniqueConfigFields(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}

	seen := make([]string, 0, 4)
	for decoder.More() {
		keyToken, tokenErr := decoder.Token()
		key, ok := keyToken.(string)
		if tokenErr != nil || !ok {
			return false
		}
		for _, previous := range seen {
			if strings.EqualFold(previous, key) {
				return false
			}
		}
		seen = append(seen, key)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}
	end, err := decoder.Token()
	return err == nil && end == json.Delim('}')
}
