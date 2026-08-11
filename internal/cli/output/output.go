package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const APIVersion = "agent-identity.cli/v1"

var formatState = struct {
	sync.RWMutex
	value string
}{value: "json"}

func SetFormat(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value != "json" && value != "yaml" && value != "table" {
		return fmt.Errorf("output must be table, json, or yaml")
	}
	formatState.Lock()
	formatState.value = value
	formatState.Unlock()
	return nil
}

func currentFormat() string {
	formatState.RLock()
	defer formatState.RUnlock()
	return formatState.value
}

type Success struct {
	APIVersion string   `json:"api_version" yaml:"api_version"`
	Kind       string   `json:"kind" yaml:"kind"`
	Data       any      `json:"data" yaml:"data"`
	RequestID  string   `json:"request_id,omitempty" yaml:"request_id,omitempty"`
	Warnings   []string `json:"warnings" yaml:"warnings"`
}

type Failure struct {
	APIVersion string `json:"api_version" yaml:"api_version"`
	Error      struct {
		Code        string         `json:"code"`
		Message     string         `json:"message"`
		Remediation map[string]any `json:"remediation,omitempty"`
	} `json:"error" yaml:"error"`
	RequestID string `json:"request_id,omitempty" yaml:"request_id,omitempty"`
}

func WriteSuccess(writer io.Writer, kind string, data any, requestID string) error {
	return WriteSuccessWithWarnings(writer, kind, data, requestID, nil)
}

func WriteSuccessWithWarnings(writer io.Writer, kind string, data any, requestID string, warnings []string) error {
	if warnings == nil {
		warnings = []string{}
	}
	result := Success{APIVersion: APIVersion, Kind: kind, Data: normalize(data), RequestID: requestID, Warnings: warnings}
	switch currentFormat() {
	case "yaml":
		encoded, err := yaml.Marshal(result)
		if err != nil {
			return err
		}
		_, err = writer.Write(encoded)
		return err
	case "table":
		_, err := fmt.Fprintf(writer, "KIND\t%s\n", kind)
		if err != nil {
			return err
		}
		if requestID != "" {
			if _, err := fmt.Fprintf(writer, "REQUEST_ID\t%s\n", requestID); err != nil {
				return err
			}
		}
		writeTable(writer, "DATA", result.Data)
		for _, warning := range result.Warnings {
			if _, err := fmt.Fprintf(writer, "WARNING\t%s\n", warning); err != nil {
				return err
			}
		}
		return nil
	default:
		return json.NewEncoder(writer).Encode(result)
	}
}

func normalize(value any) any {
	if raw, ok := value.(json.RawMessage); ok && json.Valid(raw) {
		var decoded any
		if json.Unmarshal(raw, &decoded) == nil {
			return decoded
		}
	}
	return value
}

func writeTable(writer io.Writer, prefix string, value any) {
	value = normalize(value)
	switch item := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			writeTable(writer, key, item[key])
		}
	default:
		encoded, _ := json.Marshal(item)
		_, _ = fmt.Fprintf(writer, "%s\t%s\n", strings.ToUpper(prefix), strings.Trim(string(encoded), `"`))
	}
}

func WriteFailure(writer io.Writer, code, message, requestID string, remediation map[string]any) {
	result := Failure{APIVersion: APIVersion, RequestID: requestID}
	result.Error.Code, result.Error.Message, result.Error.Remediation = code, message, remediation
	if err := json.NewEncoder(writer).Encode(result); err != nil {
		_, _ = fmt.Fprintf(writer, "agent-identity: %s\n", message)
	}
}
