package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSuccessOutputFormatsKeepStableEnvelope(t *testing.T) {
	t.Cleanup(func() { require.NoError(t, SetFormat("json")) })
	for _, format := range []string{"json", "yaml", "table"} {
		t.Run(format, func(t *testing.T) {
			require.NoError(t, SetFormat(format))
			var buffer bytes.Buffer
			require.NoError(t, WriteSuccess(&buffer, "Agent", map[string]any{"id": "agt-1", "status": "ACTIVE"}, "req-1"))
			switch format {
			case "json":
				var envelope Success
				require.NoError(t, json.Unmarshal(buffer.Bytes(), &envelope))
				require.Equal(t, APIVersion, envelope.APIVersion)
				require.Equal(t, "Agent", envelope.Kind)
			case "yaml":
				var envelope map[string]any
				require.NoError(t, yaml.Unmarshal(buffer.Bytes(), &envelope))
				require.Equal(t, APIVersion, envelope["api_version"])
				require.Equal(t, "Agent", envelope["kind"])
			case "table":
				require.Contains(t, buffer.String(), "KIND\tAgent")
				require.Contains(t, buffer.String(), "ID\tagt-1")
				require.Contains(t, buffer.String(), "STATUS\tACTIVE")
			}
		})
	}
}

func TestFailureNeverLeaksRemediationWhenAbsent(t *testing.T) {
	var buffer bytes.Buffer
	WriteFailure(&buffer, "FORBIDDEN", "not allowed", "req-1", nil)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(buffer.Bytes(), &envelope))
	require.Equal(t, APIVersion, envelope["api_version"])
	require.NotContains(t, envelope["error"].(map[string]any), "remediation")
}
