package apiclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRuntimeTokenUsesBasicOnlyAgainstConfiguredGenAuth(t *testing.T) {
	var authorization, userPool string
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("Authorization")
		userPool = request.Header.Get("x-authing-userpool-id")
		require.Equal(t, "/api/v3/agent-runtime/token", request.URL.Path)
		require.NoError(t, json.NewDecoder(request.Body).Decode(&body))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"access_token":"jwt"}`))
	}))
	defer server.Close()
	client := New(server.URL, "human-session-token", "pool-1", time.Second)
	raw, _, err := client.RuntimeToken(context.Background(), "aic_123", "secret-value", "ugr-1", "https://api.example.com", nil, 0)
	require.NoError(t, err)
	require.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("aic_123:secret-value")), authorization)
	require.Equal(t, "pool-1", userPool)
	require.NotContains(t, body, "user_pool_id")
	require.True(t, json.Valid(raw))
}

func TestDoRejectsAbsolutePaths(t *testing.T) {
	client := New("https://genauth.example.com", "token", "pool-1", time.Second)
	_, _, err := client.Do(context.Background(), http.MethodGet, "https://evil.example.com", nil, nil, nil)
	require.Error(t, err)
}

func TestDoRetriesSafeAndIdempotentRequestsOnly(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if requests < 3 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client := New(server.URL, "token", "pool-1", 3*time.Second)
	_, _, err := client.Do(context.Background(), http.MethodGet, "/safe", nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, 3, requests)

	requests = 0
	_, _, err = client.Do(context.Background(), http.MethodPost, "/unsafe", nil, map[string]any{"value": 1}, nil)
	require.Error(t, err)
	require.Equal(t, 1, requests)

	requests = 0
	_, _, err = client.Do(context.Background(), http.MethodPost, "/idempotent", nil, map[string]any{"value": 1}, map[string]string{"Idempotency-Key": "key-1"})
	require.NoError(t, err)
	require.Equal(t, 3, requests)
}
