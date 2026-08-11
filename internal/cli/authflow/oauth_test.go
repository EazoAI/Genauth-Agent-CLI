package authflow

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRefreshUsesFormPostAndKeepsRefreshTokenWhenNotRotated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/oidc/token", request.URL.Path)
		require.Equal(t, "application/x-www-form-urlencoded", request.Header.Get("Content-Type"))
		body, _ := io.ReadAll(request.Body)
		require.Contains(t, string(body), "grant_type=refresh_token")
		require.Contains(t, string(body), "refresh_token=refresh-1")
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"access_token":"access-2","expires_in":3600}`))
	}))
	defer server.Close()
	token, err := Refresh(context.Background(), server.URL, "client-1", "refresh-1")
	require.NoError(t, err)
	require.Equal(t, "access-2", token.AccessToken)
	require.Equal(t, "refresh-1", token.RefreshToken)
}

func TestRevokePrefersRefreshTokenAndUsesPublicClientAuthentication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/oidc/token/revocation", request.URL.Path)
		require.NoError(t, request.ParseForm())
		require.Equal(t, "client-1", request.Form.Get("client_id"))
		require.Equal(t, "refresh-1", request.Form.Get("token"))
		require.Equal(t, "refresh_token", request.Form.Get("token_type_hint"))
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	require.NoError(t, Revoke(context.Background(), server.URL, "client-1", Token{AccessToken: "access-1", RefreshToken: "refresh-1"}))
}
