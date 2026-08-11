package authflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

func NewPKCE() (verifier, challenge string, err error) {
	verifier = randomString(64)
	if verifier == "" {
		return "", "", errors.New("generate PKCE verifier")
	}
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func Refresh(ctx context.Context, endpoint, clientID, refreshToken string) (Token, error) {
	return RefreshWithClient(ctx, http.DefaultClient, endpoint, clientID, refreshToken)
}

func RefreshWithClient(ctx context.Context, client *http.Client, endpoint, clientID, refreshToken string) (Token, error) {
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(refreshToken) == "" {
		return Token{}, errors.New("client ID and refresh token are required")
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return Token{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Token{}, fmt.Errorf("OAuth token refresh returned %d", response.StatusCode)
	}
	var token Token
	if json.NewDecoder(response.Body).Decode(&token) != nil || token.AccessToken == "" {
		return Token{}, errors.New("invalid OAuth token response")
	}
	if token.RefreshToken == "" {
		token.RefreshToken = refreshToken
	}
	return token, nil
}

// Revoke invalidates the longest-lived available session token at GenAuth.
// The CLI is a public PKCE client, so client_id is sent without a client
// secret. GenAuth's RFC 7009 endpoint also revokes the associated terminal
// session.
func Revoke(ctx context.Context, endpoint, clientID string, token Token) error {
	return RevokeWithClient(ctx, http.DefaultClient, endpoint, clientID, token)
}

func RevokeWithClient(ctx context.Context, client *http.Client, endpoint, clientID string, token Token) error {
	if strings.TrimSpace(clientID) == "" {
		return errors.New("client ID is required")
	}
	value, hint := strings.TrimSpace(token.RefreshToken), "refresh_token"
	if value == "" {
		value, hint = strings.TrimSpace(token.AccessToken), "access_token"
	}
	if value == "" {
		return errors.New("session token is required")
	}
	form := url.Values{
		"client_id":       {clientID},
		"token":           {value},
		"token_type_hint": {hint},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/oidc/token/revocation", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("OAuth token revocation returned %d", response.StatusCode)
	}
	return nil
}

func Login(ctx context.Context, endpoint, clientID, userPoolID string, noBrowser bool, notify func(string)) (Token, error) {
	return LoginWithClient(ctx, http.DefaultClient, endpoint, clientID, userPoolID, noBrowser, notify)
}

func LoginWithClient(ctx context.Context, client *http.Client, endpoint, clientID, userPoolID string, noBrowser bool, notify func(string)) (Token, error) {
	if strings.TrimSpace(clientID) == "" {
		return Token{}, errors.New("client ID is required for browser login")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Token{}, err
	}
	defer listener.Close()
	redirectURI := "http://" + listener.Addr().String() + "/callback"
	state, verifier := randomString(32), randomString(64)
	if state == "" || verifier == "" {
		return Token{}, errors.New("generate OAuth state")
	}
	digest := sha256.Sum256([]byte(verifier))
	parameters := url.Values{"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"}, "scope": {"openid profile offline_access"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
	if strings.TrimSpace(userPoolID) != "" {
		parameters.Set("user_pool_id", userPoolID)
	}
	authorizeURL := strings.TrimRight(endpoint, "/") + "/oidc/auth?" + parameters.Encode()
	notify(authorizeURL)
	if !noBrowser {
		_ = open(authorizeURL)
	}
	type callback struct{ code, state, oauthError string }
	result := make(chan callback, 1)
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(writer http.ResponseWriter, request *http.Request) {
		value := callback{code: request.URL.Query().Get("code"), state: request.URL.Query().Get("state"), oauthError: request.URL.Query().Get("error")}
		select {
		case result <- value:
		default:
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = writer.Write([]byte("Agent Identity CLI login received. You may close this window."))
	})
	go func() { _ = server.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	var received callback
	select {
	case <-ctx.Done():
		return Token{}, ctx.Err()
	case received = <-result:
	}
	if received.oauthError != "" || received.state != state || received.code == "" {
		return Token{}, errors.New("OAuth authorization was denied or invalid")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {received.code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return Token{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Token{}, fmt.Errorf("OAuth token exchange returned %d", response.StatusCode)
	}
	var token Token
	if json.NewDecoder(response.Body).Decode(&token) != nil || token.AccessToken == "" {
		return Token{}, errors.New("invalid OAuth token response")
	}
	return token, nil
}

func randomString(size int) string {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(buffer)
}

func open(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	return command.Start()
}

// Open launches a trusted URL using the platform browser without invoking a shell.
func Open(target string) error { return open(target) }
