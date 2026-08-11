package apiclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type APIError struct {
	Status     int
	Code       string
	Message    string
	RequestID  string
	RetryAfter time.Duration
}

func (e *APIError) Error() string { return e.Message }

type Client struct {
	Endpoint, SessionToken, UserPoolID string
	RequestID                          string
	HTTP                               *http.Client
}

func New(endpoint, token, userPoolID string, timeout time.Duration) *Client {
	return &Client{Endpoint: strings.TrimRight(endpoint, "/"), SessionToken: token, UserPoolID: userPoolID, HTTP: &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body any, headers map[string]string) (json.RawMessage, string, error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "://") {
		return nil, "", errors.New("invalid API path")
	}
	var encodedBody []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, "", err
		}
		encodedBody = encoded
	}
	target := c.Endpoint + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	maxAttempts := 1
	if method == http.MethodGet || method == http.MethodHead || strings.TrimSpace(headers["Idempotency-Key"]) != "" {
		maxAttempts = 3
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var payload io.Reader
		if encodedBody != nil {
			payload = bytes.NewReader(encodedBody)
		}
		request, err := http.NewRequestWithContext(ctx, method, target, payload)
		if err != nil {
			return nil, "", err
		}
		if c.SessionToken != "" {
			request.Header.Set("Authorization", "Bearer "+c.SessionToken)
		}
		if c.UserPoolID != "" {
			request.Header.Set("x-authing-userpool-id", c.UserPoolID)
		}
		if c.RequestID != "" {
			request.Header.Set("X-Request-Id", c.RequestID)
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, err := c.HTTP.Do(request)
		if err != nil {
			if attempt+1 < maxAttempts && waitRetry(ctx, attempt) == nil {
				continue
			}
			return nil, "", err
		}
		requestID := response.Header.Get("X-Request-Id")
		content, err := io.ReadAll(io.LimitReader(response.Body, 52*1024*1024))
		_ = response.Body.Close()
		if err != nil {
			return nil, requestID, err
		}
		if attempt+1 < maxAttempts && (response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusBadGateway || response.StatusCode == http.StatusServiceUnavailable || response.StatusCode == http.StatusGatewayTimeout) {
			if waitRetry(ctx, attempt) == nil {
				continue
			}
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			var envelope struct {
				Error struct {
					Code, Message, RequestID string
				} `json:"error"`
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			_ = json.Unmarshal(content, &envelope)
			code, message := envelope.Error.Code, envelope.Error.Message
			if code == "" {
				code, message = envelope.Code, envelope.Message
			}
			if code == "" {
				code, message = "HTTP_ERROR", http.StatusText(response.StatusCode)
			}
			if envelope.Error.RequestID != "" {
				requestID = envelope.Error.RequestID
			}
			return nil, requestID, &APIError{Status: response.StatusCode, Code: code, Message: message, RequestID: requestID, RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"))}
		}
		return json.RawMessage(content), requestID, nil
	}
	return nil, "", errors.New("request retry exhausted")
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := time.ParseDuration(value + "s"); err == nil && seconds > 0 {
		return seconds
	}
	if target, err := http.ParseTime(value); err == nil {
		if delay := time.Until(target); delay > 0 {
			return delay
		}
	}
	return 0
}

func waitRetry(ctx context.Context, attempt int) error {
	base := 100 * time.Millisecond * time.Duration(1<<attempt)
	jitter := time.Duration(rand.IntN(100)) * time.Millisecond
	timer := time.NewTimer(base + jitter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) RuntimeToken(ctx context.Context, credentialID, secret, userGrantID, audience string, permissions []string, ttl int) (json.RawMessage, string, error) {
	auth := base64.StdEncoding.EncodeToString([]byte(credentialID + ":" + secret))
	return c.Do(ctx, http.MethodPost, "/api/v3/agent-runtime/token", nil, map[string]any{"user_grant_id": userGrantID, "audience": audience, "permission_ids": permissions, "token_ttl_seconds": ttl}, map[string]string{"Authorization": "Basic " + auth})
}

func DecodeData(raw json.RawMessage, target any) error {
	current := raw
	for range 3 {
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(current, &envelope) != nil || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
			break
		}
		current = envelope.Data
	}
	if err := json.Unmarshal(current, target); err != nil {
		return fmt.Errorf("decode API response: %w", err)
	}
	return nil
}
