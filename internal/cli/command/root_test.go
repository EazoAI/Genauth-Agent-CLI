package command

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Authing/genauth-agent-cli/internal/cli/authflow"
	"github.com/Authing/genauth-agent-cli/internal/cli/profile"
	"github.com/stretchr/testify/require"
)

type memorySecrets map[string]string

func (s memorySecrets) Set(reference, value string) error    { s[reference] = value; return nil }
func (s memorySecrets) Get(reference string) (string, error) { return s[reference], nil }
func (s memorySecrets) Delete(reference string) error        { delete(s, reference); return nil }

type deleteFailingSecrets struct{ memorySecrets }

func (s deleteFailingSecrets) Delete(string) error { return errors.New("keyring unavailable") }

type setFailingSecrets struct{ memorySecrets }

func (s setFailingSecrets) Set(string, string) error { return errors.New("keyring unavailable") }

type failNthSetSecrets struct {
	memorySecrets
	setCalls int
	failAt   int
}

func (s *failNthSetSecrets) Set(reference, value string) error {
	s.setCalls++
	if s.setCalls == s.failAt {
		return errors.New("keyring unavailable")
	}
	s.memorySecrets[reference] = value
	return nil
}

func TestCredentialSecretRequiresAcknowledgementForAllMachineReadableOutput(t *testing.T) {
	for _, format := range []string{"json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			app := &App{outputFormat: format}
			err := app.createCredential(context.Background(), "agent-1", "", false, false, true, false)
			var exit *ExitError
			require.ErrorAs(t, err, &exit)
			require.Equal(t, "SECRET_OUTPUT_ACKNOWLEDGEMENT_REQUIRED", exit.Code)
		})
	}
}

func TestCapabilityDraftCanBeCreatedOrUpdatedAfterAgentCreation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, http.MethodPut, request.Method)
		require.Equal(t, "/api/v3/agent-identity/admin/agents/agent-1/capability-grant/draft", request.URL.Path)
		var body map[string]any
		require.NoError(t, json.NewDecoder(request.Body).Decode(&body))
		require.Equal(t, "https://api.example.com/orders", body["audience"])
		require.Equal(t, float64(3), body["version"])
		require.ElementsMatch(t, []any{"orders.read", "orders.write"}, body["data_policy_ids"])
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"id":"capability-1","version":4,"status":"draft"}}`))
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/admin"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "admin", Profiles: map[string]profile.Profile{"admin": {Endpoint: server.URL, LoginType: "tenant_admin", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))
	stdout := &bytes.Buffer{}
	app := &App{Profiles: store, Secrets: memorySecrets{sessionRef: `{"access_token":"session"}`}, In: bytes.NewBuffer(nil), Out: stdout, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"agents", "capability", "update", "--agent-id", "agent-1", "--audience", "https://api.example.com/orders", "--permission-id", "orders.read,orders.write", "--version", "3"})
	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), "capability-1")
}

func TestAgentCreateReportsRecoverablePartialSuccessWhenCapabilityDraftFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v3/agent-identity/admin/agents":
			_, _ = writer.Write([]byte(`{"data":{"id":"agent-created","version":1}}`))
		case request.Method == http.MethodPut && request.URL.Path == "/api/v3/agent-identity/admin/agents/agent-created/capability-grant/draft":
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"error":{"code":"DEPENDENCY_UNAVAILABLE","message":"permission catalog unavailable"}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/admin"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "admin", Profiles: map[string]profile.Profile{"admin": {Endpoint: server.URL, LoginType: "tenant_admin", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))
	app := &App{Profiles: store, Secrets: memorySecrets{sessionRef: `{"access_token":"session"}`}, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second, nonInteractive: true}
	root := app.Root()
	root.SetArgs([]string{"agents", "create", "--identifier", "order_agent", "--display-name", "Order Agent", "--owner-user-id", "owner-1", "--application-id", "app-1", "--audience", "https://api.example.com/orders", "--permission-id", "orders.read"})
	err = root.Execute()
	var exit *ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "PARTIAL_AGENT_CREATE", exit.Code)
	require.Equal(t, "agent-created", exit.Remediation["agent_id"])
	require.Equal(t, "DEPENDENCY_UNAVAILABLE", exit.Remediation["cause_code"])
	require.Contains(t, exit.Remediation["next_command"], "agents capability update --agent-id agent-created")
}

func TestCredentialRevokeDeletesLocalSecretOnlyAfterRemoteSuccess(t *testing.T) {
	var status = http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/api/v3/agent-identity/admin/agents/agent-1/credentials/credential-1/revoke", request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = writer.Write([]byte(`{"data":{"credential_id":"credential-1","status":"REVOKED"}}`))
			return
		}
		_, _ = writer.Write([]byte(`{"error":{"code":"CONFLICT","message":"not revoked"}}`))
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/admin"
	credentialRef := "keychain://agent-identity/credential/credential-1"
	secrets := memorySecrets{sessionRef: `{"access_token":"session"}`, credentialRef: `{"credential_id":"credential-1","client_secret":"secret"}`}
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "admin", Profiles: map[string]profile.Profile{"admin": {Endpoint: server.URL, LoginType: "tenant_admin", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))

	run := func() error {
		app := &App{Profiles: store, Secrets: secrets, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}
		root := app.Root()
		root.SetArgs([]string{"credentials", "revoke", "--agent-id", "agent-1", "--credential-id", "credential-1", "--yes"})
		return root.Execute()
	}

	require.NoError(t, run())
	_, exists := secrets[credentialRef]
	require.False(t, exists)

	secrets[credentialRef] = `{"credential_id":"credential-1","client_secret":"secret"}`
	status = http.StatusConflict
	require.Error(t, run())
	_, exists = secrets[credentialRef]
	require.True(t, exists)
}

func TestCredentialCreateConsumesSnakeCaseSecretAndStoresItSafely(t *testing.T) {
	var humanSession string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v3/agent-identity/admin/agents/agent-1/credentials":
			humanSession = request.Header.Get("X-Human-Session-Id")
			require.NotEmpty(t, humanSession)
			_, _ = writer.Write([]byte(`{"data":{"credential":{"credential_id":"credential-1","expires_at":"2026-08-12T00:00:00Z"},"delivery":{"delivery_id":"delivery-1","delivery_code":"one-time-code","expires_in":60}}}`))
		case "/api/v3/agent-identity/admin/credential-deliveries/delivery-1/consume":
			require.Equal(t, humanSession, request.Header.Get("X-Human-Session-Id"))
			var body map[string]string
			require.NoError(t, json.NewDecoder(request.Body).Decode(&body))
			require.Equal(t, "one-time-code", body["delivery_code"])
			_, _ = writer.Write([]byte(`{"data":{"credential_id":"credential-1","client_secret":"delivered-secret"}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/admin"
	credentialRef := "keychain://agent-identity/credential/credential-1"
	secrets := memorySecrets{sessionRef: `{"access_token":"session"}`}
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "admin", Profiles: map[string]profile.Profile{"admin": {Endpoint: server.URL, LoginType: "tenant_admin", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))
	stdout := &bytes.Buffer{}
	app := &App{Profiles: store, Secrets: secrets, In: bytes.NewBuffer(nil), Out: stdout, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"credentials", "create", "--agent-id", "agent-1"})
	require.NoError(t, root.Execute())
	require.JSONEq(t, `{"credential_id":"credential-1","client_secret":"delivered-secret"}`, secrets[credentialRef])
	require.Contains(t, stdout.String(), `"secret_ref":"keychain://agent-identity/credential/credential-1"`)
	require.NotContains(t, stdout.String(), "delivered-secret")
	require.NotContains(t, stdout.String(), "one-time-code")
}

func TestCredentialCreateRevokesNewCredentialWhenSecretStoreFails(t *testing.T) {
	var revoked bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v3/agent-identity/admin/agents/agent-1/credentials":
			_, _ = writer.Write([]byte(`{"data":{"credential":{"credential_id":"credential-1","expires_at":"2026-08-12T00:00:00Z"},"delivery":{"delivery_id":"delivery-1","delivery_code":"one-time-code","expires_in":60}}}`))
		case "/api/v3/agent-identity/admin/credential-deliveries/delivery-1/consume":
			_, _ = writer.Write([]byte(`{"data":{"credential_id":"credential-1","client_secret":"delivered-secret"}}`))
		case "/api/v3/agent-identity/admin/agents/agent-1/credentials/credential-1/revoke":
			revoked = true
			_, _ = writer.Write([]byte(`{"data":{"credential_id":"credential-1","status":"REVOKED"}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/admin"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "admin", Profiles: map[string]profile.Profile{"admin": {Endpoint: server.URL, LoginType: "tenant_admin", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))
	app := &App{Profiles: store, Secrets: setFailingSecrets{memorySecrets{sessionRef: `{"access_token":"session"}`}}, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"credentials", "create", "--agent-id", "agent-1"})
	err = root.Execute()
	var exit *ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "SECRET_STORE_UNAVAILABLE", exit.Code)
	require.True(t, revoked)
}

func TestCredentialRevokeReportsLocalSecretCleanupWarning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"credential_id":"credential-1","status":"REVOKED"}}`))
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/admin"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "admin", Profiles: map[string]profile.Profile{"admin": {Endpoint: server.URL, LoginType: "tenant_admin", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))
	stdout := &bytes.Buffer{}
	app := &App{Profiles: store, Secrets: deleteFailingSecrets{memorySecrets{sessionRef: `{"access_token":"session"}`}}, In: bytes.NewBuffer(nil), Out: stdout, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"credentials", "revoke", "--agent-id", "agent-1", "--credential-id", "credential-1", "--yes"})
	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), `"warnings":["credential was revoked, but its local OS secret-store entry could not be removed"]`)
}

func TestUserGrantListUsesMeRouteAndSelectedUserPool(t *testing.T) {
	var path, authorization, userPool string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path = request.URL.Path
		authorization = request.Header.Get("Authorization")
		userPool = request.Header.Get("x-authing-userpool-id")
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	reference := "keychain://agent-identity/session/user"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "user", Profiles: map[string]profile.Profile{"user": {Endpoint: server.URL, LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: reference}}}))
	encoded, _ := json.Marshal(authflow.Token{AccessToken: "session-token"})
	stdout := &bytes.Buffer{}
	app := &App{Profiles: store, Secrets: memorySecrets{reference: string(encoded)}, In: bytes.NewBuffer(nil), Out: stdout, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"authorizations", "list-grants"})
	require.NoError(t, root.Execute())
	require.Equal(t, "/api/v3/agent-identity/me/agent-user-grants", path)
	require.Equal(t, "Bearer session-token", authorization)
	require.Equal(t, "pool-1", userPool)
	require.Contains(t, stdout.String(), `"kind":"UserGrantList"`)
}

func TestAuthStatusUsesServerIdentityContextInsteadOfAgentListProbe(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path = request.URL.Path
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"actor_id":"admin-1","actor_type":"TENANT_ADMIN","user_pool_id":"pool-1"}}`))
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	reference := "keychain://agent-identity/session/admin"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "admin", Profiles: map[string]profile.Profile{"admin": {Endpoint: server.URL, ClientID: "client-1", LoginType: "tenant_admin", SelectedUserPoolID: "pool-1", SecretRef: reference}}}))
	stdout := &bytes.Buffer{}
	app := &App{Profiles: store, Secrets: memorySecrets{reference: `{"access_token":"session"}`}, In: bytes.NewBuffer(nil), Out: stdout, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"auth", "status"})
	require.NoError(t, root.Execute())
	require.Equal(t, "/api/v3/agent-identity/admin/context", path)
	require.Contains(t, stdout.String(), `"actor_id":"admin-1"`)
}

func TestApprovalIDAndCorrelationIDAreUnambiguous(t *testing.T) {
	const correlationID = "1ab9ea4d-3b52-43a3-b6a0-730152080cef"
	const approvalID = "2bc8fb5e-4c63-44b4-a7b1-841263191df0"
	var path, requestID string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path = request.URL.Path
		requestID = request.Header.Get("X-Request-Id")
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"id":"` + approvalID + `"}}`))
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	reference := "keychain://agent-identity/session/admin"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "admin", Profiles: map[string]profile.Profile{"admin": {Endpoint: server.URL, LoginType: "tenant_admin", SelectedUserPoolID: "pool-1", SecretRef: reference}}}))
	app := &App{Profiles: store, Secrets: memorySecrets{reference: `{"access_token":"session"}`}, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"--correlation-id", correlationID, "approvals", "get", "--approval-id", approvalID})
	require.NoError(t, root.Execute())
	require.Equal(t, "/api/v3/agent-identity/admin/approvals/"+approvalID, path)
	require.Equal(t, correlationID, requestID)
}

func TestLogoutRevokesRemoteSessionBeforeDeletingLocalProfile(t *testing.T) {
	var revoked bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/oidc/token/revocation", request.URL.Path)
		require.NoError(t, request.ParseForm())
		require.Equal(t, "refresh-1", request.Form.Get("token"))
		revoked = true
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	reference := "keychain://agent-identity/session/user"
	secrets := memorySecrets{reference: `{"access_token":"access-1","refresh_token":"refresh-1"}`}
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "user", Profiles: map[string]profile.Profile{"user": {Endpoint: server.URL, ClientID: "client-1", LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: reference}}}))
	app := &App{Profiles: store, Secrets: secrets, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"auth", "logout"})
	require.NoError(t, root.Execute())
	require.True(t, revoked)
	_, exists := secrets[reference]
	require.False(t, exists)
	config, err := store.Load()
	require.NoError(t, err)
	require.NotContains(t, config.Profiles, "user")
}

func TestLogoutKeepsRemoteSuccessAndReportsSecretCleanupFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/oidc/token/revocation", request.URL.Path)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	reference := "keychain://agent-identity/session/user"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "user", Profiles: map[string]profile.Profile{"user": {Endpoint: server.URL, ClientID: "client-1", LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: reference}}}))
	stdout := &bytes.Buffer{}
	app := &App{Profiles: store, Secrets: deleteFailingSecrets{memorySecrets{reference: `{"access_token":"access-1","refresh_token":"refresh-1"}`}}, In: bytes.NewBuffer(nil), Out: stdout, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"auth", "logout"})
	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), `"warnings":["remote session was revoked and the local profile was removed, but its OS secret-store entry could not be removed"]`)
	config, err := store.Load()
	require.NoError(t, err)
	require.NotContains(t, config.Profiles, "user")
}

func TestExpiredHumanSessionRefreshesOnceAndRetriesOriginalRequest(t *testing.T) {
	var agentCalls, refreshCalls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/oidc/token":
			refreshCalls++
			require.NoError(t, request.ParseForm())
			require.Equal(t, "refresh-1", request.Form.Get("refresh_token"))
			_, _ = writer.Write([]byte(`{"access_token":"access-2","refresh_token":"refresh-2"}`))
		case "/api/v3/agent-identity/me/agents":
			agentCalls++
			if request.Header.Get("Authorization") == "Bearer access-1" {
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = writer.Write([]byte(`{"error":{"code":"SESSION_EXPIRED","message":"expired"}}`))
				return
			}
			require.Equal(t, "Bearer access-2", request.Header.Get("Authorization"))
			_, _ = writer.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	reference := "keychain://agent-identity/session/user"
	secrets := memorySecrets{reference: `{"access_token":"access-1","refresh_token":"refresh-1"}`}
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "user", Profiles: map[string]profile.Profile{"user": {Endpoint: server.URL, ClientID: "client-1", LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: reference}}}))
	app := &App{Profiles: store, Secrets: secrets, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"agents", "list"})
	require.NoError(t, root.Execute())
	require.Equal(t, 2, agentCalls)
	require.Equal(t, 1, refreshCalls)
	require.Contains(t, secrets[reference], "access-2")
	require.NotContains(t, secrets[reference], "access-1")
}

func TestAgentCreateAcceptsYAMLAndRequiresExplicitPermissionMerge(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			_, _ = writer.Write([]byte(`{"data":{"id":"agent-1","version":1}}`))
			return
		}
		var body map[string]any
		require.NoError(t, json.NewDecoder(request.Body).Decode(&body))
		require.Equal(t, "https://api.example.com/orders", body["audience"])
		require.ElementsMatch(t, []any{"orders.read"}, body["data_policy_ids"])
		_, _ = writer.Write([]byte(`{"data":{"id":"grant-1"}}`))
	}))
	defer server.Close()
	configDir := t.TempDir()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", configDir)
	inputPath := filepath.Join(configDir, "agent.yaml")
	require.NoError(t, os.WriteFile(inputPath, []byte("name: orders_agent\ndisplay_name: Orders Agent\napplication_id: app-1\ncapabilities:\n  - audience: https://api.example.com/orders\n    permissions:\n      - permission_id: orders.read\n"), 0o600))
	store, err := profile.NewStore()
	require.NoError(t, err)
	reference := "keychain://agent-identity/session/user"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "user", Profiles: map[string]profile.Profile{"user": {Endpoint: server.URL, LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: reference}}}))
	app := &App{Profiles: store, Secrets: memorySecrets{reference: `{"access_token":"session"}`}, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"--non-interactive", "agents", "create", "--file", inputPath})
	require.NoError(t, root.Execute())
	require.Equal(t, []string{"POST /api/v3/agent-identity/me/agents", "PUT /api/v3/agent-identity/me/agents/agent-1/capability-grant/draft"}, paths)

	root = app.Root()
	root.SetArgs([]string{"--non-interactive", "agents", "create", "--file", inputPath, "--permission-id", "orders.write"})
	err = root.Execute()
	var exit *ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "AMBIGUOUS_PERMISSION_MERGE", exit.Code)
}

func TestAuthorizationWaitConsumesBoundLoopbackCodeAndExchangesGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/authorization-requests/aur_wait"):
			_, _ = writer.Write([]byte(`{"data":{"status":"PENDING"}}`))
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/authorization-requests/aur_wait/exchange"):
			var body map[string]string
			require.NoError(t, json.NewDecoder(request.Body).Decode(&body))
			require.Equal(t, "callback-code", body["authorization_code"])
			require.Equal(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~", body["code_verifier"])
			_, _ = writer.Write([]byte(`{"data":{"user_grant":{"grant_id":"ugr-wait"}}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	callbackURI, err := newLoopbackRedirectURI()
	require.NoError(t, err)
	configDir := t.TempDir()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", configDir)
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/admin"
	secrets := memorySecrets{
		sessionRef: `{"access_token":"session"}`,
		"keychain://agent-identity/authorization/aur_wait/pkce":     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
		"keychain://agent-identity/authorization/aur_wait/callback": callbackURI,
	}
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "admin", Profiles: map[string]profile.Profile{"admin": {Endpoint: server.URL, LoginType: "tenant_admin", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))
	stdout := &bytes.Buffer{}
	app := &App{Profiles: store, Secrets: secrets, In: bytes.NewBuffer(nil), Out: stdout, Err: &bytes.Buffer{}, timeout: 3 * time.Second}
	done := make(chan error, 1)
	go func() {
		root := app.Root()
		root.SetArgs([]string{"authorizations", "wait", "--request-id", "aur_wait"})
		done <- root.Execute()
	}()
	time.Sleep(100 * time.Millisecond)
	callbackURL := callbackURI + "?request_id=aur_wait&code=callback-code"
	response, err := http.Get(callbackURL)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.NoError(t, <-done)
	require.Contains(t, stdout.String(), "ugr-wait")
	_, exists := secrets["keychain://agent-identity/authorization/aur_wait/pkce"]
	require.False(t, exists)
}

func TestUserAgentManagementUsesMeRoutesAndDoesNotRequireOwnerSelection(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			var body map[string]any
			require.NoError(t, json.NewDecoder(request.Body).Decode(&body))
			require.NotContains(t, body, "owner_user_id")
			_, _ = writer.Write([]byte(`{"data":{"id":"agent-1","version":1}}`))
			return
		}
		_, _ = writer.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	reference := "keychain://agent-identity/session/user"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "user", Profiles: map[string]profile.Profile{"user": {Endpoint: server.URL, LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: reference}}}))
	app := &App{Profiles: store, Secrets: memorySecrets{reference: `{"access_token":"session"}`}, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}

	root := app.Root()
	root.SetArgs([]string{"agents", "create", "--identifier", "orders_agent", "--display-name", "Orders Agent", "--application-id", "app-1"})
	require.NoError(t, root.Execute())
	root = app.Root()
	root.SetArgs([]string{"agents", "list"})
	require.NoError(t, root.Execute())

	require.Equal(t, []string{
		"POST /api/v3/agent-identity/me/agents",
		"GET /api/v3/agent-identity/me/agents",
	}, paths)
}

func TestAdminUserPoolSelectionUsesServerManageablePoolFacts(t *testing.T) {
	var selectedHeader string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		selectedHeader = request.Header.Get("x-authing-userpool-id")
		require.Equal(t, "/api/v3/agent-identity/admin/user-pools", request.URL.Path)
		require.Equal(t, "Bearer admin-session", request.Header.Get("Authorization"))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"list":[{"id":"pool-1"},{"id":"pool-2"}]}}`))
	}))
	defer server.Close()
	app := &App{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}

	selected, _, err := app.selectAdminUserPool(context.Background(), server.URL, "admin-session", "pool-2")
	require.NoError(t, err)
	require.Equal(t, "pool-2", selected)
	require.Empty(t, selectedHeader, "pool discovery must happen before a pool context is trusted")

	_, _, err = app.selectAdminUserPool(context.Background(), server.URL, "admin-session", "foreign-pool")
	var exit *ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "USER_POOL_NOT_MANAGEABLE", exit.Code)

	_, _, err = app.selectAdminUserPool(context.Background(), server.URL, "admin-session", "")
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "USER_POOL_SELECTION_REQUIRED", exit.Code)
}

func TestAPICallRejectsAmbiguousPathBeforeReadingCredentials(t *testing.T) {
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	app := &App{Profiles: store, Secrets: memorySecrets{}, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"api", "call", "--provider", "orders", "--path", "/../admin"})
	err = root.Execute()
	var exit *ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "INVALID_ARGUMENT", exit.Code)
}

func TestUserCannotRequestAnotherUserOrSilentAuthorization(t *testing.T) {
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	reference := "keychain://agent-identity/session/user"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "user", Profiles: map[string]profile.Profile{"user": {Endpoint: "http://127.0.0.1:12345", LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: reference}}}))
	app := &App{Profiles: store, Secrets: memorySecrets{reference: `{"access_token":"session"}`}, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"authorizations", "create", "--agent-id", "agent-1", "--audience", "orders", "--permission-id", "policy-1", "--user-id", "other"})
	err = root.Execute()
	var exit *ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "FORBIDDEN_USER_AUTHORIZATION_MODE", exit.Code)

	root = app.Root()
	root.SetArgs([]string{"authorizations", "create", "--agent-id", "agent-1", "--audience", "orders", "--permission-id", "policy-1", "--mode", "silent", "--yes"})
	err = root.Execute()
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "FORBIDDEN_USER_AUTHORIZATION_MODE", exit.Code)
}

func TestIrreversibleCommandsRequireExplicitConfirmation(t *testing.T) {
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	app := &App{Profiles: store, Secrets: memorySecrets{}, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"tokens", "revoke", "--agent-id", "agent-1", "--jti", "jti-1", "--reason", "incident"})
	err = root.Execute()
	var exit *ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "CONFIRMATION_REQUIRED", exit.Code)
}

func TestTokenInspectDoesNotClaimSignatureVerification(t *testing.T) {
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	stdout := &bytes.Buffer{}
	app := &App{Profiles: store, Secrets: memorySecrets{}, In: bytes.NewBufferString("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZ2VudC0xIn0.sig"), Out: stdout, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"tokens", "inspect", "--token-stdin"})
	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), `"signature_verified":false`)
	require.NotContains(t, stdout.String(), ".sig")
}

func TestExplicitAuthorizationUsesPKCEAndKeepsCodesInSecretStore(t *testing.T) {
	var challenge string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v3/agent-identity/me/agents/agent-1/authorization-requests":
			var body map[string]any
			require.NoError(t, json.NewDecoder(request.Body).Decode(&body))
			challenge, _ = body["pkce_challenge"].(string)
			require.Len(t, challenge, 43)
			require.Equal(t, "https://client.example.com/callback", body["redirect_uri"])
			_, _ = writer.Write([]byte(`{"data":{"request":{"request_id":"aur_request_1"}}}`))
		case request.Method == http.MethodPost && request.URL.Path == "/api/v3/agent-identity/me/authorization-requests/aur_request_1/consent":
			_, _ = writer.Write([]byte(`{"data":{"authorization_code":"ac_one_time_code","redirect_uri":"https://client.example.com/callback"}}`))
		case request.Method == http.MethodPost && request.URL.Path == "/api/v3/agent-identity/me/authorization-requests/aur_request_1/exchange":
			content, _ := io.ReadAll(request.Body)
			var body map[string]string
			require.NoError(t, json.Unmarshal(content, &body))
			require.Equal(t, "ac_one_time_code", body["authorization_code"])
			digest := sha256.Sum256([]byte(body["code_verifier"]))
			require.Equal(t, challenge, base64.RawURLEncoding.EncodeToString(digest[:]))
			_, _ = writer.Write([]byte(`{"data":{"user_grant":{"grant_id":"ugr_12345678901234567890"}}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/user"
	secrets := memorySecrets{sessionRef: `{"access_token":"session"}`}
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "user", Profiles: map[string]profile.Profile{"user": {Endpoint: server.URL, LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))

	stdout := &bytes.Buffer{}
	app := &App{Profiles: store, Secrets: secrets, In: bytes.NewBuffer(nil), Out: stdout, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"authorizations", "create", "--agent-id", "agent-1", "--audience", "https://api.example.com", "--permission-id", "policy-1", "--redirect-uri", "https://client.example.com/callback"})
	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), `"authorization_url":"`+server.URL+`/agent-identity/authorize?request_id=aur_request_1\u0026user_pool_id=pool-1"`)
	pkceRef := "keychain://agent-identity/authorization/aur_request_1/pkce"
	require.NotEmpty(t, secrets[pkceRef])

	stdout.Reset()
	root = app.Root()
	root.SetArgs([]string{"authorizations", "consent", "--request-id", "aur_request_1"})
	require.NoError(t, root.Execute())
	require.NotContains(t, stdout.String(), "ac_one_time_code")
	codeRef := "keychain://agent-identity/authorization/aur_request_1/code"
	require.Equal(t, "ac_one_time_code", secrets[codeRef])

	stdout.Reset()
	root = app.Root()
	root.SetArgs([]string{"authorizations", "exchange", "--request-id", "aur_request_1"})
	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), "ugr_12345678901234567890")
	_, pkceExists := secrets[pkceRef]
	_, codeExists := secrets[codeRef]
	require.False(t, pkceExists)
	require.False(t, codeExists)
}

func TestExplicitAuthorizationCancelsRemoteRequestAndCleansPartialSecretsWhenStorageFails(t *testing.T) {
	var cancelled bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-Id", "req-create-1")
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v3/agent-identity/me/agents/agent-1/authorization-requests":
			_, _ = writer.Write([]byte(`{"data":{"request":{"request_id":"aur_partial_1"}}}`))
		case request.Method == http.MethodPost && request.URL.Path == "/api/v3/agent-identity/me/authorization-requests/aur_partial_1/cancel":
			cancelled = true
			_, _ = writer.Write([]byte(`{"data":{"request_id":"aur_partial_1","status":"CANCELLED"}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/user"
	secrets := &failNthSetSecrets{memorySecrets: memorySecrets{sessionRef: `{"access_token":"session"}`}, failAt: 2}
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "user", Profiles: map[string]profile.Profile{"user": {Endpoint: server.URL, LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))
	app := &App{Profiles: store, Secrets: secrets, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"authorizations", "create", "--agent-id", "agent-1", "--audience", "https://api.example.com", "--permission-id", "policy-1", "--redirect-uri", "https://client.example.com/callback"})
	err = root.Execute()
	var exit *ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "SECRET_STORE_UNAVAILABLE", exit.Code)
	require.Equal(t, "req-create-1", exit.RequestID)
	require.True(t, cancelled)
	for _, suffix := range []string{"pkce", "code", "callback", "url"} {
		_, exists := secrets.memorySecrets["keychain://agent-identity/authorization/aur_partial_1/"+suffix]
		require.False(t, exists)
	}
}

func TestAuthorizationExchangeReportsOneTimeSecretCleanupFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/api/v3/agent-identity/me/authorization-requests/aur_request_1/exchange", request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"user_grant":{"grant_id":"ugr_12345678901234567890"}}}`))
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/user"
	pkceRef := "keychain://agent-identity/authorization/aur_request_1/pkce"
	codeRef := "keychain://agent-identity/authorization/aur_request_1/code"
	secrets := deleteFailingSecrets{memorySecrets{sessionRef: `{"access_token":"session"}`, pkceRef: "verifier", codeRef: "code"}}
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "user", Profiles: map[string]profile.Profile{"user": {Endpoint: server.URL, LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))
	stdout := &bytes.Buffer{}
	app := &App{Profiles: store, Secrets: secrets, In: bytes.NewBuffer(nil), Out: stdout, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"authorizations", "exchange", "--request-id", "aur_request_1"})
	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), `"warnings":["authorization exchange succeeded, but one or more one-time values could not be removed from the OS secret store"]`)
}

func TestAuthorizationWaitCompletesCrossDeviceConsentWithPKCEOnly(t *testing.T) {
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	var exchanged bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v3/agent-identity/admin/authorization-requests/aur_cross_device":
			_, _ = writer.Write([]byte(`{"data":{"request_id":"aur_cross_device","status":"CONSENTED","poll_after":1}}`))
		case request.Method == http.MethodPost && request.URL.Path == "/api/v3/agent-identity/admin/authorization-requests/aur_cross_device/exchange":
			var body map[string]any
			require.NoError(t, json.NewDecoder(request.Body).Decode(&body))
			require.Equal(t, verifier, body["code_verifier"])
			require.NotContains(t, body, "authorization_code")
			exchanged = true
			_, _ = writer.Write([]byte(`{"data":{"user_grant":{"grant_id":"ugr_cross_device"}}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/admin"
	pkceRef := "keychain://agent-identity/authorization/aur_cross_device/pkce"
	secrets := memorySecrets{sessionRef: `{"access_token":"session"}`, pkceRef: verifier}
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "admin", Profiles: map[string]profile.Profile{"admin": {Endpoint: server.URL, LoginType: "tenant_admin", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))
	stdout := &bytes.Buffer{}
	app := &App{Profiles: store, Secrets: secrets, In: bytes.NewBuffer(nil), Out: stdout, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"authorizations", "wait", "--authorization-id", "aur_cross_device"})
	require.NoError(t, root.Execute())
	require.True(t, exchanged)
	require.Contains(t, stdout.String(), "ugr_cross_device")
	_, exists := secrets[pkceRef]
	require.False(t, exists)
}

func TestAuthorizationConsentChecksSecretStoreBeforeRemoteMutation(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		http.NotFound(writer, request)
	}))
	defer server.Close()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", t.TempDir())
	store, err := profile.NewStore()
	require.NoError(t, err)
	sessionRef := "keychain://agent-identity/session/user"
	require.NoError(t, store.Save(profile.Config{CurrentProfile: "user", Profiles: map[string]profile.Profile{"user": {Endpoint: server.URL, LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: sessionRef}}}))
	app := &App{Profiles: store, Secrets: setFailingSecrets{memorySecrets{sessionRef: `{"access_token":"session"}`}}, In: bytes.NewBuffer(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, timeout: time.Second}
	root := app.Root()
	root.SetArgs([]string{"authorizations", "consent", "--authorization-id", "aur_request_1"})
	err = root.Execute()
	var exit *ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "SECRET_STORE_UNAVAILABLE", exit.Code)
	require.Zero(t, calls)
}

func TestLocalHTTPEndpointRequiresExplicitAcknowledgement(t *testing.T) {
	app := &App{}
	require.Error(t, app.validateEndpoint("http://127.0.0.1:3000"))
	app.allowLocalHTTP = true
	require.NoError(t, app.validateEndpoint("http://127.0.0.1:3000"))
	require.Error(t, app.validateEndpoint("http://public.example.com"))
}

func TestHTTPClientAddsCustomCAAndPinsExplicitProxy(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer tlsServer.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	require.NoError(t, os.WriteFile(caPath, certificate, 0o600))

	app := &App{caFile: caPath, proxyURL: "http://proxy.example.com:8080"}
	client, err := app.httpClient(time.Second)
	require.NoError(t, err)
	transport := client.Transport.(*http.Transport)
	proxy, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "genauth.example.com"}})
	require.NoError(t, err)
	require.Equal(t, "http://proxy.example.com:8080", proxy.String())

	transport.Proxy = nil
	response, err := client.Get(tlsServer.URL)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	require.NoError(t, response.Body.Close())
}

func TestHTTPClientRejectsProxyCredentialsAndInvalidCA(t *testing.T) {
	app := &App{proxyURL: "http://user:secret@proxy.example.com"}
	_, err := app.httpClient(time.Second)
	var exit *ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "INVALID_PROXY", exit.Code)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("not a certificate"), 0o600))
	app = &App{caFile: caPath}
	_, err = app.httpClient(time.Second)
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "INVALID_CA_FILE", exit.Code)
}
