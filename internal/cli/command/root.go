package command

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Authing/genauth-agent-cli/internal/cli/apiclient"
	"github.com/Authing/genauth-agent-cli/internal/cli/authflow"
	"github.com/Authing/genauth-agent-cli/internal/cli/output"
	"github.com/Authing/genauth-agent-cli/internal/cli/profile"
	"github.com/Authing/genauth-agent-cli/internal/cli/secretstore"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Version is overridden by release builds through -ldflags. Keep the default in
// sync with the repository VERSION file for local development builds.
var Version = "0.1.0"

type ExitError struct {
	Code, Message, RequestID string
	Exit                     int
	Remediation              map[string]any
}

func (e *ExitError) Error() string { return e.Message }

type App struct {
	Profiles         *profile.Store
	Secrets          secretstore.Store
	In               io.Reader
	Out, Err         io.Writer
	profile          string
	timeout          time.Duration
	endpointOverride string
	outputFormat     string
	requestID        string
	noBrowser        bool
	nonInteractive   bool
	quiet            bool
	debug            bool
	proxyURL         string
	caFile           string
	allowLocalHTTP   bool
}

func New() (*App, error) {
	profiles, err := profile.NewStore()
	if err != nil {
		return nil, err
	}
	return &App{Profiles: profiles, Secrets: secretstore.New(), In: os.Stdin, Out: os.Stdout, Err: os.Stderr, timeout: 15 * time.Second}, nil
}

func (a *App) Root() *cobra.Command {
	root := &cobra.Command{Use: "agent-identity", Short: "GenAuth Agent Identity CLI", SilenceUsage: true, SilenceErrors: true, PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		if err := output.SetFormat(a.outputFormat); err != nil {
			return localError("INVALID_ARGUMENT", err.Error())
		}
		if a.requestID != "" {
			if _, err := uuid.Parse(a.requestID); err != nil {
				return localError("INVALID_ARGUMENT", "request-id must be a UUID")
			}
		}
		return nil
	}}
	root.PersistentFlags().StringVar(&a.profile, "profile", "", "local profile name")
	root.PersistentFlags().DurationVar(&a.timeout, "timeout", 15*time.Second, "request timeout")
	root.PersistentFlags().StringVar(&a.endpointOverride, "endpoint", "", "override GenAuth HTTPS origin")
	root.PersistentFlags().StringVar(&a.outputFormat, "output", "json", "output format: table, json, or yaml")
	root.PersistentFlags().StringVar(&a.requestID, "request-id", "", "caller-provided UUID request ID")
	root.PersistentFlags().StringVar(&a.requestID, "correlation-id", "", "caller-provided UUID correlation ID (use on commands whose resource also has a request ID)")
	root.PersistentFlags().BoolVar(&a.noBrowser, "no-browser", false, "do not open a browser")
	root.PersistentFlags().BoolVar(&a.nonInteractive, "non-interactive", false, "fail instead of waiting for interactive input")
	root.PersistentFlags().BoolVar(&a.quiet, "quiet", false, "suppress progress output")
	root.PersistentFlags().BoolVar(&a.debug, "debug", false, "emit redacted diagnostics")
	root.PersistentFlags().StringVar(&a.proxyURL, "proxy", "", "HTTP(S) proxy URL without credentials; defaults to standard proxy environment variables")
	root.PersistentFlags().StringVar(&a.caFile, "ca-file", "", "PEM CA bundle used in addition to system roots")
	root.PersistentFlags().BoolVar(&a.allowLocalHTTP, "allow-insecure-localhost", false, "allow an explicit http://localhost or 127.0.0.1 GenAuth endpoint")
	root.AddCommand(a.authCommand(), a.configCommand(), a.permissionsCommand(), a.agentsCommand(), a.approvalsCommand(), a.credentialsCommand(), a.authorizationsCommand(), a.tokensCommand(), a.apiCommand(), a.auditCommand(), a.doctorCommand(), a.versionCommand(), a.completionCommand(root))
	return root
}

func (a *App) authCommand() *cobra.Command {
	auth := &cobra.Command{Use: "auth"}
	var userPoolID, profileName, clientID string
	var admin, tokenStdin bool
	login := &cobra.Command{Use: "login", RunE: func(cmd *cobra.Command, _ []string) error {
		if err := profile.ValidateName(profileName); err != nil || !admin && strings.TrimSpace(userPoolID) == "" {
			return localError("INVALID_ARGUMENT", "profile is required; user-pool-id is required for user login")
		}
		candidate := profile.Profile{Endpoint: strings.TrimRight(a.endpointOverride, "/"), ClientID: clientID, LoginType: map[bool]string{true: "tenant_admin", false: "user"}[admin], SelectedUserPoolID: userPoolID, SecretRef: "keychain://agent-identity/session/" + profileName}
		if err := a.validateEndpoint(candidate.Endpoint); err != nil {
			return localError("INVALID_ENDPOINT", "endpoint must be a GenAuth HTTPS origin")
		}
		if err := a.probeSecretStore(); err != nil {
			return err
		}
		var token authflow.Token
		if tokenStdin {
			value, err := io.ReadAll(io.LimitReader(a.In, 64*1024))
			if err != nil || strings.TrimSpace(string(value)) == "" {
				return localError("INVALID_SESSION", "a session token is required on stdin")
			}
			token.AccessToken = strings.TrimSpace(string(value))
		} else {
			if a.nonInteractive {
				return localError("LOGIN_INTERACTION_REQUIRED", "browser login cannot run in non-interactive mode; use session-token-stdin")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()
			var err error
			httpClient, clientErr := a.httpClient(a.timeout)
			if clientErr != nil {
				return clientErr
			}
			token, err = authflow.LoginWithClient(ctx, httpClient, candidate.Endpoint, clientID, userPoolID, a.noBrowser, func(uri string) {
				if !a.quiet {
					_, _ = fmt.Fprintf(a.Err, "Open this GenAuth login URL:\n%s\n", uri)
				}
			})
			if err != nil {
				return &ExitError{Code: "LOGIN_FAILED", Message: err.Error(), Exit: 3}
			}
		}
		candidate.SubjectID = tokenSubject(token.AccessToken)
		if admin {
			selected, requestID, err := a.selectAdminUserPool(cmd.Context(), candidate.Endpoint, token.AccessToken, userPoolID)
			if err != nil {
				return classify(err, requestID)
			}
			candidate.SelectedUserPoolID = selected
		}
		if err := profile.Validate(candidate); err != nil {
			return localError("INVALID_LOGIN_CONTEXT", "login did not produce a valid selected user pool")
		}
		encoded, _ := json.Marshal(token)
		if err := a.Secrets.Set(candidate.SecretRef, string(encoded)); err != nil {
			return &ExitError{Code: "SECRET_STORE_UNAVAILABLE", Message: "OS secret store is unavailable", Exit: 9}
		}
		config, err := a.Profiles.Load()
		if err != nil {
			return err
		}
		config.Profiles[profileName] = candidate
		config.CurrentProfile = profileName
		if err := a.Profiles.Save(config); err != nil {
			_ = a.Secrets.Delete(candidate.SecretRef)
			return err
		}
		return output.WriteSuccess(a.Out, "LoginSession", map[string]any{"profile": profileName, "login_type": candidate.LoginType, "subject_id": candidate.SubjectID, "selected_user_pool_id": candidate.SelectedUserPoolID, "secret_ref": candidate.SecretRef}, "")
	}}
	login.Flags().StringVar(&userPoolID, "user-pool-id", "", "selected user pool ID")
	login.Flags().StringVar(&profileName, "profile-name", "default", "profile to create")
	login.Flags().StringVar(&clientID, "client-id", "", "GenAuth OIDC client ID")
	login.Flags().BoolVar(&admin, "admin", false, "login as tenant administrator")
	login.Flags().BoolVar(&tokenStdin, "session-token-stdin", false, "read an existing GenAuth session token from stdin")
	status := &cobra.Command{Use: "status", RunE: func(cmd *cobra.Command, _ []string) error {
		_, _, name, item, err := a.client()
		if err != nil {
			return err
		}
		path := "/api/v3/agent-identity/me"
		if item.LoginType == "tenant_admin" {
			path = "/api/v3/agent-identity/admin/context"
		}
		raw, requestID, err := a.call(cmd.Context(), http.MethodGet, path, nil, nil, nil)
		if err != nil {
			return classify(err, requestID)
		}
		var serverContext map[string]any
		_ = json.Unmarshal(raw, &serverContext)
		return output.WriteSuccess(a.Out, "AuthStatus", map[string]any{"authenticated": true, "profile": name, "login_type": item.LoginType, "subject_id": item.SubjectID, "selected_user_pool_id": item.SelectedUserPoolID, "server_context": serverContext}, requestID)
	}}
	logout := &cobra.Command{Use: "logout", RunE: func(cmd *cobra.Command, _ []string) error {
		config, err := a.Profiles.Load()
		if err != nil {
			return err
		}
		name, item, err := config.Current(a.profile)
		if err != nil {
			return localError("NOT_LOGGED_IN", "no active profile")
		}
		encoded, err := a.Secrets.Get(item.SecretRef)
		if err != nil {
			return localError("NOT_LOGGED_IN", "stored session is unavailable")
		}
		var token authflow.Token
		if json.Unmarshal([]byte(encoded), &token) != nil {
			return localError("INVALID_SESSION", "stored session is invalid")
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
		defer cancel()
		httpClient, err := a.httpClient(10 * time.Second)
		if err != nil {
			return err
		}
		if err := authflow.RevokeWithClient(ctx, httpClient, item.Endpoint, item.ClientID, token); err != nil {
			return &ExitError{Code: "LOGOUT_REVOKE_FAILED", Message: err.Error(), Exit: 3}
		}
		delete(config.Profiles, name)
		if config.CurrentProfile == name {
			config.CurrentProfile = ""
		}
		if err := a.Profiles.Save(config); err != nil {
			return err
		}
		warnings := []string{}
		if err := a.Secrets.Delete(item.SecretRef); err != nil {
			warnings = append(warnings, "remote session was revoked and the local profile was removed, but its OS secret-store entry could not be removed")
		}
		return output.WriteSuccessWithWarnings(a.Out, "Logout", map[string]any{"profile": name}, "", warnings)
	}}
	refresh := &cobra.Command{Use: "refresh", RunE: func(cmd *cobra.Command, _ []string) error {
		_, token, name, item, err := a.client()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), a.timeout)
		defer cancel()
		if err := a.probeSecretStore(); err != nil {
			return err
		}
		httpClient, err := a.httpClient(a.timeout)
		if err != nil {
			return err
		}
		refreshed, err := authflow.RefreshWithClient(ctx, httpClient, item.Endpoint, item.ClientID, token.RefreshToken)
		if err != nil {
			return &ExitError{Code: "SESSION_REFRESH_FAILED", Message: err.Error(), Exit: 3}
		}
		encoded, _ := json.Marshal(refreshed)
		if err := a.Secrets.Set(item.SecretRef, string(encoded)); err != nil {
			return &ExitError{Code: "SECRET_STORE_UNAVAILABLE", Message: "OS secret store is unavailable", Exit: 9}
		}
		return output.WriteSuccess(a.Out, "LoginSession", map[string]any{"profile": name, "refreshed": true, "selected_user_pool_id": item.SelectedUserPoolID}, "")
	}}
	var switchPool string
	switchCommand := &cobra.Command{Use: "switch-user-pool", RunE: func(cmd *cobra.Command, _ []string) error {
		_, token, name, item, err := a.client()
		if err != nil {
			return err
		}
		if item.LoginType != "tenant_admin" || switchPool == "" {
			return localError("TENANT_CONTEXT_REQUIRED", "tenant admin and user-pool-id are required")
		}
		selected, requestID, err := a.selectAdminUserPool(cmd.Context(), item.Endpoint, token.AccessToken, switchPool)
		if err != nil {
			return classify(err, requestID)
		}
		config, _ := a.Profiles.Load()
		item.SelectedUserPoolID = selected
		config.Profiles[name] = item
		if err := a.Profiles.Save(config); err != nil {
			return err
		}
		return output.WriteSuccess(a.Out, "UserPoolContext", map[string]any{"profile": name, "selected_user_pool_id": selected}, requestID)
	}}
	switchCommand.Flags().StringVar(&switchPool, "user-pool-id", "", "user pool ID")
	auth.AddCommand(login, status, refresh, logout, switchCommand)
	return auth
}

func (a *App) selectAdminUserPool(ctx context.Context, endpoint, accessToken, requested string) (string, string, error) {
	client := apiclient.New(endpoint, accessToken, "", a.timeout)
	httpClient, err := a.httpClient(a.timeout)
	if err != nil {
		return "", "", err
	}
	client.HTTP = httpClient
	client.RequestID = a.requestID
	raw, requestID, err := client.Do(ctx, http.MethodGet, "/api/v3/agent-identity/admin/user-pools", nil, nil, nil)
	if err != nil {
		return "", requestID, err
	}
	var response struct {
		List []struct {
			ID string `json:"id"`
		} `json:"list"`
	}
	if err := apiclient.DecodeData(raw, &response); err != nil {
		return "", requestID, err
	}
	requested = strings.TrimSpace(requested)
	if requested != "" {
		for _, pool := range response.List {
			if pool.ID == requested {
				return requested, requestID, nil
			}
		}
		return "", requestID, localError("USER_POOL_NOT_MANAGEABLE", "the selected user pool is not manageable by this administrator")
	}
	if len(response.List) == 1 {
		return response.List[0].ID, requestID, nil
	}
	if len(response.List) == 0 {
		return "", requestID, localError("NO_MANAGEABLE_USER_POOL", "this administrator has no manageable user pool")
	}
	ids := make([]string, 0, len(response.List))
	for _, pool := range response.List {
		ids = append(ids, pool.ID)
	}
	return "", requestID, localError("USER_POOL_SELECTION_REQUIRED", "multiple manageable user pools found; retry with --user-pool-id ("+strings.Join(ids, ", ")+")")
}

func (a *App) configCommand() *cobra.Command {
	configCommand := &cobra.Command{Use: "config"}
	configCommand.AddCommand(&cobra.Command{Use: "get", RunE: func(_ *cobra.Command, _ []string) error {
		config, err := a.Profiles.Load()
		if err != nil {
			return err
		}
		name, item, err := config.Current(a.profile)
		if err != nil {
			return localError("PROFILE_NOT_FOUND", "profile not found")
		}
		return output.WriteSuccess(a.Out, "Profile", map[string]any{"name": name, "profile": item, "config_path": a.Profiles.Path()}, "")
	}}, &cobra.Command{Use: "list-profiles", RunE: func(_ *cobra.Command, _ []string) error {
		config, err := a.Profiles.Load()
		if err != nil {
			return err
		}
		return output.WriteSuccess(a.Out, "ProfileList", map[string]any{"current_profile": config.CurrentProfile, "profiles": config.Profiles}, "")
	}})
	var use string
	useCommand := &cobra.Command{Use: "use-profile", RunE: func(_ *cobra.Command, _ []string) error {
		config, err := a.Profiles.Load()
		if err != nil {
			return err
		}
		if _, ok := config.Profiles[use]; !ok {
			return localError("PROFILE_NOT_FOUND", "profile not found")
		}
		config.CurrentProfile = use
		if err := a.Profiles.Save(config); err != nil {
			return err
		}
		return output.WriteSuccess(a.Out, "Profile", map[string]any{"current_profile": use}, "")
	}}
	useCommand.Flags().StringVar(&use, "name", "", "profile name")
	var setEndpoint, setClientID string
	setCommand := &cobra.Command{Use: "set", RunE: func(_ *cobra.Command, _ []string) error {
		if setEndpoint == "" && setClientID == "" {
			return localError("INVALID_ARGUMENT", "at least one of endpoint or client-id is required")
		}
		config, err := a.Profiles.Load()
		if err != nil {
			return err
		}
		name, item, err := config.Current(a.profile)
		if err != nil {
			return localError("PROFILE_NOT_FOUND", "profile not found")
		}
		if setEndpoint != "" {
			if err := profile.ValidateEndpoint(setEndpoint); err != nil {
				return localError("INVALID_ENDPOINT", "endpoint must be a GenAuth HTTPS origin")
			}
			item.Endpoint = strings.TrimRight(setEndpoint, "/")
		}
		if setClientID != "" {
			item.ClientID = strings.TrimSpace(setClientID)
		}
		config.Profiles[name] = item
		if err := a.Profiles.Save(config); err != nil {
			return err
		}
		return output.WriteSuccess(a.Out, "Profile", map[string]any{"name": name, "profile": item}, "")
	}}
	setCommand.Flags().StringVar(&setEndpoint, "endpoint", "", "GenAuth HTTPS origin")
	setCommand.Flags().StringVar(&setClientID, "client-id", "", "GenAuth OIDC client ID")
	configCommand.AddCommand(setCommand, useCommand)
	return configCommand
}

func (a *App) permissionsCommand() *cobra.Command {
	command := &cobra.Command{Use: "permissions"}
	var pageSize int
	var audience, action, keyword string
	list := &cobra.Command{Use: "list", RunE: a.simple(http.MethodGet, func() string { return a.permissionCatalogPrefix() }, "PermissionList", func() (url.Values, any, map[string]string, error) {
		return compactQuery(map[string]string{"audience": audience, "action": action, "keyword": keyword, "limit": fmt.Sprint(pageSize)}), nil, nil, nil
	})}
	list.Flags().IntVar(&pageSize, "page-size", 20, "page size")
	list.Flags().StringVar(&audience, "audience", "", "ResourceServer audience")
	list.Flags().StringVar(&action, "action", "", "permission action")
	list.Flags().StringVar(&keyword, "keyword", "", "search keyword")
	var policyID string
	get := &cobra.Command{Use: "get", RunE: a.simple(http.MethodGet, funcPath("/api/v3/agent-identity/permission-catalog/", &policyID), "Permission", func() (url.Values, any, map[string]string, error) {
		return nil, nil, nil, required(policyID, "permission-id")
	})}
	get.Flags().StringVar(&policyID, "permission-id", "", "DataPolicy ID")
	var validationIDs []string
	validate := &cobra.Command{Use: "validate", RunE: a.simple(http.MethodPost, "/api/v3/agent-identity/permissions/validate", "PermissionValidation", func() (url.Values, any, map[string]string, error) {
		if len(validationIDs) == 0 {
			return nil, nil, nil, localError("INVALID_ARGUMENT", "at least one permission-id is required")
		}
		return nil, map[string]any{"permission_ids": validationIDs, "audience": audience}, idempotency(), required(audience, "audience")
	})}
	validate.Flags().StringSliceVar(&validationIDs, "permission-id", nil, "DataPolicy ID (repeatable)")
	validate.Flags().StringVar(&audience, "audience", "", "ResourceServer audience")
	command.AddCommand(list, get, validate)
	return command
}

func (a *App) agentsCommand() *cobra.Command {
	command := &cobra.Command{Use: "agents"}
	var identifier, name, displayName, description, ownerID, applicationID, audience, file string
	var policies []string
	var replacePermissions, appendPermissions bool
	create := &cobra.Command{Use: "create", RunE: func(cmd *cobra.Command, _ []string) error {
		cliPolicies := append([]string(nil), policies...)
		filePolicies := []string(nil)
		if file != "" {
			input, err := readObjectFile(file)
			if err != nil {
				return err
			}
			setIfEmpty := func(target *string, keys ...string) {
				if *target != "" {
					return
				}
				for _, key := range keys {
					if value, ok := input[key].(string); ok && strings.TrimSpace(value) != "" {
						*target = strings.TrimSpace(value)
						return
					}
				}
			}
			setIfEmpty(&identifier, "identifier", "name")
			setIfEmpty(&displayName, "display_name", "name")
			setIfEmpty(&description, "description")
			setIfEmpty(&ownerID, "owner_user_id")
			setIfEmpty(&applicationID, "application_id")
			setIfEmpty(&audience, "audience")
			filePolicies = stringSlice(input["permission_ids"])
			if len(filePolicies) == 0 {
				filePolicies = stringSlice(input["permissions"])
			}
			if capabilities, ok := input["capabilities"].([]any); ok && len(capabilities) > 0 {
				if capability, ok := capabilities[0].(map[string]any); ok {
					if audience == "" {
						audience, _ = capability["audience"].(string)
					}
					if len(filePolicies) == 0 {
						filePolicies = stringSlice(capability["permission_ids"])
						if len(filePolicies) == 0 {
							filePolicies = permissionIDs(capability["permissions"])
						}
					}
				}
			}
		}
		if name != "" {
			identifier = name
			if displayName == "" {
				displayName = name
			}
		}
		if len(filePolicies) > 0 && len(cliPolicies) > 0 {
			if replacePermissions == appendPermissions {
				return localError("AMBIGUOUS_PERMISSION_MERGE", "file and command-line permissions require exactly one of --replace-permissions or --append-permission")
			}
			if replacePermissions {
				policies = cliPolicies
			} else {
				policies = uniqueStrings(append(filePolicies, cliPolicies...))
			}
		} else if len(filePolicies) > 0 {
			policies = filePolicies
		}
		if !a.nonInteractive && file == "" && (identifier == "" || displayName == "" || applicationID == "") {
			reader := bufio.NewReader(a.In)
			var err error
			identifier, err = promptIfEmpty(reader, a.Err, "Agent identifier", identifier)
			if err != nil {
				return err
			}
			displayName, err = promptIfEmpty(reader, a.Err, "Agent display name", displayName)
			if err != nil {
				return err
			}
			applicationID, err = promptIfEmpty(reader, a.Err, "GenAuth application ID", applicationID)
			if err != nil {
				return err
			}
		}
		if err := required(identifier, "identifier", displayName, "display-name", applicationID, "application-id"); err != nil {
			return err
		}
		if !a.userProfile() {
			if err := required(ownerID, "owner-user-id"); err != nil {
				return err
			}
		}
		body := map[string]any{"identifier": identifier, "display_name": displayName, "description": description, "application_id": applicationID, "agent_type": "company"}
		if ownerID != "" {
			body["owner_user_id"] = ownerID
		}
		raw, requestID, err := a.call(cmd.Context(), http.MethodPost, a.agentManagementPrefix()+"/agents", nil, body, idempotency())
		if err != nil {
			return classify(err, requestID)
		}
		var created struct {
			ID      string `json:"id"`
			Version int64  `json:"version"`
		}
		_ = apiclient.DecodeData(raw, &created)
		if created.ID == "" {
			return serverResponseError(requestID, "Agent creation response is invalid")
		}
		if audience != "" || len(policies) > 0 {
			if audience == "" || len(policies) == 0 {
				return localError("INVALID_ARGUMENT", "audience and at least one permission-id are required together")
			}
			grantRaw, grantRequestID, grantErr := a.call(cmd.Context(), http.MethodPut, a.agentManagementPrefix()+"/agents/"+url.PathEscape(created.ID)+"/capability-grant/draft", nil, map[string]any{"audience": audience, "data_policy_ids": policies, "permission_snapshot": map[string]any{}, "version": 0}, idempotency())
			if grantErr != nil {
				classified := classify(grantErr, grantRequestID)
				var exit *ExitError
				if !errors.As(classified, &exit) {
					exit = &ExitError{Code: "CAPABILITY_DRAFT_FAILED", Message: classified.Error(), RequestID: grantRequestID, Exit: 9}
				}
				return &ExitError{
					Code: "PARTIAL_AGENT_CREATE", Message: "Agent was created, but its Capability draft could not be saved", RequestID: grantRequestID, Exit: exit.Exit,
					Remediation: map[string]any{"agent_id": created.ID, "cause_code": exit.Code, "next_command": "agent-identity agents capability update --agent-id " + created.ID + " --audience <audience> --permission-id <policy-id> --version 0"},
				}
			}
			return output.WriteSuccess(a.Out, "AgentWithCapabilityDraft", map[string]any{"agent": json.RawMessage(raw), "capability_grant": json.RawMessage(grantRaw)}, grantRequestID)
		}
		return output.WriteSuccess(a.Out, "Agent", json.RawMessage(raw), requestID)
	}}
	create.Flags().StringVar(&identifier, "identifier", "", "stable Agent identifier")
	create.Flags().StringVar(&name, "name", "", "stable Agent name (also used as display name when omitted)")
	create.Flags().StringVar(&displayName, "display-name", "", "Agent display name")
	create.Flags().StringVar(&description, "description", "", "Agent description")
	create.Flags().StringVar(&ownerID, "owner-user-id", "", "Agent owner user ID")
	create.Flags().StringVar(&applicationID, "application-id", "", "GenAuth application ID")
	create.Flags().StringVar(&audience, "audience", "", "ResourceServer audience")
	create.Flags().StringSliceVar(&policies, "permission-id", nil, "DataPolicy ID (repeatable)")
	create.Flags().StringVar(&file, "file", "", "Agent YAML or JSON input file")
	create.Flags().BoolVar(&replacePermissions, "replace-permissions", false, "replace file permissions with command-line permission-id values")
	create.Flags().BoolVar(&appendPermissions, "append-permission", false, "append command-line permission-id values to file permissions")
	var status, search string
	list := &cobra.Command{Use: "list", RunE: a.simple(http.MethodGet, func() string { return a.agentManagementPrefix() + "/agents" }, "AgentList", func() (url.Values, any, map[string]string, error) {
		return compactQuery(map[string]string{"status": status, "search": search}), nil, nil, nil
	})}
	list.Flags().StringVar(&status, "status", "", "Agent status")
	list.Flags().StringVar(&search, "search", "", "search text")
	var agentID string
	get := &cobra.Command{Use: "get", RunE: a.simple(http.MethodGet, funcPath(a.agentManagementPrefix, "/agents/", &agentID), "Agent", func() (url.Values, any, map[string]string, error) {
		return nil, nil, nil, required(agentID, "agent-id")
	})}
	get.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	capability := &cobra.Command{Use: "capability"}
	var capabilityAudience string
	var capabilityPolicies []string
	var capabilityVersion int64
	capabilityUpdate := &cobra.Command{Use: "update", RunE: a.simple(http.MethodPut, funcPath(a.agentManagementPrefix, "/agents/", &agentID, "/capability-grant/draft"), "CapabilityGrant", func() (url.Values, any, map[string]string, error) {
		if len(capabilityPolicies) == 0 {
			return nil, nil, nil, localError("INVALID_ARGUMENT", "at least one permission-id is required")
		}
		if capabilityVersion < 0 {
			return nil, nil, nil, localError("INVALID_ARGUMENT", "version cannot be negative")
		}
		return nil, map[string]any{"audience": capabilityAudience, "data_policy_ids": capabilityPolicies, "permission_snapshot": map[string]any{}, "version": capabilityVersion}, idempotency(), required(agentID, "agent-id", capabilityAudience, "audience")
	})}
	capabilityUpdate.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	capabilityUpdate.Flags().StringVar(&capabilityAudience, "audience", "", "ResourceServer audience")
	capabilityUpdate.Flags().StringSliceVar(&capabilityPolicies, "permission-id", nil, "DataPolicy ID (repeatable)")
	capabilityUpdate.Flags().Int64Var(&capabilityVersion, "version", 0, "expected Capability draft record version (0 when creating the first draft)")
	capability.AddCommand(capabilityUpdate)
	var updateDisplayName, updateDescription, updateOwnerID string
	var updateVersion int64
	update := &cobra.Command{Use: "update", RunE: a.simple(http.MethodPatch, funcPath(a.agentManagementPrefix, "/agents/", &agentID, "/profile"), "Agent", func() (url.Values, any, map[string]string, error) {
		if !a.userProfile() {
			if err := required(updateOwnerID, "owner-user-id"); err != nil {
				return nil, nil, nil, err
			}
		}
		body := map[string]any{"display_name": updateDisplayName, "description": updateDescription, "version": updateVersion}
		if updateOwnerID != "" {
			body["owner_user_id"] = updateOwnerID
		}
		return nil, body, idempotency(), required(agentID, "agent-id", updateDisplayName, "display-name")
	})}
	update.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	update.Flags().StringVar(&updateDisplayName, "display-name", "", "Agent display name")
	update.Flags().StringVar(&updateDescription, "description", "", "Agent description")
	update.Flags().StringVar(&updateOwnerID, "owner-user-id", "", "Agent owner user ID")
	update.Flags().Int64Var(&updateVersion, "version", 1, "Agent record version")
	var submitVersion int64
	submit := &cobra.Command{Use: "submit", RunE: a.simple(http.MethodPost, funcPath(a.agentManagementPrefix, "/agents/", &agentID, "/capability-grant/submit"), "ApprovalRequest", func() (url.Values, any, map[string]string, error) {
		return nil, map[string]any{"version": submitVersion}, idempotency(), required(agentID, "agent-id")
	})}
	submit.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	submit.Flags().Int64Var(&submitVersion, "version", 1, "capability draft version")
	var withdrawReason string
	var withdrawYes bool
	withdraw := &cobra.Command{Use: "withdraw", RunE: a.simple(http.MethodPost, funcPath(a.agentManagementPrefix, "/agents/", &agentID, "/capability-grant/withdraw"), "ApprovalRequest", func() (url.Values, any, map[string]string, error) {
		if !withdrawYes {
			return nil, nil, nil, confirmationRequired("withdraw Agent approval request")
		}
		return nil, map[string]any{"version": submitVersion, "reason": withdrawReason}, idempotency(), required(agentID, "agent-id", withdrawReason, "reason")
	})}
	withdraw.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	withdraw.Flags().Int64Var(&submitVersion, "version", 1, "pending capability grant version")
	withdraw.Flags().StringVar(&withdrawReason, "reason", "", "withdrawal reason")
	withdraw.Flags().BoolVar(&withdrawYes, "yes", false, "confirm withdrawal")
	readiness := &cobra.Command{Use: "readiness", RunE: a.simple(http.MethodGet, funcPath(a.agentManagementPrefix, "/agents/", &agentID, "/readiness"), "AgentReadiness", func() (url.Values, any, map[string]string, error) {
		return nil, nil, nil, required(agentID, "agent-id")
	})}
	readiness.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	command.AddCommand(create, list, get, capability, update, submit, withdraw, readiness, a.agentLifecycleAction("suspend", "pause", true), a.agentLifecycleAction("resume", "resume", true), a.agentLifecycleAction("delete", "archive", false), a.agentLifecycleCommand(), a.agentSettingsCommand())
	return command
}

func (a *App) agentLifecycleAction(use, action string, adminOnly bool) *cobra.Command {
	var agentID, reason string
	var version int64
	var yes bool
	item := &cobra.Command{Use: use, RunE: a.simple(http.MethodPost, funcPath(a.agentManagementPrefix, "/agents/", &agentID, "/", action), "Agent", func() (url.Values, any, map[string]string, error) {
		if adminOnly && a.userProfile() {
			return nil, nil, nil, localError("ADMIN_LOGIN_REQUIRED", "only a tenant administrator can "+use+" an Agent")
		}
		if !yes {
			return nil, nil, nil, confirmationRequired(use + " Agent")
		}
		return nil, map[string]any{"version": version, "reason": reason}, idempotency(), required(agentID, "agent-id", reason, "reason")
	})}
	item.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	item.Flags().StringVar(&reason, "reason", "", "lifecycle reason")
	item.Flags().Int64Var(&version, "version", 1, "Agent record version")
	item.Flags().BoolVar(&yes, "yes", false, "confirm this operation")
	return item
}

func (a *App) agentLifecycleCommand() *cobra.Command {
	command := &cobra.Command{Use: "lifecycle"}
	var agentID, reason string
	var version int64
	var yes bool
	for _, action := range []string{"pause", "resume", "archive"} {
		action := action
		item := &cobra.Command{Use: action, RunE: a.simple(http.MethodPost, funcPath(a.agentManagementPrefix, "/agents/", &agentID, "/"+action), "Agent", func() (url.Values, any, map[string]string, error) {
			if a.userProfile() && action != "archive" {
				return nil, nil, nil, localError("ADMIN_LOGIN_REQUIRED", "only a tenant administrator can pause or resume an Agent")
			}
			if action == "archive" && !yes {
				return nil, nil, nil, confirmationRequired("archive Agent")
			}
			return nil, map[string]any{"version": version, "reason": reason}, idempotency(), required(agentID, "agent-id", reason, "reason")
		})}
		item.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
		item.Flags().StringVar(&reason, "reason", "", "lifecycle reason")
		item.Flags().Int64Var(&version, "version", 1, "Agent record version")
		item.Flags().BoolVar(&yes, "yes", false, "confirm this operation")
		command.AddCommand(item)
	}
	return command
}

func (a *App) agentSettingsCommand() *cobra.Command {
	settings := &cobra.Command{Use: "settings"}
	var agentID, file string
	get := &cobra.Command{Use: "get", RunE: a.simple(http.MethodGet, funcPath(a.agentManagementPrefix, "/agents/", &agentID, "/settings"), "AgentSettings", func() (url.Values, any, map[string]string, error) {
		return nil, nil, nil, required(agentID, "agent-id")
	})}
	get.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	var authorizationMode string
	var tokenTTL, maxGrantTTL, credentialTTL, rotationOverlap time.Duration
	var redirectURIs []string
	var expectedVersion int64
	var realtimeDecision bool
	update := &cobra.Command{Use: "update"}
	update.RunE = a.simple(http.MethodPut, funcPath(a.agentManagementPrefix, "/agents/", &agentID, "/settings/draft"), "AgentSettings", func() (url.Values, any, map[string]string, error) {
		if err := required(agentID, "agent-id"); err != nil {
			return nil, nil, nil, err
		}
		if file != "" {
			for _, flag := range []string{"authorization-mode", "token-ttl", "max-user-grant-ttl", "redirect-uri", "require-realtime-decision", "credential-ttl", "rotation-overlap", "version"} {
				if update.Flags().Changed(flag) {
					return nil, nil, nil, localError("AMBIGUOUS_SETTINGS_INPUT", "--file is exclusive with Agent settings value flags")
				}
			}
			body, err := readObjectFile(file)
			return nil, body, idempotency(), err
		}
		mode := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(authorizationMode), "-", "_"))
		if mode != "EXPLICIT_ONLY" && mode != "SILENT_IF_ALLOWED" {
			return nil, nil, nil, localError("INVALID_ARGUMENT", "authorization-mode must be explicit-only or silent-if-allowed")
		}
		if tokenTTL <= 0 || maxGrantTTL <= 0 || rotationOverlap < 0 {
			return nil, nil, nil, localError("INVALID_ARGUMENT", "token-ttl and max-user-grant-ttl must be positive")
		}
		body := map[string]any{
			"expected_record_version":    expectedVersion,
			"authorization_mode":         mode,
			"token_ttl_seconds":          int(tokenTTL.Seconds()),
			"max_user_grant_ttl_seconds": int(maxGrantTTL.Seconds()),
			"redirect_uris":              redirectURIs,
			"require_realtime_decision":  realtimeDecision,
			"rotation_overlap_seconds":   int(rotationOverlap.Seconds()),
		}
		if credentialTTL > 0 {
			body["credential_ttl_seconds"] = int(credentialTTL.Seconds())
		}
		return nil, body, idempotency(), nil
	})
	update.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	update.Flags().StringVar(&file, "file", "", "complete settings JSON file (exclusive with value flags)")
	update.Flags().StringVar(&authorizationMode, "authorization-mode", "", "explicit-only or silent-if-allowed")
	update.Flags().DurationVar(&tokenTTL, "token-ttl", 0, "Agent access Token TTL")
	update.Flags().DurationVar(&maxGrantTTL, "max-user-grant-ttl", 0, "maximum UserGrant TTL")
	update.Flags().StringSliceVar(&redirectURIs, "redirect-uri", nil, "allowed authorization redirect URI")
	update.Flags().BoolVar(&realtimeDecision, "require-realtime-decision", true, "require a current GenAuth decision")
	update.Flags().DurationVar(&credentialTTL, "credential-ttl", 0, "Agent Credential TTL (zero uses platform default)")
	update.Flags().DurationVar(&rotationOverlap, "rotation-overlap", 0, "Credential rotation overlap")
	update.Flags().Int64Var(&expectedVersion, "version", 0, "expected existing DRAFT record_version; use 0 when no settings draft exists")
	submit := &cobra.Command{Use: "submit", RunE: a.simple(http.MethodPost, funcPath(a.agentManagementPrefix, "/agents/", &agentID, "/settings/submit"), "ApprovalRequest", func() (url.Values, any, map[string]string, error) {
		return nil, nil, idempotency(), required(agentID, "agent-id")
	})}
	submit.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	settings.AddCommand(get, update, submit)
	return settings
}

func (a *App) approvalsCommand() *cobra.Command {
	command := &cobra.Command{Use: "approvals"}
	var status, approvalID, reason string
	var version int64
	var settingsApproval, yes bool
	list := &cobra.Command{Use: "list", RunE: a.simple(http.MethodGet, func() string {
		if settingsApproval {
			return a.agentManagementPrefix() + "/settings-approvals"
		}
		return a.agentManagementPrefix() + "/approvals"
	}, "ApprovalList", func() (url.Values, any, map[string]string, error) {
		if a.userProfile() {
			return nil, nil, nil, localError("ADMIN_LOGIN_REQUIRED", "approval operations require a tenant administrator profile")
		}
		return compactQuery(map[string]string{"status": status}), nil, nil, nil
	})}
	list.Flags().StringVar(&status, "status", "pending", "approval status")
	list.Flags().BoolVar(&settingsApproval, "settings", false, "list Agent settings approvals")
	get := &cobra.Command{Use: "get", RunE: a.simple(http.MethodGet, func() string {
		prefix := a.agentManagementPrefix() + "/approvals/"
		if settingsApproval {
			prefix = a.agentManagementPrefix() + "/settings-approvals/"
		}
		return prefix + url.PathEscape(approvalID)
	}, "ApprovalRequest", func() (url.Values, any, map[string]string, error) {
		if a.userProfile() {
			return nil, nil, nil, localError("ADMIN_LOGIN_REQUIRED", "approval operations require a tenant administrator profile")
		}
		return nil, nil, nil, required(approvalID, "approval-id")
	})}
	get.Flags().StringVar(&approvalID, "approval-id", "", "approval request ID")
	get.Flags().StringVar(&approvalID, "request-id", "", "deprecated alias for --approval-id")
	_ = get.Flags().MarkDeprecated("request-id", "use --approval-id; use the persistent --correlation-id for request correlation")
	get.Flags().BoolVar(&settingsApproval, "settings", false, "get an Agent settings approval")
	decision := func(action string) *cobra.Command {
		result := &cobra.Command{Use: action, RunE: a.simple(http.MethodPost, func() string {
			if settingsApproval {
				return a.agentManagementPrefix() + "/settings-approvals/" + url.PathEscape(approvalID) + "/" + action
			}
			return a.agentManagementPrefix() + "/approvals/" + url.PathEscape(approvalID) + "/" + action
		}, "ApprovalRequest", func() (url.Values, any, map[string]string, error) {
			if a.userProfile() {
				return nil, nil, nil, localError("ADMIN_LOGIN_REQUIRED", "approval operations require a tenant administrator profile")
			}
			if !yes {
				return nil, nil, nil, confirmationRequired(action + " approval")
			}
			return nil, map[string]any{"version": version, "reason": reason}, idempotency(), required(approvalID, "approval-id")
		})}
		result.Flags().StringVar(&approvalID, "approval-id", "", "approval request ID")
		result.Flags().StringVar(&approvalID, "request-id", "", "deprecated alias for --approval-id")
		_ = result.Flags().MarkDeprecated("request-id", "use --approval-id; use the persistent --correlation-id for request correlation")
		result.Flags().Int64Var(&version, "version", 1, "approval version")
		result.Flags().StringVar(&reason, "reason", "", "decision reason")
		result.Flags().BoolVar(&settingsApproval, "settings", false, "decide an Agent settings approval")
		result.Flags().BoolVar(&yes, "yes", false, "confirm this decision")
		return result
	}
	command.AddCommand(list, get, decision("approve"), decision("reject"))
	return command
}

func (a *App) credentialsCommand() *cobra.Command {
	command := &cobra.Command{Use: "credentials"}
	var agentID, credentialID string
	var rotateYes, revokeYes, showSecret, allowSecretOutput, storeKeychain bool
	list := &cobra.Command{Use: "list", RunE: a.simple(http.MethodGet, funcPath(a.agentManagementPrefix, "/agents/", &agentID, "/credentials"), "CredentialList", func() (url.Values, any, map[string]string, error) {
		return nil, nil, nil, required(agentID, "agent-id")
	})}
	list.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	create := &cobra.Command{Use: "create", RunE: func(cmd *cobra.Command, _ []string) error {
		return a.createCredential(cmd.Context(), agentID, "", false, storeKeychain, showSecret, allowSecretOutput)
	}}
	create.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	create.Flags().BoolVar(&storeKeychain, "store-keychain", true, "store the delivered secret in the OS secret store")
	create.Flags().BoolVar(&showSecret, "show-secret", false, "show the one-time secret after an explicit risk acknowledgement")
	create.Flags().BoolVar(&allowSecretOutput, "allow-secret-output", false, "allow secret material in machine-readable output")
	rotate := &cobra.Command{Use: "rotate", RunE: func(cmd *cobra.Command, _ []string) error {
		if !rotateYes {
			return confirmationRequired("rotate credential")
		}
		return a.createCredential(cmd.Context(), agentID, credentialID, true, storeKeychain, showSecret, allowSecretOutput)
	}}
	rotate.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	rotate.Flags().StringVar(&credentialID, "credential-id", "", "Credential ID")
	rotate.Flags().BoolVar(&rotateYes, "yes", false, "confirm credential rotation")
	rotate.Flags().BoolVar(&storeKeychain, "store-keychain", true, "store the rotated secret in the OS secret store")
	rotate.Flags().BoolVar(&showSecret, "show-secret", false, "show the one-time rotated secret after an explicit risk acknowledgement")
	rotate.Flags().BoolVar(&allowSecretOutput, "allow-secret-output", false, "allow secret material in machine-readable output")
	revoke := &cobra.Command{Use: "revoke", RunE: func(cmd *cobra.Command, _ []string) error {
		if !revokeYes {
			return confirmationRequired("revoke credential")
		}
		if err := required(agentID, "agent-id", credentialID, "credential-id"); err != nil {
			return err
		}
		path := a.agentManagementPrefix() + "/agents/" + url.PathEscape(agentID) + "/credentials/" + url.PathEscape(credentialID) + "/revoke"
		raw, requestID, err := a.call(cmd.Context(), http.MethodPost, path, nil, nil, idempotency())
		if err != nil {
			return classify(err, requestID)
		}
		warnings := []string{}
		secretRef := "keychain://agent-identity/credential/" + credentialID
		if err := a.Secrets.Delete(secretRef); err != nil {
			warnings = append(warnings, "credential was revoked, but its local OS secret-store entry could not be removed")
		}
		return output.WriteSuccessWithWarnings(a.Out, "Credential", json.RawMessage(raw), requestID, warnings)
	}}
	revoke.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	revoke.Flags().StringVar(&credentialID, "credential-id", "", "Credential ID")
	revoke.Flags().BoolVar(&revokeYes, "yes", false, "confirm credential revocation")
	command.AddCommand(list, create, rotate, revoke)
	return command
}

func (a *App) createCredential(ctx context.Context, agentID, credentialID string, rotate, storeKeychain, showSecret, allowSecretOutput bool) error {
	if err := required(agentID, "agent-id"); err != nil {
		return err
	}
	if !storeKeychain && !showSecret {
		return localError("SECRET_DESTINATION_REQUIRED", "enable --store-keychain or explicitly use --show-secret")
	}
	if showSecret && a.outputFormat != "table" && !allowSecretOutput {
		return localError("SECRET_OUTPUT_ACKNOWLEDGEMENT_REQUIRED", "--show-secret with machine-readable output also requires --allow-secret-output")
	}
	humanSession := uuid.NewString()
	path := a.agentManagementPrefix() + "/agents/" + url.PathEscape(agentID) + "/credentials"
	if rotate {
		if err := required(credentialID, "credential-id"); err != nil {
			return err
		}
		path += "/" + url.PathEscape(credentialID) + "/rotate"
	}
	raw, requestID, err := a.call(ctx, http.MethodPost, path, nil, nil, mergeHeaders(idempotency(), map[string]string{"X-Human-Session-Id": humanSession}))
	if err != nil {
		return classify(err, requestID)
	}
	var created struct {
		Credential struct {
			CredentialID string `json:"credential_id"`
			ExpiresAt    string `json:"expires_at"`
		} `json:"credential"`
		Delivery struct {
			DeliveryID   string `json:"delivery_id"`
			DeliveryCode string `json:"delivery_code"`
			ExpiresIn    int    `json:"expires_in"`
		} `json:"delivery"`
	}
	if apiclient.DecodeData(raw, &created) != nil || created.Delivery.DeliveryID == "" || created.Delivery.DeliveryCode == "" {
		return serverResponseError(requestID, "credential delivery response is invalid")
	}
	consumed, consumeRequestID, err := a.call(ctx, http.MethodPost, a.agentManagementPrefix()+"/credential-deliveries/"+url.PathEscape(created.Delivery.DeliveryID)+"/consume", nil, map[string]any{"delivery_code": created.Delivery.DeliveryCode}, map[string]string{"X-Human-Session-Id": humanSession})
	created.Delivery.DeliveryCode = ""
	if err != nil {
		return classify(err, consumeRequestID)
	}
	var secret struct {
		CredentialID string `json:"credential_id"`
		ClientSecret string `json:"client_secret"`
	}
	if apiclient.DecodeData(consumed, &secret) != nil || secret.CredentialID == "" || secret.ClientSecret == "" {
		a.bestEffortRevokeCredential(ctx, agentID, created.Credential.CredentialID)
		return serverResponseError(consumeRequestID, "credential secret response is invalid")
	}
	reference := ""
	if storeKeychain {
		reference = "keychain://agent-identity/credential/" + secret.CredentialID
		encoded, _ := json.Marshal(map[string]string{"credential_id": secret.CredentialID, "client_secret": secret.ClientSecret})
		if err := a.Secrets.Set(reference, string(encoded)); err != nil {
			a.bestEffortRevokeCredential(ctx, agentID, secret.CredentialID)
			return &ExitError{Code: "SECRET_STORE_UNAVAILABLE", Message: "OS secret store is unavailable", Exit: 9}
		}
	}
	data := map[string]any{"credential_id": secret.CredentialID, "expires_at": created.Credential.ExpiresAt}
	if reference != "" {
		data["secret_ref"] = reference
	}
	if showSecret {
		if !a.quiet {
			_, _ = fmt.Fprintln(a.Err, "WARNING: the one-time Agent Credential secret is now visible to terminal history and screen recording.")
		}
		data["client_secret"] = secret.ClientSecret
	}
	writeErr := output.WriteSuccess(a.Out, "AgentCredential", data, consumeRequestID)
	delete(data, "client_secret")
	secret.ClientSecret = ""
	return writeErr
}

func (a *App) bestEffortRevokeCredential(ctx context.Context, agentID, credentialID string) {
	if strings.TrimSpace(agentID) == "" || strings.TrimSpace(credentialID) == "" {
		return
	}
	path := a.agentManagementPrefix() + "/agents/" + url.PathEscape(agentID) + "/credentials/" + url.PathEscape(credentialID) + "/revoke"
	_, _, _ = a.call(ctx, http.MethodPost, path, nil, nil, idempotency())
}

func (a *App) authorizationsCommand() *cobra.Command {
	command := &cobra.Command{Use: "authorizations"}
	var agentID, userID, audience, mode, redirectURI, requestID, grantID, reason string
	var permissions []string
	var ttl int
	var silentYes, revokeYes, denyYes, cancelYes, openBrowser bool
	create := &cobra.Command{Use: "create", RunE: func(cmd *cobra.Command, _ []string) error {
		if len(permissions) == 0 {
			return localError("INVALID_ARGUMENT", "at least one permission-id is required")
		}
		normalizedMode := strings.ToUpper(mode)
		if normalizedMode != "EXPLICIT" && normalizedMode != "SILENT" {
			return localError("INVALID_ARGUMENT", "mode must be explicit or silent")
		}
		if a.userProfile() && (userID != "" || normalizedMode == "SILENT") {
			return localError("FORBIDDEN_USER_AUTHORIZATION_MODE", "user profiles can authorize only themselves with explicit consent")
		}
		if normalizedMode == "SILENT" && !silentYes {
			return confirmationRequired("request silent authorization")
		}
		if err := required(agentID, "agent-id", audience, "audience"); err != nil {
			return err
		}
		body := map[string]any{"target_user_id": userID, "audience": audience, "permission_ids": permissions, "mode": normalizedMode, "user_grant_ttl_seconds": ttl}
		verifier := ""
		if normalizedMode == "EXPLICIT" {
			if strings.TrimSpace(redirectURI) == "" {
				var redirectErr error
				redirectURI, redirectErr = newLoopbackRedirectURI()
				if redirectErr != nil {
					return localError("CALLBACK_UNAVAILABLE", "could not reserve a loopback authorization callback")
				}
			}
			var challenge string
			var err error
			verifier, challenge, err = authflow.NewPKCE()
			if err != nil {
				return &ExitError{Code: "INTERNAL_ERROR", Message: "could not generate PKCE", Exit: 9}
			}
			body["redirect_uri"] = redirectURI
			body["pkce_challenge"] = challenge
		}
		path := a.agentManagementPrefix() + "/agents/" + url.PathEscape(agentID) + "/authorization-requests"
		raw, responseRequestID, err := a.call(cmd.Context(), http.MethodPost, path, nil, body, idempotency())
		if err != nil {
			return classify(err, responseRequestID)
		}
		var result struct {
			Request struct {
				RequestID string `json:"request_id"`
			} `json:"request"`
		}
		if apiclient.DecodeData(raw, &result) != nil || result.Request.RequestID == "" {
			return serverResponseError(responseRequestID, "authorization response is invalid")
		}
		data := map[string]any{"authorization": json.RawMessage(raw)}
		if normalizedMode == "EXPLICIT" {
			pkceRef := "keychain://agent-identity/authorization/" + result.Request.RequestID + "/pkce"
			if err := a.Secrets.Set(pkceRef, verifier); err != nil {
				a.compensateAuthorizationCreate(cmd.Context(), result.Request.RequestID)
				return &ExitError{Code: "SECRET_STORE_UNAVAILABLE", Message: "OS secret store is unavailable; the new authorization request was cancelled where possible", RequestID: responseRequestID, Exit: 9}
			}
			_, _, _, item, clientErr := a.client()
			if clientErr != nil {
				a.compensateAuthorizationCreate(cmd.Context(), result.Request.RequestID)
				return clientErr
			}
			authorizationURL, parseErr := url.Parse(strings.TrimRight(item.Endpoint, "/") + "/agent-identity/authorize")
			if parseErr != nil {
				a.compensateAuthorizationCreate(cmd.Context(), result.Request.RequestID)
				return localError("INVALID_PROFILE", "GenAuth endpoint is invalid")
			}
			query := authorizationURL.Query()
			query.Set("request_id", result.Request.RequestID)
			query.Set("user_pool_id", item.SelectedUserPoolID)
			authorizationURL.RawQuery = query.Encode()
			data["authorization_url"] = authorizationURL.String()
			data["pkce_ref"] = pkceRef
			callbackRef := "keychain://agent-identity/authorization/" + result.Request.RequestID + "/callback"
			urlRef := "keychain://agent-identity/authorization/" + result.Request.RequestID + "/url"
			if err := a.Secrets.Set(callbackRef, redirectURI); err != nil {
				a.compensateAuthorizationCreate(cmd.Context(), result.Request.RequestID)
				return &ExitError{Code: "SECRET_STORE_UNAVAILABLE", Message: "OS secret store is unavailable; the new authorization request was cancelled where possible", RequestID: responseRequestID, Exit: 9}
			}
			if err := a.Secrets.Set(urlRef, authorizationURL.String()); err != nil {
				a.compensateAuthorizationCreate(cmd.Context(), result.Request.RequestID)
				return &ExitError{Code: "SECRET_STORE_UNAVAILABLE", Message: "OS secret store is unavailable; the new authorization request was cancelled where possible", RequestID: responseRequestID, Exit: 9}
			}
			if openBrowser && !a.noBrowser {
				return a.waitAuthorization(cmd.Context(), result.Request.RequestID, true)
			}
		}
		return output.WriteSuccess(a.Out, "AuthorizationRequest", data, responseRequestID)
	}}
	create.Flags().StringVar(&agentID, "agent-id", "", "Agent ID")
	create.Flags().StringVar(&userID, "user-id", "", "target user ID (admin only)")
	create.Flags().StringVar(&audience, "audience", "", "ResourceServer audience")
	create.Flags().StringSliceVar(&permissions, "permission-id", nil, "DataPolicy ID")
	create.Flags().StringVar(&mode, "mode", "explicit", "explicit or silent")
	create.Flags().StringVar(&redirectURI, "redirect-uri", "", "authorization callback URI")
	create.Flags().BoolVar(&openBrowser, "open-browser", false, "open the authorization link and wait for consent")
	create.Flags().IntVar(&ttl, "grant-ttl-seconds", 3600, "UserGrant TTL")
	create.Flags().BoolVar(&silentYes, "yes", false, "confirm silent authorization")
	var consentShowCode bool
	consent := &cobra.Command{Use: "consent", RunE: func(cmd *cobra.Command, _ []string) error {
		if !a.userProfile() {
			return localError("USER_LOGIN_REQUIRED", "consent requires a user profile")
		}
		if err := required(requestID, "authorization-id"); err != nil {
			return err
		}
		if err := a.probeSecretStore(); err != nil {
			return err
		}
		raw, responseRequestID, err := a.call(cmd.Context(), http.MethodPost, "/api/v3/agent-identity/me/authorization-requests/"+url.PathEscape(requestID)+"/consent", nil, nil, nil)
		if err != nil {
			return classify(err, responseRequestID)
		}
		var result struct {
			AuthorizationCode string `json:"authorization_code"`
			RedirectURI       string `json:"redirect_uri"`
		}
		if apiclient.DecodeData(raw, &result) != nil || result.AuthorizationCode == "" {
			return serverResponseError(responseRequestID, "consent response is invalid")
		}
		codeRef := "keychain://agent-identity/authorization/" + requestID + "/code"
		if err := a.Secrets.Set(codeRef, result.AuthorizationCode); err != nil {
			return &ExitError{Code: "SECRET_STORE_UNAVAILABLE", Message: "OS secret store is unavailable", Exit: 9}
		}
		data := map[string]any{"request_id": requestID, "redirect_uri": result.RedirectURI, "code_ref": codeRef}
		if consentShowCode {
			data["authorization_code"] = result.AuthorizationCode
		}
		result.AuthorizationCode = ""
		return output.WriteSuccess(a.Out, "AuthorizationConsent", data, responseRequestID)
	}}
	addAuthorizationIDFlags(consent, &requestID)
	consent.Flags().BoolVar(&consentShowCode, "show-code", false, "include the one-time authorization code for secure handoff")
	deny := &cobra.Command{Use: "deny", RunE: func(cmd *cobra.Command, _ []string) error {
		if !a.userProfile() {
			return localError("USER_LOGIN_REQUIRED", "denial requires the target user profile")
		}
		if !denyYes {
			return confirmationRequired("deny authorization")
		}
		if err := required(requestID, "authorization-id", reason, "reason"); err != nil {
			return err
		}
		raw, responseRequestID, err := a.call(cmd.Context(), http.MethodPost, "/api/v3/agent-identity/me/authorization-requests/"+url.PathEscape(requestID)+"/deny", nil, map[string]any{"reason": reason}, nil)
		if err != nil {
			return classify(err, responseRequestID)
		}
		return output.WriteSuccess(a.Out, "AuthorizationRequest", json.RawMessage(raw), responseRequestID)
	}}
	addAuthorizationIDFlags(deny, &requestID)
	deny.Flags().StringVar(&reason, "reason", "", "denial reason")
	deny.Flags().BoolVar(&denyYes, "yes", false, "confirm authorization denial")
	cancel := &cobra.Command{Use: "cancel", RunE: func(cmd *cobra.Command, _ []string) error {
		if !cancelYes {
			return confirmationRequired("cancel authorization request")
		}
		if err := required(requestID, "authorization-id"); err != nil {
			return err
		}
		raw, responseRequestID, err := a.call(cmd.Context(), http.MethodPost, a.authorizationRequestPath(requestID)+"/cancel", nil, nil, idempotency())
		if err != nil {
			return classify(err, responseRequestID)
		}
		return output.WriteSuccess(a.Out, "AuthorizationRequest", json.RawMessage(raw), responseRequestID)
	}}
	addAuthorizationIDFlags(cancel, &requestID)
	cancel.Flags().BoolVar(&cancelYes, "yes", false, "confirm authorization cancellation")
	var exchangeCodeStdin bool
	exchange := &cobra.Command{Use: "exchange", RunE: func(cmd *cobra.Command, _ []string) error {
		if err := required(requestID, "authorization-id"); err != nil {
			return err
		}
		pkceRef := "keychain://agent-identity/authorization/" + requestID + "/pkce"
		verifier, err := a.Secrets.Get(pkceRef)
		if err != nil || verifier == "" {
			return localError("PKCE_NOT_FOUND", "PKCE verifier is unavailable in the OS secret store")
		}
		codeRef := "keychain://agent-identity/authorization/" + requestID + "/code"
		code := ""
		if exchangeCodeStdin {
			content, readErr := io.ReadAll(io.LimitReader(a.In, 4096))
			if readErr != nil {
				return readErr
			}
			code = strings.TrimSpace(string(content))
		} else {
			code, _ = a.Secrets.Get(codeRef)
		}
		verifier = ""
		return a.exchangeAuthorizationCode(cmd.Context(), requestID, code)
	}}
	addAuthorizationIDFlags(exchange, &requestID)
	exchange.Flags().BoolVar(&exchangeCodeStdin, "code-stdin", false, "read one-time authorization code from stdin")
	get := &cobra.Command{Use: "get", RunE: a.simple(http.MethodGet, func() string { return a.authorizationRequestPath(requestID) }, "AuthorizationRequest", func() (url.Values, any, map[string]string, error) {
		return nil, nil, nil, required(requestID, "authorization-id")
	})}
	addAuthorizationIDFlags(get, &requestID)
	var waitOpenBrowser bool
	wait := &cobra.Command{Use: "wait", RunE: func(cmd *cobra.Command, _ []string) error {
		return a.waitAuthorization(cmd.Context(), requestID, waitOpenBrowser)
	}}
	addAuthorizationIDFlags(wait, &requestID)
	wait.Flags().BoolVar(&waitOpenBrowser, "open-browser", false, "open the stored authorization link while polling for consent")
	list := &cobra.Command{Use: "list-grants", RunE: a.simple(http.MethodGet, func() string {
		if a.userProfile() {
			return "/api/v3/agent-identity/me/agent-user-grants"
		}
		return a.agentManagementPrefix() + "/agent-user-grants"
	}, "UserGrantList", func() (url.Values, any, map[string]string, error) {
		return nil, nil, nil, nil
	})}
	var grantVersion int64
	revoke := &cobra.Command{Use: "revoke", RunE: a.simple(http.MethodPost, func() string {
		return a.agentManagementPrefix() + "/agent-user-grants/" + url.PathEscape(grantID) + "/revoke"
	}, "UserGrant", func() (url.Values, any, map[string]string, error) {
		if !revokeYes {
			return nil, nil, nil, confirmationRequired("revoke user grant")
		}
		if grantVersion <= 0 {
			return nil, nil, nil, localError("INVALID_ARGUMENT", "version must be greater than zero")
		}
		return nil, map[string]any{"version": grantVersion, "reason": reason}, idempotency(), required(grantID, "grant-id", reason, "reason")
	})}
	revoke.Flags().StringVar(&grantID, "grant-id", "", "UserGrant ID")
	revoke.Flags().Int64Var(&grantVersion, "version", 0, "expected UserGrant version")
	revoke.Flags().StringVar(&reason, "reason", "", "revocation reason")
	revoke.Flags().BoolVar(&revokeYes, "yes", false, "confirm UserGrant revocation")
	command.AddCommand(create, get, wait, consent, deny, cancel, exchange, list, revoke)
	return command
}

func addAuthorizationIDFlags(command *cobra.Command, value *string) {
	command.Flags().StringVar(value, "authorization-id", "", "authorization request ID")
	command.Flags().StringVar(value, "request-id", "", "deprecated alias for --authorization-id")
	_ = command.Flags().MarkDeprecated("request-id", "use --authorization-id; use the persistent --correlation-id for request correlation")
}

func (a *App) waitAuthorization(ctx context.Context, requestID string, openBrowser bool) error {
	if err := required(requestID, "authorization-id"); err != nil {
		return err
	}
	waitContext, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	callbackEvents := (<-chan authorizationCallback)(nil)
	closeCallback := func() {}
	callbackRef := "keychain://agent-identity/authorization/" + requestID + "/callback"
	if callbackURI, _ := a.Secrets.Get(callbackRef); callbackURI != "" {
		if events, closeFn, err := listenAuthorizationCallback(waitContext, callbackURI, requestID); err == nil {
			callbackEvents, closeCallback = events, closeFn
		}
	}
	defer closeCallback()
	if openBrowser && !a.noBrowser {
		urlRef := "keychain://agent-identity/authorization/" + requestID + "/url"
		authorizationURL, _ := a.Secrets.Get(urlRef)
		if authorizationURL == "" {
			return localError("AUTHORIZATION_URL_NOT_FOUND", "the authorization URL is unavailable in the OS secret store")
		}
		if err := authflow.Open(authorizationURL); err != nil {
			return localError("BROWSER_OPEN_FAILED", "could not open the authorization URL")
		}
	}
	delay := time.Second
	for {
		raw, responseRequestID, err := a.call(waitContext, http.MethodGet, a.authorizationRequestPath(requestID), nil, nil, nil)
		if err != nil {
			var apiError *apiclient.APIError
			if !errors.As(err, &apiError) || (apiError.Status != http.StatusTooManyRequests && apiError.Status < 500) {
				return classify(err, responseRequestID)
			}
			if apiError.RetryAfter > 0 {
				delay = apiError.RetryAfter
			}
		}
		var item struct {
			Status    string `json:"status"`
			PollAfter int    `json:"poll_after"`
		}
		if err == nil {
			_ = apiclient.DecodeData(raw, &item)
			if item.PollAfter > 0 {
				delay = time.Duration(item.PollAfter) * time.Second
			}
		}
		switch item.Status {
		case "APPROVED", "DENIED", "EXPIRED", "CANCELLED":
			if item.Status == "DENIED" {
				return &ExitError{Code: "AUTHORIZATION_DENIED", Message: "authorization was denied", RequestID: responseRequestID, Exit: 4}
			}
			if item.Status == "EXPIRED" || item.Status == "CANCELLED" {
				return &ExitError{Code: "AUTHORIZATION_" + item.Status, Message: "authorization reached " + strings.ToLower(item.Status), RequestID: responseRequestID, Exit: 5}
			}
			return output.WriteSuccess(a.Out, "AuthorizationRequest", json.RawMessage(raw), responseRequestID)
		case "CONSENTED":
			return a.exchangeAuthorizationCode(waitContext, requestID, "")
		}
		timer := time.NewTimer(delay)
		select {
		case <-waitContext.Done():
			timer.Stop()
			return &ExitError{Code: "AUTHORIZATION_PENDING", Message: "authorization is still pending", Exit: 6}
		case <-timer.C:
		case callback := <-callbackEvents:
			timer.Stop()
			if callback.Error != "" {
				return &ExitError{Code: "AUTHORIZATION_DENIED", Message: "authorization was denied", Exit: 4}
			}
			return a.exchangeAuthorizationCode(waitContext, requestID, callback.Code)
		}
		if delay < 15*time.Second {
			delay = time.Duration(float64(delay) * 1.5)
			if delay > 15*time.Second {
				delay = 15 * time.Second
			}
		}
	}
}

func (a *App) tokensCommand() *cobra.Command {
	command := &cobra.Command{Use: "tokens"}
	var credentialRef, grantID, audience string
	var permissions []string
	var ttl int
	var showToken bool
	var execCommand string
	var execArgs []string
	var tokenAgentID, tokenJTI, tokenReason string
	var revokeYes bool
	issue := &cobra.Command{Use: "issue", RunE: func(cmd *cobra.Command, _ []string) error {
		raw, requestID, err := a.issueToken(cmd.Context(), credentialRef, grantID, audience, permissions, ttl)
		if err != nil {
			return classify(err, requestID)
		}
		if execCommand != "" {
			var item struct {
				AccessToken string `json:"access_token"`
			}
			if apiclient.DecodeData(raw, &item) != nil || item.AccessToken == "" {
				return serverResponseError(requestID, "runtime Token response is invalid")
			}
			child := exec.CommandContext(cmd.Context(), execCommand, execArgs...)
			child.Env = append(os.Environ(), "AGENT_IDENTITY_ACCESS_TOKEN="+item.AccessToken)
			child.Stdin, child.Stdout, child.Stderr = a.In, a.Out, a.Err
			err := child.Run()
			item.AccessToken = ""
			if err != nil {
				return &ExitError{Code: "EXEC_COMMAND_FAILED", Message: "Token consumer command failed", RequestID: requestID, Exit: 5}
			}
			return nil
		}
		if !showToken {
			var item map[string]any
			_ = apiclient.DecodeData(raw, &item)
			delete(item, "access_token")
			raw, _ = json.Marshal(item)
		}
		return output.WriteSuccess(a.Out, "AgentAccessToken", json.RawMessage(raw), requestID)
	}}
	issue.Flags().StringVar(&credentialRef, "credential", "", "keychain credential reference")
	issue.Flags().StringVar(&grantID, "grant-id", "", "UserGrant ID")
	issue.Flags().StringVar(&audience, "audience", "", "ResourceServer audience")
	issue.Flags().StringSliceVar(&permissions, "permission-id", nil, "requested DataPolicy ID")
	issue.Flags().IntVar(&ttl, "ttl-seconds", 0, "requested Token TTL")
	issue.Flags().BoolVar(&showToken, "show-token", false, "include the access token in JSON output")
	issue.Flags().StringVar(&execCommand, "exec", "", "execute this program with a process-lifetime AGENT_IDENTITY_ACCESS_TOKEN")
	issue.Flags().StringSliceVar(&execArgs, "exec-arg", nil, "argument passed directly to --exec (repeatable)")
	list := &cobra.Command{Use: "list", RunE: a.simple(http.MethodGet, funcPath(a.agentManagementPrefix, "/agents/", &tokenAgentID, "/tokens"), "AgentTokenList", func() (url.Values, any, map[string]string, error) {
		return nil, nil, nil, required(tokenAgentID, "agent-id")
	})}
	list.Flags().StringVar(&tokenAgentID, "agent-id", "", "Agent ID")
	revoke := &cobra.Command{Use: "revoke", RunE: a.simple(http.MethodPost, func() string {
		if a.userProfile() {
			return "/api/v3/agent-identity/me/agents/" + url.PathEscape(tokenAgentID) + "/tokens/" + url.PathEscape(tokenJTI) + "/revoke"
		}
		return "/api/v3/agent-identity/admin/runtime/tokens/" + url.PathEscape(tokenJTI) + "/revoke"
	}, "AgentToken", func() (url.Values, any, map[string]string, error) {
		if !revokeYes {
			return nil, nil, nil, confirmationRequired("revoke token")
		}
		if a.userProfile() {
			return nil, map[string]any{"reason": tokenReason}, idempotency(), required(tokenAgentID, "agent-id", tokenJTI, "jti", tokenReason, "reason")
		}
		return nil, map[string]any{"reason": tokenReason}, idempotency(), required(tokenJTI, "jti", tokenReason, "reason")
	})}
	revoke.Flags().StringVar(&tokenAgentID, "agent-id", "", "Agent ID")
	revoke.Flags().StringVar(&tokenJTI, "jti", "", "Token JTI")
	revoke.Flags().StringVar(&tokenReason, "reason", "", "revocation reason")
	revoke.Flags().BoolVar(&revokeYes, "yes", false, "confirm token revocation")
	var tokenStdin bool
	inspect := &cobra.Command{Use: "inspect", RunE: func(_ *cobra.Command, _ []string) error {
		if !tokenStdin {
			return localError("INVALID_ARGUMENT", "token-stdin is required")
		}
		serialized, err := io.ReadAll(io.LimitReader(a.In, 64*1024))
		if err != nil {
			return err
		}
		header, claims, err := inspectJWT(strings.TrimSpace(string(serialized)))
		if err != nil {
			return err
		}
		return output.WriteSuccess(a.Out, "AgentTokenClaims", map[string]any{"header": header, "claims": claims, "signature_verified": false}, "")
	}}
	inspect.Flags().BoolVar(&tokenStdin, "token-stdin", false, "read token from stdin")
	command.AddCommand(issue, list, revoke, inspect)
	return command
}

func (a *App) apiCommand() *cobra.Command {
	command := &cobra.Command{Use: "api"}
	var credentialRef, grantID, audience, provider, method, path, bodyFile string
	call := &cobra.Command{Use: "call", RunE: func(cmd *cobra.Command, _ []string) error {
		if err := required(provider, "provider", path, "path"); err != nil || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			return firstError(err, localError("INVALID_ARGUMENT", "path must be an absolute normalized provider path"))
		}
		tokenRaw, requestID, err := a.issueToken(cmd.Context(), credentialRef, grantID, audience, nil, 0)
		if err != nil {
			return classify(err, requestID)
		}
		var token struct {
			AccessToken string `json:"access_token"`
		}
		if apiclient.DecodeData(tokenRaw, &token) != nil || token.AccessToken == "" {
			return serverResponseError(requestID, "runtime Token response is invalid")
		}
		client, _, _, _, err := a.client()
		if err != nil {
			return err
		}
		var body any
		if bodyFile != "" {
			body, err = readJSONFile(bodyFile)
			if err != nil {
				return err
			}
		}
		raw, responseRequestID, err := client.Do(cmd.Context(), strings.ToUpper(method), "/api/v3/agent-runtime/providers/"+url.PathEscape(provider)+path, nil, body, map[string]string{"Authorization": "Bearer " + token.AccessToken})
		token.AccessToken = ""
		if err != nil {
			return classify(err, responseRequestID)
		}
		var data any = json.RawMessage(raw)
		if !json.Valid(raw) {
			data = map[string]any{"content_base64": base64.StdEncoding.EncodeToString(raw), "encoding": "base64"}
		}
		return output.WriteSuccess(a.Out, "ProviderResponse", data, responseRequestID)
	}}
	call.Flags().StringVar(&credentialRef, "credential", "", "keychain credential reference")
	call.Flags().StringVar(&grantID, "grant-id", "", "UserGrant ID")
	call.Flags().StringVar(&audience, "audience", "", "ResourceServer audience")
	call.Flags().StringVar(&provider, "provider", "", "fixed Provider key")
	call.Flags().StringVar(&method, "method", "GET", "HTTP method")
	call.Flags().StringVar(&path, "path", "", "Provider path")
	call.Flags().StringVar(&bodyFile, "body-file", "", "JSON request body file")
	command.AddCommand(call)
	return command
}

func (a *App) issueToken(ctx context.Context, reference, grantID, audience string, permissions []string, ttl int) (json.RawMessage, string, error) {
	if err := required(reference, "credential", grantID, "grant-id", audience, "audience"); err != nil {
		return nil, "", err
	}
	secret, err := a.Secrets.Get(reference)
	if err != nil {
		return nil, "", &ExitError{Code: "CREDENTIAL_NOT_FOUND", Message: "credential is unavailable in the OS secret store", Exit: 3}
	}
	var credential struct {
		CredentialID string `json:"credential_id"`
		ClientSecret string `json:"client_secret"`
	}
	if json.Unmarshal([]byte(secret), &credential) != nil || credential.CredentialID == "" || credential.ClientSecret == "" {
		return nil, "", localError("INVALID_CREDENTIAL_REFERENCE", "stored credential is invalid")
	}
	client, _, _, _, err := a.client()
	if err != nil {
		return nil, "", err
	}
	raw, requestID, err := client.RuntimeToken(ctx, credential.CredentialID, credential.ClientSecret, grantID, audience, permissions, ttl)
	credential.ClientSecret = ""
	return raw, requestID, err
}

func (a *App) auditCommand() *cobra.Command {
	var agentID, action string
	command := &cobra.Command{Use: "audit"}
	list := &cobra.Command{Use: "list", RunE: a.simple(http.MethodGet, func() string { return a.agentManagementPrefix() + "/audit-events" }, "AuditEventList", func() (url.Values, any, map[string]string, error) {
		return compactQuery(map[string]string{"agent_id": agentID, "action": action}), nil, nil, nil
	})}
	list.Flags().StringVar(&agentID, "agent-id", "", "optional Agent ID filter")
	list.Flags().StringVar(&action, "action", "", "optional audit action filter")
	command.AddCommand(list)
	return command
}

func (a *App) doctorCommand() *cobra.Command {
	return &cobra.Command{Use: "doctor", RunE: func(cmd *cobra.Command, _ []string) error {
		_, _, name, item, err := a.client()
		if err != nil {
			return err
		}
		path := a.agentManagementPrefix() + "/agents"
		_, requestID, err := a.call(cmd.Context(), http.MethodGet, path, url.Values{"page_size": {"1"}}, nil, nil)
		checks := map[string]any{"profile": name, "endpoint": item.Endpoint, "selected_user_pool_id": item.SelectedUserPoolID, "secret_store": "available", "genauth": err == nil}
		if err != nil {
			return classify(err, requestID)
		}
		return output.WriteSuccess(a.Out, "DoctorReport", checks, requestID)
	}}
}

func (a *App) versionCommand() *cobra.Command {
	return &cobra.Command{Use: "version", RunE: func(_ *cobra.Command, _ []string) error {
		return output.WriteSuccess(a.Out, "Version", map[string]any{"cli_version": Version, "api_version": output.APIVersion, "server_contract": "genauth-agent-identity-v1"}, "")
	}}
}

func (a *App) completionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{Use: "completion [bash|zsh|fish|powershell]", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return root.GenBashCompletion(a.Out)
		case "zsh":
			return root.GenZshCompletion(a.Out)
		case "fish":
			return root.GenFishCompletion(a.Out, true)
		case "powershell":
			return root.GenPowerShellCompletion(a.Out)
		default:
			return localError("INVALID_ARGUMENT", "shell must be bash, zsh, fish, or powershell")
		}
	}}
}

func (a *App) simple(method string, path any, kind string, input func() (url.Values, any, map[string]string, error)) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		query, body, headers, err := input()
		if err != nil {
			return err
		}
		resolved := ""
		switch value := path.(type) {
		case string:
			resolved = value
		case func() string:
			resolved = value()
		}
		raw, requestID, err := a.call(cmd.Context(), method, resolved, query, body, headers)
		if err != nil {
			return classify(err, requestID)
		}
		return output.WriteSuccess(a.Out, kind, json.RawMessage(raw), requestID)
	}
}

func (a *App) call(ctx context.Context, method, path string, query url.Values, body any, headers map[string]string) (json.RawMessage, string, error) {
	client, token, name, item, err := a.client()
	if err != nil {
		return nil, "", err
	}
	raw, requestID, callErr := client.Do(ctx, method, path, query, body, headers)
	var apiError *apiclient.APIError
	if errors.As(callErr, &apiError) && apiError.Status == http.StatusUnauthorized && token.RefreshToken != "" && item.ClientID != "" {
		httpClient, clientErr := a.httpClient(a.timeout)
		if clientErr != nil {
			return nil, requestID, clientErr
		}
		refreshed, refreshErr := authflow.RefreshWithClient(ctx, httpClient, item.Endpoint, item.ClientID, token.RefreshToken)
		if refreshErr == nil {
			encoded, _ := json.Marshal(refreshed)
			if storeErr := a.Secrets.Set(item.SecretRef, string(encoded)); storeErr == nil {
				client.SessionToken = refreshed.AccessToken
				raw, requestID, callErr = client.Do(ctx, method, path, query, body, headers)
			}
		}
	}
	if a.debug {
		status := "success"
		if callErr != nil {
			status = "failure"
		}
		_, _ = fmt.Fprintf(a.Err, "agent-identity debug method=%s path=%s profile=%s result=%s request_id=%s\n", method, path, name, status, requestID)
	}
	return raw, requestID, callErr
}

func (a *App) client() (*apiclient.Client, authflow.Token, string, profile.Profile, error) {
	config, err := a.Profiles.Load()
	if err != nil {
		return nil, authflow.Token{}, "", profile.Profile{}, err
	}
	name, item, err := config.Current(a.profile)
	if err != nil {
		return nil, authflow.Token{}, "", profile.Profile{}, localError("NOT_LOGGED_IN", "run agent-identity auth login first")
	}
	secret, err := a.Secrets.Get(item.SecretRef)
	if err != nil {
		return nil, authflow.Token{}, "", profile.Profile{}, &ExitError{Code: "SESSION_EXPIRED", Message: "login session is unavailable", Exit: 3}
	}
	var token authflow.Token
	if json.Unmarshal([]byte(secret), &token) != nil || token.AccessToken == "" {
		token.AccessToken = secret
	}
	if a.endpointOverride != "" {
		if err := a.validateEndpoint(a.endpointOverride); err != nil {
			return nil, authflow.Token{}, "", profile.Profile{}, localError("INVALID_ENDPOINT", "endpoint must be a GenAuth HTTPS origin")
		}
		item.Endpoint = strings.TrimRight(a.endpointOverride, "/")
	}
	client := apiclient.New(item.Endpoint, token.AccessToken, item.SelectedUserPoolID, a.timeout)
	httpClient, err := a.httpClient(a.timeout)
	if err != nil {
		return nil, authflow.Token{}, "", profile.Profile{}, err
	}
	client.HTTP = httpClient
	client.RequestID = a.requestID
	return client, token, name, item, nil
}

func (a *App) validateEndpoint(endpoint string) error {
	if err := profile.ValidateEndpoint(endpoint); err != nil {
		return err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if parsed.Scheme == "http" && !a.allowLocalHTTP {
		return errors.New("insecure localhost endpoint requires explicit acknowledgement")
	}
	return nil
}

func (a *App) httpClient(timeout time.Duration) (*http.Client, error) {
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		baseTransport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	transport := baseTransport.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(a.caFile) != "" {
		content, err := os.ReadFile(a.caFile)
		if err != nil {
			return nil, localError("INVALID_CA_FILE", "unable to read the configured CA file")
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(content) {
			clear(content)
			return nil, localError("INVALID_CA_FILE", "the configured CA file does not contain a PEM certificate")
		}
		clear(content)
		transport.TLSClientConfig.RootCAs = roots
	}
	if strings.TrimSpace(a.proxyURL) != "" {
		proxy, err := url.Parse(a.proxyURL)
		if err != nil || (proxy.Scheme != "http" && proxy.Scheme != "https") || proxy.Host == "" || proxy.User != nil || (proxy.Path != "" && proxy.Path != "/") || proxy.RawQuery != "" || proxy.Fragment != "" {
			return nil, localError("INVALID_PROXY", "proxy must be an HTTP(S) origin without credentials, path, query, or fragment")
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func (a *App) userProfile() bool {
	config, err := a.Profiles.Load()
	if err != nil {
		return false
	}
	_, item, err := config.Current(a.profile)
	return err == nil && item.LoginType == "user"
}

func (a *App) agentManagementPrefix() string {
	if a.userProfile() {
		return "/api/v3/agent-identity/me"
	}
	return "/api/v3/agent-identity/admin"
}

func (a *App) authorizationRequestPath(requestID string) string {
	prefix := "/api/v3/agent-identity/admin/authorization-requests/"
	if a.userProfile() {
		prefix = "/api/v3/agent-identity/me/authorization-requests/"
	}
	return prefix + url.PathEscape(requestID)
}

func (a *App) permissionCatalogPrefix() string {
	return a.agentManagementPrefix() + "/permission-catalog"
}

func Execute() int {
	app, err := New()
	if err != nil {
		output.WriteFailure(os.Stderr, "INTERNAL_ERROR", err.Error(), "", nil)
		return 9
	}
	err = app.Root().Execute()
	if err == nil {
		return 0
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		output.WriteFailure(app.Err, exit.Code, exit.Message, exit.RequestID, exit.Remediation)
		return exit.Exit
	}
	output.WriteFailure(app.Err, "INTERNAL_ERROR", err.Error(), "", nil)
	return 9
}

func classify(err error, requestID string) error {
	var exit *ExitError
	if errors.As(err, &exit) {
		return err
	}
	var api *apiclient.APIError
	if !errors.As(err, &api) {
		return &ExitError{Code: "UPSTREAM_UNAVAILABLE", Message: "GenAuth is unavailable", RequestID: requestID, Exit: 7}
	}
	exitCode := 9
	switch {
	case api.Status == 401:
		exitCode = 3
	case api.Status == 403:
		exitCode = 4
	case api.Status == 404 || api.Status == 410 || api.Status == 422:
		exitCode = 5
	case api.Status == 409:
		exitCode = 8
	case api.Status == 429 || api.Status >= 500:
		exitCode = 7
	case api.Status >= 400:
		exitCode = 2
	}
	return &ExitError{Code: api.Code, Message: api.Message, RequestID: requestID, Exit: exitCode}
}

func localError(code, message string) error {
	exit := 2
	if code == "NOT_LOGGED_IN" {
		exit = 3
	}
	return &ExitError{Code: code, Message: message, Exit: exit}
}
func serverResponseError(requestID, message string) error {
	return &ExitError{Code: "INVALID_SERVER_RESPONSE", Message: message, RequestID: requestID, Exit: 9}
}
func required(values ...string) error {
	for index := 0; index+1 < len(values); index += 2 {
		if strings.TrimSpace(values[index]) == "" {
			return localError("INVALID_ARGUMENT", values[index+1]+" is required")
		}
	}
	return nil
}
func idempotency() map[string]string {
	value, err := uuid.NewV7()
	if err != nil {
		return nil
	}
	return map[string]string{"Idempotency-Key": value.String()}
}
func mergeHeaders(values ...map[string]string) map[string]string {
	result := map[string]string{}
	for _, value := range values {
		for key, item := range value {
			result[key] = item
		}
	}
	return result
}
func compactQuery(values map[string]string) url.Values {
	result := url.Values{}
	for key, value := range values {
		if value != "" {
			result.Set(key, value)
		}
	}
	return result
}
func queryFrom(path string) url.Values { parsed, _ := url.Parse(path); return parsed.Query() }
func funcPath(values ...any) func() string {
	return func() string {
		var result strings.Builder
		for _, value := range values {
			switch item := value.(type) {
			case string:
				result.WriteString(item)
			case *string:
				result.WriteString(url.PathEscape(*item))
			case func() string:
				result.WriteString(item())
			}
		}
		return result.String()
	}
}
func firstError(values ...error) error {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
func readJSONFile(path string) (any, error) {
	clean := filepath.Clean(path)
	content, err := os.ReadFile(clean)
	if err != nil {
		return nil, err
	}
	var result any
	if json.Unmarshal(content, &result) != nil {
		return nil, localError("INVALID_JSON", "input file must contain valid JSON")
	}
	return result, nil
}

func readObjectFile(path string) (map[string]any, error) {
	clean := filepath.Clean(path)
	content, err := os.ReadFile(clean)
	if err != nil {
		return nil, err
	}
	result := map[string]any{}
	if err := yaml.Unmarshal(content, &result); err != nil {
		return nil, localError("INVALID_INPUT_FILE", "input file must contain a YAML or JSON object")
	}
	return result, nil
}

func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		if typed, typedOK := value.([]string); typedOK {
			return uniqueStrings(typed)
		}
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
			result = append(result, strings.TrimSpace(text))
		}
	}
	return uniqueStrings(result)
}

func permissionIDs(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if object, ok := item.(map[string]any); ok {
			if permissionID, ok := object["permission_id"].(string); ok {
				result = append(result, permissionID)
			}
		}
	}
	return uniqueStrings(result)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func promptIfEmpty(reader *bufio.Reader, writer io.Writer, label, current string) (string, error) {
	if strings.TrimSpace(current) != "" {
		return current, nil
	}
	_, _ = fmt.Fprintf(writer, "%s: ", label)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", localError("INVALID_ARGUMENT", label+" is required")
	}
	return value, nil
}

type authorizationCallback struct {
	Code  string
	Error string
}

func newLoopbackRedirectURI() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", err
	}
	return "http://" + address + "/callback", nil
}

func listenAuthorizationCallback(ctx context.Context, callbackURI, requestID string) (<-chan authorizationCallback, func(), error) {
	parsed, err := url.Parse(callbackURI)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.Path != "/callback" {
		return nil, func() {}, errors.New("callback is not a supported loopback URI")
	}
	listener, err := net.Listen("tcp", parsed.Host)
	if err != nil {
		return nil, func() {}, err
	}
	events := make(chan authorizationCallback, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("request_id") != requestID {
			http.Error(writer, "Invalid Agent Identity authorization callback.", http.StatusBadRequest)
			return
		}
		event := authorizationCallback{Code: request.URL.Query().Get("code"), Error: request.URL.Query().Get("error")}
		if event.Code == "" && event.Error == "" {
			http.Error(writer, "Missing Agent Identity authorization result.", http.StatusBadRequest)
			return
		}
		select {
		case events <- event:
		default:
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(writer, "Agent Identity authorization received. You may close this window.")
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	go func() { _ = server.Serve(listener) }()
	closeFn := func() {
		shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}
	go func() {
		<-ctx.Done()
		closeFn()
	}()
	return events, closeFn, nil
}

func (a *App) exchangeAuthorizationCode(ctx context.Context, requestID, code string) error {
	pkceRef := "keychain://agent-identity/authorization/" + requestID + "/pkce"
	verifier, err := a.Secrets.Get(pkceRef)
	if err != nil || verifier == "" {
		return localError("PKCE_NOT_FOUND", "PKCE verifier is unavailable in the OS secret store")
	}
	body := map[string]any{"code_verifier": verifier}
	if code != "" {
		body["authorization_code"] = code
	}
	raw, responseRequestID, callErr := a.call(ctx, http.MethodPost, a.authorizationRequestPath(requestID)+"/exchange", nil, body, idempotency())
	code, verifier = "", ""
	if callErr != nil {
		return classify(callErr, responseRequestID)
	}
	warnings := a.cleanupAuthorizationSecrets(requestID)
	return output.WriteSuccessWithWarnings(a.Out, "UserGrant", json.RawMessage(raw), responseRequestID, warnings)
}

func (a *App) authorizationSecretRefs(requestID string) []string {
	prefix := "keychain://agent-identity/authorization/" + requestID + "/"
	return []string{prefix + "pkce", prefix + "code", prefix + "callback", prefix + "url"}
}

func (a *App) probeSecretStore() error {
	reference := "keychain://agent-identity/probe/" + uuid.NewString()
	if err := a.Secrets.Set(reference, "secret-store-readiness-probe"); err != nil {
		return &ExitError{Code: "SECRET_STORE_UNAVAILABLE", Message: "OS secret store is unavailable", Exit: 9}
	}
	if err := a.Secrets.Delete(reference); err != nil {
		return &ExitError{Code: "SECRET_STORE_UNAVAILABLE", Message: "OS secret store cannot safely remove temporary entries", Exit: 9}
	}
	return nil
}

func (a *App) cleanupAuthorizationSecrets(requestID string) []string {
	failed := false
	for _, reference := range a.authorizationSecretRefs(requestID) {
		if err := a.Secrets.Delete(reference); err != nil {
			failed = true
		}
	}
	if failed {
		return []string{"authorization exchange succeeded, but one or more one-time values could not be removed from the OS secret store"}
	}
	return nil
}

func (a *App) compensateAuthorizationCreate(ctx context.Context, requestID string) {
	_ = a.cleanupAuthorizationSecrets(requestID)
	_, _, _ = a.call(ctx, http.MethodPost, a.authorizationRequestPath(requestID)+"/cancel", nil, nil, idempotency())
}

func tokenSubject(serialized string) string {
	parts := strings.Split(serialized, ".")
	if len(parts) != 3 {
		return ""
	}
	content, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	_ = json.Unmarshal(content, &claims)
	return claims.Subject
}

func confirmationRequired(action string) error {
	return localError("CONFIRMATION_REQUIRED", "pass --yes after confirming: "+action)
}

func inspectJWT(serialized string) (map[string]any, map[string]any, error) {
	parts := strings.Split(serialized, ".")
	if len(parts) != 3 {
		return nil, nil, localError("INVALID_TOKEN", "token must be a compact JWT")
	}
	decode := func(value string) (map[string]any, error) {
		content, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			return nil, localError("INVALID_TOKEN", "token contains invalid base64url")
		}
		var result map[string]any
		if json.Unmarshal(content, &result) != nil {
			return nil, localError("INVALID_TOKEN", "token contains invalid JSON")
		}
		return result, nil
	}
	header, err := decode(parts[0])
	if err != nil {
		return nil, nil, err
	}
	claims, err := decode(parts[1])
	if err != nil {
		return nil, nil, err
	}
	return header, claims, nil
}
