package profile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoreUsesPrivatePermissionsAndRoundTripsProfiles(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("AGENT_IDENTITY_CONFIG_DIR", directory)
	store, err := NewStore()
	require.NoError(t, err)
	config := Config{CurrentProfile: "acme", Profiles: map[string]Profile{"acme": {Endpoint: "https://genauth.example.com", LoginType: "tenant_admin", SelectedUserPoolID: "pool-1", SecretRef: "keychain://agent-identity/session/acme"}}}
	require.NoError(t, store.Save(config))
	info, err := os.Stat(filepath.Join(directory, "config.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	loaded, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, "pool-1", loaded.Profiles["acme"].SelectedUserPoolID)
}

func TestValidateRejectsNonGenAuthOrigins(t *testing.T) {
	tests := []string{"http://public.example.com", "https://example.com/path", "https://user:secret@example.com", "file:///tmp/socket"}
	for _, endpoint := range tests {
		t.Run(endpoint, func(t *testing.T) {
			err := Validate(Profile{Endpoint: endpoint, LoginType: "user", SelectedUserPoolID: "pool-1", SecretRef: "keychain://agent-identity/session/test"})
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}
