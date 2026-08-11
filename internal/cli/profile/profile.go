package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const APIVersion = "agent-identity.cli/v1"

var ErrInvalid = errors.New("invalid CLI profile")

type Profile struct {
	Endpoint           string `json:"endpoint"`
	ClientID           string `json:"client_id,omitempty"`
	LoginType          string `json:"login_type"`
	SubjectID          string `json:"subject_id,omitempty"`
	SelectedUserPoolID string `json:"selected_user_pool_id"`
	SecretRef          string `json:"secret_ref"`
}

type Config struct {
	APIVersion     string             `json:"api_version"`
	CurrentProfile string             `json:"current_profile"`
	Profiles       map[string]Profile `json:"profiles"`
}

type Store struct{ path string }

func NewStore() (*Store, error) {
	directory := strings.TrimSpace(os.Getenv("AGENT_IDENTITY_CONFIG_DIR"))
	if directory == "" {
		root, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		directory = filepath.Join(root, "agent-identity")
	}
	return &Store{path: filepath.Join(directory, "config.json")}, nil
}

func (s *Store) Path() string { return s.path }

func (s *Store) Load() (Config, error) {
	content, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{APIVersion: APIVersion, Profiles: map[string]Profile{}}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var result Config
	if json.Unmarshal(content, &result) != nil || result.APIVersion != APIVersion || result.Profiles == nil {
		return Config{}, ErrInvalid
	}
	return result, nil
}

func (s *Store) Save(config Config) error {
	config.APIVersion = APIVersion
	if config.Profiles == nil {
		config.Profiles = map[string]Profile{}
	}
	for name, item := range config.Profiles {
		if err := ValidateName(name); err != nil {
			return err
		}
		if err := Validate(item); err != nil {
			return fmt.Errorf("profile %s: %w", name, err)
		}
	}
	if config.CurrentProfile != "" {
		if _, ok := config.Profiles[config.CurrentProfile]; !ok {
			return ErrInvalid
		}
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".config-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, s.path)
}

func Validate(item Profile) error {
	if err := ValidateEndpoint(item.Endpoint); err != nil {
		return err
	}
	if item.LoginType != "user" && item.LoginType != "tenant_admin" || strings.TrimSpace(item.SelectedUserPoolID) == "" || !strings.HasPrefix(item.SecretRef, "keychain://agent-identity/") {
		return ErrInvalid
	}
	return nil
}

func ValidateEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost"))) {
		return ErrInvalid
	}
	return nil
}

func ValidateName(value string) error {
	if len(value) < 1 || len(value) > 64 {
		return ErrInvalid
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_' || char == '.') {
			return ErrInvalid
		}
	}
	return nil
}

func (c Config) Current(override string) (string, Profile, error) {
	name := strings.TrimSpace(override)
	if name == "" {
		name = c.CurrentProfile
	}
	item, ok := c.Profiles[name]
	if !ok {
		return "", Profile{}, ErrInvalid
	}
	return name, item, nil
}
