package secretstore

import (
	"errors"
	"strings"

	"github.com/zalando/go-keyring"
)

const service = "agent-identity-cli"

var ErrInvalidReference = errors.New("invalid secret reference")

type Store interface {
	Set(reference, value string) error
	Get(reference string) (string, error)
	Delete(reference string) error
}

type Keyring struct{}

func New() *Keyring { return &Keyring{} }

func account(reference string) (string, error) {
	const prefix = "keychain://agent-identity/"
	if !strings.HasPrefix(reference, prefix) || len(reference) <= len(prefix) || len(reference) > 256 || strings.ContainsAny(reference, "\r\n\x00") {
		return "", ErrInvalidReference
	}
	return strings.TrimPrefix(reference, prefix), nil
}

func (Keyring) Set(reference, value string) error {
	name, err := account(reference)
	if err != nil || value == "" {
		return ErrInvalidReference
	}
	return keyring.Set(service, name, value)
}

func (Keyring) Get(reference string) (string, error) {
	name, err := account(reference)
	if err != nil {
		return "", err
	}
	return keyring.Get(service, name)
}

func (Keyring) Delete(reference string) error {
	name, err := account(reference)
	if err != nil {
		return err
	}
	return keyring.Delete(service, name)
}
