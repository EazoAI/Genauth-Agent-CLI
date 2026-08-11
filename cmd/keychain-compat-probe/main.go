package main

import (
	"fmt"
	"os"

	"github.com/Authing/genauth-agent-cli/internal/cli/secretstore"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: keychain-compat-probe <set|get|delete> <reference>")
	}
	store := secretstore.New()
	var err error
	switch os.Args[1] {
	case "set":
		err = store.Set(os.Args[2], "agent-identity-keychain-compat-probe")
	case "get":
		var value string
		value, err = store.Get(os.Args[2])
		if err == nil && value != "agent-identity-keychain-compat-probe" {
			err = fmt.Errorf("unexpected probe value")
		}
	case "delete":
		err = store.Delete(os.Args[2])
	default:
		err = fmt.Errorf("unknown operation")
	}
	if err != nil {
		panic(err)
	}
	fmt.Println("ok")
}
