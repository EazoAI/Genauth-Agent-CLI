package main

import (
	"os"

	"github.com/Authing/genauth-agent-cli/internal/cli/command"
)

func main() { os.Exit(command.Execute()) }
