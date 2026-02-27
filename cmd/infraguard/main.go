package main

import (
	"os"

	"github.com/yourorg/infraguard/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
