package main

import (
	"os"

	"github.com/Abdullah1738/juno-txsign/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
