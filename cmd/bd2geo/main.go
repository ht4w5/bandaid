package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"

	"github.com/ht4w5/bd2geo/internal/app"
)

func main() {
	var cfg app.Config
	var whitelistString string

	// Register flags.
	flag.StringVar(&cfg.InFile, "i", "", "path to infile")
	flag.StringVar(&cfg.OutFile, "o", "", "path to outfile")
	flag.BoolVar(&cfg.Verbose, "v", false, "be verbose")
	flag.StringVar(&whitelistString, "w", "", "whitelist targets delimited with commas")
	flag.BoolVar(&cfg.Overwrite, "overwrite", false, "overwrite existing outfile")
	flag.StringVar(&cfg.VariableName, "varName", "$geo", "generated variable name")
	flag.StringVar(&cfg.AddressVariableName, "addrVarName", "", "generated address variable name")
	flag.StringVar(&cfg.DefaultString, "defaultStr", "", "generated default string")

	flag.Parse()

	if whitelistString != "" {
		cfg.WhitelistTargets = strings.Split(whitelistString, ",")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	done := make(chan int, 1)
	go func() { done <- app.Run(ctx, cfg) }()

	select {
	case code := <-done:
		os.Exit(code)
	case <-ctx.Done():
		select {
		case code := <-done:
			os.Exit(code)
		default:
		}
		os.Exit(130) // 128 + SIGINT
	}
}
