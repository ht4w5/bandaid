package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ht4w5/bd2geo/internal/app"
	"github.com/ht4w5/bd2geo/pkg/logx"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	var cfg app.Config
	var whitelistString string
	var logLevel string

	// Register flags.
	flag.StringVar(&cfg.URL, "url", "", "report URL to fetch")
	flag.StringVar(&cfg.CaFile, "caFile", "", "CA certificate file")
	flag.StringVar(&cfg.CertFile, "certFile", "", "client certificate file")
	flag.StringVar(&cfg.KeyFile, "keyFile", "", "client key file")
	flag.StringVar(&whitelistString, "w", "", "whitelist targets delimited with commas")
	flag.DurationVar(&cfg.UpdateInterval, "interval", time.Minute, "geo file update interval")
	flag.StringVar(&cfg.GeoFile, "geoFile", "", "generated geo file path")
	flag.StringVar(&cfg.PostCmd, "postCmd", "", "command to run after geo file update")
	flag.StringVar(&cfg.VariableName, "varName", "$geo", "generated variable name")
	flag.StringVar(&cfg.AddressVariableName, "addrVarName", "", "generated address variable name")
	flag.StringVar(&cfg.DefaultString, "defaultStr", "", "generated default string")
	flag.BoolVar(&cfg.DryRun, "dryRun", false, "fetch and generate once without running as a service")
	flag.StringVar(&logLevel, "logLevel", "info", "log level: none, error, warn, info, debug or a numeric level")
	flag.DurationVar(&cfg.FetchTimeout, "fetch-timeout", 10*time.Second, "set fetch HTTP timeout")
	flag.Uint64Var(&cfg.GeoFileMode, "geofile-mode", 0o644, "set mode of created geofile")

	flag.Parse()

	if whitelistString != "" {
		cfg.WhitelistTargets = strings.Split(whitelistString, ",")
	}

	logger := logx.NewLogger(logLevel)
	ctx = logx.WithLogger(ctx, logger)

	if err := app.Run(ctx, cfg); err != nil {
		logger.Error("run app", "err", err)
		stop()
		os.Exit(1)
	}
	stop()
	os.Exit(0)
}
