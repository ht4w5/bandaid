package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ht4w5/bandaid/internal/app"
	"github.com/ht4w5/bandaid/pkg/logx"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	var cfg app.Config
	var whitelistString string
	var logLevel string

	// Register flags.
	flag.StringVar(&cfg.URL, "url", "", "report URL to fetch")
	flag.StringVar(&cfg.CaFile, "cacert", "", "CA certificate file")
	flag.StringVar(&cfg.CertFile, "cert", "", "client certificate file")
	flag.StringVar(&cfg.KeyFile, "key", "", "client key file")
	flag.StringVar(&whitelistString, "whitelist", "", "whitelist targets delimited with commas")
	flag.DurationVar(&cfg.UpdateInterval, "update-interval", time.Minute, "geo file update interval")
	flag.StringVar(&cfg.GeoFile, "geofile", "", "generated geo file path")
	flag.StringVar(&cfg.PostExec, "post-exec", "", "command to run after geo file update")
	flag.StringVar(&cfg.VariableName, "var-name", "$geo", "generated variable name")
	flag.StringVar(&cfg.AddressVariableName, "addr-var-name", "", "generated address variable name")
	flag.StringVar(&cfg.DefaultString, "default-str", "", "generated default string")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "fetch and generate once without running as a service")
	flag.StringVar(&logLevel, "log-level", "info", "log level: none, error, warn, info, debug or a numeric level")
	flag.DurationVar(&cfg.FetchTimeout, "fetch-timeout", 10*time.Second, "set fetch HTTP timeout")
	flag.StringVar(&cfg.GeoFileMode, "geofile-mode", "644", "set mode of created geofile")

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
