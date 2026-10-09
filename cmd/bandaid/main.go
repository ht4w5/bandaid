package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/ht4w5/bandaid/internal/app"
	"github.com/ht4w5/bandaid/internal/info"
	"github.com/ht4w5/bandaid/pkg/logx"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	var cfg app.Config
	var whitelistString string
	var logLevel string

	// Register flags.
	flag.StringVarP(&cfg.URL, "url", "u", "", "report URL to fetch")
	flag.StringVar(&cfg.CaFile, "cacert", "", "CA certificate file")
	flag.StringVar(&cfg.CertFile, "cert", "", "client certificate file")
	flag.StringVar(&cfg.KeyFile, "key", "", "client key file")
	flag.StringVarP(&whitelistString, "whitelist", "w", "", "whitelist targets delimited with commas")
	flag.DurationVarP(&cfg.UpdateInterval, "update-interval", "i", time.Minute, "geo file update interval")
	flag.StringVarP(&cfg.GeoFile, "geofile", "o", "", "generated geo file path")
	flag.StringVarP(&cfg.PostExec, "post-exec", "x", "", "command and args to run after geo file update (executed directly, not through a shell)")
	flag.StringVarP(&cfg.VariableName, "var-name", "n", "$geo", "generated variable name")
	flag.StringVar(&cfg.AddressVariableName, "addr-var-name", "", "generated address variable name")
	flag.StringVar(&cfg.DefaultString, "default-str", "", "generated default string")
	flag.BoolVarP(&cfg.DryRun, "dry-run", "d", false, "fetch and generate once without running as a service")
	flag.StringVarP(&logLevel, "log-level", "l", "info", "log level: none, error, warn, info, debug or a numeric level")
	flag.DurationVarP(&cfg.FetchTimeout, "fetch-timeout", "t", 10*time.Second, "set fetch HTTP timeout")
	flag.Int64VarP(&cfg.MaxReportBytes, "max-report-bytes", "m", 32<<20, "maximum accepted report size in bytes")
	flag.StringVar(&cfg.GeoFileMode, "geofile-mode", "644", "set mode of created geofile")
	showVersion := flag.BoolP("version", "v", false, "print version and exit")
	showHelp := flag.BoolP("help", "h", false, "show this help and exit")

	flag.Parse()

	if *showHelp {
		flag.Usage()
		os.Exit(0)
	}
	if *showVersion {
		fmt.Println(info.String())
		os.Exit(0)
	}

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
