package app

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/ht4w5/bd2geo/internal/bd"
	"github.com/ht4w5/bd2geo/internal/geo"
	"github.com/ht4w5/bd2geo/pkg/ipx"
	"github.com/ht4w5/bd2geo/pkg/logx"
	"go4.org/netipx"
)

// Exit codes.
const (
	ExitSuccess int = iota
	ExitFileError
	ExitOutfileExists
	ExitInternalError
)

type Config struct {
	VariableName        string
	AddressVariableName string
	DefaultString       string
	// Prefix or Address.
	WhitelistTargets []string
	// "" for stdin.
	InFile string
	// "" for stdout.
	OutFile string
	Verbose bool
	// Overwrite existing outfile.
	Overwrite bool
}

func Run(ctx context.Context, cfg Config) int {
	// Logger.
	var logger *slog.Logger
	if cfg.Verbose {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	}
	ctx = logx.WithLogger(ctx, logger)

	// Parse whitelist.
	var whitelistB netipx.IPSetBuilder

	for _, t := range cfg.WhitelistTargets {
		prefix, err := ipx.ParsePrefixOrAddr(t)
		if err != nil {
			logger.Error("invalid whitelist target", "target", t, "err", err)
			continue
		}
		whitelistB.AddPrefix(prefix)
	}

	whitelist, err := whitelistB.IPSet()
	if err != nil {
		logger.Warn("error building whitelist ipset", "err", err)
	}

	// Open files.
	var infile, outfile *os.File
	if cfg.InFile == "" {
		infile = os.Stdin
	} else {
		f, err := os.Open(cfg.InFile)
		if err != nil {
			logger.Error("error opening infile", "err", err)
			return ExitFileError
		}
		defer f.Close()
		infile = f
	}
	if cfg.OutFile == "" {
		outfile = os.Stdout
	} else {
		if !cfg.Overwrite {
			f, err := os.OpenFile(cfg.OutFile, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o400)
			if err != nil {
				if os.IsExist(err) {
					logger.Error("outfile exists", "outfile", cfg.OutFile, "err", err)
					return ExitOutfileExists
				}
				logger.Error("error opening outfile", "err", err)
				return ExitFileError
			}
			defer f.Close()
			outfile = f
		} else {
			f, err := os.Create(cfg.OutFile)
			if err != nil {
				logger.Error("error opening outfile", "err", err)
				return ExitFileError
			}
			defer f.Close()
			outfile = f
		}
	}

	gg, err := geo.NewGeoGenerator(geo.GeoGeneratorConfig{
		VariableName:        cfg.VariableName,
		AddressVariableName: cfg.AddressVariableName,
		DefaultString:       cfg.DefaultString,
	}, time.Now)

	if err != nil {
		logger.Error("error creating geo generator", "err", err)
		return ExitInternalError
	}

	// Parse report.
	report, err := bd.ParseReport(infile)
	if err != nil {
		logger.Error("error parsing report", "err", err)
		return ExitInternalError
	}

	err = report.Exclude(whitelist)
	if err != nil {
		logger.Error("error applying whitelist", "err", err)
		return ExitInternalError
	}

	err = report.Normalize()
	if err != nil {
		logger.Error("error normalizing report", "err", err)
	}

	hash := report.Hash()

	err = gg.Generate(outfile, report, hash)
	if err != nil {
		logger.Error("error generating geo", "err", err)
		return ExitInternalError
	}

	return ExitSuccess
}
