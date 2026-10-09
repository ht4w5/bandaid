package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ht4w5/bd2geo/internal/geo"
	"github.com/ht4w5/bd2geo/internal/report"
	"github.com/ht4w5/bd2geo/pkg/execx"
	"github.com/ht4w5/bd2geo/pkg/ipx"
	"github.com/ht4w5/bd2geo/pkg/logx"
	"go4.org/netipx"
)

type Config struct {
	// Fetch config.
	URL          string
	CaFile       string
	CertFile     string
	KeyFile      string
	FetchTimeout time.Duration

	// Report config.
	// Prefix or Address.
	WhitelistTargets []string

	// Service config.
	UpdateInterval time.Duration
	GeoFile        string
	GeoFileMode    uint64
	PostCmd        string

	// Geo config.
	VariableName        string
	AddressVariableName string
	DefaultString       string

	// Misc.
	DryRun bool
}

func Run(ctx context.Context, cfg Config) error {
	// Parse whitelist.
	var whitelistB netipx.IPSetBuilder

	for _, t := range cfg.WhitelistTargets {
		prefix, err := ipx.ParsePrefixOrAddr(t)
		if err != nil {
			return fmt.Errorf("parse whitelist target: %w", err)
		}
		whitelistB.AddPrefix(prefix)
	}

	whitelist, err := whitelistB.IPSet()
	if err != nil {
		return fmt.Errorf("build whitelist set: %w", err)
	}

	g, err := geo.NewGenerator(geo.GeneratorConfig{
		VariableName:        cfg.VariableName,
		AddressVariableName: cfg.AddressVariableName,
		DefaultString:       cfg.DefaultString,
	})

	if err != nil {
		return fmt.Errorf("create geo generator: %w", err)
	}

	f, err := report.NewFetcher(report.FetcherConfig{
		URL:      cfg.URL,
		CaFile:   cfg.CaFile,
		CertFile: cfg.CertFile,
		KeyFile:  cfg.KeyFile,
		Timeout:  cfg.FetchTimeout,
	})
	if err != nil {
		return fmt.Errorf("create report fetcher: %w", err)
	}

	if cfg.DryRun {
		return runDry(ctx, f, g, whitelist)
	} else {
		return runService(ctx, cfg, f, g, whitelist)
	}
}

func runDry(ctx context.Context, f *report.Fetcher, g *geo.Generator, whitelist *netipx.IPSet) error {
	r, err := f.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("fetch report: %w", err)
	}

	if err := r.Exclude(whitelist); err != nil {
		return fmt.Errorf("exclude whitelist: %w", err)
	}

	if err := r.Normalize(); err != nil {
		return fmt.Errorf("normalize report: %w", err)
	}

	hash := r.Hash()

	if err := g.Generate(os.Stdout, time.Now, r, hash); err != nil {
		return fmt.Errorf("generate geo: %w", err)
	}

	return nil
}

func runService(ctx context.Context, cfg Config, f *report.Fetcher, g *geo.Generator, whitelist *netipx.IPSet) error {
	logger := logx.FromContext(ctx)
	if cfg.UpdateInterval < time.Minute {
		cfg.UpdateInterval = time.Minute
		logger.Warn("update interval clamped", "interval", cfg.UpdateInterval)
	}
	ticker := time.NewTicker(cfg.UpdateInterval)
	defer ticker.Stop()

	var lastHash uint32

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t := <-ticker.C:
			logger.Info("begin report update", "time", t)

			r, err := f.Fetch(ctx)
			if err != nil {
				logger.Error("fetch report", "err", err)
				continue
			}

			if err := r.Exclude(whitelist); err != nil {
				logger.Error("exclude whitelist", "err", err)
				continue
			}

			if err := r.Normalize(); err != nil {
				logger.Error("normalize report", "err", err)
				continue
			}

			hash := r.Hash()
			if hash == lastHash {
				logger.Info("report unchanged; skipping geo generation", "hash", fmt.Sprintf("%x", hash))
				continue
			}

			tmp, err := os.CreateTemp(filepath.Dir(cfg.GeoFile), "geofile-*")
			if err != nil {
				logger.Error("open temp file", "err", err)
				continue
			}
			tmpName := tmp.Name()

			cleanup := func() {
				tmp.Close()
				os.Remove(tmpName)
			}

			if err := g.Generate(tmp, func() time.Time { return t }, r, hash); err != nil {
				logger.Error("generate geo", "err", err)
				cleanup()
				continue
			}

			if err := tmp.Close(); err != nil {
				logger.Error("close temp file", "err", err)
				os.Remove(tmpName)
				continue
			}

			if err := os.Chmod(tmpName, os.FileMode(cfg.GeoFileMode&0o777)); err != nil {
				logger.Error("chmod temp file", "err", err)
				os.Remove(tmpName)
				continue
			}

			if err := os.Rename(tmpName, cfg.GeoFile); err != nil {
				logger.Error("move geo file into place", "err", err)
				os.Remove(tmpName)
				continue
			}

			logger.Debug("run post cmd", "cmd", cfg.PostCmd)
			if err := execx.Run(ctx, cfg.PostCmd); err != nil {
				logger.Warn("run post cmd", "err", err)
			}

			lastHash = hash
			logger.Info("geo file updated", "file", cfg.GeoFile, "hash", fmt.Sprintf("%x", hash))
		}
	}
}
