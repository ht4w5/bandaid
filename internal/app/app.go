package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ht4w5/bandaid/internal/geo"
	"github.com/ht4w5/bandaid/internal/report"
	"github.com/ht4w5/bandaid/pkg/execx"
	"github.com/ht4w5/bandaid/pkg/ipx"
	"github.com/ht4w5/bandaid/pkg/logx"
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
	GeoFileMode    string
	PostExec       string

	// Geo config.
	VariableName        string
	AddressVariableName string
	DefaultString       string

	// Misc.
	DryRun bool
}

func (cfg Config) validate() error {
	if cfg.URL == "" {
		return errors.New("url must not be empty")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url scheme must be http or https: %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("url host must not be empty")
	}

	if !cfg.DryRun && cfg.GeoFile == "" {
		return errors.New("geofile must not be empty in service mode")
	}

	return nil
}

func parseFileMode(s string) (os.FileMode, error) {
	if s == "" {
		return 0o644, nil
	}
	m, err := strconv.ParseUint(s, 8, 9)
	if err != nil {
		return 0, fmt.Errorf("invalid geofile mode %q: %w", s, err)
	}
	return os.FileMode(m), nil
}

func Run(ctx context.Context, cfg Config) error {
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	mode, err := parseFileMode(cfg.GeoFileMode)
	if err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

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
		return runService(ctx, cfg, f, g, whitelist, mode)
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

func runService(ctx context.Context, cfg Config, f *report.Fetcher, g *geo.Generator, whitelist *netipx.IPSet, mode os.FileMode) error {
	logger := logx.FromContext(ctx)
	if cfg.UpdateInterval < time.Minute {
		cfg.UpdateInterval = time.Minute
		logger.Warn("update interval clamped", "interval", cfg.UpdateInterval)
	}

	var lastHash uint32

	update := func(now time.Time) {
		logger.Info("begin report update", "time", now)

		r, err := f.Fetch(ctx)
		if err != nil {
			logger.Error("fetch report", "err", err)
			return
		}

		if err := r.Exclude(whitelist); err != nil {
			logger.Error("exclude whitelist", "err", err)
			return
		}

		if err := r.Normalize(); err != nil {
			logger.Error("normalize report", "err", err)
			return
		}

		hash := r.Hash()
		if hash == lastHash {
			logger.Info("report unchanged; skipping geo generation", "hash", fmt.Sprintf("%x", hash))
			return
		}

		tmp, err := os.CreateTemp(filepath.Dir(cfg.GeoFile), "geofile-*")
		if err != nil {
			logger.Error("open temp file", "err", err)
			return
		}
		tmpName := tmp.Name()

		cleanup := func() {
			tmp.Close()
			os.Remove(tmpName)
		}

		if err := g.Generate(tmp, func() time.Time { return now }, r, hash); err != nil {
			logger.Error("generate geo", "err", err)
			cleanup()
			return
		}

		if err := tmp.Close(); err != nil {
			logger.Error("close temp file", "err", err)
			os.Remove(tmpName)
			return
		}

		if err := os.Chmod(tmpName, mode); err != nil {
			logger.Error("chmod temp file", "err", err)
			os.Remove(tmpName)
			return
		}

		if err := os.Rename(tmpName, cfg.GeoFile); err != nil {
			logger.Error("move geo file into place", "err", err)
			os.Remove(tmpName)
			return
		}

		if cfg.PostExec != "" {
			logger.Debug("run post cmd", "cmd", cfg.PostExec)
			if err := execx.Run(ctx, cfg.PostExec); err != nil {
				logger.Warn("run post cmd", "err", err)
			}
		}

		lastHash = hash
		logger.Info("geo file updated", "file", cfg.GeoFile, "hash", fmt.Sprintf("%x", hash))
	}

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-timer.C:
			update(now)
			timer.Reset(cfg.UpdateInterval)
		}
	}
}
