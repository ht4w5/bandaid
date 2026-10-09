package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ht4w5/bandaid/internal/geo"
	"github.com/ht4w5/bandaid/internal/model"
	"github.com/ht4w5/bandaid/internal/report"
	"github.com/ht4w5/bandaid/pkg/execx"
	"github.com/ht4w5/bandaid/pkg/ipx"
	"github.com/ht4w5/bandaid/pkg/logx"
	"go4.org/netipx"
)

type Config struct {
	// Fetch config.
	URL            string
	CaFile         string
	CertFile       string
	KeyFile        string
	FetchTimeout   time.Duration
	MaxReportBytes int64

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

// Validate checks the config for internal consistency.
func (cfg Config) Validate() error {
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

// ParseFileMode parses an octal geo-file mode (e.g. "644");
// an empty string yields the default 0644.
func ParseFileMode(s string) (os.FileMode, error) {
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
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	mode, err := ParseFileMode(cfg.GeoFileMode)
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
		URL:            cfg.URL,
		CaFile:         cfg.CaFile,
		CertFile:       cfg.CertFile,
		KeyFile:        cfg.KeyFile,
		Timeout:        cfg.FetchTimeout,
		MaxReportBytes: cfg.MaxReportBytes,
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

// reportFetcher is the minimal fetch capability needed by updater.
// It is satisfied by *report.Fetcher and by test fakes.
type reportFetcher interface {
	Fetch(ctx context.Context) (*model.Report, error)
}

// updater runs a single report-update cycle: fetch the report, exclude
// whitelisted targets, normalize it, and atomically install the generated
// geo file. Extracted from runService's closure so that file-write
// behavior is testable; the service loop semantics are unchanged.
type updater struct {
	ctx       context.Context
	logger    *slog.Logger
	fetcher   reportFetcher
	gen       *geo.Generator
	whitelist *netipx.IPSet
	geoFile   string
	mode      os.FileMode
	postExec  string

	// lastHash is the report hash installed by the previous update;
	// an unchanged hash skips geo generation and rewrite.
	lastHash uint32
}

func (u *updater) update(now time.Time) {
	logger := u.logger
	logger.Info("begin report update", "time", now)

	r, err := u.fetcher.Fetch(u.ctx)
	if err != nil {
		logger.Error("fetch report", "err", err)
		return
	}

	if err := r.Exclude(u.whitelist); err != nil {
		logger.Error("exclude whitelist", "err", err)
		return
	}

	if err := r.Normalize(); err != nil {
		logger.Error("normalize report", "err", err)
		return
	}

	hash := r.Hash()
	if hash == u.lastHash {
		logger.Info("report unchanged; skipping geo generation", "hash", fmt.Sprintf("%x", hash))
		return
	}

	tmp, err := os.CreateTemp(filepath.Dir(u.geoFile), "geofile-*")
	if err != nil {
		logger.Error("open temp file", "err", err)
		return
	}
	tmpName := tmp.Name()

	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}

	if err := u.gen.Generate(tmp, func() time.Time { return now }, r, hash); err != nil {
		logger.Error("generate geo", "err", err)
		cleanup()
		return
	}

	if err := tmp.Close(); err != nil {
		logger.Error("close temp file", "err", err)
		os.Remove(tmpName)
		return
	}

	if err := os.Chmod(tmpName, u.mode); err != nil {
		logger.Error("chmod temp file", "err", err)
		os.Remove(tmpName)
		return
	}

	if err := os.Rename(tmpName, u.geoFile); err != nil {
		logger.Error("move geo file into place", "err", err)
		os.Remove(tmpName)
		return
	}

	if u.postExec != "" {
		logger.Debug("run post cmd", "cmd", u.postExec)
		if err := execx.Run(u.ctx, u.postExec); err != nil {
			logger.Warn("run post cmd", "err", err)
		}
	}

	u.lastHash = hash
	logger.Info("geo file updated", "file", u.geoFile, "hash", fmt.Sprintf("%x", hash))
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

	u := &updater{
		ctx:       ctx,
		logger:    logger,
		fetcher:   f,
		gen:       g,
		whitelist: whitelist,
		geoFile:   cfg.GeoFile,
		mode:      mode,
		postExec:  cfg.PostExec,
	}

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-timer.C:
			u.update(now)
			timer.Reset(cfg.UpdateInterval)
		}
	}
}
