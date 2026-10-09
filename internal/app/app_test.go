package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ht4w5/bandaid/internal/geo"
	"github.com/ht4w5/bandaid/internal/model"
	"go4.org/netipx"
)

// --- Slice 1: Validate — URL rules ---
// The four URL failure modes must produce distinct errors.

func TestValidateReportsDistinctURLErrors(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{name: "empty URL", url: "", wantErr: "url must not be empty"},
		{name: "unparseable URL", url: "http://[::1", wantErr: "parse url"},
		{name: "non-http scheme", url: "ftp://example.com/report.json", wantErr: `url scheme must be http or https: "ftp"`},
		{name: "empty host", url: "http:///report.json", wantErr: "url host must not be empty"},
	}

	seen := make(map[string]string)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (Config{URL: tt.url, GeoFile: "geo.conf"}).Validate()
			if err == nil {
				t.Fatalf("Validate(%q) = nil, want error containing %q", tt.url, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate(%q) error = %q, want it to contain %q", tt.url, err, tt.wantErr)
			}
			if prev, dup := seen[err.Error()]; dup {
				t.Errorf("Validate(%q) error = %q, want a distinct error (already reported for %q)", tt.url, err, prev)
			}
			seen[err.Error()] = tt.name
		})
	}
}

func TestValidateAcceptsHTTPAndHTTPSURLs(t *testing.T) {
	for _, u := range []string{
		"https://example.com/report.json",
		"http://localhost:8080/report.json",
	} {
		if err := (Config{URL: u, GeoFile: "geo.conf"}).Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", u, err)
		}
	}
}

// --- Slice 2: Validate — geofile rules ---

func TestValidateRequiresGeoFileOnlyInServiceMode(t *testing.T) {
	// Empty GeoFile is an error in service mode...
	err := (Config{URL: "https://example.com/report.json"}).Validate()
	if err == nil {
		t.Fatalf("Validate(service mode, empty GeoFile) = nil, want error")
	}
	if !strings.Contains(err.Error(), "geofile must not be empty in service mode") {
		t.Errorf("Validate(service mode, empty GeoFile) error = %q, want it to mention the missing geofile", err)
	}

	// ...but allowed in dry-run.
	if err := (Config{URL: "https://example.com/report.json", DryRun: true}).Validate(); err != nil {
		t.Errorf("Validate(dry-run, empty GeoFile) = %v, want nil", err)
	}
}

// --- Slice 3: ParseFileMode — octal semantics (regression 571895b) ---

func TestParseFileModeParsesOctalAndRejectsBadInput(t *testing.T) {
	tests := []struct {
		in      string
		want    os.FileMode
		wantErr bool
	}{
		{in: "", want: 0o644},
		{in: "644", want: 0o644}, // octal 644 = 420 decimal, not 644 (regression 571895b)
		{in: "600", want: 0o600},
		{in: "777", want: 0o777},
		{in: "9", wantErr: true},    // not an octal digit
		{in: "abc", wantErr: true},  // not a number
		{in: "1000", wantErr: true}, // octal 1000 exceeds the 9 mode bits
		{in: "-1", wantErr: true},   // negative
	}

	for _, tt := range tests {
		got, err := ParseFileMode(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseFileMode(%q) = %v, want error", tt.in, got)
			} else if got != 0 {
				t.Errorf("ParseFileMode(%q) = %v with error %v, want 0 on error", tt.in, got, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFileMode(%q) error = %v, want nil", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseFileMode(%q) = %#o (%d), want %#o (%d)", tt.in, got, got, tt.want, tt.want)
		}
	}
}

// --- Slices 4-5: Run — config error surfacing, without network I/O ---

// runConfigErrorFixture returns a valid base config whose URL points at a
// request-counting test server, plus the hit counter to assert against.
func runConfigErrorFixture(t *testing.T) (Config, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		URL:              srv.URL,
		FetchTimeout:     time.Second,
		MaxReportBytes:   1 << 20,
		GeoFile:          filepath.Join(t.TempDir(), "geo.conf"),
		GeoFileMode:      "644",
		VariableName:     "$geo",
		UpdateInterval:   time.Minute,
		WhitelistTargets: []string{"1.2.3.4"},
	}
	return cfg, &hits
}

func TestRunSurfacesConfigErrorsBeforeAnyNetworkIO(t *testing.T) {
	base, hits := runConfigErrorFixture(t)

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "empty URL", mutate: func(c *Config) { c.URL = "" }, wantErr: "url must not be empty"},
		{name: "unparseable URL", mutate: func(c *Config) { c.URL = "http://[::1" }, wantErr: "parse url"},
		{name: "non-http scheme", mutate: func(c *Config) { c.URL = "ftp://example.com/report.json" }, wantErr: "url scheme must be http or https"},
		{name: "empty host", mutate: func(c *Config) { c.URL = "http:///report.json" }, wantErr: "url host must not be empty"},
		{name: "missing geofile in service mode", mutate: func(c *Config) { c.GeoFile = "" }, wantErr: "geofile must not be empty in service mode"},
		{name: "bad geofile mode", mutate: func(c *Config) { c.GeoFileMode = "9" }, wantErr: "invalid geofile mode"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			err := Run(ctx, cfg)
			if err == nil {
				t.Fatalf("Run(%+v) = nil, want error containing %q", cfg, tt.wantErr)
			}
			if !strings.HasPrefix(err.Error(), "validate config: ") {
				t.Errorf("Run(%+v) error = %q, want it to start with %q", cfg, err, "validate config: ")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Run(%+v) error = %q, want it to contain %q", cfg, err, tt.wantErr)
			}
		})
	}

	if n := hits.Load(); n != 0 {
		t.Errorf("server received %d requests, want 0: config errors must surface before any network I/O", n)
	}
}

func TestRunRejectsBadWhitelistTargets(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "garbage entry", target: "a/b/c"},
		{name: "empty entry", target: ""},
		{name: "prefix length out of range", target: "1.2.3.4/33"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, hits := runConfigErrorFixture(t)
			base.WhitelistTargets = []string{"10.0.0.0/8", tt.target}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			err := Run(ctx, base)
			if err == nil {
				t.Fatalf("Run(whitelist %q) = nil, want error", tt.target)
			}
			if !strings.Contains(err.Error(), "parse whitelist target") {
				t.Errorf("Run(whitelist %q) error = %q, want it to contain %q", tt.target, err, "parse whitelist target")
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("server received %d requests, want 0", n)
			}
		})
	}
}

// --- Slices 6-10: updater — file-write behavior ---

type fetchStep struct {
	report *model.Report
	err    error
}

// fakeFetcher stands in for the network boundary: it replays a scripted
// sequence of fetch results without doing any I/O.
type fakeFetcher struct {
	steps []fetchStep
}

func (f *fakeFetcher) Fetch(context.Context) (*model.Report, error) {
	if len(f.steps) == 0 {
		return nil, errors.New("unexpected fetch")
	}
	s := f.steps[0]
	f.steps = f.steps[1:]
	return s.report, s.err
}

// testReport builds a fresh single-finding report so every fetch step
// gets its own value (update mutates the report it fetches).
func testReport(target, reason string) *model.Report {
	return &model.Report{Findings: []model.Finding{{
		Target:  netip.MustParsePrefix(target),
		Reasons: []string{reason},
	}}}
}

func testWhitelist(t *testing.T) *netipx.IPSet {
	t.Helper()
	var b netipx.IPSetBuilder
	set, err := b.IPSet()
	if err != nil {
		t.Fatalf("build empty whitelist: %v", err)
	}
	return set
}

func newTestUpdater(t *testing.T, f reportFetcher, mode os.FileMode, postExec string) (*updater, string) {
	t.Helper()
	g, err := geo.NewGenerator(geo.GeneratorConfig{VariableName: "$geo"})
	if err != nil {
		t.Fatalf("new geo generator: %v", err)
	}
	geoFile := filepath.Join(t.TempDir(), "geo.conf")
	return &updater{
		ctx:       context.Background(),
		logger:    slog.New(slog.DiscardHandler),
		fetcher:   f,
		gen:       g,
		whitelist: testWhitelist(t),
		geoFile:   geoFile,
		mode:      mode,
		postExec:  postExec,
	}, geoFile
}

func readGeoFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read geo file: %v", err)
	}
	return string(b)
}

func checkNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	tmps, err := filepath.Glob(filepath.Join(dir, "geofile-*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(tmps) != 0 {
		t.Errorf("stray temp files left behind: %v", tmps)
	}
}

// Slice 6.
func TestUpdateWritesGeoFileWithRequestedModeAndNoStrayTempFiles(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	f := &fakeFetcher{steps: []fetchStep{{report: testReport("10.1.2.0/24", "test")}}}
	u, geoFile := newTestUpdater(t, f, 0o600, "")

	u.update(now)

	fi, err := os.Stat(geoFile)
	if err != nil {
		t.Fatalf("geo file not written: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("geo file mode = %#o, want 0600", got)
	}
	// Expected block written by hand from the nginx geo format contract.
	const wantSuffix = "geo $geo {\n    10.1.2.0/24 \"test\";\n}\n"
	if content := readGeoFile(t, geoFile); !strings.HasSuffix(content, wantSuffix) {
		t.Errorf("geo file content = %q, want suffix %q", content, wantSuffix)
	}
	checkNoTempFiles(t, filepath.Dir(geoFile))
}

// Slice 7.
func TestUpdateSkipsRewriteWhenReportUnchanged(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	f := &fakeFetcher{steps: []fetchStep{
		{report: testReport("10.1.2.0/24", "test")},
		{report: testReport("10.1.2.0/24", "test")},
	}}
	u, geoFile := newTestUpdater(t, f, 0o644, "")

	u.update(now)
	fi1, err := os.Stat(geoFile)
	if err != nil {
		t.Fatalf("geo file not written: %v", err)
	}
	// Pin mtime to a known value so a rewrite cannot hide behind timestamp granularity.
	past := time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(geoFile, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	u.update(now.Add(time.Hour))

	fi2, err := os.Stat(geoFile)
	if err != nil {
		t.Fatalf("stat geo file: %v", err)
	}
	if !os.SameFile(fi1, fi2) {
		t.Error("geo file was replaced although the report was unchanged")
	}
	if !fi2.ModTime().Equal(past) {
		t.Errorf("geo file mtime = %v, want %v: file must not be rewritten when the report is unchanged", fi2.ModTime(), past)
	}
}

// Slice 8.
func TestUpdateRewritesChangedReportAndRunsPostExec(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	marker := filepath.Join(t.TempDir(), "marker")
	f := &fakeFetcher{steps: []fetchStep{
		{report: testReport("10.1.2.0/24", "first")},
		{report: testReport("10.9.9.0/24", "second")},
	}}
	u, geoFile := newTestUpdater(t, f, 0o644, "/bin/touch "+marker)

	u.update(now)
	u.update(now.Add(time.Hour))

	if _, err := os.Stat(marker); err != nil {
		t.Errorf("post-exec marker was not created: %v", err)
	}
	content := readGeoFile(t, geoFile)
	if !strings.Contains(content, `    10.9.9.0/24 "second";`) {
		t.Errorf("geo file content = %q, want it to contain the changed finding", content)
	}
	if strings.Contains(content, `    10.1.2.0/24 "first";`) {
		t.Errorf("geo file content = %q, want the stale finding replaced", content)
	}
}

// Slice 9.
func TestUpdateKeepsGeoFileWhenPostExecFails(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	f := &fakeFetcher{steps: []fetchStep{
		{report: testReport("10.1.2.0/24", "first")},
		{report: testReport("10.9.9.0/24", "second")},
		{report: testReport("10.9.9.0/24", "second")}, // unchanged re-fetch after the failed post-exec
	}}
	u, geoFile := newTestUpdater(t, f, 0o600, "/bin/false")

	u.update(now)
	u.update(now) // changed report; PostExec fails

	fi1, err := os.Stat(geoFile)
	if err != nil {
		t.Fatalf("geo file not written: %v", err)
	}
	if got := fi1.Mode().Perm(); got != 0o600 {
		t.Errorf("geo file mode = %#o, want 0600", got)
	}
	content := readGeoFile(t, geoFile)
	if !strings.Contains(content, `    10.9.9.0/24 "second";`) {
		t.Errorf("geo file content = %q, want the update kept despite the failing PostExec", content)
	}

	// The update must still count as applied: an unchanged re-fetch is
	// skipped instead of rewritten.
	u.update(now)

	fi2, err := os.Stat(geoFile)
	if err != nil {
		t.Fatalf("stat geo file: %v", err)
	}
	if !os.SameFile(fi1, fi2) {
		t.Error("update was not recorded as applied after a failing PostExec")
	}
}

// Slice 10.
func TestUpdateLeavesGeoFileIntactWhenFetchFails(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	fetchErr := errors.New("fetch failed")
	f := &fakeFetcher{steps: []fetchStep{
		{err: fetchErr},
		{report: testReport("10.1.2.0/24", "test")},
		{err: fetchErr},
	}}
	u, geoFile := newTestUpdater(t, f, 0o644, "")

	// With no previous file, a failed fetch writes nothing.
	u.update(now)
	if _, err := os.Stat(geoFile); !os.IsNotExist(err) {
		t.Fatalf("geo file exists after a failed fetch (err = %v), want nothing written", err)
	}

	u.update(now) // success
	before := readGeoFile(t, geoFile)
	fi1, err := os.Stat(geoFile)
	if err != nil {
		t.Fatalf("stat geo file: %v", err)
	}
	past := time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(geoFile, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	u.update(now) // fetch fails again

	fi2, err := os.Stat(geoFile)
	if err != nil {
		t.Fatalf("stat geo file: %v", err)
	}
	if !os.SameFile(fi1, fi2) {
		t.Error("geo file was replaced by a failed update")
	}
	if !fi2.ModTime().Equal(past) {
		t.Errorf("geo file mtime = %v, want %v: failed update must not touch the file", fi2.ModTime(), past)
	}
	if after := readGeoFile(t, geoFile); after != before {
		t.Errorf("geo file content changed from %q to %q, want it intact", before, after)
	}
	checkNoTempFiles(t, filepath.Dir(geoFile))
}
