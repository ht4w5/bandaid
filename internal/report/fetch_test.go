// Unit tests for the network-boundary seams: report.NewFetcher and
// Fetcher.Fetch. Fetch tests run against net/http/httptest servers; the
// constructor tests exercise newMTLSClient's error paths through the
// NewFetcher seam using temp files.
//
// Expected values are hand-written literals from the documented contracts
// (timeout >= 1s, 1 <= MaxReportBytes <= 1<<40, bare addresses are host
// routes), never computed the way the implementation does.
package report_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ht4w5/bandaid/internal/model"
	"github.com/ht4w5/bandaid/internal/report"
)

// newTestFetcher builds a Fetcher with sane defaults; tests override only
// the fields relevant to their slice.
func newTestFetcher(t *testing.T, cfg report.FetcherConfig) *report.Fetcher {
	t.Helper()
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxReportBytes == 0 {
		cfg.MaxReportBytes = 1 << 20
	}
	f, err := report.NewFetcher(cfg)
	if err != nil {
		t.Fatalf("NewFetcher(%+v) failed: %v", cfg, err)
	}
	return f
}

// newTestServer starts a test server answering every request with the
// given status and body.
func newTestServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body) // error ignored: test assertions cover the outcome
	}))
	t.Cleanup(srv.Close)
	return srv
}

// failWithin runs fn and fails the test if it has not returned within
// limit, so no test can hang.
func failWithin(t *testing.T, limit time.Duration, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("call did not return within %s", limit)
		return nil
	}
}

// Slice 7 (regression 24b234e/571895b): the HTTP timeout is validated at
// construction and must be at least one second.
func TestNewFetcherRejectsTimeoutUnderOneSecond(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		wantErr bool
	}{
		{"zero", 0, true},
		{"500ms", 500 * time.Millisecond, true},
		{"999ms", 999 * time.Millisecond, true},
		{"exactly 1s", time.Second, false},
		{"2s", 2 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := report.NewFetcher(report.FetcherConfig{
				URL:            "https://report.example.invalid/feeds",
				Timeout:        tc.timeout,
				MaxReportBytes: 1024,
			})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewFetcher accepted timeout %s, want error", tc.timeout)
				}
				if f != nil {
					t.Errorf("fetcher = %+v, want nil on error", f)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewFetcher rejected timeout %s: %v", tc.timeout, err)
			}
		})
	}
}

// Slice 8: MaxReportBytes must be within [1, 1<<40].
func TestNewFetcherRejectsOutOfBoundsMaxReportBytes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		max     int64
		wantErr bool
	}{
		{"zero", 0, true},
		{"negative", -1, true},
		{"over 1 TiB", 1<<40 + 1, true},
		{"one", 1, false},
		{"exactly 1 TiB", 1 << 40, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := report.NewFetcher(report.FetcherConfig{
				URL:            "https://report.example.invalid/feeds",
				Timeout:        time.Second,
				MaxReportBytes: tc.max,
			})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewFetcher accepted MaxReportBytes %d, want error", tc.max)
				}
				if f != nil {
					t.Errorf("fetcher = %+v, want nil on error", f)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewFetcher rejected MaxReportBytes %d: %v", tc.max, err)
			}
		})
	}
}

// Slice 9: TLS material is validated through the constructor — client cert
// and key must come as a pair, and the CA file must exist and hold valid
// PEM. (mTLS happy path is out of scope; see testing plan §3.)
func TestNewFetcherRejectsBadTLSMaterial(t *testing.T) {
	dir := t.TempDir()

	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("this is not a pem\n"), 0o600); err != nil {
		t.Fatalf("write bad ca file: %v", err)
	}
	missingCA := filepath.Join(dir, "missing-ca.pem")

	for _, tc := range []struct {
		name    string
		cfg     report.FetcherConfig
		wantErr bool
	}{
		{
			name: "cert without key",
			cfg:  report.FetcherConfig{CertFile: filepath.Join(dir, "cert.pem")},
		},
		{
			name: "key without cert",
			cfg:  report.FetcherConfig{KeyFile: filepath.Join(dir, "key.pem")},
		},
		{
			name: "garbage CA pem",
			cfg:  report.FetcherConfig{CaFile: badCA},
		},
		{
			name: "missing CA file",
			cfg:  report.FetcherConfig{CaFile: missingCA},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.URL = "https://report.example.invalid/feeds"
			cfg.Timeout = time.Second
			cfg.MaxReportBytes = 1024
			f, err := report.NewFetcher(cfg)
			if err == nil {
				t.Fatalf("NewFetcher(%+v) succeeded, want error", cfg)
			}
			if f != nil {
				t.Errorf("fetcher = %+v, want nil on error", f)
			}
		})
	}
}

// Slice 10: 200 + valid body yields the parsed report.
func TestFetchReturnsParsedReportOnOK(t *testing.T) {
	srv := newTestServer(t, http.StatusOK,
		`{"findings":[{"target":"1.2.3.4","reasons":["bruteforce","ssh"]},{"target":"2001:db8::/32","reasons":["tor"]}]}`)
	f := newTestFetcher(t, report.FetcherConfig{URL: srv.URL})

	got, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	assertFindings(t, got, []model.Finding{
		{Target: netip.MustParsePrefix("1.2.3.4/32"), Reasons: []string{"bruteforce", "ssh"}},
		{Target: netip.MustParsePrefix("2001:db8::/32"), Reasons: []string{"tor"}},
	})
}

// Slice 11 (regression 0e9bb7e): non-200 responses must fail even when the
// body is a perfectly valid report — the status check alone is what makes
// this test fail against the buggy behavior.
func TestFetchRejectsNonOKStatus(t *testing.T) {
	validBody := `{"findings":[{"target":"1.2.3.4","reasons":["x"]}]}`
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			srv := newTestServer(t, status, validBody)
			f := newTestFetcher(t, report.FetcherConfig{URL: srv.URL})

			got, err := f.Fetch(context.Background())
			if err == nil {
				t.Fatalf("Fetch on %d succeeded, want error", status)
			}
			if got != nil {
				t.Errorf("report = %+v, want nil on error", got)
			}
			if !strings.Contains(err.Error(), strconv.Itoa(status)) {
				t.Errorf("error %q does not mention status %d", err, status)
			}
		})
	}
}

// Slice 12 (regression 38feb94): bodies larger than MaxReportBytes are
// rejected even when valid; a body of exactly MaxReportBytes is accepted
// (the pad is trailing JSON whitespace, which is legal padding).
func TestFetchEnforcesMaxReportBytes(t *testing.T) {
	const maxBytes = 128
	base := `{"findings":[{"target":"1.2.3.4","reasons":["x"]}]}`
	if len(base) > maxBytes {
		t.Fatalf("test body (%d bytes) larger than cap (%d)", len(base), maxBytes)
	}
	padded := func(n int) string {
		return base + strings.Repeat(" ", n-len(base))
	}

	t.Run("over cap rejected", func(t *testing.T) {
		srv := newTestServer(t, http.StatusOK, padded(maxBytes+1))
		f := newTestFetcher(t, report.FetcherConfig{URL: srv.URL, MaxReportBytes: maxBytes})

		got, err := f.Fetch(context.Background())
		if err == nil {
			t.Fatalf("Fetch accepted a %d-byte body with cap %d, want error", maxBytes+1, maxBytes)
		}
		if got != nil {
			t.Errorf("report = %+v, want nil on error", got)
		}
		if !strings.Contains(err.Error(), "report too large") {
			t.Errorf("error %q does not contain %q", err, "report too large")
		}
	})

	t.Run("at cap accepted", func(t *testing.T) {
		srv := newTestServer(t, http.StatusOK, padded(maxBytes))
		f := newTestFetcher(t, report.FetcherConfig{URL: srv.URL, MaxReportBytes: maxBytes})

		got, err := f.Fetch(context.Background())
		if err != nil {
			t.Fatalf("Fetch rejected a %d-byte body with cap %d: %v", maxBytes, maxBytes, err)
		}
		assertFindings(t, got, []model.Finding{
			{Target: netip.MustParsePrefix("1.2.3.4/32"), Reasons: []string{"x"}},
		})
	})
}

// Slice 13: a 200 with an unparseable body fails.
func TestFetchRejectsUnparseableBody(t *testing.T) {
	srv := newTestServer(t, http.StatusOK, `{"findings": [`)
	f := newTestFetcher(t, report.FetcherConfig{URL: srv.URL})

	got, err := f.Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch succeeded on malformed body, want error")
	}
	if got != nil {
		t.Errorf("report = %+v, want nil on error", got)
	}
	if !strings.Contains(err.Error(), "parse report") {
		t.Errorf("error %q does not wrap %q", err, "parse report")
	}
}

// Slice 14: a cancelled context makes Fetch fail fast with the context
// error, even though the server would answer happily.
func TestFetchFailsFastWhenContextCancelled(t *testing.T) {
	srv := newTestServer(t, http.StatusOK, `{"findings":[]}`)
	f := newTestFetcher(t, report.FetcherConfig{URL: srv.URL})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := failWithin(t, 5*time.Second, func() error {
		got, err := f.Fetch(ctx)
		if got != nil {
			t.Errorf("report = %+v, want nil on error", got)
		}
		return err
	})
	if err == nil {
		t.Fatal("Fetch succeeded with cancelled context, want error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not wrap context.Canceled", err)
	}
}

// Slice 14: a short deadline makes Fetch return with context.DeadlineExceeded
// against a server that never answers; a watchdog fails (rather than hangs)
// if Fetch does not return.
func TestFetchHonorsContextDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)
	f := newTestFetcher(t, report.FetcherConfig{URL: srv.URL, Timeout: 5 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := failWithin(t, 5*time.Second, func() error {
		got, err := f.Fetch(ctx)
		if got != nil {
			t.Errorf("report = %+v, want nil on error", got)
		}
		return err
	})
	if err == nil {
		t.Fatal("Fetch succeeded after context deadline, want error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v does not wrap context.DeadlineExceeded", err)
	}
}
