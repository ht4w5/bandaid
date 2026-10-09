// Unit tests for the report wire-format seam: report.Parse.
//
// Expected values are hand-written literals from the wire-format contract
// (bare addresses are host routes: /32 for IPv4, /128 for IPv6), never
// computed the way the implementation does.
package report_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ht4w5/bandaid/internal/model"
	"github.com/ht4w5/bandaid/internal/report"
)

// assertFindings compares a parsed report against hand-written expected
// findings (same order as the wire input).
func assertFindings(t *testing.T, got *model.Report, want []model.Finding) {
	t.Helper()
	if got == nil {
		t.Fatal("report is nil")
	}
	if len(got.Findings) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(got.Findings), len(want), got.Findings)
	}
	for i := range want {
		if got.Findings[i].Target != want[i].Target {
			t.Errorf("finding %d: target = %s, want %s", i, got.Findings[i].Target, want[i].Target)
		}
		if !slices.Equal(got.Findings[i].Reasons, want[i].Reasons) {
			t.Errorf("finding %d: reasons = %q, want %q", i, got.Findings[i].Reasons, want[i].Reasons)
		}
	}
}

// Slice 1: bare addresses become full-length host prefixes (/32, /128).
func TestParseConvertsBareAddressesToHostPrefixes(t *testing.T) {
	r, err := report.Parse(strings.NewReader(
		`{"findings":[{"target":"1.2.3.4","reasons":["bruteforce"]},{"target":"2001:db8::1","reasons":["tor"]}]}`,
	))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	assertFindings(t, r, []model.Finding{
		{Target: netip.MustParsePrefix("1.2.3.4/32"), Reasons: []string{"bruteforce"}},
		{Target: netip.MustParsePrefix("2001:db8::1/128"), Reasons: []string{"tor"}},
	})
}

// Slice 2: explicit prefixes pass through verbatim with their reasons.
func TestParseKeepsExplicitPrefixesVerbatim(t *testing.T) {
	r, err := report.Parse(strings.NewReader(
		`{"findings":[{"target":"10.0.0.0/8","reasons":["reserved"]},{"target":"2001:db8::/32","reasons":["documentation","rfc3849"]}]}`,
	))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	assertFindings(t, r, []model.Finding{
		{Target: netip.MustParsePrefix("10.0.0.0/8"), Reasons: []string{"reserved"}},
		{Target: netip.MustParsePrefix("2001:db8::/32"), Reasons: []string{"documentation", "rfc3849"}},
	})
}

// Slice 3: empty or absent findings produce an empty report, not an error.
func TestParseAcceptsEmptyAndAbsentFindings(t *testing.T) {
	for _, in := range []string{
		`{}`,
		`{"findings":[]}`,
		`{"findings":null}`,
	} {
		t.Run(in, func(t *testing.T) {
			r, err := report.Parse(strings.NewReader(in))
			if err != nil {
				t.Fatalf("Parse(%s) failed: %v", in, err)
			}
			if r == nil {
				t.Fatal("report is nil")
			}
			if len(r.Findings) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(r.Findings), r.Findings)
			}
		})
	}
}

// Slice 4: malformed JSON fails with the "decode report" error contract.
func TestParseFailsOnMalformedJSON(t *testing.T) {
	for _, in := range []string{
		`{"findings": [`,
		`not json at all`,
		`{"findings":[]} trailing garbage`,
		`{"findings":[{"target":"1.2.3.4","reasons":["x"]}`,
	} {
		t.Run(in, func(t *testing.T) {
			r, err := report.Parse(strings.NewReader(in))
			if err == nil {
				t.Fatalf("Parse(%s) succeeded, want error", in)
			}
			if r != nil {
				t.Errorf("report = %+v, want nil on error", r)
			}
			if !strings.Contains(err.Error(), "decode report") {
				t.Errorf("error %q does not wrap %q", err, "decode report")
			}
		})
	}
}

// Slice 5: invalid target strings fail with the "parse target" error
// contract, including multi-slash strings and the empty string.
func TestParseRejectsInvalidTargets(t *testing.T) {
	for _, target := range []string{
		"a/b/c",
		"",
		"999.1.1.1",
		"1.2.3.4/33",
		"/8",
		"1.2.3.4/",
	} {
		t.Run(target, func(t *testing.T) {
			r, err := report.Parse(strings.NewReader(`{"findings":[{"target":"` + target + `","reasons":["x"]}]}`))
			if err == nil {
				t.Fatalf("Parse accepted target %q, want error", target)
			}
			if r != nil {
				t.Errorf("report = %+v, want nil on error", r)
			}
			if !strings.Contains(err.Error(), "parse target") {
				t.Errorf("error %q does not wrap %q", err, "parse target")
			}
		})
	}
}

// Slice 6: unknown JSON fields are ignored and reasons:null is tolerated.
func TestParseIgnoresUnknownFieldsAndToleratesNullReasons(t *testing.T) {
	t.Run("unknown fields", func(t *testing.T) {
		r, err := report.Parse(strings.NewReader(
			`{"version":2,"findings":[{"target":"1.2.3.4","reasons":["x"],"note":"ignored"}],"extra":true}`,
		))
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		assertFindings(t, r, []model.Finding{
			{Target: netip.MustParsePrefix("1.2.3.4/32"), Reasons: []string{"x"}},
		})
	})

	t.Run("null reasons", func(t *testing.T) {
		r, err := report.Parse(strings.NewReader(`{"findings":[{"target":"2001:db8::1","reasons":null}]}`))
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		assertFindings(t, r, []model.Finding{
			{Target: netip.MustParsePrefix("2001:db8::1/128"), Reasons: nil},
		})
	})
}
