package model_test

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"go4.org/netipx"

	"github.com/ht4w5/bandaid/internal/model"
)

// --- helpers -------------------------------------------------------------

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

// singleHost is how the app represents a bare address whitelist entry: the
// /32 (IPv4) or /128 (IPv6) prefix of exactly one host.
func singleHost(t *testing.T, s string) netip.Prefix {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return netip.PrefixFrom(a, a.BitLen())
}

func whitelist(t *testing.T, prefixes ...netip.Prefix) *netipx.IPSet {
	t.Helper()
	var b netipx.IPSetBuilder
	for _, p := range prefixes {
		b.AddPrefix(p)
	}
	set, err := b.IPSet()
	if err != nil {
		t.Fatalf("build whitelist set: %v", err)
	}
	return set
}

// assertFindings compares findings one by one, ignoring nil-vs-empty slice
// differences on the list itself (the behavior is "which findings result",
// not how the list is allocated).
func assertFindings(t *testing.T, got, want []model.Finding) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d findings %+v, want %d %+v", len(got), got, len(want), want)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("finding[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// --- slices 1-4: Normalize -----------------------------------------------

func TestNormalizeMasksHostBits(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4 host bits masked", "10.1.2.3/8", "10.0.0.0/8"},
		{"ipv6 host bits masked", "2001:db8::1/32", "2001:db8::/32"},
		{"already-masked prefix unchanged", "2001:db8:8000::/33", "2001:db8:8000::/33"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := model.Finding{
				Target:  mustPrefix(t, tc.in),
				Reasons: []string{"reason"},
			}
			if err := f.Normalize(); err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if want := mustPrefix(t, tc.want); f.Target != want {
				t.Errorf("Target = %v, want %v", f.Target, want)
			}
		})
	}
}

func TestNormalizeSortsFindingsByTarget(t *testing.T) {
	r := &model.Report{Findings: []model.Finding{
		{Target: mustPrefix(t, "2001:db8:1::/48"), Reasons: []string{"f"}},
		{Target: mustPrefix(t, "192.168.0.0/16"), Reasons: []string{"c"}},
		{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"b"}},
		{Target: mustPrefix(t, "2001:db8::/32"), Reasons: []string{"e"}},
		{Target: mustPrefix(t, "10.0.0.0/8"), Reasons: []string{"a"}},
	}}
	if err := r.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	// netip.Prefix.Compare order: IPv4 before IPv6, by address, then by
	// prefix length.
	want := []model.Finding{
		{Target: mustPrefix(t, "10.0.0.0/8"), Reasons: []string{"a"}},
		{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"b"}},
		{Target: mustPrefix(t, "192.168.0.0/16"), Reasons: []string{"c"}},
		{Target: mustPrefix(t, "2001:db8::/32"), Reasons: []string{"e"}},
		{Target: mustPrefix(t, "2001:db8:1::/48"), Reasons: []string{"f"}},
	}
	assertFindings(t, r.Findings, want)
}

func TestNormalizeKeepsInputOrderOfFindingsWithEqualTargets(t *testing.T) {
	r := &model.Report{Findings: []model.Finding{
		{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"b"}},
		{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a"}},
	}}
	if err := r.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	want := []model.Finding{
		{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"b"}},
		{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a"}},
	}
	assertFindings(t, r.Findings, want)
}

func TestNormalizeRejectsInvalidTarget(t *testing.T) {
	var zero netip.Prefix

	f := model.Finding{Target: zero, Reasons: []string{"a"}}
	if err := f.Normalize(); !errors.Is(err, model.ErrInvalidTarget) {
		t.Errorf("Finding.Normalize() error = %v, want ErrInvalidTarget", err)
	}

	r := &model.Report{Findings: []model.Finding{
		{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a"}},
		{Target: zero, Reasons: []string{"b"}},
	}}
	if err := r.Normalize(); !errors.Is(err, model.ErrInvalidTarget) {
		t.Errorf("Report.Normalize() error = %v, want ErrInvalidTarget", err)
	}
}

func TestNormalizeRejectsInvalidReasons(t *testing.T) {
	// Reason grammar: [A-Za-z0-9][A-Za-z0-9_.-]*
	bad := []string{
		"",     // empty
		"a b",  // space not allowed
		"-x",   // first char must be alphanumeric
		".x",   // first char must be alphanumeric
		"_x",   // first char must be alphanumeric
		"café", // non-ASCII
		"日本",   // non-ASCII
		"a:b",  // separator used by ReasonsStr must not appear in a reason
	}
	for _, reason := range bad {
		t.Run(reason, func(t *testing.T) {
			f := model.Finding{
				Target:  mustPrefix(t, "10.0.0.0/24"),
				Reasons: []string{reason},
			}
			if err := f.Normalize(); !errors.Is(err, model.ErrInvalidReason) {
				t.Errorf("Normalize() error = %v, want ErrInvalidReason", err)
			}
		})
	}
}

func TestNormalizeAcceptsValidReasonGrammar(t *testing.T) {
	good := []string{
		"a",
		"Z",
		"9",
		"9lives",
		"a-b",
		"a_b",
		"a.b",
		"Abc-123_x.y",
		"with.dots-and-dashes_09",
	}
	for _, reason := range good {
		t.Run(reason, func(t *testing.T) {
			f := model.Finding{
				Target:  mustPrefix(t, "10.0.0.0/24"),
				Reasons: []string{reason},
			}
			if err := f.Normalize(); err != nil {
				t.Errorf("Normalize() error = %v, want nil", err)
			}
		})
	}
}

// --- slices 5-8: Exclude -------------------------------------------------

func TestExcludeKeepsNonOverlappingFindingsUnchanged(t *testing.T) {
	r := &model.Report{Findings: []model.Finding{
		{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a", "b"}},
		{Target: mustPrefix(t, "2001:db8::/32"), Reasons: []string{"c"}},
	}}
	set := whitelist(t, mustPrefix(t, "192.168.0.0/16"))

	if err := r.Exclude(set); err != nil {
		t.Fatalf("Exclude() error = %v", err)
	}
	want := []model.Finding{
		{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a", "b"}},
		{Target: mustPrefix(t, "2001:db8::/32"), Reasons: []string{"c"}},
	}
	assertFindings(t, r.Findings, want)
}

func TestExcludeSplitsPartiallyOverlappingFindings(t *testing.T) {
	cases := []struct {
		name      string
		whitelist []netip.Prefix
		want      []model.Finding
	}{
		{
			// 10.0.0.0/24 minus its lower half leaves only the upper half.
			name:      "overlap at start of range",
			whitelist: []netip.Prefix{mustPrefix(t, "10.0.0.0/25")},
			want: []model.Finding{
				{Target: mustPrefix(t, "10.0.0.128/25"), Reasons: []string{"r"}},
			},
		},
		{
			// 10.0.0.0/24 (10.0.0.0-255) minus 10.0.0.64/26 (64-127)
			// leaves 10.0.0.0/26 (0-63) and 10.0.0.128/25 (128-255).
			name:      "overlap in middle of range",
			whitelist: []netip.Prefix{mustPrefix(t, "10.0.0.64/26")},
			want: []model.Finding{
				{Target: mustPrefix(t, "10.0.0.0/26"), Reasons: []string{"r"}},
				{Target: mustPrefix(t, "10.0.0.128/25"), Reasons: []string{"r"}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &model.Report{Findings: []model.Finding{
				{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"r"}},
			}}
			if err := r.Exclude(whitelist(t, tc.whitelist...)); err != nil {
				t.Fatalf("Exclude() error = %v", err)
			}
			// Reasons must survive the split unchanged.
			assertFindings(t, r.Findings, tc.want)
		})
	}
}

func TestExcludeDropsFullyCoveredFindings(t *testing.T) {
	cases := []struct {
		name      string
		findings  []model.Finding
		whitelist []netip.Prefix
		want      []model.Finding
	}{
		{
			name: "whitelist superset of target leaves no findings",
			findings: []model.Finding{
				{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a"}},
			},
			whitelist: []netip.Prefix{mustPrefix(t, "10.0.0.0/16")},
			want:      nil,
		},
		{
			name: "only the covered finding is dropped",
			findings: []model.Finding{
				{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a"}},
				{Target: mustPrefix(t, "172.16.0.0/16"), Reasons: []string{"b"}},
			},
			whitelist: []netip.Prefix{mustPrefix(t, "10.0.0.0/8")},
			want: []model.Finding{
				{Target: mustPrefix(t, "172.16.0.0/16"), Reasons: []string{"b"}},
			},
		},
		{
			name: "all findings covered leaves no findings",
			findings: []model.Finding{
				{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a"}},
				{Target: mustPrefix(t, "10.1.0.0/16"), Reasons: []string{"b"}},
			},
			whitelist: []netip.Prefix{mustPrefix(t, "10.0.0.0/8")},
			want:      nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &model.Report{Findings: tc.findings}
			if err := r.Exclude(whitelist(t, tc.whitelist...)); err != nil {
				t.Fatalf("Exclude() error = %v", err)
			}
			assertFindings(t, r.Findings, tc.want)
		})
	}
}

func TestExcludeHandlesIPv6AndBareAddressWhitelistEntries(t *testing.T) {
	cases := []struct {
		name      string
		findings  []model.Finding
		whitelist []netip.Prefix
		want      []model.Finding
	}{
		{
			// 2001:db8::/32 minus its upper half leaves the lower half.
			name: "ipv6 prefix split in half",
			findings: []model.Finding{
				{Target: mustPrefix(t, "2001:db8::/32"), Reasons: []string{"v6"}},
			},
			whitelist: []netip.Prefix{mustPrefix(t, "2001:db8:8000::/33")},
			want: []model.Finding{
				{Target: mustPrefix(t, "2001:db8::/33"), Reasons: []string{"v6"}},
			},
		},
		{
			// 1.2.3.0/30 (hosts .0-.3) minus the single host 1.2.3.2
			// leaves 1.2.3.0/31 (hosts .0-.1) and 1.2.3.3/32 (host .3).
			name: "bare ipv4 address punches out one host",
			findings: []model.Finding{
				{Target: mustPrefix(t, "1.2.3.0/30"), Reasons: []string{"v4"}},
			},
			whitelist: []netip.Prefix{singleHost(t, "1.2.3.2")},
			want: []model.Finding{
				{Target: mustPrefix(t, "1.2.3.0/31"), Reasons: []string{"v4"}},
				{Target: mustPrefix(t, "1.2.3.3/32"), Reasons: []string{"v4"}},
			},
		},
		{
			// 2001:db8::/126 (hosts ::0-::3) minus the single host ::2
			// leaves 2001:db8::/127 (::0-::1) and 2001:db8::3/128 (::3).
			name: "bare ipv6 address punches out one host",
			findings: []model.Finding{
				{Target: mustPrefix(t, "2001:db8::/126"), Reasons: []string{"v6"}},
			},
			whitelist: []netip.Prefix{singleHost(t, "2001:db8::2")},
			want: []model.Finding{
				{Target: mustPrefix(t, "2001:db8::/127"), Reasons: []string{"v6"}},
				{Target: mustPrefix(t, "2001:db8::3/128"), Reasons: []string{"v6"}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &model.Report{Findings: tc.findings}
			if err := r.Exclude(whitelist(t, tc.whitelist...)); err != nil {
				t.Fatalf("Exclude() error = %v", err)
			}
			assertFindings(t, r.Findings, tc.want)
		})
	}
}

// --- slices 9-11: Hash ---------------------------------------------------

func reportWith(findings ...model.Finding) *model.Report {
	return &model.Report{Findings: findings}
}

// Determinism is the contract the updater's change detection relies on:
// independently constructed reports with equal content must hash equal.
// Exact hash values are not a stable contract (see docs/testing-plan.md),
// so there are no golden literals here — only these properties.
func TestHashIsDeterministicForIdenticalReports(t *testing.T) {
	mk := func() *model.Report {
		return reportWith(
			model.Finding{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a", "b"}},
			model.Finding{Target: mustPrefix(t, "2001:db8::/32"), Reasons: []string{"c"}},
		)
	}
	r1, r2 := mk(), mk()
	h1, h2 := r1.Hash(), r2.Hash()
	if h1 != h2 {
		t.Errorf("independently constructed equal reports hash differently: %x vs %x", h1, h2)
	}

	// Purity check: Hash() must not carry hidden state or randomness, so
	// repeated calls on the same report must return the first call's value.
	if got := r1.Hash(); got != h1 {
		t.Errorf("repeated Hash() = %x, want %x", got, h1)
	}
}

func TestHashChainsFindingsInOrder(t *testing.T) {
	a := model.Finding{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a"}}
	b := model.Finding{Target: mustPrefix(t, "2001:db8::/32"), Reasons: []string{"b"}}
	forward := reportWith(a, b).Hash()
	backward := reportWith(b, a).Hash()
	if forward == backward {
		t.Errorf("hash ignores finding order: both orders hash to %x", forward)
	}
}

func TestHashDiscriminatesDifferences(t *testing.T) {
	cases := []struct {
		name string
		a, b model.Finding
	}{
		{
			name: "target differs",
			a:    model.Finding{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"r"}},
			b:    model.Finding{Target: mustPrefix(t, "10.0.1.0/24"), Reasons: []string{"r"}},
		},
		{
			name: "prefix length differs",
			a:    model.Finding{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"r"}},
			b:    model.Finding{Target: mustPrefix(t, "10.0.0.0/25"), Reasons: []string{"r"}},
		},
		{
			name: "reasons differ",
			a:    model.Finding{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a"}},
			b:    model.Finding{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"b"}},
		},
		{
			name: "reason count differs",
			a:    model.Finding{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a"}},
			b:    model.Finding{Target: mustPrefix(t, "10.0.0.0/24"), Reasons: []string{"a", "b"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ha := reportWith(tc.a).Hash()
			hb := reportWith(tc.b).Hash()
			if ha == hb {
				t.Errorf("distinct findings hash the same: %x", ha)
			}
		})
	}
}

// Regression for 680c392: reason boundaries must be separated by a
// delimiter when hashing. Without it, reasons that concatenate to the same
// byte string collide (["ab","c"] vs ["a","bc"]).
func TestHashSeparatesReasonsWithDelimiter(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
	}{
		{"swapped reason boundaries", []string{"ab", "c"}, []string{"a", "bc"}},
		{"single vs split reason", []string{"abc"}, []string{"ab", "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ha := reportWith(model.Finding{
				Target: mustPrefix(t, "10.0.0.0/24"), Reasons: tc.a,
			}).Hash()
			hb := reportWith(model.Finding{
				Target: mustPrefix(t, "10.0.0.0/24"), Reasons: tc.b,
			}).Hash()
			if ha == hb {
				t.Errorf("reason boundaries bleed: %v and %v both hash to %x", tc.a, tc.b, ha)
			}
		})
	}
}

// --- slice 13: String/ReasonsStr contract --------------------------------

func TestFindingStringAndReasonsStrContract(t *testing.T) {
	cases := []struct {
		name           string
		target         string
		reasons        []string
		wantReasonsStr string
		wantString     string
	}{
		{
			name:           "multiple reasons joined with colon",
			target:         "10.0.0.0/24",
			reasons:        []string{"a", "b"},
			wantReasonsStr: "a:b",
			wantString:     "10.0.0.0/24,a:b",
		},
		{
			name:           "single reason",
			target:         "10.0.0.0/24",
			reasons:        []string{"a"},
			wantReasonsStr: "a",
			wantString:     "10.0.0.0/24,a",
		},
		{
			name:           "no reasons",
			target:         "10.0.0.0/24",
			reasons:        nil,
			wantReasonsStr: "",
			wantString:     "10.0.0.0/24,",
		},
		{
			name:           "ipv6 target",
			target:         "2001:db8::/32",
			reasons:        []string{"x", "y", "z"},
			wantReasonsStr: "x:y:z",
			wantString:     "2001:db8::/32,x:y:z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := model.Finding{
				Target:  mustPrefix(t, tc.target),
				Reasons: tc.reasons,
			}
			if got := f.ReasonsStr(); got != tc.wantReasonsStr {
				t.Errorf("ReasonsStr() = %q, want %q", got, tc.wantReasonsStr)
			}
			if got := f.String(); got != tc.wantString {
				t.Errorf("String() = %q, want %q", got, tc.wantString)
			}
		})
	}
}
