package bd

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/ht4w5/bd2geo/internal/model"
)

type ReportParser struct{}

func (rp *ReportParser) ParseReport(r io.Reader) (*model.Report, error) {
	var wire struct {
		Findings []struct {
			Target  string   `json:"target"`
			Reasons []string `json:"reasons"`
		} `json:"findings"`
	}
	err := json.UnmarshalRead(r, &wire)
	if err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}

	report := model.Report{
		Findings: make([]model.Finding, 0, len(wire.Findings)),
	}
	for _, f := range wire.Findings {
		target, err := parsePrefixOrAddr(f.Target)
		if err != nil {
			return nil, fmt.Errorf("parse target: %w", err)
		}

		report.Findings = append(report.Findings, model.Finding{
			Target:  target,
			Reasons: f.Reasons,
		})
	}

	return &report, nil
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	i := strings.LastIndexByte(s, '/')
	if i >= 0 {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	} else {
		return netip.PrefixFrom(addr, 128), nil
	}
}
