package report

import (
	"encoding/json/v2"
	"fmt"
	"io"

	"github.com/ht4w5/bd2geo/internal/model"
	"github.com/ht4w5/bd2geo/pkg/ipx"
)

func Parse(r io.Reader) (*model.Report, error) {
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
		target, err := ipx.ParsePrefixOrAddr(f.Target)
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
