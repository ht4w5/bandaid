package model

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"go4.org/netipx"
)

const (
	findingHashSeed uint32 = 114514
)

var (
	ErrInvalidTarget = errors.New("invalid target")
	ErrInvalidReason = errors.New("invalid reason")
)

type Report struct {
	Findings []Finding
}

func (r *Report) Exclude(set *netipx.IPSet) error {
	newFindings := make([]Finding, 0, len(r.Findings))

	for _, f := range r.Findings {
		if set.OverlapsPrefix(f.Target) {
			var splitB netipx.IPSetBuilder
			splitB.AddPrefix(f.Target)
			splitB.RemoveSet(set)
			split, err := splitB.IPSet()
			if err != nil {
				return fmt.Errorf("split overlap: %w", err)
			}
			for _, p := range split.Prefixes() {
				newFindings = append(newFindings, Finding{
					Target:  p,
					Reasons: f.Reasons,
				})
			}
		} else {
			newFindings = append(newFindings, f)
		}
	}

	return nil
}

func (r *Report) Normalize() error {
	for i := range r.Findings {
		err := r.Findings[i].Normalize()
		if err != nil {
			return err
		}
	}

	slices.SortStableFunc(r.Findings, func(a, b Finding) int {
		return a.Target.Compare(b.Target)
	})

	return nil
}

func (r *Report) Hash() uint32 {
	prev := findingHashSeed
	for _, f := range r.Findings {
		prev = f.Hash(prev)
	}
	return prev
}

type Finding struct {
	Target  netip.Prefix
	Reasons []string
}

func (f *Finding) ReasonsStr() string {
	return strings.Join(f.Reasons, ":")
}

var reasonRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func (f *Finding) Normalize() error {
	if !f.Target.IsValid() {
		return ErrInvalidTarget
	}

	for _, r := range f.Reasons {
		if !reasonRe.MatchString(r) {
			return fmt.Errorf("%w: %s", ErrInvalidReason, r)
		}
	}

	f.Target = f.Target.Masked()
	return nil
}

func (f *Finding) Hash(prev uint32) uint32 {
	h := fnv.New32a()

	var prevBytes [4]byte
	binary.BigEndian.PutUint32(prevBytes[:], prev)

	h.Write(prevBytes[:])
	h.Write(f.Target.Addr().AsSlice())

	var b [1]byte
	b[0] = byte(f.Target.Bits())
	h.Write(b[:])

	for _, r := range f.Reasons {
		h.Write([]byte(r))
	}

	return h.Sum32()
}
