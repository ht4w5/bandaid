package model

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"net/netip"
	"slices"
)

const (
	findingHashSeed uint32 = 114514
)

var (
	ErrInvalidTarget = errors.New("invalid target")
)

type Report struct {
	Findings []Finding
}

func (r *Report) Normalize() error {
	for _, f := range r.Findings {
		err := f.Normalize()
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
	Target     netip.Prefix
	ReasonsStr string
}

func (f *Finding) Normalize() error {
	if !f.Target.IsValid() {
		return ErrInvalidTarget
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

	h.Write([]byte(f.ReasonsStr))

	return h.Sum32()
}
