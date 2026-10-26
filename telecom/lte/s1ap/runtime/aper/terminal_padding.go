// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/terminal_padding.go; SHA-256 b9840f8b644a8538d7b195ffac88d19b7d955311fddec1d88085aaf12fadf6f8.
package aper

import (
	"math"
	"strconv"
	"strings"
	"unsafe"
)

// X.691 (02/2021) §11.1.4 requires zero completion bits, including the octet
// substituted for an empty value. §11.2.1 applies the same rule to open types.
// The explicit receiver policy reports these bits without changing typed content.
func (bb *BitBuffer) startPaddingTrace() error {
	if bb.trace != nil {
		return nil
	}
	// Preserve the operation-budget charge of the original trace layout.
	if err := bb.ChargeAllocation(uint64(10*unsafe.Sizeof(uintptr(0))), 1); err != nil {
		return err
	}
	bb.trace = &decodeTrace{terminalPadding: true}
	return nil
}

func (bb *BitBuffer) enterPaddingSegment(segment pathSegment) int {
	mark := len(bb.trace.path)
	next, err := AppendValues(bb, bb.trace.path, segment)
	if err != nil {
		return -1
	}
	bb.trace.path = next
	return mark
}

func (bb *BitBuffer) observeTerminalPadding(start, width int, value uint8, path string, open bool) error {
	if start < 0 || width < 1 || width > 8 || bb.BitPos() < start {
		return ErrInvalidValue
	}
	budget := bb.decodeBudget()
	location := Location{Path: Path(path)}
	if bb.trace != nil && len(bb.trace.path) != 0 {
		// At most twenty decimal digits plus brackets per index, or name plus dot.
		var size uint64
		for _, segment := range bb.trace.path {
			if uint64(len(segment.name)) > math.MaxUint64-23 || size > math.MaxUint64-uint64(len(segment.name))-23 {
				return bb.resourceError("padding path size overflows")
			}
			size += uint64(len(segment.name)) + 23
		}
		if size > uint64(math.MaxInt) {
			return bb.resourceError("padding path exceeds host int")
		}
		if err := bb.ChargeAllocation(size, 1); err != nil {
			return err
		}
		var path strings.Builder
		path.Grow(int(size))
		for _, segment := range bb.trace.path {
			if segment.name == "" {
				path.WriteByte('[')
				var digits [20]byte
				path.Write(strconv.AppendInt(digits[:0], segment.index, 10))
				path.WriteByte(']')
			} else {
				if path.Len() != 0 {
					path.WriteByte('.')
				}
				path.WriteString(segment.name)
			}
		}
		location.Path = Path(path.String())
	}
	location.Spans, location.HasWireLocation = originalRange(bb, uint64(start), uint64(bb.BitPos()))
	if budget.err != nil {
		return budget.err
	}
	rule := SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.1.4"}
	if open {
		rule.Clause = "§11.2.1"
	}
	kind := NonzeroTerminalPadding
	if width == 8 {
		kind = NonzeroEmptyEncoding
	}
	if err := bb.ChargeLocatedReport(location, 0); err != nil {
		return err
	}
	if budget.callReport == nil {
		return ErrInvalidOptions
	}
	next, err := AppendValues(bb, budget.callReport.Observations, Observation{Location: location, Rule: rule, Kind: kind, PaddingBits: value, PaddingCount: uint8(width)})
	if err != nil {
		return err
	}
	budget.callReport.Observations = next
	if bb.trace != nil {
		bb.trace.nonzeroPadding = true
	}
	return nil
}

func (bb *BitBuffer) qualifyPaddingReports(root string) error {
	if bb.trace == nil || !bb.trace.terminalPadding || bb.nested {
		return nil
	}
	for i := range bb.budget.callReport.Observations {
		observation := &bb.budget.callReport.Observations[i]
		if observation.Kind != NonzeroTerminalPadding && observation.Kind != NonzeroEmptyEncoding {
			continue
		}
		suffix, qualified := strings.CutPrefix(string(observation.Location.Path), root)
		if qualified && (suffix == "" || strings.HasPrefix(suffix, ".") || strings.HasPrefix(suffix, "[")) {
			continue
		}
		size := uint64(len(root)) + uint64(len(observation.Location.Path)) + 1
		if size > uint64(math.MaxInt) {
			return bb.resourceError("qualified padding path exceeds host int")
		}
		if err := bb.ChargeAllocation(size, 1); err != nil {
			return err
		}
		if err := bb.ChargeWork(size); err != nil {
			return err
		}
		observation.Location.Path = Path(qualifyPath(root, string(observation.Location.Path)))
	}
	return nil
}
