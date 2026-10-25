// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/opaque.go; SHA-256 4a2cc56b18bfff569d00bfb90fc8212f2767b18aede2171a5ab77e9e63cb5553.
package aper

import (
	"fmt"
	"math"
	"math/bits"
	"sort"
)

// OpaqueReason identifies why the pinned source cannot decode an open value.
type OpaqueReason uint8

const (
	UnknownSelector OpaqueReason = iota + 1
	NotInTable
	OutcomeNotInTable
	CallerSupplied
)

// OpaqueOrigin records the received selector boundary. X.691 (02/2021)
// §11.2.1 defines the complete open type; TS 36.413 V19.2.0 §9.3.2 supplies
// the S1AP procedure selection.
type OpaqueOrigin struct {
	Reason          OpaqueReason
	Rule            SourceRule
	Location        Location
	HasWireLocation bool
	SourceVersion   string
}

// OpaqueOpenType owns an unrecognized complete open value and its provenance.
type OpaqueOpenType struct {
	image           WireSpan
	bytes           []byte
	origin          OpaqueOrigin
	parent          *BitBuffer
	payloadBase     uint64
	hasPayloadBase  bool
	payloadSegments []wireSegment
}

// wireSegment maps joined open-value bits to their original input bits.
// X.691 (02/2021) §11.9.3.8 permits length octets between fragments.
type wireSegment struct {
	localStart, localEnd uint64
	sourceStart          uint64
}

func originalRange(bb *BitBuffer, start, end uint64) ([]BitSpan, bool) {
	if bb == nil || !bb.sourceReader || end < start {
		return nil, false
	}
	budget := bb.decodeBudget()
	var segments []wireSegment
	if budget.origin != nil {
		segments = budget.origin.segments[bb]
		if len(segments) == 0 {
			segments = budget.origin.dataSegments[originDataKey(bb.data)]
		}
	}
	if len(segments) != 0 {
		cursor := start
		var spans []BitSpan
		for _, segment := range segments[sort.Search(len(segments), func(i int) bool { return segments[i].localEnd > start }):] {
			if cursor >= end {
				break
			}
			if segment.localEnd <= cursor {
				continue
			}
			if segment.localStart > cursor {
				return nil, false
			}
			limit := min(end, segment.localEnd)
			first, carry := bits.Add64(segment.sourceStart, cursor-segment.localStart, 0)
			if carry != 0 {
				return nil, false
			}
			last, carry := bits.Add64(first, limit-cursor, 0)
			if carry != 0 {
				return nil, false
			}
			if budget.locating {
				spans = append(spans, BitSpan{Start: first, End: last})
			} else {
				var err error
				spans, err = AppendValues(bb, spans, BitSpan{Start: first, End: last})
				if err != nil {
					return nil, false
				}
			}
			cursor = limit
		}
		return spans, cursor == end
	}
	span, ok := originalContiguousRange(bb, start, end)
	if !ok {
		return nil, false
	}
	if !budget.locating {
		if err := bb.ChargeAllocation(1, 16); err != nil {
			return nil, false
		}
	}
	return []BitSpan{span}, true
}

// originalContiguousRange maps an immediate-use span without allocating a
// location. Fragmented parents continue through originalRange (X.691 §11.9.3.8).
func originalContiguousRange(bb *BitBuffer, start, end uint64) (BitSpan, bool) {
	if bb == nil || !bb.sourceReader || end < start {
		return BitSpan{}, false
	}
	budget := bb.decodeBudget()
	if budget.origin != nil && (len(budget.origin.segments[bb]) != 0 || len(budget.origin.dataSegments[originDataKey(bb.data)]) != 0) {
		return BitSpan{}, false
	}
	var base uint64
	var ok bool
	if budget.origin != nil {
		base, ok = budget.origin.bases[bb]
		if !ok {
			base, ok = budget.origin.dataBases[originDataKey(bb.data)]
		}
	}
	if !bb.nested {
		base, ok = 0, true
	}
	if !ok {
		return BitSpan{}, false
	}
	first, carry := bits.Add64(base, start, 0)
	if carry != 0 {
		return BitSpan{}, false
	}
	last, carry := bits.Add64(base, end, 0)
	if carry != 0 {
		return BitSpan{}, false
	}
	return BitSpan{Start: first, End: last}, true
}

func (v OpaqueOpenType) Bytes() []byte {
	if v.parent != nil && v.parent.trace != nil && v.parent.trace.terminalPadding {
		return v.copyWithPaddingLocation()
	}
	if v.image.Present() {
		return v.image.Bytes()
	}
	return append([]byte(nil), v.bytes...)
}

// copyWithPaddingLocation preserves the origin of an accessor copy used by a
// nested known-value decoder. X.691 (02/2021) §§11.2.1 and 11.9.3.8 delimit
// the complete contents independently of their intervening length octets.
// The default Bytes path retains its original copy and allocation behavior.
func (v OpaqueOpenType) copyWithPaddingLocation() []byte {
	data := v.copyPaddingContents()
	if v.parent.decodeBudget().err != nil {
		return nil
	}
	child := NewNestedDecodeBuffer(data, v.parent)
	if err := child.MapOriginalLocation(data, v.ContentLocation()); err != nil {
		child.decodeBudget().err = err
		return nil
	}
	return data
}
func (v OpaqueOpenType) copyPaddingContents() []byte {
	if v.image.Present() {
		if v.parent != nil {
			if err := v.parent.ChargeAllocation(uint64(v.image.Len()), 1); err != nil {
				return nil
			}
		}
		return v.image.Bytes()
	}
	if v.parent != nil {
		if err := v.parent.ChargeAllocation(uint64(len(v.bytes)), 1); err != nil {
			return nil
		}
	}
	return append([]byte(nil), v.bytes...)

}

// RetainContents attaches an immutable complete open form to generated private
// state. Byte-returning public views still copy on demand.
func (v OpaqueOpenType) RetainContents(dst *WireSpan) {
	if v.image.Present() {
		*dst = v.image
	} else {
		*dst = OriginalWire(v.bytes)
	}
}
func (v OpaqueOpenType) Origin() OpaqueOrigin {
	if v.parent != nil {
		if err := v.parent.ChargeAllocation(uint64(len(v.origin.Location.Spans)), 16); err != nil {
			return OpaqueOrigin{}
		}
	}
	origin := v.origin
	origin.Location.Spans = append([]BitSpan(nil), origin.Location.Spans...)
	return origin
}

// ContentLocation identifies the complete value octets without their open
// type length determinants. X.691 (02/2021) §§11.2.1 and 11.9.3.8 permit
// those octets to occupy several original-input spans.
func (v OpaqueOpenType) ContentLocation() Location {
	if v.image.Present() {
		return v.image.contentLocation(v.parent)
	}
	if v.hasPayloadBase {
		high, width := bits.Mul64(uint64(len(v.bytes)), 8)
		end, carry := bits.Add64(v.payloadBase, width, 0)
		if high != 0 || carry != 0 {
			return Location{}
		}
		if v.parent != nil {
			if err := v.parent.ChargeAllocation(1, 16); err != nil {
				return Location{}
			}
		}
		return Location{Spans: []BitSpan{{Start: v.payloadBase, End: end}}, HasWireLocation: true}
	}
	if len(v.payloadSegments) == 0 {
		return Location{}
	}
	if v.parent != nil {
		if err := v.parent.ChargeAllocation(uint64(len(v.payloadSegments)), 16); err != nil {
			return Location{}
		}
	}
	spans := make([]BitSpan, 0, len(v.payloadSegments))
	for _, segment := range v.payloadSegments {
		if segment.localEnd < segment.localStart {
			return Location{}
		}
		end, carry := bits.Add64(segment.sourceStart, segment.localEnd-segment.localStart, 0)
		if carry != 0 {
			return Location{}
		}
		spans = append(spans, BitSpan{Start: segment.sourceStart, End: end})
	}
	return Location{Spans: spans, HasWireLocation: true}
}

// ChildDecodeBuffer shares the enclosing decode's budget and receiver
// settings while interpreting a known selected value. A detached value gets
// independent cursor and budget storage over the same immutable contents.
func (v OpaqueOpenType) ChildDecodeBuffer() *BitBuffer {
	if v.image.Present() {
		return v.image.decodeBuffer(v.parent)
	}
	var child *BitBuffer
	if v.parent == nil {
		child = NewBitBufferFromBytes(append([]byte(nil), v.bytes...))
		child.nested = v.hasPayloadBase || len(v.payloadSegments) != 0
	} else {
		child = NewNestedDecodeBuffer(v.bytes, v.parent)
	}
	if v.hasPayloadBase {
		budget := child.decodeBudget()
		if budget.origin == nil {
			if err := ChargeValue(child, originMap{}); err != nil {
				return child
			}
			budget.origin = &originMap{}
		}
		if err := ReserveMapEntry(child, budget.origin.bases, child); err != nil {
			return child
		}
		if budget.origin.bases == nil {
			budget.origin.bases = make(map[*BitBuffer]uint64)
		}
		budget.origin.bases[child] = v.payloadBase
	} else if len(v.payloadSegments) != 0 {
		budget := child.decodeBudget()
		if budget.origin == nil {
			if err := ChargeValue(child, originMap{}); err != nil {
				return child
			}
			budget.origin = &originMap{}
		}
		if err := ReserveMapEntry(child, budget.origin.segments, child); err != nil {
			return child
		}
		if budget.origin.segments == nil {
			budget.origin.segments = make(map[*BitBuffer][]wireSegment)
		}
		budget.origin.segments[child] = v.payloadSegments
	}
	return child
}

// Detached removes the ephemeral decoder reference before an unknown value
// is stored in a long-lived decoded graph.
func (v OpaqueOpenType) Detached() OpaqueOpenType {
	v.parent = nil
	return v
}

// WithPath qualifies the received selector with its source-shaped member.
func (v OpaqueOpenType) WithPath(path Path) OpaqueOpenType {
	v.origin.Location.Path = path
	return v
}

// NewOpaqueOpenType creates caller-supplied opaque content without received
// provenance. The bytes are copied so the caller cannot alter the value.
func NewOpaqueOpenType(data []byte) OpaqueOpenType {
	return OpaqueOpenType{bytes: append([]byte(nil), data...), origin: OpaqueOrigin{Reason: CallerSupplied}}
}

// newOpaqueOpenTypeWithSettings creates a selector value whose known
// child decoder inherits the caller's budget and receiver policy.
func newOpaqueOpenTypeWithSettings(data []byte, options decodeSettings) (OpaqueOpenType, error) {
	parent := NewCompleteDecodeBuffer(data, DecodeState{settings: options})
	if err := parent.setDecodeSettingsAligned(options); err != nil {
		return OpaqueOpenType{}, err
	}
	if err := parent.ChargeAllocation(uint64(len(data)), 1); err != nil {
		return OpaqueOpenType{}, err
	}
	value := OpaqueOpenType{hasPayloadBase: true, bytes: data, origin: OpaqueOrigin{Reason: CallerSupplied}}
	if options.owner == nil {
		value.bytes = append([]byte(nil), data...)
	}
	value.parent = parent
	if options.owner != nil {
		value.image = OriginalWire(data)
		value.bytes = nil
	}
	return value, nil
}

// DecodeOpaqueOpenTypeAligned derives received location from the actual
// decoder cursor. The contents obey X.691 (02/2021) §11.2.1 framing.
func DecodeOpaqueOpenTypeAligned(bb *BitBuffer, reason OpaqueReason, rule SourceRule) (OpaqueOpenType, error) {
	if bb == nil {
		return OpaqueOpenType{}, fmt.Errorf("opaque open type: nil decoder")
	}
	if reason != UnknownSelector && reason != NotInTable && reason != OutcomeNotInTable {
		return OpaqueOpenType{}, fmt.Errorf("opaque open type: invalid received reason %d", reason)
	}
	if bb.ownsInput() {
		return decodeOwnedOpaque(bb, reason, rule)
	}
	start := bb.BitPos()
	var payloadSegments []wireSegment
	var firstSegment wireSegment
	hasFirstSegment := false
	mapValid := true
	data, err := decodeOpenTypeAlignedObserved(bb, func(offset, length int64, bitStart int) {
		if !mapValid || offset < 0 || length < 0 || bitStart < 0 {
			mapValid = false
			return
		}
		startHigh, localStart := bits.Mul64(uint64(offset), 8)
		lengthHigh, lengthBits := bits.Mul64(uint64(length), 8)
		endLocal, carry := bits.Add64(localStart, lengthBits, 0)
		endSource, sourceCarry := bits.Add64(uint64(bitStart), lengthBits, 0)
		if startHigh != 0 || lengthHigh != 0 || carry != 0 || sourceCarry != 0 {
			mapValid = false
			return
		}
		var scratch [1]BitSpan
		var spans []BitSpan
		span, ok := originalContiguousRange(bb, uint64(bitStart), endSource)
		if ok {
			scratch[0] = span
			spans = scratch[:]
		} else {
			spans, ok = originalRange(bb, uint64(bitStart), endSource)
		}
		if !ok {
			mapValid = false
			return
		}
		cursor := localStart
		for _, span := range spans {
			if span.End < span.Start {
				mapValid = false
				return
			}
			spanEnd, spanCarry := bits.Add64(cursor, span.End-span.Start, 0)
			if spanCarry != 0 || spanEnd > endLocal {
				mapValid = false
				return
			}
			segment := wireSegment{localStart: cursor, localEnd: spanEnd, sourceStart: span.Start}
			if !hasFirstSegment {
				firstSegment, hasFirstSegment = segment, true
			} else {
				var failure error
				if len(payloadSegments) == 0 {
					payloadSegments, failure = AppendValues(bb, payloadSegments, firstSegment, segment)
				} else {
					payloadSegments, failure = AppendValues(bb, payloadSegments, segment)
				}
				if failure != nil {
					mapValid = false
					return
				}
			}
			cursor = spanEnd
		}
		if cursor != endLocal {
			mapValid = false
		}
	})
	if err != nil {
		return OpaqueOpenType{}, err
	}
	if err := bb.decodeBudget().err; err != nil {
		return OpaqueOpenType{}, err
	}
	end := bb.BitPos()
	location := Location{}
	var payloadBase uint64
	var hasPayloadBase bool
	if start >= 0 && end >= start {
		if spans, ok := originalRange(bb, uint64(start), uint64(end)); ok {
			location = Location{Spans: spans, HasWireLocation: true}
		}
	}
	if mapValid && hasFirstSegment && len(payloadSegments) == 0 && firstSegment.localStart == 0 {
		if high, length := bits.Mul64(uint64(len(data)), 8); high == 0 && firstSegment.localEnd == length {
			payloadBase, hasPayloadBase = firstSegment.sourceStart, true
		}
	}
	if !mapValid {
		payloadSegments = nil
	}
	if err := bb.decodeBudget().err; err != nil {
		return OpaqueOpenType{}, err
	}
	return OpaqueOpenType{bytes: data, parent: bb, payloadBase: payloadBase, hasPayloadBase: hasPayloadBase, payloadSegments: payloadSegments, origin: OpaqueOrigin{
		Reason: reason, Rule: rule, Location: location, HasWireLocation: location.HasWireLocation, SourceVersion: rule.Edition,
	}}, nil
}

// Observe records a legal opaque boundary in the enclosing operation.
func (v OpaqueOpenType) Observe(kind ObservationKind) error {
	if v.parent == nil {
		return nil
	}
	budget := v.parent.decodeBudget()
	if budget.callReport == nil {
		return nil
	}
	if budget.operational == (Limits{}) && len(budget.callReport.Observations) >= 1024 {
		return &DecodeError{Kind: Limit, Location: v.origin.Location, Rule: v.origin.Rule, Err: ErrLimit}
	}
	if err := v.parent.ChargeLocatedReport(v.origin.Location, 0); err != nil {
		return err
	}
	location := v.origin.Location
	if budget.owner != nil && len(location.Spans) <= len(budget.owner.reportSpans)-budget.owner.nextReportSpan {
		o := budget.owner
		start := o.nextReportSpan
		o.nextReportSpan += len(location.Spans)
		copy(o.reportSpans[start:o.nextReportSpan], location.Spans)
		location.Spans = o.reportSpans[start:o.nextReportSpan:o.nextReportSpan]
	} else {
		location = v.Origin().Location
	}
	if budget.owner != nil && budget.callReport.Observations == nil {
		budget.callReport.Observations = budget.owner.observations[:0]
	}
	next, err := AppendValues(v.parent, budget.callReport.Observations, Observation{Location: location, Rule: v.origin.Rule, Kind: kind})
	if err != nil {
		return err
	}
	budget.callReport.Observations = next
	return nil
}

func originDataKey(data []byte) *byte {
	if len(data) == 0 {
		return nil
	}
	return &data[0]
}

// MapOriginalLocation maps a caller-owned child without retaining its buffer
// pointer. X.691 (02/2021) §11.9.3.8 may put length octets between spans.
// Generated decoders use this after NewNestedDecodeBuffer, keeping the
// enclosing buffer and its budget on the stack when no addition is present.
func (bb *BitBuffer) MapOriginalLocation(data []byte, location Location) error {
	if len(data) != len(bb.data) || (len(data) > 0 && &data[0] != &bb.data[0]) {
		return ErrInvalidValue
	}
	if !location.HasWireLocation {
		return nil
	}
	high, length := bits.Mul64(uint64(len(data)), 8)
	if high != 0 || length == 0 || uint64(len(location.Spans)) > length {
		return ErrInvalidValue
	}
	total := uint64(0)
	for _, span := range location.Spans {
		if span.End <= span.Start {
			return ErrInvalidValue
		}
		next, carry := bits.Add64(total, span.End-span.Start, 0)
		if carry != 0 || next > length {
			return ErrInvalidValue
		}
		total = next
	}
	if total != length {
		return ErrInvalidValue
	}
	budget := bb.decodeBudget()
	if budget.origin == nil {
		if err := ChargeValue(bb, originMap{}); err != nil {
			return err
		}
		budget.origin = &originMap{}
	}
	key := originDataKey(data)
	delete(budget.origin.bases, bb)
	delete(budget.origin.segments, bb)
	if len(location.Spans) == 1 {
		delete(budget.origin.dataSegments, key)
		if err := ReserveMapEntry(bb, budget.origin.dataBases, key); err != nil {
			return err
		}
		if budget.origin.dataBases == nil {
			budget.origin.dataBases = make(map[*byte]uint64)
		}
		budget.origin.dataBases[key] = location.Spans[0].Start
		return nil
	}
	// A wireSegment holds three uint64s; check the requested product
	// before allocating the original-fragment map.
	if len(location.Spans) > math.MaxInt/24 {
		return &DecodeError{Kind: Limit, Location: location, Err: ErrResourceLimit}
	}
	if err := ChargeSlice[wireSegment](bb, uint64(len(location.Spans))); err != nil {
		return err
	}
	segments := make([]wireSegment, 0, len(location.Spans))
	cursor := uint64(0)
	for _, span := range location.Spans {
		next, _ := bits.Add64(cursor, span.End-span.Start, 0)
		segments = append(segments, wireSegment{localStart: cursor, localEnd: next, sourceStart: span.Start})
		cursor = next
	}
	if err := ReserveMapEntry(bb, budget.origin.dataSegments, key); err != nil {
		return err
	}
	if budget.origin.dataSegments == nil {
		budget.origin.dataSegments = make(map[*byte][]wireSegment)
	}
	delete(budget.origin.dataBases, key)
	budget.origin.dataSegments[key] = segments
	return nil
}

// EncodeBytes copies opaque content under its enclosing operation budget.
func (v OpaqueOpenType) EncodeBytes(budget *DecodeBudget) ([]byte, error) {
	bb := NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(v.bytes)), 1); err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(v.bytes))); err != nil {
		return nil, err
	}
	return append([]byte(nil), v.bytes...), nil
}

// BudgetBuffer shares operation accounting while a selected union is decoded.
func (v OpaqueOpenType) BudgetBuffer() *BitBuffer {
	if v.parent != nil {
		return v.parent
	}
	return NewBitBuffer()
}

// BuildOpaqueOpenType reserves caller-owned content before making its copy.
// X.691 (02/2021) §11.2.1 still requires a complete nonempty open value.
func BuildOpaqueOpenType(data []byte, budget *DecodeBudget) (OpaqueOpenType, error) {
	bb := NewBudgetBuffer(budget)
	if len(data) == 0 {
		return OpaqueOpenType{}, ErrInvalidValue
	}
	if err := bb.CheckOutput(uint64(len(data))); err != nil {
		return OpaqueOpenType{}, err
	}
	if uint64(len(data)) > bb.openTypeMaximum() {
		return OpaqueOpenType{}, bb.resourceError("open type bytes exceeded")
	}
	if err := bb.ChargeAllocation(uint64(len(data)), 1); err != nil {
		return OpaqueOpenType{}, err
	}
	return NewOpaqueOpenType(data), nil
}

// ObserveIndexed records an indexed member only when the operation collects
// observations. The retained origin keeps its unindexed path so extension
// views can attach the bitmap index once (X.691 (02/2021) §§19.8–19.9).
func (v OpaqueOpenType) ObserveIndexed(kind ObservationKind, index int64) error {
	if v.parent == nil || v.parent.decodeBudget().callReport == nil {
		return nil
	}
	v.origin.Location.Path = Path(fmt.Sprintf("%s[%d]", v.origin.Location.Path, index))
	return v.Observe(kind)
}

// The mapped-copy route keeps the complete-open-type refusal's source rule.
// X.691 (02/2021) §11.2.1 still forbids a zero-octet complete encoding.
func decodeOpenTypeWithPaddingLocation(bb *BitBuffer) (data []byte, err error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, "§11.2.1", &err)
	// A caller-supplied nested copy may share the input owner without a
	// source mapping. Decode its contents normally; provenance is optional.
	if bb.nested {
		if _, contiguous := originalContiguousRange(bb, 0, 0); !contiguous {
			origin := bb.decodeBudget().origin
			if origin == nil || (len(origin.segments[bb]) == 0 && len(origin.dataSegments[originDataKey(bb.data)]) == 0) {
				return decodeOpenTypeAlignedObserved(bb, nil)
			}
		}
	}
	raw, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{})
	if err != nil {
		return nil, err
	}
	data = raw.Bytes()
	return data, bb.decodeBudget().err
}
