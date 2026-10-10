package per

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"sync"

	"github.com/gomaja/go-asn1/runtime"
)

// ContainedDecoding selects how a UPER decode treats a value carried in a
// BIT STRING or OCTET STRING (CONTAINING ...).
//
// TS 36.331 V19.4.0 8.1 and TS 38.331 V19.4.0 8.1 say that automatic decoding
// of a contained type "should not be performed because errors in the decoding
// of the contained type should not cause the decoding of the entire RRC
// message PDU to fail", and recommend decoding the outer PDU first and the
// contained value as a separate step. TS 25.331 V19.0.1 has no such rule for
// contained types.
//
// Only the inner decode is deferred. The enclosing BIT STRING or OCTET STRING
// is still decoded and checked, so its length determinant and every sibling
// stay fail-closed in each mode. A deferred value keeps its exact raw bits and
// re-encodes to them while unchanged (see Deferred).
//
// The modes apply to generated UPER decoders. Generated APER decoders always
// decode contained values eagerly, and their UnmarshalAPERWithOptions rejects
// the other modes (see BitBuffer.SetDecodeOptionsAligned).
type ContainedDecoding uint8

const (
	// Eager decodes every contained value as part of the enclosing value, so
	// a contained value that fails to decode fails the whole decode. It is
	// the default.
	Eager ContainedDecoding = iota
	// DeferOnError keeps a contained value whose decode fails as its raw
	// encoding, together with the error, and decodes the rest of the value.
	// Contained values that decode stay typed. It applies at every nesting
	// level independently: a value nested in a contained value that decodes
	// is itself decoded or deferred.
	DeferOnError
	// DeferAll decodes no contained value: each is kept as its raw encoding,
	// with no error, for a separate later decode, the two-step procedure of
	// TS 36.331 V19.4.0 8.1 and TS 38.331 V19.4.0 8.1. A value nested in a
	// deferred value is part of its raw encoding, so only the outermost
	// contained values are deferred.
	DeferAll
)

func (mode ContainedDecoding) String() string {
	switch mode {
	case Eager:
		return "Eager"
	case DeferOnError:
		return "DeferOnError"
	case DeferAll:
		return "DeferAll"
	default:
		return "ContainedDecoding(" + strconv.Itoa(int(mode)) + ")"
	}
}

// ContainerKind names the string type that carries a contained value.
type ContainerKind uint8

const (
	// OctetStringContainer is an OCTET STRING (CONTAINING ...), whose
	// contents are a complete encoding (X.691 (02/2021) 11.1.3.1 and 11.1.4).
	OctetStringContainer ContainerKind = iota + 1
	// BitStringContainer is a BIT STRING (CONTAINING ...), whose contents
	// are the value's bits without octet padding (X.691 (02/2021) 11.1.3.2).
	BitStringContainer
)

func (kind ContainerKind) String() string {
	switch kind {
	case OctetStringContainer:
		return "OCTET STRING"
	case BitStringContainer:
		return "BIT STRING"
	default:
		return "ContainerKind(" + strconv.Itoa(int(kind)) + ")"
	}
}

var (
	// ErrEditedDeferred reports an encode of a deferred contained value with a
	// nonzero typed field. The check reads the shell's state: a field set to
	// its zero value cannot be told apart from an unedited one. Replace the
	// value with a new one, or reset it with PERPadding_ = per.FinalPadding{}
	// to discard the raw bits so that its typed fields are encoded; both work
	// for any replacement, zero values included.
	ErrEditedDeferred = errors.New("per: deferred contained value has typed edits; replace the value or zero its PERPadding_")
	// ErrMisplacedDeferred reports an encode of a deferred contained value
	// through MarshalUPERTo, at a position that is not a contained string, or
	// in a BIT STRING or OCTET STRING (CONTAINING ...) of the other kind.
	ErrMisplacedDeferred = errors.New("per: deferred contained value encoded outside its BIT STRING or OCTET STRING (CONTAINING ...)")
)

// Deferred is a contained value that a decode kept as its raw encoding under
// DeferOnError or DeferAll. It is held by the PERPadding_ of the value's
// typed shell: the field stays present, with the zero value of its type, and
// FinalPadding.Deferred returns the state. It never changes after the decode.
//
// While every typed field of the shell is zero, encoding reproduces the raw
// bits exactly; a nonzero typed field makes it return ErrEditedDeferred.
type Deferred struct {
	kind      ContainerKind
	raw       []byte
	bitLength int
	err       error
}

// Deferred returns the raw state of a contained value kept raw by the
// decode, or nil for any other value.
func (f FinalPadding) Deferred() *Deferred {
	if f.bits == nil {
		return nil
	}
	return f.bits.deferred
}

// Kind reports whether the value was carried in an OCTET STRING or a BIT
// STRING.
func (d *Deferred) Kind() ContainerKind { return d.kind }

// Bytes returns a copy of the raw contents, MSB first. For a BIT STRING the
// unused low bits of the last octet are zero.
func (d *Deferred) Bytes() []byte { return append([]byte(nil), d.raw...) }

// BitLength is the exact length of the contents in bits: eight per octet
// for an OCTET STRING.
func (d *Deferred) BitLength() int { return d.bitLength }

// Err returns the error that made DeferOnError keep the value raw, with the
// field path from the top-level value. Outside another contained value it
// reads as the error an Eager decode returns when that value fails first.
// It is nil under DeferAll.
func (d *Deferred) Err() error { return d.err }

// BitBuffer returns a read buffer over the contents of a value deferred from
// a BIT STRING, bounded to its bit length, for a later decode with options.
// Decode the contained type from it with its UnmarshalUPERFrom, then call
// CaptureDeferredBits. An OCTET STRING value is a complete encoding: decode
// Bytes with the contained type's UnmarshalUPERWithOptions instead.
func (d *Deferred) BitBuffer(options DecodeOptions) (*BitBuffer, error) {
	if d.kind != BitStringContainer {
		return nil, fmt.Errorf("%w: a deferred %v value is a complete encoding; decode Bytes with UnmarshalUPERWithOptions", ErrInvalidValue, d.kind)
	}
	bb, err := NewBitBufferFromBits(d.Bytes(), d.bitLength)
	if err != nil {
		return nil, err
	}
	bb.SetDecodeOptions(options)
	// The contents arrived with the BIT STRING's full length, so an extension
	// addition they cut short is not a cut input: it stays an error under
	// TruncatedExtensionTolerance.
	bb.outermost = false
	return bb, nil
}

// CaptureDeferredBits completes the later decode of a BIT STRING value
// started with Deferred.BitBuffer. It checks the bits after the value as the
// enclosing decode does (CaptureContainedBits), then publishes the decode's
// records, qualified by root, as CaptureFinalBits does. Store the returned
// FinalPadding in the host's <Field>PERPadding_ with the decoded value.
func CaptureDeferredBits(bb *BitBuffer, root string) (FinalPadding, error) {
	if err := bb.checkContainedDecoding(); err != nil {
		return FinalPadding{}, err
	}
	final, err := CaptureContainedBits(bb)
	if err != nil {
		return FinalPadding{}, err
	}
	bb.commitRecords(root)
	return final, nil
}

// Deferral records one contained value that a decode kept raw.
type Deferral struct {
	// Path is the generated field path of the value in the form used by
	// runtime.DecodePathError, starting with the top-level type name.
	Path string
	Kind ContainerKind
	// BitLength is the length of the raw contents in bits.
	BitLength int
	// Err is the decode error under DeferOnError, the same error as the
	// value's Deferred.Err; it is nil under DeferAll.
	Err error
}

// DeferralLog collects the deferrals of PER decodes. A zero value is ready
// for use, and one log may be shared by concurrent decoders. Each successful
// top-level decode appends its records together, in decode order, and in the
// same commit as its tolerance records; a failed decode appends nothing.
type DeferralLog struct {
	mu      sync.Mutex
	records []Deferral
}

// Snapshot returns the records collected so far without exposing the log's
// storage.
func (log *DeferralLog) Snapshot() []Deferral {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]Deferral(nil), log.records...)
}

// Reset discards all records collected so far.
func (log *DeferralLog) Reset() {
	log.mu.Lock()
	log.records = nil
	log.mu.Unlock()
}

func (log *DeferralLog) append(records []Deferral) {
	log.mu.Lock()
	log.records = append(log.records, records...)
	log.mu.Unlock()
}

// pendingDeferral is a deferral record awaiting the top-level commit, which
// completes the path of the record and of its error.
type pendingDeferral struct {
	record Deferral
	err    *runtime.DecodePathError
}

// checkContainedDecoding rejects a decode with an unknown ContainedDecoding,
// or one that defers without a log to report to.
func (bb *BitBuffer) checkContainedDecoding() error {
	switch bb.contained {
	case Eager:
		return nil
	case DeferOnError, DeferAll:
		if bb.trace == nil || bb.trace.deferrals == nil {
			return fmt.Errorf("%w: ContainedDecoding %v requires DecodeOptions.Deferrals", ErrInvalidValue, bb.contained)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown %v", ErrInvalidValue, bb.contained)
	}
}

// ContainedSite is the state of one contained value's decode. A generated
// decoder takes it with EnterContained after reading the enclosing BIT
// STRING or OCTET STRING, inside that component's path segment.
type ContainedSite struct {
	trace      *decodeTrace
	mode       ContainedDecoding
	path       int
	tolerances int
	deferrals  int
}

// EnterContained marks the start of a contained value's decode.
func (bb *BitBuffer) EnterContained() ContainedSite {
	site := ContainedSite{trace: bb.trace, mode: bb.contained}
	if bb.trace != nil {
		site.path, site.tolerances, site.deferrals = len(bb.trace.path), len(bb.trace.pending), len(bb.trace.deferred)
	}
	return site
}

// Decodes reports whether the contained value is decoded now; under
// DeferAll it is kept raw without a decode.
func (site ContainedSite) Decodes() bool { return site.mode != DeferAll }

// DefersErrors reports whether a contained value that fails to decode is
// kept raw instead of failing the decode.
func (site ContainedSite) DefersErrors() bool { return site.mode == DeferOnError }

// DeferOctets keeps the contents of an OCTET STRING (CONTAINING ...) raw,
// with the decode error, or nil under DeferAll. Store the result in the
// PERPadding_ of the contained value's zero shell.
func (site ContainedSite) DeferOctets(raw []byte, err error) FinalPadding {
	// raw was read from an input whose bit length fits an int.
	bitLength := math.MaxInt
	if len(raw) <= math.MaxInt/8 {
		bitLength = 8 * len(raw)
	}
	return site.deferContained(OctetStringContainer, raw, bitLength, err)
}

// DeferBits keeps the contents of a BIT STRING (CONTAINING ...) raw, with
// their exact bit length and the decode error, or nil under DeferAll. Store
// the result in the PERPadding_ of the contained value's zero shell.
func (site ContainedSite) DeferBits(raw []byte, bitLength int, err error) FinalPadding {
	return site.deferContained(BitStringContainer, raw, bitLength, err)
}

func (site ContainedSite) deferContained(kind ContainerKind, raw []byte, bitLength int, err error) FinalPadding {
	deferred := &Deferred{kind: kind, raw: raw, bitLength: bitLength, err: err}
	if trace := site.trace; trace != nil {
		// The abandoned decode's tolerance and deferral records describe a
		// value that is now raw, and its error left its path segments in
		// place; drop both back to this site.
		if site.tolerances <= len(trace.pending) {
			trace.pending = trace.pending[:site.tolerances]
		}
		if site.deferrals <= len(trace.deferred) {
			trace.deferred = trace.deferred[:site.deferrals]
		}
		if site.path <= len(trace.path) {
			trace.path = trace.path[:site.path]
		}
		pending := pendingDeferral{record: Deferral{Path: trace.relativePath(), Kind: kind, BitLength: bitLength}}
		if err != nil {
			pending.err = &runtime.DecodePathError{Path: pending.record.Path, Err: err}
			deferred.err, pending.record.Err = pending.err, pending.err
		}
		trace.deferred = append(trace.deferred, pending)
	}
	return FinalPadding{bits: &finalBits{deferred: deferred}}
}

// MarshalDeferred returns the raw encoding held by final, the PERPadding_ of
// shell, a deferred value from an OCTET STRING (CONTAINING ...): a generated
// MarshalUPER calls it for a value whose PERPadding_ holds a Deferred. The
// result is a copy. It returns ErrEditedDeferred if any other field of shell
// is set, and ErrMisplacedDeferred for a value deferred from a BIT STRING,
// whose contents are not a complete encoding.
func MarshalDeferred(shell any, final FinalPadding) ([]byte, error) {
	deferred, err := unchangedDeferred(shell, final, OctetStringContainer)
	if err != nil {
		return nil, err
	}
	return deferred.Bytes(), nil
}

// AppendDeferred writes the raw contents held by final, the PERPadding_ of
// shell, a deferred value from a BIT STRING (CONTAINING ...), with their
// exact bit length. It returns ErrEditedDeferred if any other field of shell
// is set, and ErrMisplacedDeferred for a value deferred from an OCTET STRING.
func AppendDeferred(bb *BitBuffer, shell any, final FinalPadding) error {
	deferred, err := unchangedDeferred(shell, final, BitStringContainer)
	if err != nil {
		return err
	}
	return bb.WriteBitsFromBytes(deferred.raw, deferred.bitLength)
}

func unchangedDeferred(shell any, final FinalPadding, kind ContainerKind) (*Deferred, error) {
	deferred := final.Deferred()
	if deferred == nil {
		return nil, fmt.Errorf("%w: value holds no deferred encoding", ErrInvalidValue)
	}
	if deferred.kind != kind {
		return nil, fmt.Errorf("%w: value deferred from a %v encoded in a %v", ErrMisplacedDeferred, deferred.kind, kind)
	}
	if !zeroShell(shell) {
		return nil, ErrEditedDeferred
	}
	return deferred, nil
}

// zeroShell reports whether every field of the struct shell points to,
// other than its PERPadding_, has its zero value.
func zeroShell(shell any) bool {
	value := reflect.ValueOf(shell)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return false
	}
	value = value.Elem()
	for i := range value.NumField() {
		if value.Type().Field(i).Name != "PERPadding_" && !value.Field(i).IsZero() {
			return false
		}
	}
	return true
}
