// Code generated from ASN.1. DO NOT EDIT.

package tcap

import (
	"bytes"
	"fmt"
	rt "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	ber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	tag "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"math"
	"math/big"
)

// DialogueContentKind identifies the syntax resolved by the dialogue envelope.
type DialogueContentKind uint8

const (
	UnknownSyntax DialogueContentKind = iota
	Structured
	Unstructured
	UnresolvedIdentification
)

// DialoguePortion owns one content value. The metadata and received envelope
// remain private so raw bytes can never override an edited recognized APDU.
// ITU-T Q.773 (06/1997) sections 3.2.1, 3.2.2, 4.2.3; X.690 (02/2021) 8.18.
type DialoguePortion struct {
	metadata            rt.External
	kind                DialogueContentKind
	dialogue            *DialoguePDU
	unidialogue         *UniDialoguePDU
	originalDialogue    *DialoguePDU
	originalUniDialogue *UniDialoguePDU
	originalBER         []byte
	originalInner       []byte
	editable            bool
	berReplayNode_      *ber.ReplayNode
}

// NewDialoguePortionDialogue uses the structured syntax and single-ASN1-type.
func NewDialoguePortionDialogue(value DialoguePDU) DialoguePortion {
	return DialoguePortion{metadata: rt.External{DirectReference: DialogueAsId(), Encoding: rt.ExternalSingleASN1Type}, kind: Structured, dialogue: &value, editable: true}
}

// NewDialoguePortionUniDialogue uses the unstructured syntax.
func NewDialoguePortionUniDialogue(value UniDialoguePDU) DialoguePortion {
	return DialoguePortion{metadata: rt.External{DirectReference: UniDialogueAsId(), Encoding: rt.ExternalSingleASN1Type}, kind: Unstructured, unidialogue: &value, editable: true}
}

// NewDialoguePortionExternal validates and detaches a generic EXTERNAL.
// Direct-only identification selects an abstract syntax (X.690 8.18.4 Table 2).
func NewDialoguePortionExternal(value rt.External, opts ...ber.DecodeOption) (DialoguePortion, error) {
	var result DialoguePortion
	if err := ber.ValidateDecodeOptions(opts...); err != nil {
		return result, err
	}
	encoded, err := encodeDialogueExternal(value, false)
	if err != nil {
		return result, err
	}
	encoded, err = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 11, encoded)
	if err != nil {
		return result, err
	}
	if err = result.UnmarshalBER(encoded, opts...); err != nil {
		return DialoguePortion{}, err
	}
	return result, nil
}

// Dialogue returns the authoritative, editable structured value.
func (value *DialoguePortion) Dialogue() (*DialoguePDU, bool) {
	if value == nil || value.kind != Structured || value.dialogue == nil {
		return nil, false
	}
	if !value.editable {
		// The enclosing generated decoder's baseline may share private pointers.
		// Detach the fixed source-defined APDU graph before publishing edits. Its
		// fields contain no unsupported clone kinds; a clone error is an internal
		// source-shape invariant failure, never a condition caused by wire values.
		detached, err := ber.CloneBERValue(value.dialogue)
		if err != nil {
			panic(fmt.Errorf("detaching source-defined DialoguePDU: %w", err))
		}
		value.dialogue = detached.(*DialoguePDU)
		value.editable = true
	}
	return value.dialogue, true
}

// UniDialogue returns the authoritative, editable unstructured value.
func (value *DialoguePortion) UniDialogue() (*UniDialoguePDU, bool) {
	if value == nil || value.kind != Unstructured || value.unidialogue == nil {
		return nil, false
	}
	if !value.editable {
		detached, err := ber.CloneBERValue(value.unidialogue)
		if err != nil {
			panic(fmt.Errorf("detaching source-defined UniDialoguePDU: %w", err))
		}
		value.unidialogue = detached.(*UniDialoguePDU)
		value.editable = true
	}
	return value.unidialogue, true
}

func (value *DialoguePortion) ContentKind() DialogueContentKind {
	if value == nil {
		return UnknownSyntax
	}
	return value.kind
}

func (value *DialoguePortion) hasTCAPPresenceEdit() bool {
	if value == nil {
		return false
	}
	for _, content := range []any{value.dialogue, value.unidialogue} {
		if typed, ok := content.(interface{ hasTCAPPresenceEdit() bool }); ok && typed.hasTCAPPresenceEdit() {
			return true
		}
	}
	return false
}
func (value *DialoguePortion) dialogueReplayNode() *ber.ReplayNode {
	if value.hasTCAPPresenceEdit() {
		return nil
	}
	return value.berReplayNode_
}
func dialogueContentEqual(left, right any) bool {
	if typed, ok := left.(interface{ equalTCAPValue(any) bool }); ok {
		return typed.equalTCAPValue(right)
	}
	return false
}
func (value *DialoguePortion) dialogueUnchanged() bool {
	switch value.kind {
	case Structured:
		return value.dialogue != nil && value.originalDialogue != nil && dialogueContentEqual(*value.dialogue, *value.originalDialogue)
	case Unstructured:
		return value.unidialogue != nil && value.originalUniDialogue != nil && dialogueContentEqual(*value.unidialogue, *value.originalUniDialogue)
	default:
		return true
	}
}
func (value DialoguePortion) equalTCAPValue(other any) bool {
	right, ok := other.(DialoguePortion)
	if !ok || value.kind != right.kind || !equalDialogueExternal(value.metadata, right.metadata) {
		return false
	}
	if value.dialogue != nil || right.dialogue != nil {
		return value.dialogue != nil && right.dialogue != nil && dialogueContentEqual(*value.dialogue, *right.dialogue)
	}
	if value.unidialogue != nil || right.unidialogue != nil {
		return value.unidialogue != nil && right.unidialogue != nil && dialogueContentEqual(*value.unidialogue, *right.unidialogue)
	}
	return bytes.Equal(value.originalBER, right.originalBER)
}
func equalDialogueExternal(a, b rt.External) bool {
	if !a.DirectReference.Equal(b.DirectReference) || a.Encoding != b.Encoding || (a.IndirectReference == nil) != (b.IndirectReference == nil) || (a.DataValueDescriptor == nil) != (b.DataValueDescriptor == nil) {
		return false
	}
	if a.IndirectReference != nil && a.IndirectReference.Cmp(b.IndirectReference) != 0 {
		return false
	}
	if a.DataValueDescriptor != nil && *a.DataValueDescriptor != *b.DataValueDescriptor {
		return false
	}
	return a.SingleASN1Type.Class == b.SingleASN1Type.Class && a.SingleASN1Type.Tag == b.SingleASN1Type.Tag && a.SingleASN1Type.Constructed == b.SingleASN1Type.Constructed && bytes.Equal(a.SingleASN1Type.Bytes, b.SingleASN1Type.Bytes) && bytes.Equal(a.OctetAligned, b.OctetAligned) && a.Arbitrary.BitLength == b.Arbitrary.BitLength && bytes.Equal(a.Arbitrary.Bytes, b.Arbitrary.Bytes)
}

// copyDialogueExternal strips provenance and detaches every mutable field.
func copyDialogueExternal(value rt.External) rt.External {
	result := rt.External{DirectReference: value.DirectReference, Encoding: value.Encoding,
		SingleASN1Type: value.SingleASN1Type, OctetAligned: bytes.Clone(value.OctetAligned),
		Arbitrary: rt.BitString{Bytes: bytes.Clone(value.Arbitrary.Bytes), BitLength: value.Arbitrary.BitLength}}
	result.SingleASN1Type.Bytes = bytes.Clone(value.SingleASN1Type.Bytes)
	if value.IndirectReference != nil {
		result.IndirectReference = new(big.Int).Set(value.IndirectReference)
	}
	if value.DataValueDescriptor != nil {
		descriptor := *value.DataValueDescriptor
		result.DataValueDescriptor = &descriptor
	}
	return result
}

// Fresh encodings normalize non-semantic unused bits. An opaque BER element
// may be copied into canonical output only if generic DER validation succeeds;
// foreign-schema DER semantics remain the wrapper codec's responsibility.
// X.690 (02/2021) 8.6.2.4, 11.2.1 and 8.18.
func encodeDialogueExternal(value rt.External, der bool, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	// Comparison passes suppress received-form shortcuts, but still compare BER.
	// Only an explicit replay prohibition requests canonical opaque contents.
	// X.690 (02/2021) §§8.1.3, 8.18.9; Q.773 (06/1997) §4.1.1.
	if der || ber.CheckBEROpaqueReplay(opts...) != nil {
		return ber.EncodeExternalDER(value)
	}
	return ber.EncodeExternal(value, opts...)
}

// External materializes a detached snapshot from the current typed content.
func (value *DialoguePortion) External() (rt.External, error) {
	if value == nil {
		return rt.External{}, fmt.Errorf("%w: nil dialogue portion", ber.ErrInvalidValue)
	}
	inner, err := value.dialogueInner(false, nil)
	if err != nil {
		return rt.External{}, err
	}
	return value.dialogueExternal(inner)
}

func (value *DialoguePortion) dialogueInner(der bool, opts []ber.EncodeOption) ([]byte, error) {
	switch value.kind {
	case Structured:
		if value.dialogue == nil || value.unidialogue != nil {
			return nil, fmt.Errorf("%w: missing structured dialogue", ber.ErrInvalidValue)
		}
		if der {
			return value.dialogue.MarshalDER()
		}
		return value.dialogue.MarshalBER(ber.ChildEncodeOptions(opts, "dialogue")...)
	case Unstructured:
		if value.unidialogue == nil || value.dialogue != nil {
			return nil, fmt.Errorf("%w: missing unstructured dialogue", ber.ErrInvalidValue)
		}
		if der {
			return value.unidialogue.MarshalDER()
		}
		return value.unidialogue.MarshalBER(ber.ChildEncodeOptions(opts, "unidialogue")...)
	default:
		return nil, nil
	}
}

// dialogueArbitraryBitLength checks the host-int representation before any
// payload clone. X.690 (02/2021) 8.18.6 permits integral-octet BER in arbitrary;
// its bit count must also fit the runtime BitString representation.
func dialogueArbitraryBitLength(octets int) (int, error) {
	if octets < 0 || octets > math.MaxInt/8 {
		return 0, fmt.Errorf("%w: dialogue arbitrary bit length exceeds host int", ber.ErrInvalidValue)
	}
	return octets * 8, nil
}

func (value *DialoguePortion) dialogueExternal(inner []byte) (rt.External, error) {
	var bitLength int
	if (value.kind == Structured || value.kind == Unstructured) && value.metadata.Encoding == rt.ExternalArbitrary {
		var err error
		bitLength, err = dialogueArbitraryBitLength(len(inner))
		if err != nil {
			return rt.External{}, err
		}
	}
	result := copyDialogueExternal(value.metadata)
	if value.kind != Structured && value.kind != Unstructured {
		return result, nil
	}
	// Q.773 4.2.3.1 Tables 33-34; X.690 8.18.6: all three choices carry BER.
	switch result.Encoding {
	case rt.ExternalSingleASN1Type:
		// X.690 (02/2021) §§8.1.2.1, 8.1.2.5, 8.18.6: retain the inner identifier.
		identifier, _, err := ber.DecodeTag(inner)
		if err != nil {
			return rt.External{}, err
		}
		result.SingleASN1Type = rt.RawValue{Class: int(identifier.Class), Tag: identifier.Number, Constructed: identifier.Constructed, Bytes: bytes.Clone(inner)}
	case rt.ExternalOctetAligned:
		result.OctetAligned = bytes.Clone(inner)
	case rt.ExternalArbitrary:
		result.Arbitrary = rt.BitString{Bytes: bytes.Clone(inner), BitLength: bitLength}
	}
	return result, nil
}

// MarshalBER validates the current APDU before considering envelope replay.
func (value *DialoguePortion) MarshalBER(opts ...ber.EncodeOption) (encoded []byte, returnErr error) {
	opts, commit := ber.StageEncodeReports(opts)
	defer func() { commit(returnErr == nil) }()
	var finishProfile func([]byte, error) error
	opts, finishProfile = ber.StageTCAPEncode(opts, "DialoguePortion", "TCAPMessages")
	defer func() {
		returnErr = finishProfile(encoded, returnErr)
		if returnErr != nil {
			encoded = nil
		}
	}()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("%w: nil dialogue portion", ber.ErrInvalidValue)
	}
	if value.kind == UnresolvedIdentification {
		if err := ber.CheckEncodedValue(ber.EncodeSource(opts, "TCAPMessages.DialoguePortion"), "identification", "Q.773 (06/1997) 4.2.3 / X.690 (02/2021) 8.18.4: direct-only abstract syntax identification", "presentation-context-dependent EXTERNAL"); err != nil {
			return nil, err
		}
	}
	var err error
	opts, err = ber.PrepareBERReplay(value.dialogueReplayNode(), opts, func(mode ber.EncodeOption) ([]byte, error) { return value.MarshalBER(mode) }, value)
	if err != nil {
		return nil, err
	}
	// The private envelope can change only through its typed content accessor,
	// which detaches that content from the received baseline before publishing it.
	if replay, ok := ber.PreparedBERReplay(value.dialogueReplayNode(), opts, value.dialogueUnchanged); ok {
		return replay, nil
	}
	inner, err := value.dialogueInner(false, opts)
	if err != nil {
		return nil, err
	}
	if ber.BERReplayEnabled(opts) && value.originalBER != nil && value.dialogueUnchanged() {
		return ber.PreserveEncodedBERNode(bytes.Clone(value.originalBER), value.dialogueReplayNode(), opts), nil
	}
	if !value.hasTCAPPresenceEdit() && value.berReplayNode_ == nil && ber.BERReplayEnabled(opts) && value.originalBER != nil && bytes.Equal(inner, value.originalInner) {
		return bytes.Clone(value.originalBER), nil
	}
	external, err := value.dialogueExternal(inner)
	if err != nil {
		return nil, err
	}
	if value.kind == Structured || value.kind == Unstructured {
		// The inner value was rebuilt by its owned typed codec above. The generic
		// EXTERNAL encoder's opaque-value refusal does not apply to that value.
		encoded, err = encodeDialogueExternal(external, false)
	} else {
		encoded, err = encodeDialogueExternal(external, false, opts...)
	}
	if err != nil {
		return nil, err
	}
	encoded, err = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 11, encoded)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, value.dialogueReplayNode(), opts), nil
}

// MarshalDER rebuilds recognized APDUs and their selected EXTERNAL encoding.
func (value *DialoguePortion) MarshalDER() ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: nil dialogue portion", ber.ErrInvalidValue)
	}
	if value.kind == UnresolvedIdentification {
		return nil, ber.CheckEncodedValue(ber.EncodeSource(nil, "TCAPMessages.DialoguePortion"), "identification", "Q.773 (06/1997) 4.2.3 / X.690 (02/2021) 8.18.4: direct-only abstract syntax identification", "presentation-context-dependent EXTERNAL")
	}
	inner, err := value.dialogueInner(true, nil)
	if err != nil {
		return nil, err
	}
	external, err := value.dialogueExternal(inner)
	if err != nil {
		return nil, err
	}
	encoded, err := encodeDialogueExternal(external, true)
	if err != nil {
		return nil, err
	}
	return ber.EncodeExplicitTagWithClass(tag.ClassApplication, 11, encoded)
}

// UnmarshalBER commits the receiver and reports only after complete decoding.
func (value *DialoguePortion) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	opts, commit := ber.StageDecodeReports(opts)
	defer func() { commit(returnErr == nil) }()
	if value == nil {
		return fmt.Errorf("%w: nil dialogue portion destination", ber.ErrInvalidValue)
	}
	opts = ber.TrackTCAPForm(opts, "DialoguePortion", "TCAPMessages")
	owned, err := ber.OwnGeneratedBERInput(data, opts)
	if err != nil {
		return err
	}
	data = owned
	prepared, preparedOpts, err := ber.PrepareGeneratedBERInput(data, opts)
	if err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe DialoguePortion
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = prepared, preparedOpts
	opts = ber.LocateDecodedElement(data, "TCAPMessages.DialoguePortion", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	identifier, n, content, err := ber.DecodeTLV(data, opts...)
	if err != nil {
		return err
	}
	if n != len(data) {
		return ber.ErrExtraData
	}
	if identifier.Class != tag.ClassApplication || identifier.Number != 11 || !identifier.Constructed {
		return fmt.Errorf("%w: expected constructed dialogue portion [APPLICATION 11]", ber.ErrInvalidTag)
	}
	external, n, err := ber.DecodeExternal(content, opts...)
	if err != nil {
		return err
	}
	if n != len(content) {
		return ber.ErrExtraData
	}
	result := DialoguePortion{metadata: copyDialogueExternal(external), kind: UnknownSyntax}
	if external.IndirectReference != nil {
		if err = ber.CheckDecodedValue(opts, "identification", "Q.773 (06/1997) 4.2.3 / X.690 (02/2021) 8.18.4: direct-only abstract syntax identification", "presentation-context-dependent EXTERNAL"); err != nil {
			return err
		}
		result.kind = UnresolvedIdentification
	} else if external.DirectReference.Equal(DialogueAsId()) || external.DirectReference.Equal(UniDialogueAsId()) {
		var inner []byte
		switch external.Encoding {
		case rt.ExternalSingleASN1Type:
			inner = external.SingleASN1Type.Bytes
		case rt.ExternalOctetAligned:
			inner = external.OctetAligned
		case rt.ExternalArbitrary:
			if external.Arbitrary.BitLength%8 != 0 {
				return fmt.Errorf("%w: known dialogue BER requires integral octets (X.690 8.18.6)", ber.ErrInvalidValue)
			}
			inner = external.Arbitrary.Bytes
		}
		innerOptions := ber.LocateDialogueContent(data, inner, opts)
		if external.DirectReference.Equal(DialogueAsId()) {
			result.kind = Structured
			result.dialogue = new(DialoguePDU)
			if err = result.dialogue.UnmarshalBER(inner, ber.ChildDecodeOptions(innerOptions, "dialogue")...); err != nil {
				return err
			}
		} else {
			result.kind = Unstructured
			result.unidialogue = new(UniDialoguePDU)
			if err = result.unidialogue.UnmarshalBER(inner, ber.ChildDecodeOptions(innerOptions, "unidialogue")...); err != nil {
				return err
			}
		}
		if ber.ReplayCaptureEnabled(opts) {
			result.originalInner = bytes.Clone(inner)
			result.originalDialogue = result.dialogue
			result.originalUniDialogue = result.unidialogue
		}
		// The typed APDU is authoritative; metadata retains no competing raw copy.
		result.metadata.SingleASN1Type = rt.RawValue{}
		result.metadata.OctetAligned = nil
		result.metadata.Arbitrary = rt.BitString{}
	}
	if ber.ReplayCaptureEnabled(opts) {
		result.originalBER = bytes.Clone(data)
	}
	if ber.BERNeedsPreservation(opts) {
		result.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		if err = ber.CompleteGeneratedBERDecode(opts, &result, func(current *DialoguePortion, encodeOpts ...ber.EncodeOption) ([]byte, error) {
			return current.MarshalBER(encodeOpts...)
		}, compareTCAPDialoguePortion); err != nil {
			return err
		}
	}
	*value = result
	return nil
}
func compareTCAPDialogueContentKind(a, b *DialogueContentKind, nodes *ber.BERReplayComparisons) int {
	if a == nil || b == nil {
		if a == b {
			return 1
		}
		return 0
	}
	if a == b {
		return 0
	}
	result := compareTCAPDialogueContentKindValue(a, b, nodes, 1, true, false)
	if result == 0 && nodes != nil {
		nodes.ProveEqual(compareTCAPDialogueContentKindValue(a, b, nil, 1, true, true) == 1)
	}
	return result
}
func compareTCAPDialogueContentKindValue(a, b *DialogueContentKind, nodes *ber.BERReplayComparisons, depth int, accessible, source bool) int {
	if depth > 1024 {
		return 0
	}
	return tcapReplayVerdict((*a) == (*b))
}
func compareTCAPDialoguePortion(a, b *DialoguePortion, nodes *ber.BERReplayComparisons) int {
	if a == nil || b == nil {
		if a == b {
			return 1
		}
		return 0
	}
	if a == b {
		return 0
	}
	result := compareTCAPDialoguePortionValue(a, b, nodes, 1, true, false)
	if result == 0 && nodes != nil {
		nodes.ProveEqual(compareTCAPDialoguePortionValue(a, b, nil, 1, true, true) == 1)
	}
	return result
}
func compareTCAPDialoguePortionValue(a, b *DialoguePortion, nodes *ber.BERReplayComparisons, depth int, accessible, source bool) int {
	if depth > 1024 {
		return 0
	}
	result := 1
	{
		part := ber.CompareBERReplayPrimitive((*rt.External)(&a.metadata), (*rt.External)(&b.metadata), source)
		if part == 2 {
			if result != 2 {
				result = 0
			}
		} else if part == 0 && result != 2 {
			result = 0
		}
	}
	{
		part := compareTCAPDialogueContentKindValue(&a.kind, &b.kind, nodes, depth+1, source, source)
		if part == 2 {
			if result != 2 {
				result = 0
			}
		} else if part == 0 && result != 2 {
			result = 0
		}
	}
	{
		part := func() int {
			if depth+1 > 1024 {
				return 0
			}
			if a.dialogue == nil || b.dialogue == nil {
				if a.dialogue == b.dialogue {
					return 1
				}
				return 0
			}
			return func() int {
				if a.dialogue == b.dialogue {
					if source {
						return 1
					}
					return 0
				}
				return compareTCAPDialoguePDUValue(a.dialogue, b.dialogue, nodes, (depth+1)+1, source, source)
			}()
		}()
		if part == 2 {
			if result != 2 {
				result = 0
			}
		} else if part == 0 && result != 2 {
			result = 0
		}
	}
	{
		part := func() int {
			if depth+1 > 1024 {
				return 0
			}
			if a.unidialogue == nil || b.unidialogue == nil {
				if a.unidialogue == b.unidialogue {
					return 1
				}
				return 0
			}
			return func() int {
				if a.unidialogue == b.unidialogue {
					if source {
						return 1
					}
					return 0
				}
				return compareTCAPUniDialoguePDUValue(a.unidialogue, b.unidialogue, nodes, (depth+1)+1, source, source)
			}()
		}()
		if part == 2 {
			if result != 2 {
				result = 0
			}
		} else if part == 0 && result != 2 {
			result = 0
		}
	}
	{
		part := func() int {
			if depth+1 > 1024 {
				return 0
			}
			if a.originalDialogue == nil || b.originalDialogue == nil {
				if a.originalDialogue == b.originalDialogue {
					return 1
				}
				return 0
			}
			return func() int {
				if a.originalDialogue == b.originalDialogue {
					if source {
						return 1
					}
					return 0
				}
				return compareTCAPDialoguePDUValue(a.originalDialogue, b.originalDialogue, nodes, (depth+1)+1, source, source)
			}()
		}()
		if part == 2 {
			if result != 2 {
				result = 0
			}
		} else if part == 0 && result != 2 {
			result = 0
		}
	}
	{
		part := func() int {
			if depth+1 > 1024 {
				return 0
			}
			if a.originalUniDialogue == nil || b.originalUniDialogue == nil {
				if a.originalUniDialogue == b.originalUniDialogue {
					return 1
				}
				return 0
			}
			return func() int {
				if a.originalUniDialogue == b.originalUniDialogue {
					if source {
						return 1
					}
					return 0
				}
				return compareTCAPUniDialoguePDUValue(a.originalUniDialogue, b.originalUniDialogue, nodes, (depth+1)+1, source, source)
			}()
		}()
		if part == 2 {
			if result != 2 {
				result = 0
			}
		} else if part == 0 && result != 2 {
			result = 0
		}
	}
	{
		part := tcapReplayVerdict(equalTCAPReplayBytes(a.originalBER, b.originalBER))
		if part == 2 {
			if result != 2 {
				result = 0
			}
		} else if part == 0 && result != 2 {
			result = 0
		}
	}
	{
		part := tcapReplayVerdict(equalTCAPReplayBytes(a.originalInner, b.originalInner))
		if part == 2 {
			if result != 2 {
				result = 0
			}
		} else if part == 0 && result != 2 {
			result = 0
		}
	}
	{
		part := tcapReplayVerdict(a.editable == b.editable)
		if part == 2 {
			if result != 2 {
				result = 0
			}
		} else if part == 0 && result != 2 {
			result = 0
		}
	}
	{
		part := func() int {
			if depth+1 > 1024 {
				return 0
			}
			if a.berReplayNode_ == b.berReplayNode_ {
				return 1
			}
			return 0
		}()
		if part == 2 {
			if result != 2 {
				result = 0
			}
		} else if part == 0 && result != 2 {
			result = 0
		}
	}
	nodes.Record(a.berReplayNode_, b.berReplayNode_, result, func() bool { return compareTCAPDialoguePortionValue(a, b, nil, depth, true, true) == 1 })
	return result
}
