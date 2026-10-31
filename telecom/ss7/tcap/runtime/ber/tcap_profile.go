// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_profile.go; SHA-256 2fc917d0d73085e13f7d0c4c6f63bebc22b7d6f5738a300fe9655a92aec17060.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"math"
)

// Resolve the public root name once per scan. An unclassified non-empty
// root remains distinct from the empty kind used for universal-tag fallback.
type tcapKind uint8

const (
	tcapKindUnknown tcapKind = iota
	tcapKindUnclassified
	tcapKindAAREApdu
	tcapKindAARQApdu
	tcapKindABRTApdu
	tcapKindAUDTApdu
	tcapKindAbort
	tcapKindAbortReason
	tcapKindAssociateSourceDiagnostic
	tcapKindBegin
	tcapKindBind
	tcapKindBitString
	tcapKindComponent
	tcapKindComponentPortion
	tcapKindContinue
	tcapKindDestTransactionID
	tcapKindDialogueContent
	tcapKindDialogueExternal
	tcapKindDialoguePDU
	tcapKindDialoguePortion
	tcapKindEnd
	tcapKindExplicitDiagnostic
	tcapKindExplicitValue
	tcapKindExplicitOpenValue
	tcapKindExternal
	tcapKindExternalEncoding
	tcapKindInteger
	tcapKindInvoke
	tcapKindInvokeLinkedId
	tcapKindNull
	tcapKindOctetString
	tcapKindOpenValue
	tcapKindOrigTransactionID
	tcapKindPAbortCause
	tcapKindRLREApdu
	tcapKindRLRQApdu
	tcapKindROS
	tcapKindROSConsumerAS
	tcapKindROSSingleAS
	tcapKindROSSupplierAS
	tcapKindReject
	tcapKindRejectProblemChoice
	tcapKindReturnError
	tcapKindReturnResult
	tcapKindReturnResultResult
	tcapKindTCMessage
	tcapKindUnbind
	tcapKindUniDialogueContent
	tcapKindUniDialoguePDU
	tcapKindUnidirectional
	tcapKindUserInformation
)

func tcapRootKind(name string) tcapKind {
	switch name {
	case "":
		return tcapKindUnknown
	case "AAREApdu":
		return tcapKindAAREApdu
	case "AARQApdu":
		return tcapKindAARQApdu
	case "ABRTApdu":
		return tcapKindABRTApdu
	case "AUDTApdu":
		return tcapKindAUDTApdu
	case "Abort":
		return tcapKindAbort
	case "AbortReason":
		return tcapKindAbortReason
	case "AssociateSourceDiagnostic":
		return tcapKindAssociateSourceDiagnostic
	case "Begin":
		return tcapKindBegin
	case "Bind":
		return tcapKindBind
	case "BitString":
		return tcapKindBitString
	case "Component":
		return tcapKindComponent
	case "ComponentPortion":
		return tcapKindComponentPortion
	case "Continue":
		return tcapKindContinue
	case "DestTransactionID":
		return tcapKindDestTransactionID
	case "DialogueContent":
		return tcapKindDialogueContent
	case "DialogueExternal":
		return tcapKindDialogueExternal
	case "DialoguePDU":
		return tcapKindDialoguePDU
	case "DialoguePortion":
		return tcapKindDialoguePortion
	case "End":
		return tcapKindEnd
	case "ExplicitDiagnostic":
		return tcapKindExplicitDiagnostic
	case "ExplicitValue":
		return tcapKindExplicitValue
	case "External":
		return tcapKindExternal
	case "ExternalEncoding":
		return tcapKindExternalEncoding
	case "Integer":
		return tcapKindInteger
	case "Invoke":
		return tcapKindInvoke
	case "InvokeLinkedId":
		return tcapKindInvokeLinkedId
	case "Null":
		return tcapKindNull
	case "OctetString":
		return tcapKindOctetString
	case "OpenValue":
		return tcapKindOpenValue
	case "OrigTransactionID":
		return tcapKindOrigTransactionID
	case "PAbortCause":
		return tcapKindPAbortCause
	case "RLREApdu":
		return tcapKindRLREApdu
	case "RLRQApdu":
		return tcapKindRLRQApdu
	case "ROS":
		return tcapKindROS
	case "ROSConsumerAS":
		return tcapKindROSConsumerAS
	case "ROSSingleAS":
		return tcapKindROSSingleAS
	case "ROSSupplierAS":
		return tcapKindROSSupplierAS
	case "Reject":
		return tcapKindReject
	case "RejectProblemChoice":
		return tcapKindRejectProblemChoice
	case "ReturnError":
		return tcapKindReturnError
	case "ReturnResult":
		return tcapKindReturnResult
	case "ReturnResultResult":
		return tcapKindReturnResultResult
	case "TCMessage":
		return tcapKindTCMessage
	case "Unbind":
		return tcapKindUnbind
	case "UniDialogueContent":
		return tcapKindUniDialogueContent
	case "UniDialoguePDU":
		return tcapKindUniDialoguePDU
	case "Unidirectional":
		return tcapKindUnidirectional
	case "UserInformation":
		return tcapKindUserInformation
	}
	return tcapKindUnclassified
}

type tcapProfileOption struct {
	source, ruleSource string
	nested             bool
}

func (option tcapProfileOption) applyDecode(c *decodeConfig) error {
	c.profile = true
	c.profileNested = option.nested
	c.profileType = option.source
	c.profileSource = option.ruleSource
	return nil
}

// TrackTCAPForm applies Q.773 (06/1997) §4.1.1 to TCAP-owned syntax;
// X.690 (02/2021) §8.15 open-type values remain foreign.
// Without a source, or with an empty first source string, it scans a whole
// TCMessage (Q.773 Annex A), or preserves an already active profile's root.
//
// For a subtree, source takes the generated Go root type name, optionally
// followed by its ASN.1 module and assignment names. Use the names passed by
// that type's generated UnmarshalBER method, for example "Invoke",
// "Remote-Operations-Generic-ROS-PDUs", "Invoke". The root type selects schema
// ownership, including IMPLICIT strings and open-type boundaries; the module
// and assignment only label reports. Assignment defaults to the root type.
// Unknown type names provide no schema ownership information.
//
// ValidateBERElement with these options checks BER and the encoding profile;
// generated decoders additionally check schema constraints and text rules.
// Generic BER helpers remain usable independently of this protocol profile.
// The returned options can be reused for validation and generated decodes and
// are safe to share between goroutines; each operation keeps its own form state.
func TrackTCAPForm(options []DecodeOption, source ...string) []DecodeOption {
	name := ""
	if len(source) > 0 {
		name = source[0]
	}
	c, err := decodeOptions(options)
	if !c.profile && name == "" {
		name = "TCMessage"
		if len(source) <= 1 {
			source = []string{"TCMessage", "TCAPMessages", "TCMessage"}
		} else {
			source = append([]string(nil), source...)
			source[0] = name
		}
	}
	if err == nil && (!c.profile || name != "" && name != c.profileType) {
		// The outer profile pass owns every nested finding. Its source is
		// already resolved; a nested pass cannot publish a profile report.
		ruleSource := c.profileSource
		if !c.profile {
			ruleSource = sourceAssignment(source)
			if module := profileModule(source); module != "" {
				ruleSource = module + "." + ruleSource
			}
		}
		if len(options) == 1 {
			if context, ok := options[0].(*generatedDecodeOption); ok && context != nil {
				storage := new(generatedDecodeContextStorage)
				storage.context = *context
				storage.context.config.profile = true
				storage.context.config.profileNested = c.profile
				storage.context.config.profileType = name
				storage.context.config.profileSource = ruleSource
				storage.options[0] = &storage.context
				return storage.options[:]
			}
		}
		options = append(options[:len(options):len(options)], tcapProfileOption{source: name, ruleSource: ruleSource, nested: c.profile})
		c.profile, c.profileNested, c.profileType, c.profileSource = true, c.profile, name, ruleSource
	}
	return trackBERForm(options, &c, err)
}

func tcapProfileViolation(data []byte, pos, tagLen, lenLen int, indefinite bool, t tag.Tag, kind tcapKind) bool {
	return !indefinite && lenLen > 1 && (data[pos+tagLen+1] == 0 || lenLen == 2 && data[pos+tagLen+1] < 128) || t.Constructed && (kind == tcapKindOctetString || kind == tcapKindBitString || t.Class == tag.ClassUniversal && (t.Number == tag.TagOctetString || t.Number == tag.TagBitString))
}

// Q.773 (06/1997) §4.1.1 applies to the TC message and the dialogue
// abstract syntaxes in §§3.2 and 4.2.3. An X.690 (02/2021) §8.15 open type
// begins with its own identifier, so even that header belongs to the
// TC-user's syntax. X.690 §8.18.6–8.18.11 keeps EXTERNAL's encoding-choice
// header in the containing syntax; only its value belongs to the identified
// syntax. Q.773 dialogue is owned (§4.2.3); X.880 (07/1994) Annex A linkedId [0]/[1] puts opcode at index 2.
func tcapProfileOwnsChild(parent tcapKind, index int, linked bool) bool {
	switch parent {
	case tcapKindOpenValue, tcapKindExplicitOpenValue:
		return false
	case tcapKindInvoke:
		return index < 2 || linked && index == 2
	case tcapKindReturnResultResult:
		return index == 0
	case tcapKindReturnError:
		return index < 2
	}
	return true
}

func checkTCAPProfileElement(data []byte, pos, tagLen, lenLen int, indefinite bool, t tag.Tag, indexes []int, config decodeConfig, options []DecodeOption, kind tcapKind, path string) error {
	if !config.profile || config.profileNested {
		return nil
	}
	report := func(rule, observation string) error {
		offset := pos
		if config.location != nil {
			if absolute, ok := config.location.wireOffset(data[pos:]); ok {
				offset = absolute
				var err error
				indexes, err = config.location.decodeOrigin().ancestry(absolute)
				if err != nil {
					return err
				}
			}
		}

		reportedPath := path
		if config.location != nil && config.location.segments() != nil {
			prefix := config.location.segments().path
			if prefix != "" {
				reportedPath = prefix
				if path != "" {
					reportedPath += "." + path
				}
			}
		}
		v := identifyViolation(Violation{Kind: ProtocolRule, Path: reportedPath, Constraint: "Q.773 §4.1.1: " + rule, Source: profileRuleSource(config.profileSource, reportedPath), ObservedValue: observation, Offset: new(offset), ChildIndexes: append([]int(nil), indexes...), preflight: false, scope: config.reportScope})
		if !config.tolerant {
			return &ValidationError{boundedViolation(v)}
		}
		if config.profileEncode {
			// Encode reports describe abstract values. Keep child positions
			// privately for idempotence: DialoguePortion and its EXTERNAL
			// child share a path, and byte lengths can move either header.
			// No output offset is a received-wire coordinate.
			v.encodeRecord = true
		}
		return config.violations.append(v, config.diagnostics)
	}
	if !indefinite && lenLen > 1 {
		if lenLen == 2 && data[pos+tagLen+1] < 128 {
			if err := report("short-length", "definite length below 128 uses long form"); err != nil {
				return err
			}
		} else if data[pos+tagLen+1] == 0 {
			if err := report("minimum-length-octets", "long length has a leading zero octet"); err != nil {
				return err
			}
		}
	}
	if t.Constructed {
		if kind == tcapKindOctetString || t.Class == tag.ClassUniversal && t.Number == tag.TagOctetString {
			return report("primitive-octet-string", "constructed OCTET STRING")
		}
		if kind == tcapKindBitString || t.Class == tag.ClassUniversal && t.Number == tag.TagBitString {
			return report("primitive-bit-string", "constructed BIT STRING")
		}
	}
	return nil
}

// The IMPLICIT string-form check covers TCAP-owned fields; nested foreign
// content has its own encoding rules (Q.773 (06/1997) §4.1.1; X.690
// (02/2021) §§8.15, 8.18.10–8.18.11).
func checkTCAPStringForm(constructed bool, kind int, options []DecodeOption) error {
	config, err := decodeOptions(options)
	if err != nil {
		return err
	}
	if !config.profile || config.profileNested || !constructed {
		return nil
	}
	rule := "primitive-octet-string"
	if kind == tag.TagBitString {
		rule = "primitive-bit-string"
	}
	field := ""
	if config.location != nil {
		field = config.location.field
	}
	return CheckDecodedValue(options, field, "Q.773 §4.1.1: "+rule, "constructed string")
}

type tcapEncodeOption struct{}

func (tcapEncodeOption) applyEncode(c *encodeConfig) error { c.tcapEncoding = true; return nil }

// StageTCAPEncode checks the final public encoding before staged reports commit.
// Nested codecs share this boundary, so a replay produces one profile report.
func StageTCAPEncode(options []EncodeOption, source ...string) ([]EncodeOption, func([]byte, error) error) {
	name := ""
	if len(source) > 0 {
		name = source[0]
	}
	config, err := encodeOptions(options)
	finish := func(_ []byte, err error) error { return err }
	// The strict pre-replay walk checks current values and text rules only.
	// Its canonical bytes have no received locations. Q.773 (06/1997)
	// §4.1.1 is checked by the final public pass, after replay selection.
	for _, option := range options {
		if mode, ok := option.(replayModeOption); ok && (mode.comparison || mode.baseline || mode.fast != nil) {
			return options, finish
		}
	}
	if err != nil || config.tcapEncoding {
		return options, finish
	}
	options = append(options[:len(options):len(options)], tcapEncodeOption{})
	profile := tcapEncodedProfileOption{kind: name, source: sourceAssignment(source), tolerant: config.tolerant, violations: config.violations, scope: config.reportScope}
	if module := profileModule(source); module != "" {
		profile.source = module + "." + sourceAssignment(source)
	}
	return options, func(data []byte, prior error) error {
		if prior != nil {
			return prior
		}
		return ValidateBERElement(data, encodingStructureOption(data), profile)
	}
}

type tcapEncodedProfileOption struct {
	kind, source string
	tolerant     bool
	violations   *ViolationLog
	scope        *reportScope
}

func (option tcapEncodedProfileOption) applyDecode(config *decodeConfig) error {
	config.profile, config.profileEncode = true, true
	// Encoding validates already-owned bytes. A segmented dialogue is visited
	// once as wire segments and once as its identified APDU (X.690 §§8.6.4,
	// 8.7.3, 8.18.10–8.18.11). Decode callers retain their explicit budget.
	if config.limits.MaxWork <= math.MaxInt/2 {
		config.limits.MaxWork *= 2
	}
	config.profileType, config.profileSource = option.kind, option.source
	config.tolerant, config.violations, config.reportScope = option.tolerant, option.violations, option.scope
	return nil
}

// The schema boundary is confined to TCAP-owned fields. An unknown IMPLICIT
// payload never receives a guessed underlying type. X.680 (02/2021) §31.2.7
// and X.690 (02/2021) §8.14.4 retain the base form and contents rules
// under IMPLICIT tags; TCAPMessages, Remote-Operations-Generic-ROS-PDUs,
// and DialoguePDUs identify the assignments below.
// The generated root decoder checks its own outer tag before inspecting
// fields. An unrelated tag cannot acquire the requested root's schema.
// X.680 (02/2021) §31; X.690 (02/2021) §§8.14.3–8.14.4.
func tcapRootAdmits(root tcapKind, t tag.Tag) bool {
	class, number := tag.ClassUniversal, tag.TagSequence
	switch root {
	case tcapKindBegin, tcapKindContinue, tcapKindEnd, tcapKindUnidirectional, tcapKindAbort, tcapKindInvoke,
		tcapKindReturnResult, tcapKindReturnResultResult, tcapKindReturnError, tcapKindReject, tcapKindUserInformation:
	case tcapKindOrigTransactionID:
		class, number = tag.ClassApplication, 8
	case tcapKindDestTransactionID:
		class, number = tag.ClassApplication, 9
	case tcapKindPAbortCause:
		class, number = tag.ClassApplication, 10
	case tcapKindDialoguePortion:
		class, number = tag.ClassApplication, 11
	case tcapKindComponentPortion:
		class, number = tag.ClassApplication, 12
	case tcapKindAARQApdu, tcapKindAUDTApdu:
		class, number = tag.ClassApplication, 0
	case tcapKindAAREApdu:
		class, number = tag.ClassApplication, 1
	case tcapKindRLRQApdu:
		class, number = tag.ClassApplication, 2
	case tcapKindRLREApdu:
		class, number = tag.ClassApplication, 3
	case tcapKindABRTApdu:
		class, number = tag.ClassApplication, 4
	case tcapKindExternal:
		number = tag.TagExternal
	default:
		return true // CHOICE roots classify their alternatives below.
	}
	return t.Class == class && t.Number == number
}

func tcapElementType(root, parent tcapKind, t tag.Tag, index int, isRoot bool, syntax int) tcapKind {
	kind := tcapKindUnknown
	if isRoot {
		if tcapRootAdmits(root, t) {
			kind = root
		}
	} else {
		switch parent {
		case tcapKindComponentPortion:
			kind = tcapKindComponent
		case tcapKindUserInformation:
			if t.Class == tag.ClassUniversal && t.Number == tag.TagExternal {
				kind = tcapKindExternal
			}
		case tcapKindDialogueContent:
			if index == 0 {
				kind = tcapKindDialoguePDU
			}
		case tcapKindUniDialogueContent:
			if index == 0 {
				kind = tcapKindUniDialoguePDU
			}
		case tcapKindExplicitDiagnostic:
			if index == 0 {
				kind = tcapKindAssociateSourceDiagnostic
			}
		}
	}
	switch kind {
	case tcapKindOrigTransactionID, tcapKindDestTransactionID:
		kind = tcapKindOctetString
	case tcapKindPAbortCause:
		if t.Class == tag.ClassApplication && t.Number == 10 {
			kind = tcapKindInteger
		}
	case tcapKindInvokeLinkedId:
		kind = tcapKindUnknown
		if t.Class == tag.ClassContextSpecific {
			switch t.Number {
			case 0:
				kind = tcapKindInteger
			case 1:
				kind = tcapKindNull
			}
		}
	// X.690 (02/2021) §8.15: ROS instances share the same open-value
	// boundaries and IMPLICIT base types as their instantiated ROS syntax.
	case tcapKindComponent, tcapKindROS, tcapKindROSSingleAS, tcapKindROSConsumerAS, tcapKindROSSupplierAS:
		component := kind == tcapKindComponent
		kind = tcapKindUnknown
		if t.Class == tag.ClassContextSpecific {
			switch t.Number {
			case 1:
				kind = tcapKindInvoke
			case 2:
				kind = tcapKindReturnResult
			case 7:
				if component {
					kind = tcapKindReturnResult
				}
			case 3:
				kind = tcapKindReturnError
			case 4:
				kind = tcapKindReject
			}
		}
	case tcapKindRejectProblemChoice:
		kind = tcapKindUnknown
		if t.Class == tag.ClassContextSpecific && t.Number <= 3 {
			kind = tcapKindInteger
		}
	case tcapKindAbortReason:
		kind = tcapKindUnknown
		if t.Class == tag.ClassApplication && t.Number == 10 {
			kind = tcapKindInteger
		}
		if t.Class == tag.ClassApplication && t.Number == 11 {
			kind = tcapKindDialoguePortion
		}
	case tcapKindTCMessage:
		kind = tcapKindUnknown
		if t.Class == tag.ClassApplication {
			switch t.Number {
			case 1:
				kind = tcapKindUnidirectional
			case 2:
				kind = tcapKindBegin
			case 4:
				kind = tcapKindEnd
			case 5:
				kind = tcapKindContinue
			case 7:
				kind = tcapKindAbort
			}
		}
	case tcapKindDialoguePDU:
		kind = tcapKindUnknown
		if t.Class == tag.ClassApplication {
			switch t.Number {
			case 0:
				kind = tcapKindAARQApdu
			case 1:
				kind = tcapKindAAREApdu
			case 4:
				kind = tcapKindABRTApdu
			}
		}
	case tcapKindUniDialoguePDU:
		kind = tcapKindUnknown
		if t.Class == tag.ClassApplication && t.Number == 0 {
			kind = tcapKindAUDTApdu
		}
	case tcapKindBind, tcapKindUnbind:
		parentKind := kind
		kind = tcapKindUnknown
		if t.Class == tag.ClassContextSpecific &&
			(parentKind == tcapKindBind && t.Number >= 16 && t.Number <= 18 ||
				parentKind == tcapKindUnbind && t.Number >= 19 && t.Number <= 21) {
			// X.680 (02/2021) §31.2.7(c); X.690 (02/2021) §8.14.3.
			kind = tcapKindExplicitOpenValue
		}
	case tcapKindAssociateSourceDiagnostic:
		kind = tcapKindUnknown
		if t.Class == tag.ClassContextSpecific && (t.Number == 1 || t.Number == 2) {
			kind = tcapKindExplicitValue
		}
	}
	if kind == tcapKindUnknown && t.Class == tag.ClassUniversal {
		switch t.Number {
		case 8:
			kind = tcapKindExternal
		case 3:
			kind = tcapKindBitString
		case 4:
			kind = tcapKindOctetString
		}
	}
	return kind
}

// The next field is a grammar position, independent of the physical child
// index: OPTIONAL and DEFAULT components may be absent. X.680 (02/2021)
// §§25, 31 and X.690 (02/2021) §§8.14.3–8.14.4 do not assign a base
// type to a tag outside the sequence's admitted position.
type tcapProfileField struct {
	class    tag.Class
	number   int
	kind     tcapKind
	optional bool
	next     int
}

func tcapSequenceElementType(parent tcapKind, t tag.Tag, field, syntax int) (tcapKind, int, bool) {
	var fields []tcapProfileField
	switch parent {
	case tcapKindBegin:
		fields = []tcapProfileField{{tag.ClassApplication, 8, tcapKindOctetString, false, 1}, {tag.ClassApplication, 11, tcapKindDialoguePortion, true, 2}, {tag.ClassApplication, 12, tcapKindComponentPortion, true, 3}}
	case tcapKindEnd:
		fields = []tcapProfileField{{tag.ClassApplication, 9, tcapKindOctetString, false, 1}, {tag.ClassApplication, 11, tcapKindDialoguePortion, true, 2}, {tag.ClassApplication, 12, tcapKindComponentPortion, true, 3}}
	case tcapKindContinue:
		fields = []tcapProfileField{{tag.ClassApplication, 8, tcapKindOctetString, false, 1}, {tag.ClassApplication, 9, tcapKindOctetString, false, 2}, {tag.ClassApplication, 11, tcapKindDialoguePortion, true, 3}, {tag.ClassApplication, 12, tcapKindComponentPortion, true, 4}}
	case tcapKindUnidirectional:
		fields = []tcapProfileField{{tag.ClassApplication, 11, tcapKindDialoguePortion, true, 1}, {tag.ClassApplication, 12, tcapKindComponentPortion, false, 2}}
	case tcapKindAbort:
		fields = []tcapProfileField{{tag.ClassApplication, 9, tcapKindOctetString, false, 1}, {tag.ClassApplication, -5, tcapKindAbortReason, true, 2}}
	case tcapKindInvoke:
		fields = []tcapProfileField{{tag.ClassUniversal, -3, tcapKindUnknown, false, 1}, {tag.ClassContextSpecific, -4, tcapKindInvokeLinkedId, true, 2}, {tag.ClassUniversal, -2, tcapKindUnknown, false, 3}, {0, -1, tcapKindUnknown, true, 4}}
	case tcapKindReturnResult:
		fields = []tcapProfileField{{tag.ClassUniversal, -3, tcapKindUnknown, false, 1}, {tag.ClassUniversal, tag.TagSequence, tcapKindReturnResultResult, true, 2}}
	case tcapKindReturnResultResult:
		fields = []tcapProfileField{{tag.ClassUniversal, -2, tcapKindUnknown, false, 1}, {0, -1, tcapKindUnknown, false, 2}}
	case tcapKindReturnError:
		fields = []tcapProfileField{{tag.ClassUniversal, -3, tcapKindUnknown, false, 1}, {tag.ClassUniversal, -2, tcapKindUnknown, false, 2}, {0, -1, tcapKindUnknown, true, 3}}
	case tcapKindReject:
		fields = []tcapProfileField{{tag.ClassUniversal, -3, tcapKindUnknown, false, 1}, {tag.ClassContextSpecific, -7, tcapKindInteger, false, 2}}
	case tcapKindDialoguePortion:
		fields = []tcapProfileField{{tag.ClassUniversal, tag.TagExternal, tcapKindDialogueExternal, false, 1}}
	case tcapKindExternal, tcapKindDialogueExternal:
		fields = []tcapProfileField{{tag.ClassUniversal, tag.TagObjectID, tcapKindUnknown, true, 1}, {tag.ClassUniversal, tag.TagInteger, tcapKindUnknown, true, 2}, {tag.ClassUniversal, 7, tcapKindUnknown, true, 3}, {tag.ClassContextSpecific, -6, tcapKindExternalEncoding, false, 4}}
	case tcapKindAARQApdu, tcapKindAUDTApdu:
		fields = []tcapProfileField{{tag.ClassContextSpecific, 0, tcapKindBitString, true, 1}, {tag.ClassContextSpecific, 1, tcapKindExplicitValue, false, 2}, {tag.ClassContextSpecific, 30, tcapKindUserInformation, true, 3}}
	case tcapKindAAREApdu:
		fields = []tcapProfileField{{tag.ClassContextSpecific, 0, tcapKindBitString, true, 1}, {tag.ClassContextSpecific, 1, tcapKindExplicitValue, false, 2}, {tag.ClassContextSpecific, 2, tcapKindExplicitValue, false, 3}, {tag.ClassContextSpecific, 3, tcapKindExplicitDiagnostic, false, 4}, {tag.ClassContextSpecific, 30, tcapKindUserInformation, true, 5}}
	case tcapKindABRTApdu:
		fields = []tcapProfileField{{tag.ClassContextSpecific, 0, tcapKindInteger, false, 1}, {tag.ClassContextSpecific, 30, tcapKindUserInformation, true, 2}}
	case tcapKindRLRQApdu, tcapKindRLREApdu:
		fields = []tcapProfileField{{tag.ClassContextSpecific, 0, tcapKindInteger, true, 1}, {tag.ClassContextSpecific, 30, tcapKindUserInformation, true, 2}}
	default:
		return tcapKindUnknown, field, false
	}
	if field < 0 {
		return tcapKindUnknown, field, true
	}
	for i, candidate := range fields {
		if i < field {
			continue
		}
		matches := t.Class == candidate.class && t.Number == candidate.number
		if candidate.number < 0 {
			matches = t.Class == candidate.class
			switch candidate.number {
			case -1:
				matches = true // A complete open value supplies its own tag.
			case -2:
				matches = matches && (t.Number == tag.TagInteger || t.Number == tag.TagObjectID)
			case -3:
				matches = matches && (t.Number == tag.TagInteger || t.Number == tag.TagNull)
			case -4:
				matches = matches && (t.Number == 0 || t.Number == 1)
			case -5:
				matches = matches && (t.Number == 10 || t.Number == 11)
			case -6:
				matches = matches && t.Number <= 2
			case -7:
				matches = matches && t.Number <= 3
			}
		}
		if matches {
			kind := candidate.kind
			switch kind {
			case tcapKindInvokeLinkedId:
				if t.Number == 0 {
					kind = tcapKindInteger
				} else {
					kind = tcapKindNull
				}
			case tcapKindAbortReason:
				if t.Number == 10 {
					kind = tcapKindInteger
				} else {
					kind = tcapKindDialoguePortion
				}
			case tcapKindExternalEncoding:
				switch t.Number {
				case 0:
					kind = tcapKindExplicitValue
					if parent == tcapKindDialogueExternal {
						if syntax == 1 {
							kind = tcapKindDialogueContent
						}
						if syntax == 2 {
							kind = tcapKindUniDialogueContent
						}
					}
				case 1:
					kind = tcapKindOctetString
				case 2:
					kind = tcapKindBitString
				}
			}
			return kind, candidate.next, true
		}
		if !candidate.optional {
			break
		}
	}
	// Once a required position mismatches, subsequent tags have no schema
	// interpretation. The typed decoder diagnoses the unexpected element.
	return tcapKindUnknown, -1, true
}

// X.690 (02/2021) §8.14.3: an EXPLICIT wrapper is constructed. Generated
// decoders retain their own first error and schema Path; the independent
// validation scan checks these positions even behind value constraints.
func tcapExplicitType(kind tcapKind) bool {
	switch kind {
	case tcapKindDialoguePortion, tcapKindDialogueContent, tcapKindUniDialogueContent, tcapKindExplicitValue, tcapKindExplicitDiagnostic, tcapKindExplicitOpenValue:
		return true
	}
	return false
}

func tcapPathSegment(root string, parent, kind tcapKind, t tag.Tag, index int, isRoot bool) string {
	if isRoot {
		if root == "TCMessage" {
			switch kind {
			case tcapKindBegin:
				return "begin"
			case tcapKindEnd:
				return "end"
			case tcapKindContinue:
				return "continue"
			case tcapKindAbort:
				return "abort"
			case tcapKindUnidirectional:
				return "unidirectional"
			}
		}
		return ""
	}
	switch parent {
	case tcapKindBegin, tcapKindContinue, tcapKindEnd, tcapKindUnidirectional, tcapKindAbort:
		if t.Class == tag.ClassApplication {
			switch t.Number {
			case 8:
				return "otid"
			case 9:
				return "dtid"
			case 11:
				if parent == tcapKindAbort {
					return "reason.uAbortCause"
				}
				return "dialoguePortion"
			case 12:
				return "components"
			case 10:
				return "reason.pAbortCause"
			}
		}
	case tcapKindComponentPortion:
		branch := ""
		switch t.Number {
		case 1:
			branch = "basicROS.invoke"
		case 2:
			branch = "basicROS.returnResult"
		case 3:
			branch = "basicROS.returnError"
		case 4:
			branch = "basicROS.reject"
		case 7:
			branch = "returnResultNotLast"
		}
		if branch == "" {
			return fmt.Sprintf("element[%d]", index)
		}
		return fmt.Sprintf("element[%d].%s", index, branch)
	case tcapKindInvoke, tcapKindReturnError, tcapKindReturnResult, tcapKindReject:
		if index == 0 {
			if t.Number == 5 {
				return "invokeId.absent"
			}
			return "invokeId.present"
		}
		if parent == tcapKindInvoke {
			// X.880 (07/1994) Annex A: linkedId CHOICE has both
			// present [0] and absent [1] alternatives.
			if t.Class == tag.ClassContextSpecific {
				switch t.Number {
				case 0:
					return "linkedId.present"
				case 1:
					return "linkedId.absent"
				}
			}
			if t.Class == tag.ClassUniversal && t.Number == 2 {
				return "opcode.local"
			}
			if t.Class == tag.ClassUniversal && t.Number == 6 {
				return "opcode.global"
			}
			return "argument"
		}
		if parent == tcapKindReturnResult {
			return "result"
		}
		if parent == tcapKindReturnError {
			if index == 1 {
				return "errcode"
			}
			return "parameter"
		}
		return "problem"
	case tcapKindReturnResultResult:
		if index == 0 {
			return "opcode"
		}
		return "result"
	case tcapKindDialoguePortion:
		return ""
	case tcapKindDialogueExternal, tcapKindExternal:
		if kind == tcapKindDialogueContent || kind == tcapKindUniDialogueContent {
			return ""
		}
		if t.Class == tag.ClassUniversal {
			switch t.Number {
			case 6:
				return "direct-reference"
			case 2:
				return "indirect-reference"
			case 7:
				return "data-value-descriptor"
			}
		}
		if t.Class == tag.ClassContextSpecific {
			switch t.Number {
			case 0:
				return "encoding.single-ASN1-type"
			case 1:
				return "encoding.octet-aligned"
			case 2:
				return "encoding.arbitrary"
			}
		}
	case tcapKindDialogueContent:
		switch kind {
		case tcapKindAARQApdu:
			return "dialogue.dialogueRequest"
		case tcapKindAAREApdu:
			return "dialogue.dialogueResponse"
		case tcapKindABRTApdu:
			return "dialogue.dialogueAbort"
		}
	case tcapKindUniDialogueContent:
		return "unidialogue.unidialoguePDU"
	case tcapKindAARQApdu, tcapKindAAREApdu, tcapKindAUDTApdu:
		if t.Class == tag.ClassContextSpecific {
			switch t.Number {
			case 0:
				return "protocol-version"
			case 1:
				return "application-context-name"
			case 2:
				return "result"
			case 3:
				return "result-source-diagnostic"
			case 30:
				return "user-information"
			}
		}
	case tcapKindUserInformation:
		return fmt.Sprintf("element[%d]", index)
	}
	return fmt.Sprintf("child[%d]", index)
}

func profileModule(source []string) string {
	if len(source) > 1 {
		return source[1]
	}
	return ""
}

func tcapSegmentTag(t tag.Tag, kind tcapKind) int {
	if kind == tcapKindOctetString {
		return tag.TagOctetString
	}
	if kind == tcapKindBitString {
		return tag.TagBitString
	}
	return berSegmentTag(t)
}

func profileRuleSource(source, path string) string {
	if source == "" {
		return path
	}
	return source + "." + path
}

func sourceAssignment(source []string) string {
	if len(source) > 2 {
		return source[2]
	}
	if len(source) > 0 {
		return source[0]
	}
	return ""
}

// Resolve ownership only for a profile violation. Q.773 (06/1997) §4.1.1
// governs TCAP's syntax; X.690 (02/2021) §§8.15, 8.18.6–8.18.11 leave
// open-type data foreign while retaining EXTERNAL choice and segment headers.
func tcapProfileOwnsElement(data []byte, stack []berScanFrame, parent berScanFrame) bool {
	if !tcapProfileOwnsChildAt(data, parent, parent.nextChild) {
		return false
	}
	outer := stack[0]
	for _, ancestor := range stack[1:] {
		if !tcapProfileOwnsChildAt(data, outer, ancestor.index) {
			return false
		}
		if outer.profileType != tcapKindExternal && outer.profileType != tcapKindDialogueExternal {
			outer = ancestor
			continue
		}
		identifier, _, err := DecodeTag(data[ancestor.offset:])
		if err != nil {
			// The scanner already decoded this ancestor. If its record is
			// inconsistent, keep the profile check rather than waive it.
			return true
		}
		if identifier.Class == tag.ClassContextSpecific &&
			!(identifier.Constructed && (ancestor.profileType == tcapKindOctetString || ancestor.profileType == tcapKindBitString) ||
				outer.profileType == tcapKindDialogueExternal && outer.dialogueSyntax > 0 &&
					(ancestor.profileType == tcapKindDialogueContent || ancestor.profileType == tcapKindUniDialogueContent ||
						ancestor.profileType == tcapKindOctetString || ancestor.profileType == tcapKindBitString)) {
			return false
		}
		outer = ancestor
	}
	return true
}

func tcapProfileOwnsChildAt(data []byte, parent berScanFrame, index int) bool {
	linked := parent.profileType == tcapKindInvoke && index == 2 && tcapProfileInvokeLinked(data, parent.offset)
	return tcapProfileOwnsChild(parent.profileType, index, linked)
}

// X.880 (07/1994) Annex A defines linkedId [0]/[1] between invokeId and
// opcode. The scanner has already accepted both preceding elements; reread
// their headers only when a profile violation needs ownership classification.
func tcapProfileInvokeLinked(data []byte, invokeOffset int) bool {
	invoke := data[invokeOffset:]
	_, tagLen, err := DecodeTag(invoke)
	if err != nil {
		return false
	}
	withoutTag := invoke[tagLen:]
	_, _, lenLen, err := DecodeLength(withoutTag)
	if err != nil {
		return false
	}
	first := withoutTag[lenLen:]
	_, firstTagLen, err := DecodeTag(first)
	if err != nil {
		return false
	}
	withoutFirstTag := first[firstTagLen:]
	firstLength, indefinite, firstLenLen, err := DecodeLength(withoutFirstTag)
	if err != nil || indefinite {
		return false
	}
	firstValue := withoutFirstTag[firstLenLen:]
	if firstLength > len(firstValue) {
		return false
	}
	identifier, _, err := DecodeTag(firstValue[firstLength:])
	return err == nil && identifier.Class == tag.ClassContextSpecific && (identifier.Number == 0 || identifier.Number == 1)
}

// X.680 (02/2021) §31.2.7 and X.690 (02/2021) §8.14.4 retain
// the universal base encoding for each schema-known IMPLICIT position.
// SEQUENCE/SEQUENCE OF are constructed (§§8.9.1, 8.10.1), INTEGER
// and NULL are primitive (§§8.3.1, 8.8.1); strings keep §§8.6–8.7.
func tcapImplicitUniversalTag(kind tcapKind) int {
	switch kind {
	case tcapKindInteger:
		return tag.TagInteger
	case tcapKindNull:
		return tag.TagNull
	case tcapKindBitString:
		return tag.TagBitString
	case tcapKindOctetString:
		return tag.TagOctetString
	case tcapKindBegin, tcapKindContinue, tcapKindEnd, tcapKindUnidirectional, tcapKindAbort,
		tcapKindInvoke, tcapKindReturnResult, tcapKindReturnResultResult, tcapKindReturnError, tcapKindReject,
		tcapKindAARQApdu, tcapKindAAREApdu, tcapKindABRTApdu, tcapKindRLRQApdu, tcapKindRLREApdu, tcapKindAUDTApdu,
		tcapKindComponentPortion, tcapKindUserInformation:
		return tag.TagSequence
	}
	return 0
}
