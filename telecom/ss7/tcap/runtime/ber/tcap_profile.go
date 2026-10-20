// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_profile.go; SHA-256 98662b40ace1f58e2dd00b0b6eab46a474caeb63f520df3c6c76f921b694f380.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"math"
)

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
				copied := *context
				copied.config.profile = true
				copied.config.profileNested = c.profile
				copied.config.profileType = name
				copied.config.profileSource = ruleSource
				return []DecodeOption{&copied}
			}
		}
		options = append(options[:len(options):len(options)], tcapProfileOption{source: name, ruleSource: ruleSource, nested: c.profile})
	}
	return TrackBERForm(options)
}

func tcapProfileViolation(data []byte, pos, tagLen, lenLen int, indefinite bool, t tag.Tag, kind string) bool {
	return !indefinite && lenLen > 1 && (data[pos+tagLen+1] == 0 || lenLen == 2 && data[pos+tagLen+1] < 128) || t.Constructed && (kind == "OctetString" || kind == "BitString" || t.Class == tag.ClassUniversal && (t.Number == tag.TagOctetString || t.Number == tag.TagBitString))
}

// Q.773 (06/1997) §4.1.1 applies to the TC message and the dialogue
// abstract syntaxes in §§3.2 and 4.2.3. An X.690 (02/2021) §8.15 open type
// begins with its own identifier, so even that header belongs to the
// TC-user's syntax. X.690 §8.18.6–8.18.11 keeps EXTERNAL's encoding-choice
// header in the containing syntax; only its value belongs to the identified
// syntax. Q.773 dialogue is owned (§4.2.3); X.880 (07/1994) Annex A linkedId [0]/[1] puts opcode at index 2.
func tcapProfileOwnsChild(parent string, index int, linked bool) bool {
	switch parent {
	case "Invoke":
		return index < 2 || linked && index == 2
	case "ReturnResultResult":
		return index == 0
	case "ReturnError":
		return index < 2
	}
	return true
}

func checkTCAPProfileElement(data []byte, pos, tagLen, lenLen int, indefinite bool, t tag.Tag, indexes []int, config decodeConfig, options []DecodeOption, kind, path string) error {
	if !config.profile || config.profileNested {
		return nil
	}
	report := func(rule, observation string) error {
		offset := pos
		if config.location != nil {
			if absolute, ok := config.location.wireOffset(data[pos:]); ok {
				offset = absolute
				var err error
				indexes, err = config.location.origin.ancestry(absolute)
				if err != nil {
					return err
				}
			}
		}

		reportedPath := path
		if config.location != nil && config.location.origin.search.segments != nil {
			prefix := config.location.origin.search.segments.path
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
		if kind == "OctetString" || t.Class == tag.ClassUniversal && t.Number == tag.TagOctetString {
			return report("primitive-octet-string", "constructed OCTET STRING")
		}
		if kind == "BitString" || t.Class == tag.ClassUniversal && t.Number == tag.TagBitString {
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
// payload never receives a guessed underlying type. Q.773 §§3, 4.1.1, 4.2.3.
func tcapElementType(root, parent string, t tag.Tag, isRoot bool, syntax int) string {
	kind := ""
	if isRoot {
		kind = root
	} else {
		switch parent {
		case "Begin", "Continue", "End", "Unidirectional", "Abort":
			if t.Class == tag.ClassApplication {
				switch t.Number {
				case 8, 9:
					kind = "OctetString"
				case 11:
					kind = "DialoguePortion"
				case 12:
					kind = "ComponentPortion"
				}
			}
		case "ComponentPortion":
			kind = "Component"
		case "Invoke":
			if t.Class == tag.ClassContextSpecific && t.Number == 0 {
				kind = "InvokeLinkedId"
			}
		case "ReturnResult":
			if t.Class == tag.ClassUniversal && t.Number == 16 {
				kind = "ReturnResultResult"
			}
		case "DialoguePortion":
			if t.Class == tag.ClassUniversal && t.Number == 8 {
				kind = "DialogueExternal"
			}
		case "External", "DialogueExternal":
			if t.Class == tag.ClassContextSpecific {
				switch t.Number {
				case 1:
					kind = "OctetString"
				case 2:
					kind = "BitString"
				case 0:
					if parent == "DialogueExternal" && syntax == 1 {
						kind = "DialogueContent"
					} else if parent == "DialogueExternal" && syntax == 2 {
						kind = "UniDialogueContent"
					}
				}
			}
		case "DialogueContent":
			kind = "DialoguePDU"
		case "UniDialogueContent":
			kind = "UniDialoguePDU"
		case "AARQApdu", "AAREApdu", "AUDTApdu":
			if t.Class == tag.ClassContextSpecific {
				if t.Number == 0 {
					kind = "BitString"
				}
				if t.Number == 30 {
					kind = "UserInformation"
				}
			}
		}
	}
	switch kind {
	case "OrigTransactionID", "DestTransactionID":
		kind = "OctetString"
	case "Component", "ROS":
		if t.Class == tag.ClassContextSpecific {
			switch t.Number {
			case 1:
				kind = "Invoke"
			case 2, 7:
				kind = "ReturnResult"
			case 3:
				kind = "ReturnError"
			case 4:
				kind = "Reject"
			}
		}
	case "AbortReason":
		if t.Class == tag.ClassApplication && t.Number == 11 {
			kind = "DialoguePortion"
		}
	case "TCMessage":
		if t.Class == tag.ClassApplication {
			switch t.Number {
			case 1:
				kind = "Unidirectional"
			case 2:
				kind = "Begin"
			case 4:
				kind = "End"
			case 5:
				kind = "Continue"
			case 7:
				kind = "Abort"
			}
		}
	case "DialoguePDU":
		if t.Class == tag.ClassApplication {
			switch t.Number {
			case 0:
				kind = "AARQApdu"
			case 1:
				kind = "AAREApdu"
			case 4:
				kind = "ABRTApdu"
			}
		}
	case "UniDialoguePDU":
		kind = "AUDTApdu"
	}
	if kind == "" && t.Class == tag.ClassUniversal {
		switch t.Number {
		case 8:
			kind = "External"
		case 3:
			kind = "BitString"
		case 4:
			kind = "OctetString"
		}
	}
	return kind
}

func tcapPathSegment(root, parent, kind string, t tag.Tag, index int, isRoot bool) string {
	if isRoot {
		if root == "TCMessage" {
			switch kind {
			case "Begin":
				return "begin"
			case "End":
				return "end"
			case "Continue":
				return "continue"
			case "Abort":
				return "abort"
			case "Unidirectional":
				return "unidirectional"
			}
		}
		return ""
	}
	switch parent {
	case "Begin", "Continue", "End", "Unidirectional", "Abort":
		if t.Class == tag.ClassApplication {
			switch t.Number {
			case 8:
				return "otid"
			case 9:
				return "dtid"
			case 11:
				if parent == "Abort" {
					return "reason.uAbortCause"
				}
				return "dialoguePortion"
			case 12:
				return "components"
			case 10:
				return "reason.pAbortCause"
			}
		}
	case "ComponentPortion":
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
	case "Invoke", "ReturnError", "ReturnResult", "Reject":
		if index == 0 {
			if t.Number == 5 {
				return "invokeId.absent"
			}
			return "invokeId.present"
		}
		if parent == "Invoke" {
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
		if parent == "ReturnResult" {
			return "result"
		}
		if parent == "ReturnError" {
			if index == 1 {
				return "errcode"
			}
			return "parameter"
		}
		return "problem"
	case "ReturnResultResult":
		if index == 0 {
			return "opcode"
		}
		return "result"
	case "DialoguePortion":
		return ""
	case "DialogueExternal", "External":
		if kind == "DialogueContent" || kind == "UniDialogueContent" {
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
	case "DialogueContent":
		switch kind {
		case "AARQApdu":
			return "dialogue.dialogueRequest"
		case "AAREApdu":
			return "dialogue.dialogueResponse"
		case "ABRTApdu":
			return "dialogue.dialogueAbort"
		}
	case "UniDialogueContent":
		return "unidialogue.unidialoguePDU"
	case "AARQApdu", "AAREApdu", "AUDTApdu":
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
	case "UserInformation":
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

func tcapSegmentTag(t tag.Tag, kind string) int {
	if kind == "OctetString" {
		return tag.TagOctetString
	}
	if kind == "BitString" {
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
		if outer.profileType != "External" && outer.profileType != "DialogueExternal" {
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
			!(identifier.Constructed && (identifier.Number == 1 || identifier.Number == 2) ||
				outer.profileType == "DialogueExternal" && outer.dialogueSyntax > 0) {
			return false
		}
		outer = ancestor
	}
	return true
}

func tcapProfileOwnsChildAt(data []byte, parent berScanFrame, index int) bool {
	linked := parent.profileType == "Invoke" && index == 2 && tcapProfileInvokeLinked(data, parent.offset)
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
