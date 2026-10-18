// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_profile.go; SHA-256 a56dde8456ae0da49059c98ebbafa5f3068ec3d1470c058cabb010032029c416.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
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

// TrackTCAPForm applies Q.773 (06/1997) §4.1.1 to a generated decode.
// Generic BER helpers remain usable independently of that protocol profile.
func TrackTCAPForm(options []DecodeOption, source ...string) []DecodeOption {
	name := ""
	if len(source) > 0 {
		name = source[0]
	}
	c, err := decodeOptions(options)
	if err == nil && (!c.profile || name != "" && name != c.profileType) {
		ruleSource := sourceAssignment(source)
		if module := profileModule(source); module != "" {
			ruleSource = module + "." + ruleSource
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

		v := identifyViolation(Violation{Kind: ProtocolRule, Path: path, Constraint: "Q.773 §4.1.1: " + rule, Source: profileRuleSource(config.profileSource, path), ObservedValue: observation, Offset: new(offset), ChildIndexes: append([]int(nil), indexes...), preflight: false, scope: config.reportScope})
		if !config.tolerant {
			return &ValidationError{boundedViolation(v)}
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
	config.profile = true
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
			if t.Class == tag.ClassContextSpecific && t.Number == 0 {
				return "linkedId.present"
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
