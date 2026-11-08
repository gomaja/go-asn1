// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/string_controls.go; SHA-256 e2cd37024826e5934446c877afacb6f83f1d1abc4d6c7ea3841c68143417eb48.
package ber

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// stringControlState recognizes characters, not the octets of their UCS form.
// X.690 (02/2021) §§8.23.5.3, 8.23.9–8.23.10; ISO/IEC 2022:1994
// §§7.3, 13.1–13.2 (Tables 2, 3.a, 3.b); ISO/IEC 10646:2003 §§15–16.
// ISO/IEC 2022 §13.1 requires ESC, zero or more U+0020–U+002F
// intermediates, and a U+0030–U+007E final. An incomplete ESC is not
// a complete escape sequence. State is retained across BER string leaves.
type stringControlState struct {
	phase byte // 1 ESC, 2 intermediates, 3 CSI parameters, 4 CSI space
	first rune
}

func (s *stringControlState) consume(number int, r rune) bool {
	if s.phase == 0 && r != 0x1b && r != 0x0e && r != 0x0f && r != 0x8e && r != 0x8f && r != 0x9b {
		return false
	}
	allEscapes := number == tag.TagIA5String || number == tag.TagUTF8String
	unicodeString := number == tag.TagBMPString || number == tag.TagUniversalString || number == tag.TagUTF8String
	// ISO/IEC 10646:2003 §15 prohibits ISO/IEC 2022 code extension,
	// including single and locking shifts. X.690 §8.23.9 c) repeats this
	// for BMPString and UniversalString. IA5String §8.23.5.3 prohibits
	// explicit escape sequences; its C0 repertoire still includes SI and SO.
	if unicodeString && (r == 0x0e || r == 0x0f || r == 0x8e || r == 0x8f) {
		s.phase = 0
		return true
	}
	switch s.phase {
	case 1, 2:
		if r >= 0x20 && r <= 0x2f {
			if s.phase == 1 {
				s.first = r
			}
			s.phase = 2
			return false
		}
		if r >= 0x30 && r <= 0x7e {
			phase, first := s.phase, s.first
			s.phase = 0
			if allEscapes {
				return true
			}
			if phase == 2 {
				// Table 3.b: 3F is a single control function; 7F and 12F are
				// reserved. The other nF types announce, designate or identify codes.
				return first != 0x23 && first != 0x27 && first != 0x2c
			}
			if r == '[' {
				s.phase = 3
				return false
			}
			return r == 'N' || r == 'O' || r == 'n' || r == 'o' || r == '|' || r == '}' || r == '~'
		}
		// ISO/IEC 2022:1994 §13.1: a control is not an escape final byte.
		s.phase = 0
	case 3:
		// ISO/IEC 10646:2003 §16.3: IUCS = CSI Ps... SP m;
		// Ps are decimal collection numbers separated by semicolons.
		if r >= '0' && r <= '9' || r == ';' {
			return false
		}
		if r == ' ' {
			s.phase = 4
			return false
		}
		s.phase = 0
	case 4:
		s.phase = 0
		if r == 'm' {
			return true
		}
	}
	if r == 0x1b {
		s.phase = 1
		s.first = 0
	} else if !allEscapes && r == 0x9b {
		s.phase = 3
	}
	return false
}

func validStringControls(number int, value string) bool {
	// X.690 (02/2021) §8.23.5.3 forbids IA5 escapes, not standalone SI/SO.
	if number == tag.TagIA5String && strings.IndexByte(value, 0x1b) < 0 {
		return true
	}
	var state stringControlState
	for _, r := range value {
		if state.consume(number, r) {
			return false
		}
	}
	return true
}

// X.680 (02/2021) §§41.6, 41.15–41.16 adopt ISO/IEC 10646:2003;
// §§7 a), 8 permanently reserve the plane-end cells and U+FDD0–U+FDEF.
func isUnicodeNoncharacter(r rune) bool {
	return r >= 0xfdd0 && r <= 0xfdef || r >= 0 && r <= utf8.MaxRune && r&0xffff >= 0xfffe
}

const unicodeNoncharacterConstraint = "UCS repertoire excludes permanently reserved noncharacters (X.680 (02/2021) §§41.6, 41.15–41.16; ISO/IEC 10646:2003 §§7 a), 8)"

func unicodeNoncharacterRule() RuleRef {
	return RuleRef{Document: "ISO/IEC 10646", Edition: "2003", Clause: "7 a), 8"}
}

func validUTF8Contents(contents []byte) bool {
	if !utf8.Valid(contents) {
		return false
	}
	var controls stringControlState
	for _, r := range string(contents) {
		// ISO/IEC 10646:2003 §§7 a), 8 exclude permanently reserved noncharacters.
		if isUnicodeNoncharacter(r) || controls.consume(tag.TagUTF8String, r) {
			return false
		}
	}
	return true
}

func invalidStringControl(number int) error {
	return fmt.Errorf("%w: universal string tag %d contains forbidden code-extension controls (X.690 (02/2021) §§8.23.5.3, 8.23.9–8.23.10)", ErrInvalidValue, number)
}

func stringControlConstraint(number int) string {
	if number == tag.TagIA5String {
		return "IA5String forbids explicit escape sequences (X.690 (02/2021) §8.23.5.3/Table 3)"
	}
	return "UTF8String forbids escapes and code-extension shifts (X.690 (02/2021) §8.23.10; ISO/IEC 10646:2003 §15)"
}

// X.680 (02/2021) §§41.6, 41.15–41.16 and ISO/IEC 10646:2003 §§7 a), 8
// require scalar characters outside the permanently reserved noncharacter cells.
func validUCSCharacter(r rune) bool { return utf8.ValidRune(r) && !isUnicodeNoncharacter(r) }
