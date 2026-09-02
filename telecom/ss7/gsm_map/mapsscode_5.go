// Code generated from ASN.1 module "MAP-SS-Code". DO NOT EDIT.

package gsm_map

import (
	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

const (

	// AllSS5 is the octet string constant for AllSS5.
	AllSS5 = "\x00"

	// AllLineIdentificationSS5 is the octet string constant for AllLineIdentificationSS5.
	AllLineIdentificationSS5 = "\x10"

	// Clip5 is the octet string constant for Clip5.
	Clip5 = "\x11"

	// Clir5 is the octet string constant for Clir5.
	Clir5 = "\x12"

	// Colp5 is the octet string constant for Colp5.
	Colp5 = "\x13"

	// Colr5 is the octet string constant for Colr5.
	Colr5 = "\x14"

	// Mci5 is the octet string constant for Mci5.
	Mci5 = "\x15"

	// AllNameIdentificationSS5 is the octet string constant for AllNameIdentificationSS5.
	AllNameIdentificationSS5 = "\x18"

	// Cnap5 is the octet string constant for Cnap5.
	Cnap5 = "\x19"

	// AllForwardingSS5 is the octet string constant for AllForwardingSS5.
	AllForwardingSS5 = "\x20"

	// Cfu5 is the octet string constant for Cfu5.
	Cfu5 = "\x21"

	// AllCondForwardingSS5 is the octet string constant for AllCondForwardingSS5.
	AllCondForwardingSS5 = "\x28"

	// Cfb5 is the octet string constant for Cfb5.
	Cfb5 = "\x29"

	// Cfnry5 is the octet string constant for Cfnry5.
	Cfnry5 = "\x2a"

	// Cfnrc5 is the octet string constant for Cfnrc5.
	Cfnrc5 = "\x2b"

	// Cd5 is the octet string constant for Cd5.
	Cd5 = "\x24"

	// AllCallOfferingSS5 is the octet string constant for AllCallOfferingSS5.
	AllCallOfferingSS5 = "\x30"

	// Ect5 is the octet string constant for Ect5.
	Ect5 = "\x31"

	// Mah5 is the octet string constant for Mah5.
	Mah5 = "\x32"

	// AllCallCompletionSS5 is the octet string constant for AllCallCompletionSS5.
	AllCallCompletionSS5 = "\x40"

	// Cw5 is the octet string constant for Cw5.
	Cw5 = "\x41"

	// Hold5 is the octet string constant for Hold5.
	Hold5 = "\x42"

	// CcbsA5 is the octet string constant for CcbsA5.
	CcbsA5 = "\x43"

	// CcbsB5 is the octet string constant for CcbsB5.
	CcbsB5 = "\x44"

	// Mc5 is the octet string constant for Mc5.
	Mc5 = "\x45"

	// AllMultiPartySS5 is the octet string constant for AllMultiPartySS5.
	AllMultiPartySS5 = "\x50"

	// MultiPTY5 is the octet string constant for MultiPTY5.
	MultiPTY5 = "\x51"

	// AllCommunityOfInterestSS5 is the octet string constant for AllCommunityOfInterestSS5.
	AllCommunityOfInterestSS5 = "\x60"

	// Cug5 is the octet string constant for Cug5.
	Cug5 = "\x61"

	// AllChargingSS5 is the octet string constant for AllChargingSS5.
	AllChargingSS5 = "\x70"

	// Aoci5 is the octet string constant for Aoci5.
	Aoci5 = "\x71"

	// Aocc5 is the octet string constant for Aocc5.
	Aocc5 = "\x72"

	// AllAdditionalInfoTransferSS5 is the octet string constant for AllAdditionalInfoTransferSS5.
	AllAdditionalInfoTransferSS5 = "\x80"

	// Uus15 is the octet string constant for Uus15.
	Uus15 = "\x81"

	// Uus25 is the octet string constant for Uus25.
	Uus25 = "\x82"

	// Uus35 is the octet string constant for Uus35.
	Uus35 = "\x83"

	// AllBarringSS5 is the octet string constant for AllBarringSS5.
	AllBarringSS5 = "\x90"

	// BarringOfOutgoingCalls5 is the octet string constant for BarringOfOutgoingCalls5.
	BarringOfOutgoingCalls5 = "\x91"

	// Baoc5 is the octet string constant for Baoc5.
	Baoc5 = "\x92"

	// Boic5 is the octet string constant for Boic5.
	Boic5 = "\x93"

	// BoicExHC5 is the octet string constant for BoicExHC5.
	BoicExHC5 = "\x94"

	// BarringOfIncomingCalls5 is the octet string constant for BarringOfIncomingCalls5.
	BarringOfIncomingCalls5 = "\x99"

	// Baic5 is the octet string constant for Baic5.
	Baic5 = "\x9a"

	// BicRoam5 is the octet string constant for BicRoam5.
	BicRoam5 = "\x9b"

	// AllPLMNSpecificSS5 is the octet string constant for AllPLMNSpecificSS5.
	AllPLMNSpecificSS5 = "\xf0"

	// PlmnSpecificSS15 is the octet string constant for PlmnSpecificSS15.
	PlmnSpecificSS15 = "\xf1"

	// PlmnSpecificSS25 is the octet string constant for PlmnSpecificSS25.
	PlmnSpecificSS25 = "\xf2"

	// PlmnSpecificSS35 is the octet string constant for PlmnSpecificSS35.
	PlmnSpecificSS35 = "\xf3"

	// PlmnSpecificSS45 is the octet string constant for PlmnSpecificSS45.
	PlmnSpecificSS45 = "\xf4"

	// PlmnSpecificSS55 is the octet string constant for PlmnSpecificSS55.
	PlmnSpecificSS55 = "\xf5"

	// PlmnSpecificSS65 is the octet string constant for PlmnSpecificSS65.
	PlmnSpecificSS65 = "\xf6"

	// PlmnSpecificSS75 is the octet string constant for PlmnSpecificSS75.
	PlmnSpecificSS75 = "\xf7"

	// PlmnSpecificSS85 is the octet string constant for PlmnSpecificSS85.
	PlmnSpecificSS85 = "\xf8"

	// PlmnSpecificSS95 is the octet string constant for PlmnSpecificSS95.
	PlmnSpecificSS95 = "\xf9"

	// PlmnSpecificSSA5 is the octet string constant for PlmnSpecificSSA5.
	PlmnSpecificSSA5 = "\xfa"

	// PlmnSpecificSSB5 is the octet string constant for PlmnSpecificSSB5.
	PlmnSpecificSSB5 = "\xfb"

	// PlmnSpecificSSC5 is the octet string constant for PlmnSpecificSSC5.
	PlmnSpecificSSC5 = "\xfc"

	// PlmnSpecificSSD5 is the octet string constant for PlmnSpecificSSD5.
	PlmnSpecificSSD5 = "\xfd"

	// PlmnSpecificSSE5 is the octet string constant for PlmnSpecificSSE5.
	PlmnSpecificSSE5 = "\xfe"

	// PlmnSpecificSSF5 is the octet string constant for PlmnSpecificSSF5.
	PlmnSpecificSSF5 = "\xff"

	// AllCallPrioritySS5 is the octet string constant for AllCallPrioritySS5.
	AllCallPrioritySS5 = "\xa0"

	// Emlpp5 is the octet string constant for Emlpp5.
	Emlpp5 = "\xa1"

	// AllLCSPrivacyException5 is the octet string constant for AllLCSPrivacyException5.
	AllLCSPrivacyException5 = "\xb0"

	// Universal5 is the octet string constant for Universal5.
	Universal5 = "\xb1"

	// CallSessionRelated5 is the octet string constant for CallSessionRelated5.
	CallSessionRelated5 = "\xb2"

	// CallSessionUnrelated5 is the octet string constant for CallSessionUnrelated5.
	CallSessionUnrelated5 = "\xb3"

	// Plmnoperator5 is the octet string constant for Plmnoperator5.
	Plmnoperator5 = "\xb4"

	// ServiceTypeValue5 is the octet string constant for ServiceTypeValue5.
	ServiceTypeValue5 = "\xb5"

	// AllMOLRSS5 is the octet string constant for AllMOLRSS5.
	AllMOLRSS5 = "\xc0"

	// BasicSelfLocation5 is the octet string constant for BasicSelfLocation5.
	BasicSelfLocation5 = "\xc1"

	// AutonomousSelfLocation5 is the octet string constant for AutonomousSelfLocation5.
	AutonomousSelfLocation5 = "\xc2"

	// TransferToThirdParty5 is the octet string constant for TransferToThirdParty5.
	TransferToThirdParty5 = "\xc3"
)

// SSCode5 represents the ASN.1 type SS-Code (OCTET_STRING).
type SSCode5 = []byte
