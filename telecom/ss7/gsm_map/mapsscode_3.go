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

	// AllSS3 is the octet string constant for AllSS3.
	AllSS3 = "\x00"

	// AllLineIdentificationSS3 is the octet string constant for AllLineIdentificationSS3.
	AllLineIdentificationSS3 = "\x10"

	// Clip3 is the octet string constant for Clip3.
	Clip3 = "\x11"

	// Clir3 is the octet string constant for Clir3.
	Clir3 = "\x12"

	// Colp3 is the octet string constant for Colp3.
	Colp3 = "\x13"

	// Colr3 is the octet string constant for Colr3.
	Colr3 = "\x14"

	// Mci3 is the octet string constant for Mci3.
	Mci3 = "\x15"

	// AllNameIdentificationSS3 is the octet string constant for AllNameIdentificationSS3.
	AllNameIdentificationSS3 = "\x18"

	// Cnap3 is the octet string constant for Cnap3.
	Cnap3 = "\x19"

	// AllForwardingSS3 is the octet string constant for AllForwardingSS3.
	AllForwardingSS3 = "\x20"

	// Cfu3 is the octet string constant for Cfu3.
	Cfu3 = "\x21"

	// AllCondForwardingSS3 is the octet string constant for AllCondForwardingSS3.
	AllCondForwardingSS3 = "\x28"

	// Cfb3 is the octet string constant for Cfb3.
	Cfb3 = "\x29"

	// Cfnry3 is the octet string constant for Cfnry3.
	Cfnry3 = "\x2a"

	// Cfnrc3 is the octet string constant for Cfnrc3.
	Cfnrc3 = "\x2b"

	// Cd3 is the octet string constant for Cd3.
	Cd3 = "\x24"

	// AllCallOfferingSS3 is the octet string constant for AllCallOfferingSS3.
	AllCallOfferingSS3 = "\x30"

	// Ect3 is the octet string constant for Ect3.
	Ect3 = "\x31"

	// Mah3 is the octet string constant for Mah3.
	Mah3 = "\x32"

	// AllCallCompletionSS3 is the octet string constant for AllCallCompletionSS3.
	AllCallCompletionSS3 = "\x40"

	// Cw3 is the octet string constant for Cw3.
	Cw3 = "\x41"

	// Hold3 is the octet string constant for Hold3.
	Hold3 = "\x42"

	// CcbsA3 is the octet string constant for CcbsA3.
	CcbsA3 = "\x43"

	// CcbsB3 is the octet string constant for CcbsB3.
	CcbsB3 = "\x44"

	// Mc3 is the octet string constant for Mc3.
	Mc3 = "\x45"

	// AllMultiPartySS3 is the octet string constant for AllMultiPartySS3.
	AllMultiPartySS3 = "\x50"

	// MultiPTY3 is the octet string constant for MultiPTY3.
	MultiPTY3 = "\x51"

	// AllCommunityOfInterestSS3 is the octet string constant for AllCommunityOfInterestSS3.
	AllCommunityOfInterestSS3 = "\x60"

	// Cug3 is the octet string constant for Cug3.
	Cug3 = "\x61"

	// AllChargingSS3 is the octet string constant for AllChargingSS3.
	AllChargingSS3 = "\x70"

	// Aoci3 is the octet string constant for Aoci3.
	Aoci3 = "\x71"

	// Aocc3 is the octet string constant for Aocc3.
	Aocc3 = "\x72"

	// AllAdditionalInfoTransferSS3 is the octet string constant for AllAdditionalInfoTransferSS3.
	AllAdditionalInfoTransferSS3 = "\x80"

	// Uus13 is the octet string constant for Uus13.
	Uus13 = "\x81"

	// Uus23 is the octet string constant for Uus23.
	Uus23 = "\x82"

	// Uus33 is the octet string constant for Uus33.
	Uus33 = "\x83"

	// AllBarringSS3 is the octet string constant for AllBarringSS3.
	AllBarringSS3 = "\x90"

	// BarringOfOutgoingCalls3 is the octet string constant for BarringOfOutgoingCalls3.
	BarringOfOutgoingCalls3 = "\x91"

	// Baoc3 is the octet string constant for Baoc3.
	Baoc3 = "\x92"

	// Boic3 is the octet string constant for Boic3.
	Boic3 = "\x93"

	// BoicExHC3 is the octet string constant for BoicExHC3.
	BoicExHC3 = "\x94"

	// BarringOfIncomingCalls3 is the octet string constant for BarringOfIncomingCalls3.
	BarringOfIncomingCalls3 = "\x99"

	// Baic3 is the octet string constant for Baic3.
	Baic3 = "\x9a"

	// BicRoam3 is the octet string constant for BicRoam3.
	BicRoam3 = "\x9b"

	// AllPLMNSpecificSS3 is the octet string constant for AllPLMNSpecificSS3.
	AllPLMNSpecificSS3 = "\xf0"

	// PlmnSpecificSS13 is the octet string constant for PlmnSpecificSS13.
	PlmnSpecificSS13 = "\xf1"

	// PlmnSpecificSS23 is the octet string constant for PlmnSpecificSS23.
	PlmnSpecificSS23 = "\xf2"

	// PlmnSpecificSS33 is the octet string constant for PlmnSpecificSS33.
	PlmnSpecificSS33 = "\xf3"

	// PlmnSpecificSS43 is the octet string constant for PlmnSpecificSS43.
	PlmnSpecificSS43 = "\xf4"

	// PlmnSpecificSS53 is the octet string constant for PlmnSpecificSS53.
	PlmnSpecificSS53 = "\xf5"

	// PlmnSpecificSS63 is the octet string constant for PlmnSpecificSS63.
	PlmnSpecificSS63 = "\xf6"

	// PlmnSpecificSS73 is the octet string constant for PlmnSpecificSS73.
	PlmnSpecificSS73 = "\xf7"

	// PlmnSpecificSS83 is the octet string constant for PlmnSpecificSS83.
	PlmnSpecificSS83 = "\xf8"

	// PlmnSpecificSS93 is the octet string constant for PlmnSpecificSS93.
	PlmnSpecificSS93 = "\xf9"

	// PlmnSpecificSSA3 is the octet string constant for PlmnSpecificSSA3.
	PlmnSpecificSSA3 = "\xfa"

	// PlmnSpecificSSB3 is the octet string constant for PlmnSpecificSSB3.
	PlmnSpecificSSB3 = "\xfb"

	// PlmnSpecificSSC3 is the octet string constant for PlmnSpecificSSC3.
	PlmnSpecificSSC3 = "\xfc"

	// PlmnSpecificSSD3 is the octet string constant for PlmnSpecificSSD3.
	PlmnSpecificSSD3 = "\xfd"

	// PlmnSpecificSSE3 is the octet string constant for PlmnSpecificSSE3.
	PlmnSpecificSSE3 = "\xfe"

	// PlmnSpecificSSF3 is the octet string constant for PlmnSpecificSSF3.
	PlmnSpecificSSF3 = "\xff"

	// AllCallPrioritySS3 is the octet string constant for AllCallPrioritySS3.
	AllCallPrioritySS3 = "\xa0"

	// Emlpp3 is the octet string constant for Emlpp3.
	Emlpp3 = "\xa1"

	// AllLCSPrivacyException3 is the octet string constant for AllLCSPrivacyException3.
	AllLCSPrivacyException3 = "\xb0"

	// Universal3 is the octet string constant for Universal3.
	Universal3 = "\xb1"

	// CallSessionRelated3 is the octet string constant for CallSessionRelated3.
	CallSessionRelated3 = "\xb2"

	// CallSessionUnrelated3 is the octet string constant for CallSessionUnrelated3.
	CallSessionUnrelated3 = "\xb3"

	// Plmnoperator3 is the octet string constant for Plmnoperator3.
	Plmnoperator3 = "\xb4"

	// ServiceTypeValue3 is the octet string constant for ServiceTypeValue3.
	ServiceTypeValue3 = "\xb5"

	// AllMOLRSS3 is the octet string constant for AllMOLRSS3.
	AllMOLRSS3 = "\xc0"

	// BasicSelfLocation3 is the octet string constant for BasicSelfLocation3.
	BasicSelfLocation3 = "\xc1"

	// AutonomousSelfLocation3 is the octet string constant for AutonomousSelfLocation3.
	AutonomousSelfLocation3 = "\xc2"

	// TransferToThirdParty3 is the octet string constant for TransferToThirdParty3.
	TransferToThirdParty3 = "\xc3"
)

// SSCode3 represents the ASN.1 type SSCode3 (OCTET_STRING).
type SSCode3 = []byte
