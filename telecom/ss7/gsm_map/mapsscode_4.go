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

	// AllSS4 is the octet string constant for AllSS4.
	AllSS4 = "\x00"

	// AllLineIdentificationSS4 is the octet string constant for AllLineIdentificationSS4.
	AllLineIdentificationSS4 = "\x10"

	// Clip4 is the octet string constant for Clip4.
	Clip4 = "\x11"

	// Clir4 is the octet string constant for Clir4.
	Clir4 = "\x12"

	// Colp4 is the octet string constant for Colp4.
	Colp4 = "\x13"

	// Colr4 is the octet string constant for Colr4.
	Colr4 = "\x14"

	// Mci4 is the octet string constant for Mci4.
	Mci4 = "\x15"

	// AllNameIdentificationSS4 is the octet string constant for AllNameIdentificationSS4.
	AllNameIdentificationSS4 = "\x18"

	// Cnap4 is the octet string constant for Cnap4.
	Cnap4 = "\x19"

	// AllForwardingSS4 is the octet string constant for AllForwardingSS4.
	AllForwardingSS4 = "\x20"

	// Cfu4 is the octet string constant for Cfu4.
	Cfu4 = "\x21"

	// AllCondForwardingSS4 is the octet string constant for AllCondForwardingSS4.
	AllCondForwardingSS4 = "\x28"

	// Cfb4 is the octet string constant for Cfb4.
	Cfb4 = "\x29"

	// Cfnry4 is the octet string constant for Cfnry4.
	Cfnry4 = "\x2a"

	// Cfnrc4 is the octet string constant for Cfnrc4.
	Cfnrc4 = "\x2b"

	// Cd4 is the octet string constant for Cd4.
	Cd4 = "\x24"

	// AllCallOfferingSS4 is the octet string constant for AllCallOfferingSS4.
	AllCallOfferingSS4 = "\x30"

	// Ect4 is the octet string constant for Ect4.
	Ect4 = "\x31"

	// Mah4 is the octet string constant for Mah4.
	Mah4 = "\x32"

	// AllCallCompletionSS4 is the octet string constant for AllCallCompletionSS4.
	AllCallCompletionSS4 = "\x40"

	// Cw4 is the octet string constant for Cw4.
	Cw4 = "\x41"

	// Hold4 is the octet string constant for Hold4.
	Hold4 = "\x42"

	// CcbsA4 is the octet string constant for CcbsA4.
	CcbsA4 = "\x43"

	// CcbsB4 is the octet string constant for CcbsB4.
	CcbsB4 = "\x44"

	// Mc4 is the octet string constant for Mc4.
	Mc4 = "\x45"

	// AllMultiPartySS4 is the octet string constant for AllMultiPartySS4.
	AllMultiPartySS4 = "\x50"

	// MultiPTY4 is the octet string constant for MultiPTY4.
	MultiPTY4 = "\x51"

	// AllCommunityOfInterestSS4 is the octet string constant for AllCommunityOfInterestSS4.
	AllCommunityOfInterestSS4 = "\x60"

	// Cug4 is the octet string constant for Cug4.
	Cug4 = "\x61"

	// AllChargingSS4 is the octet string constant for AllChargingSS4.
	AllChargingSS4 = "\x70"

	// Aoci4 is the octet string constant for Aoci4.
	Aoci4 = "\x71"

	// Aocc4 is the octet string constant for Aocc4.
	Aocc4 = "\x72"

	// AllAdditionalInfoTransferSS4 is the octet string constant for AllAdditionalInfoTransferSS4.
	AllAdditionalInfoTransferSS4 = "\x80"

	// Uus14 is the octet string constant for Uus14.
	Uus14 = "\x81"

	// Uus24 is the octet string constant for Uus24.
	Uus24 = "\x82"

	// Uus34 is the octet string constant for Uus34.
	Uus34 = "\x83"

	// AllBarringSS4 is the octet string constant for AllBarringSS4.
	AllBarringSS4 = "\x90"

	// BarringOfOutgoingCalls4 is the octet string constant for BarringOfOutgoingCalls4.
	BarringOfOutgoingCalls4 = "\x91"

	// Baoc4 is the octet string constant for Baoc4.
	Baoc4 = "\x92"

	// Boic4 is the octet string constant for Boic4.
	Boic4 = "\x93"

	// BoicExHC4 is the octet string constant for BoicExHC4.
	BoicExHC4 = "\x94"

	// BarringOfIncomingCalls4 is the octet string constant for BarringOfIncomingCalls4.
	BarringOfIncomingCalls4 = "\x99"

	// Baic4 is the octet string constant for Baic4.
	Baic4 = "\x9a"

	// BicRoam4 is the octet string constant for BicRoam4.
	BicRoam4 = "\x9b"

	// AllPLMNSpecificSS4 is the octet string constant for AllPLMNSpecificSS4.
	AllPLMNSpecificSS4 = "\xf0"

	// PlmnSpecificSS14 is the octet string constant for PlmnSpecificSS14.
	PlmnSpecificSS14 = "\xf1"

	// PlmnSpecificSS24 is the octet string constant for PlmnSpecificSS24.
	PlmnSpecificSS24 = "\xf2"

	// PlmnSpecificSS34 is the octet string constant for PlmnSpecificSS34.
	PlmnSpecificSS34 = "\xf3"

	// PlmnSpecificSS44 is the octet string constant for PlmnSpecificSS44.
	PlmnSpecificSS44 = "\xf4"

	// PlmnSpecificSS54 is the octet string constant for PlmnSpecificSS54.
	PlmnSpecificSS54 = "\xf5"

	// PlmnSpecificSS64 is the octet string constant for PlmnSpecificSS64.
	PlmnSpecificSS64 = "\xf6"

	// PlmnSpecificSS74 is the octet string constant for PlmnSpecificSS74.
	PlmnSpecificSS74 = "\xf7"

	// PlmnSpecificSS84 is the octet string constant for PlmnSpecificSS84.
	PlmnSpecificSS84 = "\xf8"

	// PlmnSpecificSS94 is the octet string constant for PlmnSpecificSS94.
	PlmnSpecificSS94 = "\xf9"

	// PlmnSpecificSSA4 is the octet string constant for PlmnSpecificSSA4.
	PlmnSpecificSSA4 = "\xfa"

	// PlmnSpecificSSB4 is the octet string constant for PlmnSpecificSSB4.
	PlmnSpecificSSB4 = "\xfb"

	// PlmnSpecificSSC4 is the octet string constant for PlmnSpecificSSC4.
	PlmnSpecificSSC4 = "\xfc"

	// PlmnSpecificSSD4 is the octet string constant for PlmnSpecificSSD4.
	PlmnSpecificSSD4 = "\xfd"

	// PlmnSpecificSSE4 is the octet string constant for PlmnSpecificSSE4.
	PlmnSpecificSSE4 = "\xfe"

	// PlmnSpecificSSF4 is the octet string constant for PlmnSpecificSSF4.
	PlmnSpecificSSF4 = "\xff"

	// AllCallPrioritySS4 is the octet string constant for AllCallPrioritySS4.
	AllCallPrioritySS4 = "\xa0"

	// Emlpp4 is the octet string constant for Emlpp4.
	Emlpp4 = "\xa1"

	// AllLCSPrivacyException4 is the octet string constant for AllLCSPrivacyException4.
	AllLCSPrivacyException4 = "\xb0"

	// Universal4 is the octet string constant for Universal4.
	Universal4 = "\xb1"

	// CallSessionRelated4 is the octet string constant for CallSessionRelated4.
	CallSessionRelated4 = "\xb2"

	// CallSessionUnrelated4 is the octet string constant for CallSessionUnrelated4.
	CallSessionUnrelated4 = "\xb3"

	// Plmnoperator4 is the octet string constant for Plmnoperator4.
	Plmnoperator4 = "\xb4"

	// ServiceTypeValue4 is the octet string constant for ServiceTypeValue4.
	ServiceTypeValue4 = "\xb5"

	// AllMOLRSS4 is the octet string constant for AllMOLRSS4.
	AllMOLRSS4 = "\xc0"

	// BasicSelfLocation4 is the octet string constant for BasicSelfLocation4.
	BasicSelfLocation4 = "\xc1"

	// AutonomousSelfLocation4 is the octet string constant for AutonomousSelfLocation4.
	AutonomousSelfLocation4 = "\xc2"

	// TransferToThirdParty4 is the octet string constant for TransferToThirdParty4.
	TransferToThirdParty4 = "\xc3"
)

// SSCode4 represents the ASN.1 type SS-Code (OCTET_STRING).
type SSCode4 = []byte
