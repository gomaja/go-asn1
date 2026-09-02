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

	// AllSS4 is the octet string constant for allSS.
	AllSS4 = "\x00"

	// AllLineIdentificationSS4 is the octet string constant for allLineIdentificationSS.
	AllLineIdentificationSS4 = "\x10"

	// Clip4 is the octet string constant for clip.
	Clip4 = "\x11"

	// Clir4 is the octet string constant for clir.
	Clir4 = "\x12"

	// Colp4 is the octet string constant for colp.
	Colp4 = "\x13"

	// Colr4 is the octet string constant for colr.
	Colr4 = "\x14"

	// Mci4 is the octet string constant for mci.
	Mci4 = "\x15"

	// AllNameIdentificationSS4 is the octet string constant for allNameIdentificationSS.
	AllNameIdentificationSS4 = "\x18"

	// Cnap4 is the octet string constant for cnap.
	Cnap4 = "\x19"

	// AllForwardingSS4 is the octet string constant for allForwardingSS.
	AllForwardingSS4 = "\x20"

	// Cfu4 is the octet string constant for cfu.
	Cfu4 = "\x21"

	// AllCondForwardingSS4 is the octet string constant for allCondForwardingSS.
	AllCondForwardingSS4 = "\x28"

	// Cfb4 is the octet string constant for cfb.
	Cfb4 = "\x29"

	// Cfnry4 is the octet string constant for cfnry.
	Cfnry4 = "\x2a"

	// Cfnrc4 is the octet string constant for cfnrc.
	Cfnrc4 = "\x2b"

	// Cd4 is the octet string constant for cd.
	Cd4 = "\x24"

	// AllCallOfferingSS4 is the octet string constant for allCallOfferingSS.
	AllCallOfferingSS4 = "\x30"

	// Ect4 is the octet string constant for ect.
	Ect4 = "\x31"

	// Mah4 is the octet string constant for mah.
	Mah4 = "\x32"

	// AllCallCompletionSS4 is the octet string constant for allCallCompletionSS.
	AllCallCompletionSS4 = "\x40"

	// Cw4 is the octet string constant for cw.
	Cw4 = "\x41"

	// Hold4 is the octet string constant for hold.
	Hold4 = "\x42"

	// CcbsA4 is the octet string constant for ccbs-A.
	CcbsA4 = "\x43"

	// CcbsB4 is the octet string constant for ccbs-B.
	CcbsB4 = "\x44"

	// Mc4 is the octet string constant for mc.
	Mc4 = "\x45"

	// AllMultiPartySS4 is the octet string constant for allMultiPartySS.
	AllMultiPartySS4 = "\x50"

	// MultiPTY4 is the octet string constant for multiPTY.
	MultiPTY4 = "\x51"

	// AllCommunityOfInterestSS4 is the octet string constant for allCommunityOfInterest-SS.
	AllCommunityOfInterestSS4 = "\x60"

	// Cug4 is the octet string constant for cug.
	Cug4 = "\x61"

	// AllChargingSS4 is the octet string constant for allChargingSS.
	AllChargingSS4 = "\x70"

	// Aoci4 is the octet string constant for aoci.
	Aoci4 = "\x71"

	// Aocc4 is the octet string constant for aocc.
	Aocc4 = "\x72"

	// AllAdditionalInfoTransferSS4 is the octet string constant for allAdditionalInfoTransferSS.
	AllAdditionalInfoTransferSS4 = "\x80"

	// Uus14 is the octet string constant for uus1.
	Uus14 = "\x81"

	// Uus24 is the octet string constant for uus2.
	Uus24 = "\x82"

	// Uus34 is the octet string constant for uus3.
	Uus34 = "\x83"

	// AllBarringSS4 is the octet string constant for allBarringSS.
	AllBarringSS4 = "\x90"

	// BarringOfOutgoingCalls4 is the octet string constant for barringOfOutgoingCalls.
	BarringOfOutgoingCalls4 = "\x91"

	// Baoc4 is the octet string constant for baoc.
	Baoc4 = "\x92"

	// Boic4 is the octet string constant for boic.
	Boic4 = "\x93"

	// BoicExHC4 is the octet string constant for boicExHC.
	BoicExHC4 = "\x94"

	// BarringOfIncomingCalls4 is the octet string constant for barringOfIncomingCalls.
	BarringOfIncomingCalls4 = "\x99"

	// Baic4 is the octet string constant for baic.
	Baic4 = "\x9a"

	// BicRoam4 is the octet string constant for bicRoam.
	BicRoam4 = "\x9b"

	// AllPLMNSpecificSS4 is the octet string constant for allPLMN-specificSS.
	AllPLMNSpecificSS4 = "\xf0"

	// PlmnSpecificSS14 is the octet string constant for plmn-specificSS-1.
	PlmnSpecificSS14 = "\xf1"

	// PlmnSpecificSS24 is the octet string constant for plmn-specificSS-2.
	PlmnSpecificSS24 = "\xf2"

	// PlmnSpecificSS34 is the octet string constant for plmn-specificSS-3.
	PlmnSpecificSS34 = "\xf3"

	// PlmnSpecificSS44 is the octet string constant for plmn-specificSS-4.
	PlmnSpecificSS44 = "\xf4"

	// PlmnSpecificSS54 is the octet string constant for plmn-specificSS-5.
	PlmnSpecificSS54 = "\xf5"

	// PlmnSpecificSS64 is the octet string constant for plmn-specificSS-6.
	PlmnSpecificSS64 = "\xf6"

	// PlmnSpecificSS74 is the octet string constant for plmn-specificSS-7.
	PlmnSpecificSS74 = "\xf7"

	// PlmnSpecificSS84 is the octet string constant for plmn-specificSS-8.
	PlmnSpecificSS84 = "\xf8"

	// PlmnSpecificSS94 is the octet string constant for plmn-specificSS-9.
	PlmnSpecificSS94 = "\xf9"

	// PlmnSpecificSSA4 is the octet string constant for plmn-specificSS-A.
	PlmnSpecificSSA4 = "\xfa"

	// PlmnSpecificSSB4 is the octet string constant for plmn-specificSS-B.
	PlmnSpecificSSB4 = "\xfb"

	// PlmnSpecificSSC4 is the octet string constant for plmn-specificSS-C.
	PlmnSpecificSSC4 = "\xfc"

	// PlmnSpecificSSD4 is the octet string constant for plmn-specificSS-D.
	PlmnSpecificSSD4 = "\xfd"

	// PlmnSpecificSSE4 is the octet string constant for plmn-specificSS-E.
	PlmnSpecificSSE4 = "\xfe"

	// PlmnSpecificSSF4 is the octet string constant for plmn-specificSS-F.
	PlmnSpecificSSF4 = "\xff"

	// AllCallPrioritySS4 is the octet string constant for allCallPrioritySS.
	AllCallPrioritySS4 = "\xa0"

	// Emlpp4 is the octet string constant for emlpp.
	Emlpp4 = "\xa1"

	// AllLCSPrivacyException4 is the octet string constant for allLCSPrivacyException.
	AllLCSPrivacyException4 = "\xb0"

	// Universal4 is the octet string constant for universal.
	Universal4 = "\xb1"

	// CallSessionRelated4 is the octet string constant for callSessionRelated.
	CallSessionRelated4 = "\xb2"

	// CallSessionUnrelated4 is the octet string constant for callSessionUnrelated.
	CallSessionUnrelated4 = "\xb3"

	// Plmnoperator4 is the octet string constant for plmnoperator.
	Plmnoperator4 = "\xb4"

	// ServiceTypeValue4 is the octet string constant for serviceType.
	ServiceTypeValue4 = "\xb5"

	// AllMOLRSS4 is the octet string constant for allMOLR-SS.
	AllMOLRSS4 = "\xc0"

	// BasicSelfLocation4 is the octet string constant for basicSelfLocation.
	BasicSelfLocation4 = "\xc1"

	// AutonomousSelfLocation4 is the octet string constant for autonomousSelfLocation.
	AutonomousSelfLocation4 = "\xc2"

	// TransferToThirdParty4 is the octet string constant for transferToThirdParty.
	TransferToThirdParty4 = "\xc3"
)

// SSCode4 represents the ASN.1 type SS-Code (OCTET_STRING).
type SSCode4 = []byte
