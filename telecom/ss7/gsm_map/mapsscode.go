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

	// AllSS is the octet string constant for AllSS.
	AllSS = "\x00"

	// AllLineIdentificationSS is the octet string constant for AllLineIdentificationSS.
	AllLineIdentificationSS = "\x10"

	// Clip is the octet string constant for Clip.
	Clip = "\x11"

	// Clir is the octet string constant for Clir.
	Clir = "\x12"

	// Colp is the octet string constant for Colp.
	Colp = "\x13"

	// Colr is the octet string constant for Colr.
	Colr = "\x14"

	// Mci is the octet string constant for Mci.
	Mci = "\x15"

	// AllNameIdentificationSS is the octet string constant for AllNameIdentificationSS.
	AllNameIdentificationSS = "\x18"

	// Cnap is the octet string constant for Cnap.
	Cnap = "\x19"

	// AllForwardingSS is the octet string constant for AllForwardingSS.
	AllForwardingSS = "\x20"

	// Cfu is the octet string constant for Cfu.
	Cfu = "\x21"

	// AllCondForwardingSS is the octet string constant for AllCondForwardingSS.
	AllCondForwardingSS = "\x28"

	// Cfb is the octet string constant for Cfb.
	Cfb = "\x29"

	// Cfnry is the octet string constant for Cfnry.
	Cfnry = "\x2a"

	// Cfnrc is the octet string constant for Cfnrc.
	Cfnrc = "\x2b"

	// Cd is the octet string constant for Cd.
	Cd = "\x24"

	// AllCallOfferingSS is the octet string constant for AllCallOfferingSS.
	AllCallOfferingSS = "\x30"

	// Ect is the octet string constant for Ect.
	Ect = "\x31"

	// Mah is the octet string constant for Mah.
	Mah = "\x32"

	// AllCallCompletionSS is the octet string constant for AllCallCompletionSS.
	AllCallCompletionSS = "\x40"

	// Cw is the octet string constant for Cw.
	Cw = "\x41"

	// Hold is the octet string constant for Hold.
	Hold = "\x42"

	// CcbsA is the octet string constant for CcbsA.
	CcbsA = "\x43"

	// CcbsB is the octet string constant for CcbsB.
	CcbsB = "\x44"

	// Mc is the octet string constant for Mc.
	Mc = "\x45"

	// AllMultiPartySS is the octet string constant for AllMultiPartySS.
	AllMultiPartySS = "\x50"

	// MultiPTY is the octet string constant for MultiPTY.
	MultiPTY = "\x51"

	// AllCommunityOfInterestSS is the octet string constant for AllCommunityOfInterestSS.
	AllCommunityOfInterestSS = "\x60"

	// Cug is the octet string constant for Cug.
	Cug = "\x61"

	// AllChargingSS is the octet string constant for AllChargingSS.
	AllChargingSS = "\x70"

	// Aoci is the octet string constant for Aoci.
	Aoci = "\x71"

	// Aocc is the octet string constant for Aocc.
	Aocc = "\x72"

	// AllAdditionalInfoTransferSS is the octet string constant for AllAdditionalInfoTransferSS.
	AllAdditionalInfoTransferSS = "\x80"

	// Uus1 is the octet string constant for Uus1.
	Uus1 = "\x81"

	// Uus2 is the octet string constant for Uus2.
	Uus2 = "\x82"

	// Uus3 is the octet string constant for Uus3.
	Uus3 = "\x83"

	// AllBarringSS is the octet string constant for AllBarringSS.
	AllBarringSS = "\x90"

	// BarringOfOutgoingCalls is the octet string constant for BarringOfOutgoingCalls.
	BarringOfOutgoingCalls = "\x91"

	// Baoc is the octet string constant for Baoc.
	Baoc = "\x92"

	// Boic is the octet string constant for Boic.
	Boic = "\x93"

	// BoicExHC is the octet string constant for BoicExHC.
	BoicExHC = "\x94"

	// BarringOfIncomingCalls is the octet string constant for BarringOfIncomingCalls.
	BarringOfIncomingCalls = "\x99"

	// Baic is the octet string constant for Baic.
	Baic = "\x9a"

	// BicRoam is the octet string constant for BicRoam.
	BicRoam = "\x9b"

	// AllPLMNSpecificSS is the octet string constant for AllPLMNSpecificSS.
	AllPLMNSpecificSS = "\xf0"

	// PlmnSpecificSS1 is the octet string constant for PlmnSpecificSS1.
	PlmnSpecificSS1 = "\xf1"

	// PlmnSpecificSS2 is the octet string constant for PlmnSpecificSS2.
	PlmnSpecificSS2 = "\xf2"

	// PlmnSpecificSS3 is the octet string constant for PlmnSpecificSS3.
	PlmnSpecificSS3 = "\xf3"

	// PlmnSpecificSS4 is the octet string constant for PlmnSpecificSS4.
	PlmnSpecificSS4 = "\xf4"

	// PlmnSpecificSS5 is the octet string constant for PlmnSpecificSS5.
	PlmnSpecificSS5 = "\xf5"

	// PlmnSpecificSS6 is the octet string constant for PlmnSpecificSS6.
	PlmnSpecificSS6 = "\xf6"

	// PlmnSpecificSS7 is the octet string constant for PlmnSpecificSS7.
	PlmnSpecificSS7 = "\xf7"

	// PlmnSpecificSS8 is the octet string constant for PlmnSpecificSS8.
	PlmnSpecificSS8 = "\xf8"

	// PlmnSpecificSS9 is the octet string constant for PlmnSpecificSS9.
	PlmnSpecificSS9 = "\xf9"

	// PlmnSpecificSSA is the octet string constant for PlmnSpecificSSA.
	PlmnSpecificSSA = "\xfa"

	// PlmnSpecificSSB is the octet string constant for PlmnSpecificSSB.
	PlmnSpecificSSB = "\xfb"

	// PlmnSpecificSSC is the octet string constant for PlmnSpecificSSC.
	PlmnSpecificSSC = "\xfc"

	// PlmnSpecificSSD is the octet string constant for PlmnSpecificSSD.
	PlmnSpecificSSD = "\xfd"

	// PlmnSpecificSSE is the octet string constant for PlmnSpecificSSE.
	PlmnSpecificSSE = "\xfe"

	// PlmnSpecificSSF is the octet string constant for PlmnSpecificSSF.
	PlmnSpecificSSF = "\xff"

	// AllCallPrioritySS is the octet string constant for AllCallPrioritySS.
	AllCallPrioritySS = "\xa0"

	// Emlpp is the octet string constant for Emlpp.
	Emlpp = "\xa1"

	// AllLCSPrivacyException is the octet string constant for AllLCSPrivacyException.
	AllLCSPrivacyException = "\xb0"

	// Universal is the octet string constant for Universal.
	Universal = "\xb1"

	// CallSessionRelated is the octet string constant for CallSessionRelated.
	CallSessionRelated = "\xb2"

	// CallSessionUnrelated is the octet string constant for CallSessionUnrelated.
	CallSessionUnrelated = "\xb3"

	// Plmnoperator is the octet string constant for Plmnoperator.
	Plmnoperator = "\xb4"

	// ServiceTypeValue is the octet string constant for ServiceTypeValue.
	ServiceTypeValue = "\xb5"

	// AllMOLRSS is the octet string constant for AllMOLRSS.
	AllMOLRSS = "\xc0"

	// BasicSelfLocation is the octet string constant for BasicSelfLocation.
	BasicSelfLocation = "\xc1"

	// AutonomousSelfLocation is the octet string constant for AutonomousSelfLocation.
	AutonomousSelfLocation = "\xc2"

	// TransferToThirdParty is the octet string constant for TransferToThirdParty.
	TransferToThirdParty = "\xc3"
)

// SSCode represents the ASN.1 type SSCode (OCTET_STRING).
type SSCode = []byte
