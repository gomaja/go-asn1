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

	// AllSS is the octet string constant for allSS.
	AllSS = "\x00"

	// AllLineIdentificationSS is the octet string constant for allLineIdentificationSS.
	AllLineIdentificationSS = "\x10"

	// Clip is the octet string constant for clip.
	Clip = "\x11"

	// Clir is the octet string constant for clir.
	Clir = "\x12"

	// Colp is the octet string constant for colp.
	Colp = "\x13"

	// Colr is the octet string constant for colr.
	Colr = "\x14"

	// Mci is the octet string constant for mci.
	Mci = "\x15"

	// AllNameIdentificationSS is the octet string constant for allNameIdentificationSS.
	AllNameIdentificationSS = "\x18"

	// Cnap is the octet string constant for cnap.
	Cnap = "\x19"

	// AllForwardingSS is the octet string constant for allForwardingSS.
	AllForwardingSS = "\x20"

	// Cfu is the octet string constant for cfu.
	Cfu = "\x21"

	// AllCondForwardingSS is the octet string constant for allCondForwardingSS.
	AllCondForwardingSS = "\x28"

	// Cfb is the octet string constant for cfb.
	Cfb = "\x29"

	// Cfnry is the octet string constant for cfnry.
	Cfnry = "\x2a"

	// Cfnrc is the octet string constant for cfnrc.
	Cfnrc = "\x2b"

	// Cd is the octet string constant for cd.
	Cd = "\x24"

	// AllCallOfferingSS is the octet string constant for allCallOfferingSS.
	AllCallOfferingSS = "\x30"

	// Ect is the octet string constant for ect.
	Ect = "\x31"

	// Mah is the octet string constant for mah.
	Mah = "\x32"

	// AllCallCompletionSS is the octet string constant for allCallCompletionSS.
	AllCallCompletionSS = "\x40"

	// Cw is the octet string constant for cw.
	Cw = "\x41"

	// Hold is the octet string constant for hold.
	Hold = "\x42"

	// CcbsA is the octet string constant for ccbs-A.
	CcbsA = "\x43"

	// CcbsB is the octet string constant for ccbs-B.
	CcbsB = "\x44"

	// Mc is the octet string constant for mc.
	Mc = "\x45"

	// AllMultiPartySS is the octet string constant for allMultiPartySS.
	AllMultiPartySS = "\x50"

	// MultiPTY is the octet string constant for multiPTY.
	MultiPTY = "\x51"

	// AllCommunityOfInterestSS is the octet string constant for allCommunityOfInterest-SS.
	AllCommunityOfInterestSS = "\x60"

	// Cug is the octet string constant for cug.
	Cug = "\x61"

	// AllChargingSS is the octet string constant for allChargingSS.
	AllChargingSS = "\x70"

	// Aoci is the octet string constant for aoci.
	Aoci = "\x71"

	// Aocc is the octet string constant for aocc.
	Aocc = "\x72"

	// AllAdditionalInfoTransferSS is the octet string constant for allAdditionalInfoTransferSS.
	AllAdditionalInfoTransferSS = "\x80"

	// Uus1 is the octet string constant for uus1.
	Uus1 = "\x81"

	// Uus2 is the octet string constant for uus2.
	Uus2 = "\x82"

	// Uus3 is the octet string constant for uus3.
	Uus3 = "\x83"

	// AllBarringSS is the octet string constant for allBarringSS.
	AllBarringSS = "\x90"

	// BarringOfOutgoingCalls is the octet string constant for barringOfOutgoingCalls.
	BarringOfOutgoingCalls = "\x91"

	// Baoc is the octet string constant for baoc.
	Baoc = "\x92"

	// Boic is the octet string constant for boic.
	Boic = "\x93"

	// BoicExHC is the octet string constant for boicExHC.
	BoicExHC = "\x94"

	// BarringOfIncomingCalls is the octet string constant for barringOfIncomingCalls.
	BarringOfIncomingCalls = "\x99"

	// Baic is the octet string constant for baic.
	Baic = "\x9a"

	// BicRoam is the octet string constant for bicRoam.
	BicRoam = "\x9b"

	// AllPLMNSpecificSS is the octet string constant for allPLMN-specificSS.
	AllPLMNSpecificSS = "\xf0"

	// PlmnSpecificSS1 is the octet string constant for plmn-specificSS-1.
	PlmnSpecificSS1 = "\xf1"

	// PlmnSpecificSS2 is the octet string constant for plmn-specificSS-2.
	PlmnSpecificSS2 = "\xf2"

	// PlmnSpecificSS3 is the octet string constant for plmn-specificSS-3.
	PlmnSpecificSS3 = "\xf3"

	// PlmnSpecificSS4 is the octet string constant for plmn-specificSS-4.
	PlmnSpecificSS4 = "\xf4"

	// PlmnSpecificSS5 is the octet string constant for plmn-specificSS-5.
	PlmnSpecificSS5 = "\xf5"

	// PlmnSpecificSS6 is the octet string constant for plmn-specificSS-6.
	PlmnSpecificSS6 = "\xf6"

	// PlmnSpecificSS7 is the octet string constant for plmn-specificSS-7.
	PlmnSpecificSS7 = "\xf7"

	// PlmnSpecificSS8 is the octet string constant for plmn-specificSS-8.
	PlmnSpecificSS8 = "\xf8"

	// PlmnSpecificSS9 is the octet string constant for plmn-specificSS-9.
	PlmnSpecificSS9 = "\xf9"

	// PlmnSpecificSSA is the octet string constant for plmn-specificSS-A.
	PlmnSpecificSSA = "\xfa"

	// PlmnSpecificSSB is the octet string constant for plmn-specificSS-B.
	PlmnSpecificSSB = "\xfb"

	// PlmnSpecificSSC is the octet string constant for plmn-specificSS-C.
	PlmnSpecificSSC = "\xfc"

	// PlmnSpecificSSD is the octet string constant for plmn-specificSS-D.
	PlmnSpecificSSD = "\xfd"

	// PlmnSpecificSSE is the octet string constant for plmn-specificSS-E.
	PlmnSpecificSSE = "\xfe"

	// PlmnSpecificSSF is the octet string constant for plmn-specificSS-F.
	PlmnSpecificSSF = "\xff"

	// AllCallPrioritySS is the octet string constant for allCallPrioritySS.
	AllCallPrioritySS = "\xa0"

	// Emlpp is the octet string constant for emlpp.
	Emlpp = "\xa1"

	// AllLCSPrivacyException is the octet string constant for allLCSPrivacyException.
	AllLCSPrivacyException = "\xb0"

	// Universal is the octet string constant for universal.
	Universal = "\xb1"

	// CallSessionRelated is the octet string constant for callSessionRelated.
	CallSessionRelated = "\xb2"

	// CallSessionUnrelated is the octet string constant for callSessionUnrelated.
	CallSessionUnrelated = "\xb3"

	// Plmnoperator is the octet string constant for plmnoperator.
	Plmnoperator = "\xb4"

	// ServiceTypeValue is the octet string constant for serviceType.
	ServiceTypeValue = "\xb5"

	// AllMOLRSS is the octet string constant for allMOLR-SS.
	AllMOLRSS = "\xc0"

	// BasicSelfLocation is the octet string constant for basicSelfLocation.
	BasicSelfLocation = "\xc1"

	// AutonomousSelfLocation is the octet string constant for autonomousSelfLocation.
	AutonomousSelfLocation = "\xc2"

	// TransferToThirdParty is the octet string constant for transferToThirdParty.
	TransferToThirdParty = "\xc3"
)

// SSCode represents the ASN.1 type SS-Code (OCTET_STRING).
type SSCode = []byte
