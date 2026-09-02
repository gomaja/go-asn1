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

	// AllSS3 is the octet string constant for allSS.
	AllSS3 = "\x00"

	// AllLineIdentificationSS3 is the octet string constant for allLineIdentificationSS.
	AllLineIdentificationSS3 = "\x10"

	// Clip3 is the octet string constant for clip.
	Clip3 = "\x11"

	// Clir3 is the octet string constant for clir.
	Clir3 = "\x12"

	// Colp3 is the octet string constant for colp.
	Colp3 = "\x13"

	// Colr3 is the octet string constant for colr.
	Colr3 = "\x14"

	// Mci3 is the octet string constant for mci.
	Mci3 = "\x15"

	// AllNameIdentificationSS3 is the octet string constant for allNameIdentificationSS.
	AllNameIdentificationSS3 = "\x18"

	// Cnap3 is the octet string constant for cnap.
	Cnap3 = "\x19"

	// AllForwardingSS3 is the octet string constant for allForwardingSS.
	AllForwardingSS3 = "\x20"

	// Cfu3 is the octet string constant for cfu.
	Cfu3 = "\x21"

	// AllCondForwardingSS3 is the octet string constant for allCondForwardingSS.
	AllCondForwardingSS3 = "\x28"

	// Cfb3 is the octet string constant for cfb.
	Cfb3 = "\x29"

	// Cfnry3 is the octet string constant for cfnry.
	Cfnry3 = "\x2a"

	// Cfnrc3 is the octet string constant for cfnrc.
	Cfnrc3 = "\x2b"

	// Cd3 is the octet string constant for cd.
	Cd3 = "\x24"

	// AllCallOfferingSS3 is the octet string constant for allCallOfferingSS.
	AllCallOfferingSS3 = "\x30"

	// Ect3 is the octet string constant for ect.
	Ect3 = "\x31"

	// Mah3 is the octet string constant for mah.
	Mah3 = "\x32"

	// AllCallCompletionSS3 is the octet string constant for allCallCompletionSS.
	AllCallCompletionSS3 = "\x40"

	// Cw3 is the octet string constant for cw.
	Cw3 = "\x41"

	// Hold3 is the octet string constant for hold.
	Hold3 = "\x42"

	// CcbsA3 is the octet string constant for ccbs-A.
	CcbsA3 = "\x43"

	// CcbsB3 is the octet string constant for ccbs-B.
	CcbsB3 = "\x44"

	// Mc3 is the octet string constant for mc.
	Mc3 = "\x45"

	// AllMultiPartySS3 is the octet string constant for allMultiPartySS.
	AllMultiPartySS3 = "\x50"

	// MultiPTY3 is the octet string constant for multiPTY.
	MultiPTY3 = "\x51"

	// AllCommunityOfInterestSS3 is the octet string constant for allCommunityOfInterest-SS.
	AllCommunityOfInterestSS3 = "\x60"

	// Cug3 is the octet string constant for cug.
	Cug3 = "\x61"

	// AllChargingSS3 is the octet string constant for allChargingSS.
	AllChargingSS3 = "\x70"

	// Aoci3 is the octet string constant for aoci.
	Aoci3 = "\x71"

	// Aocc3 is the octet string constant for aocc.
	Aocc3 = "\x72"

	// AllAdditionalInfoTransferSS3 is the octet string constant for allAdditionalInfoTransferSS.
	AllAdditionalInfoTransferSS3 = "\x80"

	// Uus13 is the octet string constant for uus1.
	Uus13 = "\x81"

	// Uus23 is the octet string constant for uus2.
	Uus23 = "\x82"

	// Uus33 is the octet string constant for uus3.
	Uus33 = "\x83"

	// AllBarringSS3 is the octet string constant for allBarringSS.
	AllBarringSS3 = "\x90"

	// BarringOfOutgoingCalls3 is the octet string constant for barringOfOutgoingCalls.
	BarringOfOutgoingCalls3 = "\x91"

	// Baoc3 is the octet string constant for baoc.
	Baoc3 = "\x92"

	// Boic3 is the octet string constant for boic.
	Boic3 = "\x93"

	// BoicExHC3 is the octet string constant for boicExHC.
	BoicExHC3 = "\x94"

	// BarringOfIncomingCalls3 is the octet string constant for barringOfIncomingCalls.
	BarringOfIncomingCalls3 = "\x99"

	// Baic3 is the octet string constant for baic.
	Baic3 = "\x9a"

	// BicRoam3 is the octet string constant for bicRoam.
	BicRoam3 = "\x9b"

	// AllPLMNSpecificSS3 is the octet string constant for allPLMN-specificSS.
	AllPLMNSpecificSS3 = "\xf0"

	// PlmnSpecificSS13 is the octet string constant for plmn-specificSS-1.
	PlmnSpecificSS13 = "\xf1"

	// PlmnSpecificSS23 is the octet string constant for plmn-specificSS-2.
	PlmnSpecificSS23 = "\xf2"

	// PlmnSpecificSS33 is the octet string constant for plmn-specificSS-3.
	PlmnSpecificSS33 = "\xf3"

	// PlmnSpecificSS43 is the octet string constant for plmn-specificSS-4.
	PlmnSpecificSS43 = "\xf4"

	// PlmnSpecificSS53 is the octet string constant for plmn-specificSS-5.
	PlmnSpecificSS53 = "\xf5"

	// PlmnSpecificSS63 is the octet string constant for plmn-specificSS-6.
	PlmnSpecificSS63 = "\xf6"

	// PlmnSpecificSS73 is the octet string constant for plmn-specificSS-7.
	PlmnSpecificSS73 = "\xf7"

	// PlmnSpecificSS83 is the octet string constant for plmn-specificSS-8.
	PlmnSpecificSS83 = "\xf8"

	// PlmnSpecificSS93 is the octet string constant for plmn-specificSS-9.
	PlmnSpecificSS93 = "\xf9"

	// PlmnSpecificSSA3 is the octet string constant for plmn-specificSS-A.
	PlmnSpecificSSA3 = "\xfa"

	// PlmnSpecificSSB3 is the octet string constant for plmn-specificSS-B.
	PlmnSpecificSSB3 = "\xfb"

	// PlmnSpecificSSC3 is the octet string constant for plmn-specificSS-C.
	PlmnSpecificSSC3 = "\xfc"

	// PlmnSpecificSSD3 is the octet string constant for plmn-specificSS-D.
	PlmnSpecificSSD3 = "\xfd"

	// PlmnSpecificSSE3 is the octet string constant for plmn-specificSS-E.
	PlmnSpecificSSE3 = "\xfe"

	// PlmnSpecificSSF3 is the octet string constant for plmn-specificSS-F.
	PlmnSpecificSSF3 = "\xff"

	// AllCallPrioritySS3 is the octet string constant for allCallPrioritySS.
	AllCallPrioritySS3 = "\xa0"

	// Emlpp3 is the octet string constant for emlpp.
	Emlpp3 = "\xa1"

	// AllLCSPrivacyException3 is the octet string constant for allLCSPrivacyException.
	AllLCSPrivacyException3 = "\xb0"

	// Universal3 is the octet string constant for universal.
	Universal3 = "\xb1"

	// CallSessionRelated3 is the octet string constant for callSessionRelated.
	CallSessionRelated3 = "\xb2"

	// CallSessionUnrelated3 is the octet string constant for callSessionUnrelated.
	CallSessionUnrelated3 = "\xb3"

	// Plmnoperator3 is the octet string constant for plmnoperator.
	Plmnoperator3 = "\xb4"

	// ServiceTypeValue3 is the octet string constant for serviceType.
	ServiceTypeValue3 = "\xb5"

	// AllMOLRSS3 is the octet string constant for allMOLR-SS.
	AllMOLRSS3 = "\xc0"

	// BasicSelfLocation3 is the octet string constant for basicSelfLocation.
	BasicSelfLocation3 = "\xc1"

	// AutonomousSelfLocation3 is the octet string constant for autonomousSelfLocation.
	AutonomousSelfLocation3 = "\xc2"

	// TransferToThirdParty3 is the octet string constant for transferToThirdParty.
	TransferToThirdParty3 = "\xc3"
)

// SSCode3 represents the ASN.1 type SS-Code (OCTET_STRING).
type SSCode3 = []byte
