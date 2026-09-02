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

	// AllSS5 is the octet string constant for allSS.
	AllSS5 = "\x00"

	// AllLineIdentificationSS5 is the octet string constant for allLineIdentificationSS.
	AllLineIdentificationSS5 = "\x10"

	// Clip5 is the octet string constant for clip.
	Clip5 = "\x11"

	// Clir5 is the octet string constant for clir.
	Clir5 = "\x12"

	// Colp5 is the octet string constant for colp.
	Colp5 = "\x13"

	// Colr5 is the octet string constant for colr.
	Colr5 = "\x14"

	// Mci5 is the octet string constant for mci.
	Mci5 = "\x15"

	// AllNameIdentificationSS5 is the octet string constant for allNameIdentificationSS.
	AllNameIdentificationSS5 = "\x18"

	// Cnap5 is the octet string constant for cnap.
	Cnap5 = "\x19"

	// AllForwardingSS5 is the octet string constant for allForwardingSS.
	AllForwardingSS5 = "\x20"

	// Cfu5 is the octet string constant for cfu.
	Cfu5 = "\x21"

	// AllCondForwardingSS5 is the octet string constant for allCondForwardingSS.
	AllCondForwardingSS5 = "\x28"

	// Cfb5 is the octet string constant for cfb.
	Cfb5 = "\x29"

	// Cfnry5 is the octet string constant for cfnry.
	Cfnry5 = "\x2a"

	// Cfnrc5 is the octet string constant for cfnrc.
	Cfnrc5 = "\x2b"

	// Cd5 is the octet string constant for cd.
	Cd5 = "\x24"

	// AllCallOfferingSS5 is the octet string constant for allCallOfferingSS.
	AllCallOfferingSS5 = "\x30"

	// Ect5 is the octet string constant for ect.
	Ect5 = "\x31"

	// Mah5 is the octet string constant for mah.
	Mah5 = "\x32"

	// AllCallCompletionSS5 is the octet string constant for allCallCompletionSS.
	AllCallCompletionSS5 = "\x40"

	// Cw5 is the octet string constant for cw.
	Cw5 = "\x41"

	// Hold5 is the octet string constant for hold.
	Hold5 = "\x42"

	// CcbsA5 is the octet string constant for ccbs-A.
	CcbsA5 = "\x43"

	// CcbsB5 is the octet string constant for ccbs-B.
	CcbsB5 = "\x44"

	// Mc5 is the octet string constant for mc.
	Mc5 = "\x45"

	// AllMultiPartySS5 is the octet string constant for allMultiPartySS.
	AllMultiPartySS5 = "\x50"

	// MultiPTY5 is the octet string constant for multiPTY.
	MultiPTY5 = "\x51"

	// AllCommunityOfInterestSS5 is the octet string constant for allCommunityOfInterest-SS.
	AllCommunityOfInterestSS5 = "\x60"

	// Cug5 is the octet string constant for cug.
	Cug5 = "\x61"

	// AllChargingSS5 is the octet string constant for allChargingSS.
	AllChargingSS5 = "\x70"

	// Aoci5 is the octet string constant for aoci.
	Aoci5 = "\x71"

	// Aocc5 is the octet string constant for aocc.
	Aocc5 = "\x72"

	// AllAdditionalInfoTransferSS5 is the octet string constant for allAdditionalInfoTransferSS.
	AllAdditionalInfoTransferSS5 = "\x80"

	// Uus15 is the octet string constant for uus1.
	Uus15 = "\x81"

	// Uus25 is the octet string constant for uus2.
	Uus25 = "\x82"

	// Uus35 is the octet string constant for uus3.
	Uus35 = "\x83"

	// AllBarringSS5 is the octet string constant for allBarringSS.
	AllBarringSS5 = "\x90"

	// BarringOfOutgoingCalls5 is the octet string constant for barringOfOutgoingCalls.
	BarringOfOutgoingCalls5 = "\x91"

	// Baoc5 is the octet string constant for baoc.
	Baoc5 = "\x92"

	// Boic5 is the octet string constant for boic.
	Boic5 = "\x93"

	// BoicExHC5 is the octet string constant for boicExHC.
	BoicExHC5 = "\x94"

	// BarringOfIncomingCalls5 is the octet string constant for barringOfIncomingCalls.
	BarringOfIncomingCalls5 = "\x99"

	// Baic5 is the octet string constant for baic.
	Baic5 = "\x9a"

	// BicRoam5 is the octet string constant for bicRoam.
	BicRoam5 = "\x9b"

	// AllPLMNSpecificSS5 is the octet string constant for allPLMN-specificSS.
	AllPLMNSpecificSS5 = "\xf0"

	// PlmnSpecificSS15 is the octet string constant for plmn-specificSS-1.
	PlmnSpecificSS15 = "\xf1"

	// PlmnSpecificSS25 is the octet string constant for plmn-specificSS-2.
	PlmnSpecificSS25 = "\xf2"

	// PlmnSpecificSS35 is the octet string constant for plmn-specificSS-3.
	PlmnSpecificSS35 = "\xf3"

	// PlmnSpecificSS45 is the octet string constant for plmn-specificSS-4.
	PlmnSpecificSS45 = "\xf4"

	// PlmnSpecificSS55 is the octet string constant for plmn-specificSS-5.
	PlmnSpecificSS55 = "\xf5"

	// PlmnSpecificSS65 is the octet string constant for plmn-specificSS-6.
	PlmnSpecificSS65 = "\xf6"

	// PlmnSpecificSS75 is the octet string constant for plmn-specificSS-7.
	PlmnSpecificSS75 = "\xf7"

	// PlmnSpecificSS85 is the octet string constant for plmn-specificSS-8.
	PlmnSpecificSS85 = "\xf8"

	// PlmnSpecificSS95 is the octet string constant for plmn-specificSS-9.
	PlmnSpecificSS95 = "\xf9"

	// PlmnSpecificSSA5 is the octet string constant for plmn-specificSS-A.
	PlmnSpecificSSA5 = "\xfa"

	// PlmnSpecificSSB5 is the octet string constant for plmn-specificSS-B.
	PlmnSpecificSSB5 = "\xfb"

	// PlmnSpecificSSC5 is the octet string constant for plmn-specificSS-C.
	PlmnSpecificSSC5 = "\xfc"

	// PlmnSpecificSSD5 is the octet string constant for plmn-specificSS-D.
	PlmnSpecificSSD5 = "\xfd"

	// PlmnSpecificSSE5 is the octet string constant for plmn-specificSS-E.
	PlmnSpecificSSE5 = "\xfe"

	// PlmnSpecificSSF5 is the octet string constant for plmn-specificSS-F.
	PlmnSpecificSSF5 = "\xff"

	// AllCallPrioritySS5 is the octet string constant for allCallPrioritySS.
	AllCallPrioritySS5 = "\xa0"

	// Emlpp5 is the octet string constant for emlpp.
	Emlpp5 = "\xa1"

	// AllLCSPrivacyException5 is the octet string constant for allLCSPrivacyException.
	AllLCSPrivacyException5 = "\xb0"

	// Universal5 is the octet string constant for universal.
	Universal5 = "\xb1"

	// CallSessionRelated5 is the octet string constant for callSessionRelated.
	CallSessionRelated5 = "\xb2"

	// CallSessionUnrelated5 is the octet string constant for callSessionUnrelated.
	CallSessionUnrelated5 = "\xb3"

	// Plmnoperator5 is the octet string constant for plmnoperator.
	Plmnoperator5 = "\xb4"

	// ServiceTypeValue5 is the octet string constant for serviceType.
	ServiceTypeValue5 = "\xb5"

	// AllMOLRSS5 is the octet string constant for allMOLR-SS.
	AllMOLRSS5 = "\xc0"

	// BasicSelfLocation5 is the octet string constant for basicSelfLocation.
	BasicSelfLocation5 = "\xc1"

	// AutonomousSelfLocation5 is the octet string constant for autonomousSelfLocation.
	AutonomousSelfLocation5 = "\xc2"

	// TransferToThirdParty5 is the octet string constant for transferToThirdParty.
	TransferToThirdParty5 = "\xc3"
)

// SSCode5 represents the ASN.1 type SS-Code (OCTET_STRING).
type SSCode5 = []byte
