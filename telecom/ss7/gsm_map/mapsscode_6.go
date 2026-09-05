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

	// AllSS6 is the octet string constant for allSS.
	AllSS6 = "\x00"

	// AllLineIdentificationSS6 is the octet string constant for allLineIdentificationSS.
	AllLineIdentificationSS6 = "\x10"

	// Clip6 is the octet string constant for clip.
	Clip6 = "\x11"

	// Clir6 is the octet string constant for clir.
	Clir6 = "\x12"

	// Colp6 is the octet string constant for colp.
	Colp6 = "\x13"

	// Colr6 is the octet string constant for colr.
	Colr6 = "\x14"

	// Mci6 is the octet string constant for mci.
	Mci6 = "\x15"

	// AllNameIdentificationSS6 is the octet string constant for allNameIdentificationSS.
	AllNameIdentificationSS6 = "\x18"

	// Cnap6 is the octet string constant for cnap.
	Cnap6 = "\x19"

	// AllForwardingSS6 is the octet string constant for allForwardingSS.
	AllForwardingSS6 = "\x20"

	// Cfu6 is the octet string constant for cfu.
	Cfu6 = "\x21"

	// AllCondForwardingSS6 is the octet string constant for allCondForwardingSS.
	AllCondForwardingSS6 = "\x28"

	// Cfb6 is the octet string constant for cfb.
	Cfb6 = "\x29"

	// Cfnry6 is the octet string constant for cfnry.
	Cfnry6 = "\x2a"

	// Cfnrc6 is the octet string constant for cfnrc.
	Cfnrc6 = "\x2b"

	// Cd6 is the octet string constant for cd.
	Cd6 = "\x24"

	// AllCallOfferingSS6 is the octet string constant for allCallOfferingSS.
	AllCallOfferingSS6 = "\x30"

	// Ect6 is the octet string constant for ect.
	Ect6 = "\x31"

	// Mah6 is the octet string constant for mah.
	Mah6 = "\x32"

	// AllCallCompletionSS6 is the octet string constant for allCallCompletionSS.
	AllCallCompletionSS6 = "\x40"

	// Cw6 is the octet string constant for cw.
	Cw6 = "\x41"

	// Hold6 is the octet string constant for hold.
	Hold6 = "\x42"

	// CcbsA6 is the octet string constant for ccbs-A.
	CcbsA6 = "\x43"

	// CcbsB6 is the octet string constant for ccbs-B.
	CcbsB6 = "\x44"

	// Mc6 is the octet string constant for mc.
	Mc6 = "\x45"

	// AllMultiPartySS6 is the octet string constant for allMultiPartySS.
	AllMultiPartySS6 = "\x50"

	// MultiPTY6 is the octet string constant for multiPTY.
	MultiPTY6 = "\x51"

	// AllCommunityOfInterestSS6 is the octet string constant for allCommunityOfInterest-SS.
	AllCommunityOfInterestSS6 = "\x60"

	// Cug6 is the octet string constant for cug.
	Cug6 = "\x61"

	// AllChargingSS6 is the octet string constant for allChargingSS.
	AllChargingSS6 = "\x70"

	// Aoci6 is the octet string constant for aoci.
	Aoci6 = "\x71"

	// Aocc6 is the octet string constant for aocc.
	Aocc6 = "\x72"

	// AllAdditionalInfoTransferSS6 is the octet string constant for allAdditionalInfoTransferSS.
	AllAdditionalInfoTransferSS6 = "\x80"

	// Uus16 is the octet string constant for uus1.
	Uus16 = "\x81"

	// Uus26 is the octet string constant for uus2.
	Uus26 = "\x82"

	// Uus36 is the octet string constant for uus3.
	Uus36 = "\x83"

	// AllBarringSS6 is the octet string constant for allBarringSS.
	AllBarringSS6 = "\x90"

	// BarringOfOutgoingCalls6 is the octet string constant for barringOfOutgoingCalls.
	BarringOfOutgoingCalls6 = "\x91"

	// Baoc6 is the octet string constant for baoc.
	Baoc6 = "\x92"

	// Boic6 is the octet string constant for boic.
	Boic6 = "\x93"

	// BoicExHC6 is the octet string constant for boicExHC.
	BoicExHC6 = "\x94"

	// BarringOfIncomingCalls6 is the octet string constant for barringOfIncomingCalls.
	BarringOfIncomingCalls6 = "\x99"

	// Baic6 is the octet string constant for baic.
	Baic6 = "\x9a"

	// BicRoam6 is the octet string constant for bicRoam.
	BicRoam6 = "\x9b"

	// AllPLMNSpecificSS6 is the octet string constant for allPLMN-specificSS.
	AllPLMNSpecificSS6 = "\xf0"

	// PlmnSpecificSS16 is the octet string constant for plmn-specificSS-1.
	PlmnSpecificSS16 = "\xf1"

	// PlmnSpecificSS26 is the octet string constant for plmn-specificSS-2.
	PlmnSpecificSS26 = "\xf2"

	// PlmnSpecificSS36 is the octet string constant for plmn-specificSS-3.
	PlmnSpecificSS36 = "\xf3"

	// PlmnSpecificSS46 is the octet string constant for plmn-specificSS-4.
	PlmnSpecificSS46 = "\xf4"

	// PlmnSpecificSS56 is the octet string constant for plmn-specificSS-5.
	PlmnSpecificSS56 = "\xf5"

	// PlmnSpecificSS66 is the octet string constant for plmn-specificSS-6.
	PlmnSpecificSS66 = "\xf6"

	// PlmnSpecificSS76 is the octet string constant for plmn-specificSS-7.
	PlmnSpecificSS76 = "\xf7"

	// PlmnSpecificSS86 is the octet string constant for plmn-specificSS-8.
	PlmnSpecificSS86 = "\xf8"

	// PlmnSpecificSS96 is the octet string constant for plmn-specificSS-9.
	PlmnSpecificSS96 = "\xf9"

	// PlmnSpecificSSA6 is the octet string constant for plmn-specificSS-A.
	PlmnSpecificSSA6 = "\xfa"

	// PlmnSpecificSSB6 is the octet string constant for plmn-specificSS-B.
	PlmnSpecificSSB6 = "\xfb"

	// PlmnSpecificSSC6 is the octet string constant for plmn-specificSS-C.
	PlmnSpecificSSC6 = "\xfc"

	// PlmnSpecificSSD6 is the octet string constant for plmn-specificSS-D.
	PlmnSpecificSSD6 = "\xfd"

	// PlmnSpecificSSE6 is the octet string constant for plmn-specificSS-E.
	PlmnSpecificSSE6 = "\xfe"

	// PlmnSpecificSSF6 is the octet string constant for plmn-specificSS-F.
	PlmnSpecificSSF6 = "\xff"

	// AllCallPrioritySS6 is the octet string constant for allCallPrioritySS.
	AllCallPrioritySS6 = "\xa0"

	// Emlpp6 is the octet string constant for emlpp.
	Emlpp6 = "\xa1"

	// AllLCSPrivacyException6 is the octet string constant for allLCSPrivacyException.
	AllLCSPrivacyException6 = "\xb0"

	// Universal6 is the octet string constant for universal.
	Universal6 = "\xb1"

	// CallSessionRelated6 is the octet string constant for callSessionRelated.
	CallSessionRelated6 = "\xb2"

	// CallSessionUnrelated6 is the octet string constant for callSessionUnrelated.
	CallSessionUnrelated6 = "\xb3"

	// Plmnoperator6 is the octet string constant for plmnoperator.
	Plmnoperator6 = "\xb4"

	// ServiceTypeValue6 is the octet string constant for serviceType.
	ServiceTypeValue6 = "\xb5"

	// AllMOLRSS6 is the octet string constant for allMOLR-SS.
	AllMOLRSS6 = "\xc0"

	// BasicSelfLocation6 is the octet string constant for basicSelfLocation.
	BasicSelfLocation6 = "\xc1"

	// AutonomousSelfLocation6 is the octet string constant for autonomousSelfLocation.
	AutonomousSelfLocation6 = "\xc2"

	// TransferToThirdParty6 is the octet string constant for transferToThirdParty.
	TransferToThirdParty6 = "\xc3"
)

// SSCode6 represents the ASN.1 type SS-Code (OCTET_STRING).
type SSCode6 = []byte
