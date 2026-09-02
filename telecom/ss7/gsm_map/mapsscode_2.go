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

	// SSAllSS is the octet string constant for allSS.
	SSAllSS = "\x00"

	// SSAllLineIdentificationSS is the octet string constant for allLineIdentificationSS.
	SSAllLineIdentificationSS = "\x10"

	// SSClip is the octet string constant for clip.
	SSClip = "\x11"

	// SSClir is the octet string constant for clir.
	SSClir = "\x12"

	// SSColp is the octet string constant for colp.
	SSColp = "\x13"

	// SSColr is the octet string constant for colr.
	SSColr = "\x14"

	// SSMci is the octet string constant for mci.
	SSMci = "\x15"

	// SSAllNameIdentificationSS is the octet string constant for allNameIdentificationSS.
	SSAllNameIdentificationSS = "\x18"

	// SSCnap is the octet string constant for cnap.
	SSCnap = "\x19"

	// SSAllForwardingSS is the octet string constant for allForwardingSS.
	SSAllForwardingSS = "\x20"

	// SSCfu is the octet string constant for cfu.
	SSCfu = "\x21"

	// SSAllCondForwardingSS is the octet string constant for allCondForwardingSS.
	SSAllCondForwardingSS = "\x28"

	// SSCfb is the octet string constant for cfb.
	SSCfb = "\x29"

	// SSCfnry is the octet string constant for cfnry.
	SSCfnry = "\x2a"

	// SSCfnrc is the octet string constant for cfnrc.
	SSCfnrc = "\x2b"

	// SSCd is the octet string constant for cd.
	SSCd = "\x24"

	// SSAllCallOfferingSS is the octet string constant for allCallOfferingSS.
	SSAllCallOfferingSS = "\x30"

	// SSEct is the octet string constant for ect.
	SSEct = "\x31"

	// SSMah is the octet string constant for mah.
	SSMah = "\x32"

	// SSAllCallCompletionSS is the octet string constant for allCallCompletionSS.
	SSAllCallCompletionSS = "\x40"

	// SSCw is the octet string constant for cw.
	SSCw = "\x41"

	// SSHold is the octet string constant for hold.
	SSHold = "\x42"

	// SSCcbsA is the octet string constant for ccbs-A.
	SSCcbsA = "\x43"

	// SSCcbsB is the octet string constant for ccbs-B.
	SSCcbsB = "\x44"

	// SSMc is the octet string constant for mc.
	SSMc = "\x45"

	// SSAllMultiPartySS is the octet string constant for allMultiPartySS.
	SSAllMultiPartySS = "\x50"

	// SSMultiPTY is the octet string constant for multiPTY.
	SSMultiPTY = "\x51"

	// SSAllCommunityOfInterestSS is the octet string constant for allCommunityOfInterest-SS.
	SSAllCommunityOfInterestSS = "\x60"

	// SSCug is the octet string constant for cug.
	SSCug = "\x61"

	// SSAllChargingSS is the octet string constant for allChargingSS.
	SSAllChargingSS = "\x70"

	// SSAoci is the octet string constant for aoci.
	SSAoci = "\x71"

	// SSAocc is the octet string constant for aocc.
	SSAocc = "\x72"

	// SSAllAdditionalInfoTransferSS is the octet string constant for allAdditionalInfoTransferSS.
	SSAllAdditionalInfoTransferSS = "\x80"

	// SSUus1 is the octet string constant for uus1.
	SSUus1 = "\x81"

	// SSUus2 is the octet string constant for uus2.
	SSUus2 = "\x82"

	// SSUus3 is the octet string constant for uus3.
	SSUus3 = "\x83"

	// SSAllBarringSS is the octet string constant for allBarringSS.
	SSAllBarringSS = "\x90"

	// SSBarringOfOutgoingCalls is the octet string constant for barringOfOutgoingCalls.
	SSBarringOfOutgoingCalls = "\x91"

	// SSBaoc is the octet string constant for baoc.
	SSBaoc = "\x92"

	// SSBoic is the octet string constant for boic.
	SSBoic = "\x93"

	// SSBoicExHC is the octet string constant for boicExHC.
	SSBoicExHC = "\x94"

	// SSBarringOfIncomingCalls is the octet string constant for barringOfIncomingCalls.
	SSBarringOfIncomingCalls = "\x99"

	// SSBaic is the octet string constant for baic.
	SSBaic = "\x9a"

	// SSBicRoam is the octet string constant for bicRoam.
	SSBicRoam = "\x9b"

	// SSAllPLMNSpecificSS is the octet string constant for allPLMN-specificSS.
	SSAllPLMNSpecificSS = "\xf0"

	// SSPlmnSpecificSS1 is the octet string constant for plmn-specificSS-1.
	SSPlmnSpecificSS1 = "\xf1"

	// SSPlmnSpecificSS2 is the octet string constant for plmn-specificSS-2.
	SSPlmnSpecificSS2 = "\xf2"

	// SSPlmnSpecificSS3 is the octet string constant for plmn-specificSS-3.
	SSPlmnSpecificSS3 = "\xf3"

	// SSPlmnSpecificSS4 is the octet string constant for plmn-specificSS-4.
	SSPlmnSpecificSS4 = "\xf4"

	// SSPlmnSpecificSS5 is the octet string constant for plmn-specificSS-5.
	SSPlmnSpecificSS5 = "\xf5"

	// SSPlmnSpecificSS6 is the octet string constant for plmn-specificSS-6.
	SSPlmnSpecificSS6 = "\xf6"

	// SSPlmnSpecificSS7 is the octet string constant for plmn-specificSS-7.
	SSPlmnSpecificSS7 = "\xf7"

	// SSPlmnSpecificSS8 is the octet string constant for plmn-specificSS-8.
	SSPlmnSpecificSS8 = "\xf8"

	// SSPlmnSpecificSS9 is the octet string constant for plmn-specificSS-9.
	SSPlmnSpecificSS9 = "\xf9"

	// SSPlmnSpecificSSA is the octet string constant for plmn-specificSS-A.
	SSPlmnSpecificSSA = "\xfa"

	// SSPlmnSpecificSSB is the octet string constant for plmn-specificSS-B.
	SSPlmnSpecificSSB = "\xfb"

	// SSPlmnSpecificSSC is the octet string constant for plmn-specificSS-C.
	SSPlmnSpecificSSC = "\xfc"

	// SSPlmnSpecificSSD is the octet string constant for plmn-specificSS-D.
	SSPlmnSpecificSSD = "\xfd"

	// SSPlmnSpecificSSE is the octet string constant for plmn-specificSS-E.
	SSPlmnSpecificSSE = "\xfe"

	// SSPlmnSpecificSSF is the octet string constant for plmn-specificSS-F.
	SSPlmnSpecificSSF = "\xff"

	// SSAllCallPrioritySS is the octet string constant for allCallPrioritySS.
	SSAllCallPrioritySS = "\xa0"

	// SSEmlpp is the octet string constant for emlpp.
	SSEmlpp = "\xa1"

	// SSAllLCSPrivacyException is the octet string constant for allLCSPrivacyException.
	SSAllLCSPrivacyException = "\xb0"

	// SSUniversal is the octet string constant for universal.
	SSUniversal = "\xb1"

	// SSCallSessionRelated is the octet string constant for callSessionRelated.
	SSCallSessionRelated = "\xb2"

	// SSCallSessionUnrelated is the octet string constant for callSessionUnrelated.
	SSCallSessionUnrelated = "\xb3"

	// SSPlmnoperator is the octet string constant for plmnoperator.
	SSPlmnoperator = "\xb4"

	// SSServiceTypeValue is the octet string constant for serviceType.
	SSServiceTypeValue = "\xb5"

	// SSAllMOLRSS is the octet string constant for allMOLR-SS.
	SSAllMOLRSS = "\xc0"

	// SSBasicSelfLocation is the octet string constant for basicSelfLocation.
	SSBasicSelfLocation = "\xc1"

	// SSAutonomousSelfLocation is the octet string constant for autonomousSelfLocation.
	SSAutonomousSelfLocation = "\xc2"

	// SSTransferToThirdParty is the octet string constant for transferToThirdParty.
	SSTransferToThirdParty = "\xc3"
)

// SSSSCode represents the ASN.1 type SS-Code (OCTET_STRING).
type SSSSCode = []byte
