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

	// SSAllSS is the octet string constant for SSAllSS.
	SSAllSS = "\x00"

	// SSAllLineIdentificationSS is the octet string constant for SSAllLineIdentificationSS.
	SSAllLineIdentificationSS = "\x10"

	// SSClip is the octet string constant for SSClip.
	SSClip = "\x11"

	// SSClir is the octet string constant for SSClir.
	SSClir = "\x12"

	// SSColp is the octet string constant for SSColp.
	SSColp = "\x13"

	// SSColr is the octet string constant for SSColr.
	SSColr = "\x14"

	// SSMci is the octet string constant for SSMci.
	SSMci = "\x15"

	// SSAllNameIdentificationSS is the octet string constant for SSAllNameIdentificationSS.
	SSAllNameIdentificationSS = "\x18"

	// SSCnap is the octet string constant for SSCnap.
	SSCnap = "\x19"

	// SSAllForwardingSS is the octet string constant for SSAllForwardingSS.
	SSAllForwardingSS = "\x20"

	// SSCfu is the octet string constant for SSCfu.
	SSCfu = "\x21"

	// SSAllCondForwardingSS is the octet string constant for SSAllCondForwardingSS.
	SSAllCondForwardingSS = "\x28"

	// SSCfb is the octet string constant for SSCfb.
	SSCfb = "\x29"

	// SSCfnry is the octet string constant for SSCfnry.
	SSCfnry = "\x2a"

	// SSCfnrc is the octet string constant for SSCfnrc.
	SSCfnrc = "\x2b"

	// SSCd is the octet string constant for SSCd.
	SSCd = "\x24"

	// SSAllCallOfferingSS is the octet string constant for SSAllCallOfferingSS.
	SSAllCallOfferingSS = "\x30"

	// SSEct is the octet string constant for SSEct.
	SSEct = "\x31"

	// SSMah is the octet string constant for SSMah.
	SSMah = "\x32"

	// SSAllCallCompletionSS is the octet string constant for SSAllCallCompletionSS.
	SSAllCallCompletionSS = "\x40"

	// SSCw is the octet string constant for SSCw.
	SSCw = "\x41"

	// SSHold is the octet string constant for SSHold.
	SSHold = "\x42"

	// SSCcbsA is the octet string constant for SSCcbsA.
	SSCcbsA = "\x43"

	// SSCcbsB is the octet string constant for SSCcbsB.
	SSCcbsB = "\x44"

	// SSMc is the octet string constant for SSMc.
	SSMc = "\x45"

	// SSAllMultiPartySS is the octet string constant for SSAllMultiPartySS.
	SSAllMultiPartySS = "\x50"

	// SSMultiPTY is the octet string constant for SSMultiPTY.
	SSMultiPTY = "\x51"

	// SSAllCommunityOfInterestSS is the octet string constant for SSAllCommunityOfInterestSS.
	SSAllCommunityOfInterestSS = "\x60"

	// SSCug is the octet string constant for SSCug.
	SSCug = "\x61"

	// SSAllChargingSS is the octet string constant for SSAllChargingSS.
	SSAllChargingSS = "\x70"

	// SSAoci is the octet string constant for SSAoci.
	SSAoci = "\x71"

	// SSAocc is the octet string constant for SSAocc.
	SSAocc = "\x72"

	// SSAllAdditionalInfoTransferSS is the octet string constant for SSAllAdditionalInfoTransferSS.
	SSAllAdditionalInfoTransferSS = "\x80"

	// SSUus1 is the octet string constant for SSUus1.
	SSUus1 = "\x81"

	// SSUus2 is the octet string constant for SSUus2.
	SSUus2 = "\x82"

	// SSUus3 is the octet string constant for SSUus3.
	SSUus3 = "\x83"

	// SSAllBarringSS is the octet string constant for SSAllBarringSS.
	SSAllBarringSS = "\x90"

	// SSBarringOfOutgoingCalls is the octet string constant for SSBarringOfOutgoingCalls.
	SSBarringOfOutgoingCalls = "\x91"

	// SSBaoc is the octet string constant for SSBaoc.
	SSBaoc = "\x92"

	// SSBoic is the octet string constant for SSBoic.
	SSBoic = "\x93"

	// SSBoicExHC is the octet string constant for SSBoicExHC.
	SSBoicExHC = "\x94"

	// SSBarringOfIncomingCalls is the octet string constant for SSBarringOfIncomingCalls.
	SSBarringOfIncomingCalls = "\x99"

	// SSBaic is the octet string constant for SSBaic.
	SSBaic = "\x9a"

	// SSBicRoam is the octet string constant for SSBicRoam.
	SSBicRoam = "\x9b"

	// SSAllPLMNSpecificSS is the octet string constant for SSAllPLMNSpecificSS.
	SSAllPLMNSpecificSS = "\xf0"

	// SSPlmnSpecificSS1 is the octet string constant for SSPlmnSpecificSS1.
	SSPlmnSpecificSS1 = "\xf1"

	// SSPlmnSpecificSS2 is the octet string constant for SSPlmnSpecificSS2.
	SSPlmnSpecificSS2 = "\xf2"

	// SSPlmnSpecificSS3 is the octet string constant for SSPlmnSpecificSS3.
	SSPlmnSpecificSS3 = "\xf3"

	// SSPlmnSpecificSS4 is the octet string constant for SSPlmnSpecificSS4.
	SSPlmnSpecificSS4 = "\xf4"

	// SSPlmnSpecificSS5 is the octet string constant for SSPlmnSpecificSS5.
	SSPlmnSpecificSS5 = "\xf5"

	// SSPlmnSpecificSS6 is the octet string constant for SSPlmnSpecificSS6.
	SSPlmnSpecificSS6 = "\xf6"

	// SSPlmnSpecificSS7 is the octet string constant for SSPlmnSpecificSS7.
	SSPlmnSpecificSS7 = "\xf7"

	// SSPlmnSpecificSS8 is the octet string constant for SSPlmnSpecificSS8.
	SSPlmnSpecificSS8 = "\xf8"

	// SSPlmnSpecificSS9 is the octet string constant for SSPlmnSpecificSS9.
	SSPlmnSpecificSS9 = "\xf9"

	// SSPlmnSpecificSSA is the octet string constant for SSPlmnSpecificSSA.
	SSPlmnSpecificSSA = "\xfa"

	// SSPlmnSpecificSSB is the octet string constant for SSPlmnSpecificSSB.
	SSPlmnSpecificSSB = "\xfb"

	// SSPlmnSpecificSSC is the octet string constant for SSPlmnSpecificSSC.
	SSPlmnSpecificSSC = "\xfc"

	// SSPlmnSpecificSSD is the octet string constant for SSPlmnSpecificSSD.
	SSPlmnSpecificSSD = "\xfd"

	// SSPlmnSpecificSSE is the octet string constant for SSPlmnSpecificSSE.
	SSPlmnSpecificSSE = "\xfe"

	// SSPlmnSpecificSSF is the octet string constant for SSPlmnSpecificSSF.
	SSPlmnSpecificSSF = "\xff"

	// SSAllCallPrioritySS is the octet string constant for SSAllCallPrioritySS.
	SSAllCallPrioritySS = "\xa0"

	// SSEmlpp is the octet string constant for SSEmlpp.
	SSEmlpp = "\xa1"

	// SSAllLCSPrivacyException is the octet string constant for SSAllLCSPrivacyException.
	SSAllLCSPrivacyException = "\xb0"

	// SSUniversal is the octet string constant for SSUniversal.
	SSUniversal = "\xb1"

	// SSCallSessionRelated is the octet string constant for SSCallSessionRelated.
	SSCallSessionRelated = "\xb2"

	// SSCallSessionUnrelated is the octet string constant for SSCallSessionUnrelated.
	SSCallSessionUnrelated = "\xb3"

	// SSPlmnoperator is the octet string constant for SSPlmnoperator.
	SSPlmnoperator = "\xb4"

	// SSServiceTypeValue is the octet string constant for SSServiceTypeValue.
	SSServiceTypeValue = "\xb5"

	// SSAllMOLRSS is the octet string constant for SSAllMOLRSS.
	SSAllMOLRSS = "\xc0"

	// SSBasicSelfLocation is the octet string constant for SSBasicSelfLocation.
	SSBasicSelfLocation = "\xc1"

	// SSAutonomousSelfLocation is the octet string constant for SSAutonomousSelfLocation.
	SSAutonomousSelfLocation = "\xc2"

	// SSTransferToThirdParty is the octet string constant for SSTransferToThirdParty.
	SSTransferToThirdParty = "\xc3"
)

// SSSSCode represents the ASN.1 type SSSSCode (OCTET_STRING).
type SSSSCode = []byte
