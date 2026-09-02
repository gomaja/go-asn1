// Code generated from ASN.1 module "MAP-TS-Code". DO NOT EDIT.

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

	// TSAllTeleservices is the octet string constant for allTeleservices.
	TSAllTeleservices = "\x00"

	// TSAllSpeechTransmissionServices is the octet string constant for allSpeechTransmissionServices.
	TSAllSpeechTransmissionServices = "\x10"

	// TSTelephony is the octet string constant for telephony.
	TSTelephony = "\x11"

	// TSEmergencyCalls is the octet string constant for emergencyCalls.
	TSEmergencyCalls = "\x12"

	// TSAllShortMessageServices is the octet string constant for allShortMessageServices.
	TSAllShortMessageServices = "\x20"

	// TSShortMessageMTPP is the octet string constant for shortMessageMT-PP.
	TSShortMessageMTPP = "\x21"

	// TSShortMessageMOPP is the octet string constant for shortMessageMO-PP.
	TSShortMessageMOPP = "\x22"

	// TSAllFacsimileTransmissionServices is the octet string constant for allFacsimileTransmissionServices.
	TSAllFacsimileTransmissionServices = "\x60"

	// TSFacsimileGroup3AndAlterSpeech is the octet string constant for facsimileGroup3AndAlterSpeech.
	TSFacsimileGroup3AndAlterSpeech = "\x61"

	// TSAutomaticFacsimileGroup3 is the octet string constant for automaticFacsimileGroup3.
	TSAutomaticFacsimileGroup3 = "\x62"

	// TSFacsimileGroup4 is the octet string constant for facsimileGroup4.
	TSFacsimileGroup4 = "\x63"

	// TSAllDataTeleservices is the octet string constant for allDataTeleservices.
	TSAllDataTeleservices = "\x70"

	// TSAllTeleservicesExeptSMS is the octet string constant for allTeleservices-ExeptSMS.
	TSAllTeleservicesExeptSMS = "\x80"

	// TSAllVoiceGroupCallServices is the octet string constant for allVoiceGroupCallServices.
	TSAllVoiceGroupCallServices = "\x90"

	// TSVoiceGroupCall is the octet string constant for voiceGroupCall.
	TSVoiceGroupCall = "\x91"

	// TSVoiceBroadcastCall is the octet string constant for voiceBroadcastCall.
	TSVoiceBroadcastCall = "\x92"

	// TSAllPLMNSpecificTS is the octet string constant for allPLMN-specificTS.
	TSAllPLMNSpecificTS = "\xd0"

	// TSPlmnSpecificTS1 is the octet string constant for plmn-specificTS-1.
	TSPlmnSpecificTS1 = "\xd1"

	// TSPlmnSpecificTS2 is the octet string constant for plmn-specificTS-2.
	TSPlmnSpecificTS2 = "\xd2"

	// TSPlmnSpecificTS3 is the octet string constant for plmn-specificTS-3.
	TSPlmnSpecificTS3 = "\xd3"

	// TSPlmnSpecificTS4 is the octet string constant for plmn-specificTS-4.
	TSPlmnSpecificTS4 = "\xd4"

	// TSPlmnSpecificTS5 is the octet string constant for plmn-specificTS-5.
	TSPlmnSpecificTS5 = "\xd5"

	// TSPlmnSpecificTS6 is the octet string constant for plmn-specificTS-6.
	TSPlmnSpecificTS6 = "\xd6"

	// TSPlmnSpecificTS7 is the octet string constant for plmn-specificTS-7.
	TSPlmnSpecificTS7 = "\xd7"

	// TSPlmnSpecificTS8 is the octet string constant for plmn-specificTS-8.
	TSPlmnSpecificTS8 = "\xd8"

	// TSPlmnSpecificTS9 is the octet string constant for plmn-specificTS-9.
	TSPlmnSpecificTS9 = "\xd9"

	// TSPlmnSpecificTSA is the octet string constant for plmn-specificTS-A.
	TSPlmnSpecificTSA = "\xda"

	// TSPlmnSpecificTSB is the octet string constant for plmn-specificTS-B.
	TSPlmnSpecificTSB = "\xdb"

	// TSPlmnSpecificTSC is the octet string constant for plmn-specificTS-C.
	TSPlmnSpecificTSC = "\xdc"

	// TSPlmnSpecificTSD is the octet string constant for plmn-specificTS-D.
	TSPlmnSpecificTSD = "\xdd"

	// TSPlmnSpecificTSE is the octet string constant for plmn-specificTS-E.
	TSPlmnSpecificTSE = "\xde"

	// TSPlmnSpecificTSF is the octet string constant for plmn-specificTS-F.
	TSPlmnSpecificTSF = "\xdf"
)

// TSTeleserviceCode represents the ASN.1 type TeleserviceCode (OCTET_STRING).
type TSTeleserviceCode = []byte

// TSExtTeleserviceCode represents the ASN.1 type Ext-TeleserviceCode (OCTET_STRING).
type TSExtTeleserviceCode = []byte
