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

	// TSAllTeleservices is the octet string constant for TSAllTeleservices.
	TSAllTeleservices = "\x00"

	// TSAllSpeechTransmissionServices is the octet string constant for TSAllSpeechTransmissionServices.
	TSAllSpeechTransmissionServices = "\x10"

	// TSTelephony is the octet string constant for TSTelephony.
	TSTelephony = "\x11"

	// TSEmergencyCalls is the octet string constant for TSEmergencyCalls.
	TSEmergencyCalls = "\x12"

	// TSAllShortMessageServices is the octet string constant for TSAllShortMessageServices.
	TSAllShortMessageServices = "\x20"

	// TSShortMessageMTPP is the octet string constant for TSShortMessageMTPP.
	TSShortMessageMTPP = "\x21"

	// TSShortMessageMOPP is the octet string constant for TSShortMessageMOPP.
	TSShortMessageMOPP = "\x22"

	// TSAllFacsimileTransmissionServices is the octet string constant for TSAllFacsimileTransmissionServices.
	TSAllFacsimileTransmissionServices = "\x60"

	// TSFacsimileGroup3AndAlterSpeech is the octet string constant for TSFacsimileGroup3AndAlterSpeech.
	TSFacsimileGroup3AndAlterSpeech = "\x61"

	// TSAutomaticFacsimileGroup3 is the octet string constant for TSAutomaticFacsimileGroup3.
	TSAutomaticFacsimileGroup3 = "\x62"

	// TSFacsimileGroup4 is the octet string constant for TSFacsimileGroup4.
	TSFacsimileGroup4 = "\x63"

	// TSAllDataTeleservices is the octet string constant for TSAllDataTeleservices.
	TSAllDataTeleservices = "\x70"

	// TSAllTeleservicesExeptSMS is the octet string constant for TSAllTeleservicesExeptSMS.
	TSAllTeleservicesExeptSMS = "\x80"

	// TSAllVoiceGroupCallServices is the octet string constant for TSAllVoiceGroupCallServices.
	TSAllVoiceGroupCallServices = "\x90"

	// TSVoiceGroupCall is the octet string constant for TSVoiceGroupCall.
	TSVoiceGroupCall = "\x91"

	// TSVoiceBroadcastCall is the octet string constant for TSVoiceBroadcastCall.
	TSVoiceBroadcastCall = "\x92"

	// TSAllPLMNSpecificTS is the octet string constant for TSAllPLMNSpecificTS.
	TSAllPLMNSpecificTS = "\xd0"

	// TSPlmnSpecificTS1 is the octet string constant for TSPlmnSpecificTS1.
	TSPlmnSpecificTS1 = "\xd1"

	// TSPlmnSpecificTS2 is the octet string constant for TSPlmnSpecificTS2.
	TSPlmnSpecificTS2 = "\xd2"

	// TSPlmnSpecificTS3 is the octet string constant for TSPlmnSpecificTS3.
	TSPlmnSpecificTS3 = "\xd3"

	// TSPlmnSpecificTS4 is the octet string constant for TSPlmnSpecificTS4.
	TSPlmnSpecificTS4 = "\xd4"

	// TSPlmnSpecificTS5 is the octet string constant for TSPlmnSpecificTS5.
	TSPlmnSpecificTS5 = "\xd5"

	// TSPlmnSpecificTS6 is the octet string constant for TSPlmnSpecificTS6.
	TSPlmnSpecificTS6 = "\xd6"

	// TSPlmnSpecificTS7 is the octet string constant for TSPlmnSpecificTS7.
	TSPlmnSpecificTS7 = "\xd7"

	// TSPlmnSpecificTS8 is the octet string constant for TSPlmnSpecificTS8.
	TSPlmnSpecificTS8 = "\xd8"

	// TSPlmnSpecificTS9 is the octet string constant for TSPlmnSpecificTS9.
	TSPlmnSpecificTS9 = "\xd9"

	// TSPlmnSpecificTSA is the octet string constant for TSPlmnSpecificTSA.
	TSPlmnSpecificTSA = "\xda"

	// TSPlmnSpecificTSB is the octet string constant for TSPlmnSpecificTSB.
	TSPlmnSpecificTSB = "\xdb"

	// TSPlmnSpecificTSC is the octet string constant for TSPlmnSpecificTSC.
	TSPlmnSpecificTSC = "\xdc"

	// TSPlmnSpecificTSD is the octet string constant for TSPlmnSpecificTSD.
	TSPlmnSpecificTSD = "\xdd"

	// TSPlmnSpecificTSE is the octet string constant for TSPlmnSpecificTSE.
	TSPlmnSpecificTSE = "\xde"

	// TSPlmnSpecificTSF is the octet string constant for TSPlmnSpecificTSF.
	TSPlmnSpecificTSF = "\xdf"
)

// TSTeleserviceCode represents the ASN.1 type TeleserviceCode (OCTET_STRING).
type TSTeleserviceCode = []byte

// TSExtTeleserviceCode represents the ASN.1 type Ext-TeleserviceCode (OCTET_STRING).
type TSExtTeleserviceCode = []byte
