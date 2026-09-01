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

	// AllTeleservices is the octet string constant for AllTeleservices.
	AllTeleservices = "\x00"

	// AllSpeechTransmissionServices is the octet string constant for AllSpeechTransmissionServices.
	AllSpeechTransmissionServices = "\x10"

	// Telephony is the octet string constant for Telephony.
	Telephony = "\x11"

	// EmergencyCalls is the octet string constant for EmergencyCalls.
	EmergencyCalls = "\x12"

	// AllShortMessageServices is the octet string constant for AllShortMessageServices.
	AllShortMessageServices = "\x20"

	// ShortMessageMTPP is the octet string constant for ShortMessageMTPP.
	ShortMessageMTPP = "\x21"

	// ShortMessageMOPP is the octet string constant for ShortMessageMOPP.
	ShortMessageMOPP = "\x22"

	// AllFacsimileTransmissionServices is the octet string constant for AllFacsimileTransmissionServices.
	AllFacsimileTransmissionServices = "\x60"

	// FacsimileGroup3AndAlterSpeech is the octet string constant for FacsimileGroup3AndAlterSpeech.
	FacsimileGroup3AndAlterSpeech = "\x61"

	// AutomaticFacsimileGroup3 is the octet string constant for AutomaticFacsimileGroup3.
	AutomaticFacsimileGroup3 = "\x62"

	// FacsimileGroup4 is the octet string constant for FacsimileGroup4.
	FacsimileGroup4 = "\x63"

	// AllDataTeleservices is the octet string constant for AllDataTeleservices.
	AllDataTeleservices = "\x70"

	// AllTeleservicesExeptSMS is the octet string constant for AllTeleservicesExeptSMS.
	AllTeleservicesExeptSMS = "\x80"

	// AllVoiceGroupCallServices is the octet string constant for AllVoiceGroupCallServices.
	AllVoiceGroupCallServices = "\x90"

	// VoiceGroupCall is the octet string constant for VoiceGroupCall.
	VoiceGroupCall = "\x91"

	// VoiceBroadcastCall is the octet string constant for VoiceBroadcastCall.
	VoiceBroadcastCall = "\x92"

	// AllPLMNSpecificTS is the octet string constant for AllPLMNSpecificTS.
	AllPLMNSpecificTS = "\xd0"

	// PlmnSpecificTS1 is the octet string constant for PlmnSpecificTS1.
	PlmnSpecificTS1 = "\xd1"

	// PlmnSpecificTS2 is the octet string constant for PlmnSpecificTS2.
	PlmnSpecificTS2 = "\xd2"

	// PlmnSpecificTS3 is the octet string constant for PlmnSpecificTS3.
	PlmnSpecificTS3 = "\xd3"

	// PlmnSpecificTS4 is the octet string constant for PlmnSpecificTS4.
	PlmnSpecificTS4 = "\xd4"

	// PlmnSpecificTS5 is the octet string constant for PlmnSpecificTS5.
	PlmnSpecificTS5 = "\xd5"

	// PlmnSpecificTS6 is the octet string constant for PlmnSpecificTS6.
	PlmnSpecificTS6 = "\xd6"

	// PlmnSpecificTS7 is the octet string constant for PlmnSpecificTS7.
	PlmnSpecificTS7 = "\xd7"

	// PlmnSpecificTS8 is the octet string constant for PlmnSpecificTS8.
	PlmnSpecificTS8 = "\xd8"

	// PlmnSpecificTS9 is the octet string constant for PlmnSpecificTS9.
	PlmnSpecificTS9 = "\xd9"

	// PlmnSpecificTSA is the octet string constant for PlmnSpecificTSA.
	PlmnSpecificTSA = "\xda"

	// PlmnSpecificTSB is the octet string constant for PlmnSpecificTSB.
	PlmnSpecificTSB = "\xdb"

	// PlmnSpecificTSC is the octet string constant for PlmnSpecificTSC.
	PlmnSpecificTSC = "\xdc"

	// PlmnSpecificTSD is the octet string constant for PlmnSpecificTSD.
	PlmnSpecificTSD = "\xdd"

	// PlmnSpecificTSE is the octet string constant for PlmnSpecificTSE.
	PlmnSpecificTSE = "\xde"

	// PlmnSpecificTSF is the octet string constant for PlmnSpecificTSF.
	PlmnSpecificTSF = "\xdf"
)

// TeleserviceCode represents the ASN.1 type TeleserviceCode (OCTET_STRING).
type TeleserviceCode = []byte

// ExtTeleserviceCode represents the ASN.1 type ExtTeleserviceCode (OCTET_STRING).
type ExtTeleserviceCode = []byte
