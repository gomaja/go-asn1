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

	// AllTeleservices4 is the octet string constant for AllTeleservices4.
	AllTeleservices4 = "\x00"

	// AllSpeechTransmissionServices4 is the octet string constant for AllSpeechTransmissionServices4.
	AllSpeechTransmissionServices4 = "\x10"

	// Telephony4 is the octet string constant for Telephony4.
	Telephony4 = "\x11"

	// EmergencyCalls4 is the octet string constant for EmergencyCalls4.
	EmergencyCalls4 = "\x12"

	// AllShortMessageServices4 is the octet string constant for AllShortMessageServices4.
	AllShortMessageServices4 = "\x20"

	// ShortMessageMTPP4 is the octet string constant for ShortMessageMTPP4.
	ShortMessageMTPP4 = "\x21"

	// ShortMessageMOPP4 is the octet string constant for ShortMessageMOPP4.
	ShortMessageMOPP4 = "\x22"

	// AllFacsimileTransmissionServices4 is the octet string constant for AllFacsimileTransmissionServices4.
	AllFacsimileTransmissionServices4 = "\x60"

	// FacsimileGroup3AndAlterSpeech4 is the octet string constant for FacsimileGroup3AndAlterSpeech4.
	FacsimileGroup3AndAlterSpeech4 = "\x61"

	// AutomaticFacsimileGroup34 is the octet string constant for AutomaticFacsimileGroup34.
	AutomaticFacsimileGroup34 = "\x62"

	// FacsimileGroup44 is the octet string constant for FacsimileGroup44.
	FacsimileGroup44 = "\x63"

	// AllDataTeleservices4 is the octet string constant for AllDataTeleservices4.
	AllDataTeleservices4 = "\x70"

	// AllTeleservicesExeptSMS4 is the octet string constant for AllTeleservicesExeptSMS4.
	AllTeleservicesExeptSMS4 = "\x80"

	// AllVoiceGroupCallServices4 is the octet string constant for AllVoiceGroupCallServices4.
	AllVoiceGroupCallServices4 = "\x90"

	// VoiceGroupCall4 is the octet string constant for VoiceGroupCall4.
	VoiceGroupCall4 = "\x91"

	// VoiceBroadcastCall4 is the octet string constant for VoiceBroadcastCall4.
	VoiceBroadcastCall4 = "\x92"

	// AllPLMNSpecificTS4 is the octet string constant for AllPLMNSpecificTS4.
	AllPLMNSpecificTS4 = "\xd0"

	// PlmnSpecificTS14 is the octet string constant for PlmnSpecificTS14.
	PlmnSpecificTS14 = "\xd1"

	// PlmnSpecificTS24 is the octet string constant for PlmnSpecificTS24.
	PlmnSpecificTS24 = "\xd2"

	// PlmnSpecificTS34 is the octet string constant for PlmnSpecificTS34.
	PlmnSpecificTS34 = "\xd3"

	// PlmnSpecificTS44 is the octet string constant for PlmnSpecificTS44.
	PlmnSpecificTS44 = "\xd4"

	// PlmnSpecificTS54 is the octet string constant for PlmnSpecificTS54.
	PlmnSpecificTS54 = "\xd5"

	// PlmnSpecificTS64 is the octet string constant for PlmnSpecificTS64.
	PlmnSpecificTS64 = "\xd6"

	// PlmnSpecificTS74 is the octet string constant for PlmnSpecificTS74.
	PlmnSpecificTS74 = "\xd7"

	// PlmnSpecificTS84 is the octet string constant for PlmnSpecificTS84.
	PlmnSpecificTS84 = "\xd8"

	// PlmnSpecificTS94 is the octet string constant for PlmnSpecificTS94.
	PlmnSpecificTS94 = "\xd9"

	// PlmnSpecificTSA4 is the octet string constant for PlmnSpecificTSA4.
	PlmnSpecificTSA4 = "\xda"

	// PlmnSpecificTSB4 is the octet string constant for PlmnSpecificTSB4.
	PlmnSpecificTSB4 = "\xdb"

	// PlmnSpecificTSC4 is the octet string constant for PlmnSpecificTSC4.
	PlmnSpecificTSC4 = "\xdc"

	// PlmnSpecificTSD4 is the octet string constant for PlmnSpecificTSD4.
	PlmnSpecificTSD4 = "\xdd"

	// PlmnSpecificTSE4 is the octet string constant for PlmnSpecificTSE4.
	PlmnSpecificTSE4 = "\xde"

	// PlmnSpecificTSF4 is the octet string constant for PlmnSpecificTSF4.
	PlmnSpecificTSF4 = "\xdf"
)

// TeleserviceCode4 represents the ASN.1 type TeleserviceCode (OCTET_STRING).
type TeleserviceCode4 = []byte

// ExtTeleserviceCode4 represents the ASN.1 type Ext-TeleserviceCode (OCTET_STRING).
type ExtTeleserviceCode4 = []byte
