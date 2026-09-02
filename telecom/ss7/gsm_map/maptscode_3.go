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

	// AllTeleservices3 is the octet string constant for AllTeleservices3.
	AllTeleservices3 = "\x00"

	// AllSpeechTransmissionServices3 is the octet string constant for AllSpeechTransmissionServices3.
	AllSpeechTransmissionServices3 = "\x10"

	// Telephony3 is the octet string constant for Telephony3.
	Telephony3 = "\x11"

	// EmergencyCalls3 is the octet string constant for EmergencyCalls3.
	EmergencyCalls3 = "\x12"

	// AllShortMessageServices3 is the octet string constant for AllShortMessageServices3.
	AllShortMessageServices3 = "\x20"

	// ShortMessageMTPP3 is the octet string constant for ShortMessageMTPP3.
	ShortMessageMTPP3 = "\x21"

	// ShortMessageMOPP3 is the octet string constant for ShortMessageMOPP3.
	ShortMessageMOPP3 = "\x22"

	// AllFacsimileTransmissionServices3 is the octet string constant for AllFacsimileTransmissionServices3.
	AllFacsimileTransmissionServices3 = "\x60"

	// FacsimileGroup3AndAlterSpeech3 is the octet string constant for FacsimileGroup3AndAlterSpeech3.
	FacsimileGroup3AndAlterSpeech3 = "\x61"

	// AutomaticFacsimileGroup33 is the octet string constant for AutomaticFacsimileGroup33.
	AutomaticFacsimileGroup33 = "\x62"

	// FacsimileGroup43 is the octet string constant for FacsimileGroup43.
	FacsimileGroup43 = "\x63"

	// AllDataTeleservices3 is the octet string constant for AllDataTeleservices3.
	AllDataTeleservices3 = "\x70"

	// AllTeleservicesExeptSMS3 is the octet string constant for AllTeleservicesExeptSMS3.
	AllTeleservicesExeptSMS3 = "\x80"

	// AllVoiceGroupCallServices3 is the octet string constant for AllVoiceGroupCallServices3.
	AllVoiceGroupCallServices3 = "\x90"

	// VoiceGroupCall3 is the octet string constant for VoiceGroupCall3.
	VoiceGroupCall3 = "\x91"

	// VoiceBroadcastCall3 is the octet string constant for VoiceBroadcastCall3.
	VoiceBroadcastCall3 = "\x92"

	// AllPLMNSpecificTS3 is the octet string constant for AllPLMNSpecificTS3.
	AllPLMNSpecificTS3 = "\xd0"

	// PlmnSpecificTS13 is the octet string constant for PlmnSpecificTS13.
	PlmnSpecificTS13 = "\xd1"

	// PlmnSpecificTS23 is the octet string constant for PlmnSpecificTS23.
	PlmnSpecificTS23 = "\xd2"

	// PlmnSpecificTS33 is the octet string constant for PlmnSpecificTS33.
	PlmnSpecificTS33 = "\xd3"

	// PlmnSpecificTS43 is the octet string constant for PlmnSpecificTS43.
	PlmnSpecificTS43 = "\xd4"

	// PlmnSpecificTS53 is the octet string constant for PlmnSpecificTS53.
	PlmnSpecificTS53 = "\xd5"

	// PlmnSpecificTS63 is the octet string constant for PlmnSpecificTS63.
	PlmnSpecificTS63 = "\xd6"

	// PlmnSpecificTS73 is the octet string constant for PlmnSpecificTS73.
	PlmnSpecificTS73 = "\xd7"

	// PlmnSpecificTS83 is the octet string constant for PlmnSpecificTS83.
	PlmnSpecificTS83 = "\xd8"

	// PlmnSpecificTS93 is the octet string constant for PlmnSpecificTS93.
	PlmnSpecificTS93 = "\xd9"

	// PlmnSpecificTSA3 is the octet string constant for PlmnSpecificTSA3.
	PlmnSpecificTSA3 = "\xda"

	// PlmnSpecificTSB3 is the octet string constant for PlmnSpecificTSB3.
	PlmnSpecificTSB3 = "\xdb"

	// PlmnSpecificTSC3 is the octet string constant for PlmnSpecificTSC3.
	PlmnSpecificTSC3 = "\xdc"

	// PlmnSpecificTSD3 is the octet string constant for PlmnSpecificTSD3.
	PlmnSpecificTSD3 = "\xdd"

	// PlmnSpecificTSE3 is the octet string constant for PlmnSpecificTSE3.
	PlmnSpecificTSE3 = "\xde"

	// PlmnSpecificTSF3 is the octet string constant for PlmnSpecificTSF3.
	PlmnSpecificTSF3 = "\xdf"
)

// TeleserviceCode3 represents the ASN.1 type TeleserviceCode (OCTET_STRING).
type TeleserviceCode3 = []byte

// ExtTeleserviceCode3 represents the ASN.1 type Ext-TeleserviceCode (OCTET_STRING).
type ExtTeleserviceCode3 = []byte
