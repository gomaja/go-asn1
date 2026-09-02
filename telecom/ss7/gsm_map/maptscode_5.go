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

	// AllTeleservices5 is the octet string constant for allTeleservices.
	AllTeleservices5 = "\x00"

	// AllSpeechTransmissionServices5 is the octet string constant for allSpeechTransmissionServices.
	AllSpeechTransmissionServices5 = "\x10"

	// Telephony5 is the octet string constant for telephony.
	Telephony5 = "\x11"

	// EmergencyCalls5 is the octet string constant for emergencyCalls.
	EmergencyCalls5 = "\x12"

	// AllShortMessageServices5 is the octet string constant for allShortMessageServices.
	AllShortMessageServices5 = "\x20"

	// ShortMessageMTPP5 is the octet string constant for shortMessageMT-PP.
	ShortMessageMTPP5 = "\x21"

	// ShortMessageMOPP5 is the octet string constant for shortMessageMO-PP.
	ShortMessageMOPP5 = "\x22"

	// AllFacsimileTransmissionServices5 is the octet string constant for allFacsimileTransmissionServices.
	AllFacsimileTransmissionServices5 = "\x60"

	// FacsimileGroup3AndAlterSpeech5 is the octet string constant for facsimileGroup3AndAlterSpeech.
	FacsimileGroup3AndAlterSpeech5 = "\x61"

	// AutomaticFacsimileGroup35 is the octet string constant for automaticFacsimileGroup3.
	AutomaticFacsimileGroup35 = "\x62"

	// FacsimileGroup45 is the octet string constant for facsimileGroup4.
	FacsimileGroup45 = "\x63"

	// AllDataTeleservices5 is the octet string constant for allDataTeleservices.
	AllDataTeleservices5 = "\x70"

	// AllTeleservicesExeptSMS5 is the octet string constant for allTeleservices-ExeptSMS.
	AllTeleservicesExeptSMS5 = "\x80"

	// AllVoiceGroupCallServices5 is the octet string constant for allVoiceGroupCallServices.
	AllVoiceGroupCallServices5 = "\x90"

	// VoiceGroupCall5 is the octet string constant for voiceGroupCall.
	VoiceGroupCall5 = "\x91"

	// VoiceBroadcastCall5 is the octet string constant for voiceBroadcastCall.
	VoiceBroadcastCall5 = "\x92"

	// AllPLMNSpecificTS5 is the octet string constant for allPLMN-specificTS.
	AllPLMNSpecificTS5 = "\xd0"

	// PlmnSpecificTS15 is the octet string constant for plmn-specificTS-1.
	PlmnSpecificTS15 = "\xd1"

	// PlmnSpecificTS25 is the octet string constant for plmn-specificTS-2.
	PlmnSpecificTS25 = "\xd2"

	// PlmnSpecificTS35 is the octet string constant for plmn-specificTS-3.
	PlmnSpecificTS35 = "\xd3"

	// PlmnSpecificTS45 is the octet string constant for plmn-specificTS-4.
	PlmnSpecificTS45 = "\xd4"

	// PlmnSpecificTS55 is the octet string constant for plmn-specificTS-5.
	PlmnSpecificTS55 = "\xd5"

	// PlmnSpecificTS65 is the octet string constant for plmn-specificTS-6.
	PlmnSpecificTS65 = "\xd6"

	// PlmnSpecificTS75 is the octet string constant for plmn-specificTS-7.
	PlmnSpecificTS75 = "\xd7"

	// PlmnSpecificTS85 is the octet string constant for plmn-specificTS-8.
	PlmnSpecificTS85 = "\xd8"

	// PlmnSpecificTS95 is the octet string constant for plmn-specificTS-9.
	PlmnSpecificTS95 = "\xd9"

	// PlmnSpecificTSA5 is the octet string constant for plmn-specificTS-A.
	PlmnSpecificTSA5 = "\xda"

	// PlmnSpecificTSB5 is the octet string constant for plmn-specificTS-B.
	PlmnSpecificTSB5 = "\xdb"

	// PlmnSpecificTSC5 is the octet string constant for plmn-specificTS-C.
	PlmnSpecificTSC5 = "\xdc"

	// PlmnSpecificTSD5 is the octet string constant for plmn-specificTS-D.
	PlmnSpecificTSD5 = "\xdd"

	// PlmnSpecificTSE5 is the octet string constant for plmn-specificTS-E.
	PlmnSpecificTSE5 = "\xde"

	// PlmnSpecificTSF5 is the octet string constant for plmn-specificTS-F.
	PlmnSpecificTSF5 = "\xdf"
)

// TeleserviceCode5 represents the ASN.1 type TeleserviceCode (OCTET_STRING).
type TeleserviceCode5 = []byte

// ExtTeleserviceCode5 represents the ASN.1 type Ext-TeleserviceCode (OCTET_STRING).
type ExtTeleserviceCode5 = []byte
