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

	// AllTeleservices4 is the octet string constant for allTeleservices.
	AllTeleservices4 = "\x00"

	// AllSpeechTransmissionServices4 is the octet string constant for allSpeechTransmissionServices.
	AllSpeechTransmissionServices4 = "\x10"

	// Telephony4 is the octet string constant for telephony.
	Telephony4 = "\x11"

	// EmergencyCalls4 is the octet string constant for emergencyCalls.
	EmergencyCalls4 = "\x12"

	// AllShortMessageServices4 is the octet string constant for allShortMessageServices.
	AllShortMessageServices4 = "\x20"

	// ShortMessageMTPP4 is the octet string constant for shortMessageMT-PP.
	ShortMessageMTPP4 = "\x21"

	// ShortMessageMOPP4 is the octet string constant for shortMessageMO-PP.
	ShortMessageMOPP4 = "\x22"

	// AllFacsimileTransmissionServices4 is the octet string constant for allFacsimileTransmissionServices.
	AllFacsimileTransmissionServices4 = "\x60"

	// FacsimileGroup3AndAlterSpeech4 is the octet string constant for facsimileGroup3AndAlterSpeech.
	FacsimileGroup3AndAlterSpeech4 = "\x61"

	// AutomaticFacsimileGroup34 is the octet string constant for automaticFacsimileGroup3.
	AutomaticFacsimileGroup34 = "\x62"

	// FacsimileGroup44 is the octet string constant for facsimileGroup4.
	FacsimileGroup44 = "\x63"

	// AllDataTeleservices4 is the octet string constant for allDataTeleservices.
	AllDataTeleservices4 = "\x70"

	// AllTeleservicesExeptSMS4 is the octet string constant for allTeleservices-ExeptSMS.
	AllTeleservicesExeptSMS4 = "\x80"

	// AllVoiceGroupCallServices4 is the octet string constant for allVoiceGroupCallServices.
	AllVoiceGroupCallServices4 = "\x90"

	// VoiceGroupCall4 is the octet string constant for voiceGroupCall.
	VoiceGroupCall4 = "\x91"

	// VoiceBroadcastCall4 is the octet string constant for voiceBroadcastCall.
	VoiceBroadcastCall4 = "\x92"

	// AllPLMNSpecificTS4 is the octet string constant for allPLMN-specificTS.
	AllPLMNSpecificTS4 = "\xd0"

	// PlmnSpecificTS14 is the octet string constant for plmn-specificTS-1.
	PlmnSpecificTS14 = "\xd1"

	// PlmnSpecificTS24 is the octet string constant for plmn-specificTS-2.
	PlmnSpecificTS24 = "\xd2"

	// PlmnSpecificTS34 is the octet string constant for plmn-specificTS-3.
	PlmnSpecificTS34 = "\xd3"

	// PlmnSpecificTS44 is the octet string constant for plmn-specificTS-4.
	PlmnSpecificTS44 = "\xd4"

	// PlmnSpecificTS54 is the octet string constant for plmn-specificTS-5.
	PlmnSpecificTS54 = "\xd5"

	// PlmnSpecificTS64 is the octet string constant for plmn-specificTS-6.
	PlmnSpecificTS64 = "\xd6"

	// PlmnSpecificTS74 is the octet string constant for plmn-specificTS-7.
	PlmnSpecificTS74 = "\xd7"

	// PlmnSpecificTS84 is the octet string constant for plmn-specificTS-8.
	PlmnSpecificTS84 = "\xd8"

	// PlmnSpecificTS94 is the octet string constant for plmn-specificTS-9.
	PlmnSpecificTS94 = "\xd9"

	// PlmnSpecificTSA4 is the octet string constant for plmn-specificTS-A.
	PlmnSpecificTSA4 = "\xda"

	// PlmnSpecificTSB4 is the octet string constant for plmn-specificTS-B.
	PlmnSpecificTSB4 = "\xdb"

	// PlmnSpecificTSC4 is the octet string constant for plmn-specificTS-C.
	PlmnSpecificTSC4 = "\xdc"

	// PlmnSpecificTSD4 is the octet string constant for plmn-specificTS-D.
	PlmnSpecificTSD4 = "\xdd"

	// PlmnSpecificTSE4 is the octet string constant for plmn-specificTS-E.
	PlmnSpecificTSE4 = "\xde"

	// PlmnSpecificTSF4 is the octet string constant for plmn-specificTS-F.
	PlmnSpecificTSF4 = "\xdf"
)

// TeleserviceCode4 represents the ASN.1 type TeleserviceCode (OCTET_STRING).
type TeleserviceCode4 = []byte

// ExtTeleserviceCode4 represents the ASN.1 type Ext-TeleserviceCode (OCTET_STRING).
type ExtTeleserviceCode4 = []byte
