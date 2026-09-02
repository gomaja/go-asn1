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

	// AllTeleservices3 is the octet string constant for allTeleservices.
	AllTeleservices3 = "\x00"

	// AllSpeechTransmissionServices3 is the octet string constant for allSpeechTransmissionServices.
	AllSpeechTransmissionServices3 = "\x10"

	// Telephony3 is the octet string constant for telephony.
	Telephony3 = "\x11"

	// EmergencyCalls3 is the octet string constant for emergencyCalls.
	EmergencyCalls3 = "\x12"

	// AllShortMessageServices3 is the octet string constant for allShortMessageServices.
	AllShortMessageServices3 = "\x20"

	// ShortMessageMTPP3 is the octet string constant for shortMessageMT-PP.
	ShortMessageMTPP3 = "\x21"

	// ShortMessageMOPP3 is the octet string constant for shortMessageMO-PP.
	ShortMessageMOPP3 = "\x22"

	// AllFacsimileTransmissionServices3 is the octet string constant for allFacsimileTransmissionServices.
	AllFacsimileTransmissionServices3 = "\x60"

	// FacsimileGroup3AndAlterSpeech3 is the octet string constant for facsimileGroup3AndAlterSpeech.
	FacsimileGroup3AndAlterSpeech3 = "\x61"

	// AutomaticFacsimileGroup33 is the octet string constant for automaticFacsimileGroup3.
	AutomaticFacsimileGroup33 = "\x62"

	// FacsimileGroup43 is the octet string constant for facsimileGroup4.
	FacsimileGroup43 = "\x63"

	// AllDataTeleservices3 is the octet string constant for allDataTeleservices.
	AllDataTeleservices3 = "\x70"

	// AllTeleservicesExeptSMS3 is the octet string constant for allTeleservices-ExeptSMS.
	AllTeleservicesExeptSMS3 = "\x80"

	// AllVoiceGroupCallServices3 is the octet string constant for allVoiceGroupCallServices.
	AllVoiceGroupCallServices3 = "\x90"

	// VoiceGroupCall3 is the octet string constant for voiceGroupCall.
	VoiceGroupCall3 = "\x91"

	// VoiceBroadcastCall3 is the octet string constant for voiceBroadcastCall.
	VoiceBroadcastCall3 = "\x92"

	// AllPLMNSpecificTS3 is the octet string constant for allPLMN-specificTS.
	AllPLMNSpecificTS3 = "\xd0"

	// PlmnSpecificTS13 is the octet string constant for plmn-specificTS-1.
	PlmnSpecificTS13 = "\xd1"

	// PlmnSpecificTS23 is the octet string constant for plmn-specificTS-2.
	PlmnSpecificTS23 = "\xd2"

	// PlmnSpecificTS33 is the octet string constant for plmn-specificTS-3.
	PlmnSpecificTS33 = "\xd3"

	// PlmnSpecificTS43 is the octet string constant for plmn-specificTS-4.
	PlmnSpecificTS43 = "\xd4"

	// PlmnSpecificTS53 is the octet string constant for plmn-specificTS-5.
	PlmnSpecificTS53 = "\xd5"

	// PlmnSpecificTS63 is the octet string constant for plmn-specificTS-6.
	PlmnSpecificTS63 = "\xd6"

	// PlmnSpecificTS73 is the octet string constant for plmn-specificTS-7.
	PlmnSpecificTS73 = "\xd7"

	// PlmnSpecificTS83 is the octet string constant for plmn-specificTS-8.
	PlmnSpecificTS83 = "\xd8"

	// PlmnSpecificTS93 is the octet string constant for plmn-specificTS-9.
	PlmnSpecificTS93 = "\xd9"

	// PlmnSpecificTSA3 is the octet string constant for plmn-specificTS-A.
	PlmnSpecificTSA3 = "\xda"

	// PlmnSpecificTSB3 is the octet string constant for plmn-specificTS-B.
	PlmnSpecificTSB3 = "\xdb"

	// PlmnSpecificTSC3 is the octet string constant for plmn-specificTS-C.
	PlmnSpecificTSC3 = "\xdc"

	// PlmnSpecificTSD3 is the octet string constant for plmn-specificTS-D.
	PlmnSpecificTSD3 = "\xdd"

	// PlmnSpecificTSE3 is the octet string constant for plmn-specificTS-E.
	PlmnSpecificTSE3 = "\xde"

	// PlmnSpecificTSF3 is the octet string constant for plmn-specificTS-F.
	PlmnSpecificTSF3 = "\xdf"
)

// TeleserviceCode3 represents the ASN.1 type TeleserviceCode (OCTET_STRING).
type TeleserviceCode3 = []byte

// ExtTeleserviceCode3 represents the ASN.1 type Ext-TeleserviceCode (OCTET_STRING).
type ExtTeleserviceCode3 = []byte
