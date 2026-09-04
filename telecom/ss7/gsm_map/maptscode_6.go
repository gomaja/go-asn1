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

	// AllTeleservices6 is the octet string constant for allTeleservices.
	AllTeleservices6 = "\x00"

	// AllSpeechTransmissionServices6 is the octet string constant for allSpeechTransmissionServices.
	AllSpeechTransmissionServices6 = "\x10"

	// Telephony6 is the octet string constant for telephony.
	Telephony6 = "\x11"

	// EmergencyCalls6 is the octet string constant for emergencyCalls.
	EmergencyCalls6 = "\x12"

	// AllShortMessageServices6 is the octet string constant for allShortMessageServices.
	AllShortMessageServices6 = "\x20"

	// ShortMessageMTPP6 is the octet string constant for shortMessageMT-PP.
	ShortMessageMTPP6 = "\x21"

	// ShortMessageMOPP6 is the octet string constant for shortMessageMO-PP.
	ShortMessageMOPP6 = "\x22"

	// AllFacsimileTransmissionServices6 is the octet string constant for allFacsimileTransmissionServices.
	AllFacsimileTransmissionServices6 = "\x60"

	// FacsimileGroup3AndAlterSpeech6 is the octet string constant for facsimileGroup3AndAlterSpeech.
	FacsimileGroup3AndAlterSpeech6 = "\x61"

	// AutomaticFacsimileGroup36 is the octet string constant for automaticFacsimileGroup3.
	AutomaticFacsimileGroup36 = "\x62"

	// FacsimileGroup46 is the octet string constant for facsimileGroup4.
	FacsimileGroup46 = "\x63"

	// AllDataTeleservices6 is the octet string constant for allDataTeleservices.
	AllDataTeleservices6 = "\x70"

	// AllTeleservicesExeptSMS6 is the octet string constant for allTeleservices-ExeptSMS.
	AllTeleservicesExeptSMS6 = "\x80"

	// AllVoiceGroupCallServices6 is the octet string constant for allVoiceGroupCallServices.
	AllVoiceGroupCallServices6 = "\x90"

	// VoiceGroupCall6 is the octet string constant for voiceGroupCall.
	VoiceGroupCall6 = "\x91"

	// VoiceBroadcastCall6 is the octet string constant for voiceBroadcastCall.
	VoiceBroadcastCall6 = "\x92"

	// AllPLMNSpecificTS6 is the octet string constant for allPLMN-specificTS.
	AllPLMNSpecificTS6 = "\xd0"

	// PlmnSpecificTS16 is the octet string constant for plmn-specificTS-1.
	PlmnSpecificTS16 = "\xd1"

	// PlmnSpecificTS26 is the octet string constant for plmn-specificTS-2.
	PlmnSpecificTS26 = "\xd2"

	// PlmnSpecificTS36 is the octet string constant for plmn-specificTS-3.
	PlmnSpecificTS36 = "\xd3"

	// PlmnSpecificTS46 is the octet string constant for plmn-specificTS-4.
	PlmnSpecificTS46 = "\xd4"

	// PlmnSpecificTS56 is the octet string constant for plmn-specificTS-5.
	PlmnSpecificTS56 = "\xd5"

	// PlmnSpecificTS66 is the octet string constant for plmn-specificTS-6.
	PlmnSpecificTS66 = "\xd6"

	// PlmnSpecificTS76 is the octet string constant for plmn-specificTS-7.
	PlmnSpecificTS76 = "\xd7"

	// PlmnSpecificTS86 is the octet string constant for plmn-specificTS-8.
	PlmnSpecificTS86 = "\xd8"

	// PlmnSpecificTS96 is the octet string constant for plmn-specificTS-9.
	PlmnSpecificTS96 = "\xd9"

	// PlmnSpecificTSA6 is the octet string constant for plmn-specificTS-A.
	PlmnSpecificTSA6 = "\xda"

	// PlmnSpecificTSB6 is the octet string constant for plmn-specificTS-B.
	PlmnSpecificTSB6 = "\xdb"

	// PlmnSpecificTSC6 is the octet string constant for plmn-specificTS-C.
	PlmnSpecificTSC6 = "\xdc"

	// PlmnSpecificTSD6 is the octet string constant for plmn-specificTS-D.
	PlmnSpecificTSD6 = "\xdd"

	// PlmnSpecificTSE6 is the octet string constant for plmn-specificTS-E.
	PlmnSpecificTSE6 = "\xde"

	// PlmnSpecificTSF6 is the octet string constant for plmn-specificTS-F.
	PlmnSpecificTSF6 = "\xdf"
)

// TeleserviceCode6 represents the ASN.1 type TeleserviceCode (OCTET_STRING).
type TeleserviceCode6 = []byte

// ExtTeleserviceCode6 represents the ASN.1 type Ext-TeleserviceCode (OCTET_STRING).
type ExtTeleserviceCode6 = []byte
