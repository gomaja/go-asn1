// Code generated from ASN.1 module "MAP-BS-Code". DO NOT EDIT.

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

	// AllBearerServices4 is the octet string constant for AllBearerServices4.
	AllBearerServices4 = "\x00"

	// AllDataCDAServices4 is the octet string constant for AllDataCDAServices4.
	AllDataCDAServices4 = "\x10"

	// DataCDA300bps4 is the octet string constant for DataCDA300bps4.
	DataCDA300bps4 = "\x11"

	// DataCDA1200bps4 is the octet string constant for DataCDA1200bps4.
	DataCDA1200bps4 = "\x12"

	// DataCDA120075bps4 is the octet string constant for DataCDA120075bps4.
	DataCDA120075bps4 = "\x13"

	// DataCDA2400bps4 is the octet string constant for DataCDA2400bps4.
	DataCDA2400bps4 = "\x14"

	// DataCDA4800bps4 is the octet string constant for DataCDA4800bps4.
	DataCDA4800bps4 = "\x15"

	// DataCDA9600bps4 is the octet string constant for DataCDA9600bps4.
	DataCDA9600bps4 = "\x16"

	// GeneralDataCDA4 is the octet string constant for GeneralDataCDA4.
	GeneralDataCDA4 = "\x17"

	// AllDataCDSServices4 is the octet string constant for AllDataCDSServices4.
	AllDataCDSServices4 = "\x18"

	// DataCDS1200bps4 is the octet string constant for DataCDS1200bps4.
	DataCDS1200bps4 = "\x1a"

	// DataCDS2400bps4 is the octet string constant for DataCDS2400bps4.
	DataCDS2400bps4 = "\x1c"

	// DataCDS4800bps4 is the octet string constant for DataCDS4800bps4.
	DataCDS4800bps4 = "\x1d"

	// DataCDS9600bps4 is the octet string constant for DataCDS9600bps4.
	DataCDS9600bps4 = "\x1e"

	// GeneralDataCDS4 is the octet string constant for GeneralDataCDS4.
	GeneralDataCDS4 = "\x1f"

	// AllPadAccessCAServices4 is the octet string constant for AllPadAccessCAServices4.
	AllPadAccessCAServices4 = "\x20"

	// PadAccessCA300bps4 is the octet string constant for PadAccessCA300bps4.
	PadAccessCA300bps4 = "\x21"

	// PadAccessCA1200bps4 is the octet string constant for PadAccessCA1200bps4.
	PadAccessCA1200bps4 = "\x22"

	// PadAccessCA120075bps4 is the octet string constant for PadAccessCA120075bps4.
	PadAccessCA120075bps4 = "\x23"

	// PadAccessCA2400bps4 is the octet string constant for PadAccessCA2400bps4.
	PadAccessCA2400bps4 = "\x24"

	// PadAccessCA4800bps4 is the octet string constant for PadAccessCA4800bps4.
	PadAccessCA4800bps4 = "\x25"

	// PadAccessCA9600bps4 is the octet string constant for PadAccessCA9600bps4.
	PadAccessCA9600bps4 = "\x26"

	// GeneralPadAccessCA4 is the octet string constant for GeneralPadAccessCA4.
	GeneralPadAccessCA4 = "\x27"

	// AllDataPDSServices4 is the octet string constant for AllDataPDSServices4.
	AllDataPDSServices4 = "\x28"

	// DataPDS2400bps4 is the octet string constant for DataPDS2400bps4.
	DataPDS2400bps4 = "\x2c"

	// DataPDS4800bps4 is the octet string constant for DataPDS4800bps4.
	DataPDS4800bps4 = "\x2d"

	// DataPDS9600bps4 is the octet string constant for DataPDS9600bps4.
	DataPDS9600bps4 = "\x2e"

	// GeneralDataPDS4 is the octet string constant for GeneralDataPDS4.
	GeneralDataPDS4 = "\x2f"

	// AllAlternateSpeechDataCDA4 is the octet string constant for AllAlternateSpeechDataCDA4.
	AllAlternateSpeechDataCDA4 = "\x30"

	// AllAlternateSpeechDataCDS4 is the octet string constant for AllAlternateSpeechDataCDS4.
	AllAlternateSpeechDataCDS4 = "\x38"

	// AllSpeechFollowedByDataCDA4 is the octet string constant for AllSpeechFollowedByDataCDA4.
	AllSpeechFollowedByDataCDA4 = "\x40"

	// AllSpeechFollowedByDataCDS4 is the octet string constant for AllSpeechFollowedByDataCDS4.
	AllSpeechFollowedByDataCDS4 = "\x48"

	// AllDataCircuitAsynchronous4 is the octet string constant for AllDataCircuitAsynchronous4.
	AllDataCircuitAsynchronous4 = "\x50"

	// AllAsynchronousServices4 is the octet string constant for AllAsynchronousServices4.
	AllAsynchronousServices4 = "\x60"

	// AllDataCircuitSynchronous4 is the octet string constant for AllDataCircuitSynchronous4.
	AllDataCircuitSynchronous4 = "\x58"

	// AllSynchronousServices4 is the octet string constant for AllSynchronousServices4.
	AllSynchronousServices4 = "\x68"

	// AllPLMNSpecificBS4 is the octet string constant for AllPLMNSpecificBS4.
	AllPLMNSpecificBS4 = "\xd0"

	// PlmnSpecificBS14 is the octet string constant for PlmnSpecificBS14.
	PlmnSpecificBS14 = "\xd1"

	// PlmnSpecificBS24 is the octet string constant for PlmnSpecificBS24.
	PlmnSpecificBS24 = "\xd2"

	// PlmnSpecificBS34 is the octet string constant for PlmnSpecificBS34.
	PlmnSpecificBS34 = "\xd3"

	// PlmnSpecificBS44 is the octet string constant for PlmnSpecificBS44.
	PlmnSpecificBS44 = "\xd4"

	// PlmnSpecificBS54 is the octet string constant for PlmnSpecificBS54.
	PlmnSpecificBS54 = "\xd5"

	// PlmnSpecificBS64 is the octet string constant for PlmnSpecificBS64.
	PlmnSpecificBS64 = "\xd6"

	// PlmnSpecificBS74 is the octet string constant for PlmnSpecificBS74.
	PlmnSpecificBS74 = "\xd7"

	// PlmnSpecificBS84 is the octet string constant for PlmnSpecificBS84.
	PlmnSpecificBS84 = "\xd8"

	// PlmnSpecificBS94 is the octet string constant for PlmnSpecificBS94.
	PlmnSpecificBS94 = "\xd9"

	// PlmnSpecificBSA4 is the octet string constant for PlmnSpecificBSA4.
	PlmnSpecificBSA4 = "\xda"

	// PlmnSpecificBSB4 is the octet string constant for PlmnSpecificBSB4.
	PlmnSpecificBSB4 = "\xdb"

	// PlmnSpecificBSC4 is the octet string constant for PlmnSpecificBSC4.
	PlmnSpecificBSC4 = "\xdc"

	// PlmnSpecificBSD4 is the octet string constant for PlmnSpecificBSD4.
	PlmnSpecificBSD4 = "\xdd"

	// PlmnSpecificBSE4 is the octet string constant for PlmnSpecificBSE4.
	PlmnSpecificBSE4 = "\xde"

	// PlmnSpecificBSF4 is the octet string constant for PlmnSpecificBSF4.
	PlmnSpecificBSF4 = "\xdf"
)

// BearerServiceCode4 represents the ASN.1 type BearerServiceCode4 (OCTET_STRING).
type BearerServiceCode4 = []byte

// ExtBearerServiceCode4 represents the ASN.1 type ExtBearerServiceCode4 (OCTET_STRING).
type ExtBearerServiceCode4 = []byte
