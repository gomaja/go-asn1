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

	// AllBearerServices3 is the octet string constant for AllBearerServices3.
	AllBearerServices3 = "\x00"

	// AllDataCDAServices3 is the octet string constant for AllDataCDAServices3.
	AllDataCDAServices3 = "\x10"

	// DataCDA300bps3 is the octet string constant for DataCDA300bps3.
	DataCDA300bps3 = "\x11"

	// DataCDA1200bps3 is the octet string constant for DataCDA1200bps3.
	DataCDA1200bps3 = "\x12"

	// DataCDA120075bps3 is the octet string constant for DataCDA120075bps3.
	DataCDA120075bps3 = "\x13"

	// DataCDA2400bps3 is the octet string constant for DataCDA2400bps3.
	DataCDA2400bps3 = "\x14"

	// DataCDA4800bps3 is the octet string constant for DataCDA4800bps3.
	DataCDA4800bps3 = "\x15"

	// DataCDA9600bps3 is the octet string constant for DataCDA9600bps3.
	DataCDA9600bps3 = "\x16"

	// GeneralDataCDA3 is the octet string constant for GeneralDataCDA3.
	GeneralDataCDA3 = "\x17"

	// AllDataCDSServices3 is the octet string constant for AllDataCDSServices3.
	AllDataCDSServices3 = "\x18"

	// DataCDS1200bps3 is the octet string constant for DataCDS1200bps3.
	DataCDS1200bps3 = "\x1a"

	// DataCDS2400bps3 is the octet string constant for DataCDS2400bps3.
	DataCDS2400bps3 = "\x1c"

	// DataCDS4800bps3 is the octet string constant for DataCDS4800bps3.
	DataCDS4800bps3 = "\x1d"

	// DataCDS9600bps3 is the octet string constant for DataCDS9600bps3.
	DataCDS9600bps3 = "\x1e"

	// GeneralDataCDS3 is the octet string constant for GeneralDataCDS3.
	GeneralDataCDS3 = "\x1f"

	// AllPadAccessCAServices3 is the octet string constant for AllPadAccessCAServices3.
	AllPadAccessCAServices3 = "\x20"

	// PadAccessCA300bps3 is the octet string constant for PadAccessCA300bps3.
	PadAccessCA300bps3 = "\x21"

	// PadAccessCA1200bps3 is the octet string constant for PadAccessCA1200bps3.
	PadAccessCA1200bps3 = "\x22"

	// PadAccessCA120075bps3 is the octet string constant for PadAccessCA120075bps3.
	PadAccessCA120075bps3 = "\x23"

	// PadAccessCA2400bps3 is the octet string constant for PadAccessCA2400bps3.
	PadAccessCA2400bps3 = "\x24"

	// PadAccessCA4800bps3 is the octet string constant for PadAccessCA4800bps3.
	PadAccessCA4800bps3 = "\x25"

	// PadAccessCA9600bps3 is the octet string constant for PadAccessCA9600bps3.
	PadAccessCA9600bps3 = "\x26"

	// GeneralPadAccessCA3 is the octet string constant for GeneralPadAccessCA3.
	GeneralPadAccessCA3 = "\x27"

	// AllDataPDSServices3 is the octet string constant for AllDataPDSServices3.
	AllDataPDSServices3 = "\x28"

	// DataPDS2400bps3 is the octet string constant for DataPDS2400bps3.
	DataPDS2400bps3 = "\x2c"

	// DataPDS4800bps3 is the octet string constant for DataPDS4800bps3.
	DataPDS4800bps3 = "\x2d"

	// DataPDS9600bps3 is the octet string constant for DataPDS9600bps3.
	DataPDS9600bps3 = "\x2e"

	// GeneralDataPDS3 is the octet string constant for GeneralDataPDS3.
	GeneralDataPDS3 = "\x2f"

	// AllAlternateSpeechDataCDA3 is the octet string constant for AllAlternateSpeechDataCDA3.
	AllAlternateSpeechDataCDA3 = "\x30"

	// AllAlternateSpeechDataCDS3 is the octet string constant for AllAlternateSpeechDataCDS3.
	AllAlternateSpeechDataCDS3 = "\x38"

	// AllSpeechFollowedByDataCDA3 is the octet string constant for AllSpeechFollowedByDataCDA3.
	AllSpeechFollowedByDataCDA3 = "\x40"

	// AllSpeechFollowedByDataCDS3 is the octet string constant for AllSpeechFollowedByDataCDS3.
	AllSpeechFollowedByDataCDS3 = "\x48"

	// AllDataCircuitAsynchronous3 is the octet string constant for AllDataCircuitAsynchronous3.
	AllDataCircuitAsynchronous3 = "\x50"

	// AllAsynchronousServices3 is the octet string constant for AllAsynchronousServices3.
	AllAsynchronousServices3 = "\x60"

	// AllDataCircuitSynchronous3 is the octet string constant for AllDataCircuitSynchronous3.
	AllDataCircuitSynchronous3 = "\x58"

	// AllSynchronousServices3 is the octet string constant for AllSynchronousServices3.
	AllSynchronousServices3 = "\x68"

	// AllPLMNSpecificBS3 is the octet string constant for AllPLMNSpecificBS3.
	AllPLMNSpecificBS3 = "\xd0"

	// PlmnSpecificBS13 is the octet string constant for PlmnSpecificBS13.
	PlmnSpecificBS13 = "\xd1"

	// PlmnSpecificBS23 is the octet string constant for PlmnSpecificBS23.
	PlmnSpecificBS23 = "\xd2"

	// PlmnSpecificBS33 is the octet string constant for PlmnSpecificBS33.
	PlmnSpecificBS33 = "\xd3"

	// PlmnSpecificBS43 is the octet string constant for PlmnSpecificBS43.
	PlmnSpecificBS43 = "\xd4"

	// PlmnSpecificBS53 is the octet string constant for PlmnSpecificBS53.
	PlmnSpecificBS53 = "\xd5"

	// PlmnSpecificBS63 is the octet string constant for PlmnSpecificBS63.
	PlmnSpecificBS63 = "\xd6"

	// PlmnSpecificBS73 is the octet string constant for PlmnSpecificBS73.
	PlmnSpecificBS73 = "\xd7"

	// PlmnSpecificBS83 is the octet string constant for PlmnSpecificBS83.
	PlmnSpecificBS83 = "\xd8"

	// PlmnSpecificBS93 is the octet string constant for PlmnSpecificBS93.
	PlmnSpecificBS93 = "\xd9"

	// PlmnSpecificBSA3 is the octet string constant for PlmnSpecificBSA3.
	PlmnSpecificBSA3 = "\xda"

	// PlmnSpecificBSB3 is the octet string constant for PlmnSpecificBSB3.
	PlmnSpecificBSB3 = "\xdb"

	// PlmnSpecificBSC3 is the octet string constant for PlmnSpecificBSC3.
	PlmnSpecificBSC3 = "\xdc"

	// PlmnSpecificBSD3 is the octet string constant for PlmnSpecificBSD3.
	PlmnSpecificBSD3 = "\xdd"

	// PlmnSpecificBSE3 is the octet string constant for PlmnSpecificBSE3.
	PlmnSpecificBSE3 = "\xde"

	// PlmnSpecificBSF3 is the octet string constant for PlmnSpecificBSF3.
	PlmnSpecificBSF3 = "\xdf"
)

// BearerServiceCode3 represents the ASN.1 type BearerServiceCode3 (OCTET_STRING).
type BearerServiceCode3 = []byte

// ExtBearerServiceCode3 represents the ASN.1 type ExtBearerServiceCode3 (OCTET_STRING).
type ExtBearerServiceCode3 = []byte
