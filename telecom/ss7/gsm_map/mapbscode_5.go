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

	// AllBearerServices5 is the octet string constant for AllBearerServices5.
	AllBearerServices5 = "\x00"

	// AllDataCDAServices5 is the octet string constant for AllDataCDAServices5.
	AllDataCDAServices5 = "\x10"

	// DataCDA300bps5 is the octet string constant for DataCDA300bps5.
	DataCDA300bps5 = "\x11"

	// DataCDA1200bps5 is the octet string constant for DataCDA1200bps5.
	DataCDA1200bps5 = "\x12"

	// DataCDA120075bps5 is the octet string constant for DataCDA120075bps5.
	DataCDA120075bps5 = "\x13"

	// DataCDA2400bps5 is the octet string constant for DataCDA2400bps5.
	DataCDA2400bps5 = "\x14"

	// DataCDA4800bps5 is the octet string constant for DataCDA4800bps5.
	DataCDA4800bps5 = "\x15"

	// DataCDA9600bps5 is the octet string constant for DataCDA9600bps5.
	DataCDA9600bps5 = "\x16"

	// GeneralDataCDA5 is the octet string constant for GeneralDataCDA5.
	GeneralDataCDA5 = "\x17"

	// AllDataCDSServices5 is the octet string constant for AllDataCDSServices5.
	AllDataCDSServices5 = "\x18"

	// DataCDS1200bps5 is the octet string constant for DataCDS1200bps5.
	DataCDS1200bps5 = "\x1a"

	// DataCDS2400bps5 is the octet string constant for DataCDS2400bps5.
	DataCDS2400bps5 = "\x1c"

	// DataCDS4800bps5 is the octet string constant for DataCDS4800bps5.
	DataCDS4800bps5 = "\x1d"

	// DataCDS9600bps5 is the octet string constant for DataCDS9600bps5.
	DataCDS9600bps5 = "\x1e"

	// GeneralDataCDS5 is the octet string constant for GeneralDataCDS5.
	GeneralDataCDS5 = "\x1f"

	// AllPadAccessCAServices5 is the octet string constant for AllPadAccessCAServices5.
	AllPadAccessCAServices5 = "\x20"

	// PadAccessCA300bps5 is the octet string constant for PadAccessCA300bps5.
	PadAccessCA300bps5 = "\x21"

	// PadAccessCA1200bps5 is the octet string constant for PadAccessCA1200bps5.
	PadAccessCA1200bps5 = "\x22"

	// PadAccessCA120075bps5 is the octet string constant for PadAccessCA120075bps5.
	PadAccessCA120075bps5 = "\x23"

	// PadAccessCA2400bps5 is the octet string constant for PadAccessCA2400bps5.
	PadAccessCA2400bps5 = "\x24"

	// PadAccessCA4800bps5 is the octet string constant for PadAccessCA4800bps5.
	PadAccessCA4800bps5 = "\x25"

	// PadAccessCA9600bps5 is the octet string constant for PadAccessCA9600bps5.
	PadAccessCA9600bps5 = "\x26"

	// GeneralPadAccessCA5 is the octet string constant for GeneralPadAccessCA5.
	GeneralPadAccessCA5 = "\x27"

	// AllDataPDSServices5 is the octet string constant for AllDataPDSServices5.
	AllDataPDSServices5 = "\x28"

	// DataPDS2400bps5 is the octet string constant for DataPDS2400bps5.
	DataPDS2400bps5 = "\x2c"

	// DataPDS4800bps5 is the octet string constant for DataPDS4800bps5.
	DataPDS4800bps5 = "\x2d"

	// DataPDS9600bps5 is the octet string constant for DataPDS9600bps5.
	DataPDS9600bps5 = "\x2e"

	// GeneralDataPDS5 is the octet string constant for GeneralDataPDS5.
	GeneralDataPDS5 = "\x2f"

	// AllAlternateSpeechDataCDA5 is the octet string constant for AllAlternateSpeechDataCDA5.
	AllAlternateSpeechDataCDA5 = "\x30"

	// AllAlternateSpeechDataCDS5 is the octet string constant for AllAlternateSpeechDataCDS5.
	AllAlternateSpeechDataCDS5 = "\x38"

	// AllSpeechFollowedByDataCDA5 is the octet string constant for AllSpeechFollowedByDataCDA5.
	AllSpeechFollowedByDataCDA5 = "\x40"

	// AllSpeechFollowedByDataCDS5 is the octet string constant for AllSpeechFollowedByDataCDS5.
	AllSpeechFollowedByDataCDS5 = "\x48"

	// AllDataCircuitAsynchronous5 is the octet string constant for AllDataCircuitAsynchronous5.
	AllDataCircuitAsynchronous5 = "\x50"

	// AllAsynchronousServices5 is the octet string constant for AllAsynchronousServices5.
	AllAsynchronousServices5 = "\x60"

	// AllDataCircuitSynchronous5 is the octet string constant for AllDataCircuitSynchronous5.
	AllDataCircuitSynchronous5 = "\x58"

	// AllSynchronousServices5 is the octet string constant for AllSynchronousServices5.
	AllSynchronousServices5 = "\x68"

	// AllPLMNSpecificBS5 is the octet string constant for AllPLMNSpecificBS5.
	AllPLMNSpecificBS5 = "\xd0"

	// PlmnSpecificBS15 is the octet string constant for PlmnSpecificBS15.
	PlmnSpecificBS15 = "\xd1"

	// PlmnSpecificBS25 is the octet string constant for PlmnSpecificBS25.
	PlmnSpecificBS25 = "\xd2"

	// PlmnSpecificBS35 is the octet string constant for PlmnSpecificBS35.
	PlmnSpecificBS35 = "\xd3"

	// PlmnSpecificBS45 is the octet string constant for PlmnSpecificBS45.
	PlmnSpecificBS45 = "\xd4"

	// PlmnSpecificBS55 is the octet string constant for PlmnSpecificBS55.
	PlmnSpecificBS55 = "\xd5"

	// PlmnSpecificBS65 is the octet string constant for PlmnSpecificBS65.
	PlmnSpecificBS65 = "\xd6"

	// PlmnSpecificBS75 is the octet string constant for PlmnSpecificBS75.
	PlmnSpecificBS75 = "\xd7"

	// PlmnSpecificBS85 is the octet string constant for PlmnSpecificBS85.
	PlmnSpecificBS85 = "\xd8"

	// PlmnSpecificBS95 is the octet string constant for PlmnSpecificBS95.
	PlmnSpecificBS95 = "\xd9"

	// PlmnSpecificBSA5 is the octet string constant for PlmnSpecificBSA5.
	PlmnSpecificBSA5 = "\xda"

	// PlmnSpecificBSB5 is the octet string constant for PlmnSpecificBSB5.
	PlmnSpecificBSB5 = "\xdb"

	// PlmnSpecificBSC5 is the octet string constant for PlmnSpecificBSC5.
	PlmnSpecificBSC5 = "\xdc"

	// PlmnSpecificBSD5 is the octet string constant for PlmnSpecificBSD5.
	PlmnSpecificBSD5 = "\xdd"

	// PlmnSpecificBSE5 is the octet string constant for PlmnSpecificBSE5.
	PlmnSpecificBSE5 = "\xde"

	// PlmnSpecificBSF5 is the octet string constant for PlmnSpecificBSF5.
	PlmnSpecificBSF5 = "\xdf"
)

// BearerServiceCode5 represents the ASN.1 type BearerServiceCode5 (OCTET_STRING).
type BearerServiceCode5 = []byte

// ExtBearerServiceCode5 represents the ASN.1 type ExtBearerServiceCode5 (OCTET_STRING).
type ExtBearerServiceCode5 = []byte
