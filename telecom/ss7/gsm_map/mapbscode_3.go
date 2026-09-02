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

	// AllBearerServices3 is the octet string constant for allBearerServices.
	AllBearerServices3 = "\x00"

	// AllDataCDAServices3 is the octet string constant for allDataCDA-Services.
	AllDataCDAServices3 = "\x10"

	// DataCDA300bps3 is the octet string constant for dataCDA-300bps.
	DataCDA300bps3 = "\x11"

	// DataCDA1200bps3 is the octet string constant for dataCDA-1200bps.
	DataCDA1200bps3 = "\x12"

	// DataCDA120075bps3 is the octet string constant for dataCDA-1200-75bps.
	DataCDA120075bps3 = "\x13"

	// DataCDA2400bps3 is the octet string constant for dataCDA-2400bps.
	DataCDA2400bps3 = "\x14"

	// DataCDA4800bps3 is the octet string constant for dataCDA-4800bps.
	DataCDA4800bps3 = "\x15"

	// DataCDA9600bps3 is the octet string constant for dataCDA-9600bps.
	DataCDA9600bps3 = "\x16"

	// GeneralDataCDA3 is the octet string constant for general-dataCDA.
	GeneralDataCDA3 = "\x17"

	// AllDataCDSServices3 is the octet string constant for allDataCDS-Services.
	AllDataCDSServices3 = "\x18"

	// DataCDS1200bps3 is the octet string constant for dataCDS-1200bps.
	DataCDS1200bps3 = "\x1a"

	// DataCDS2400bps3 is the octet string constant for dataCDS-2400bps.
	DataCDS2400bps3 = "\x1c"

	// DataCDS4800bps3 is the octet string constant for dataCDS-4800bps.
	DataCDS4800bps3 = "\x1d"

	// DataCDS9600bps3 is the octet string constant for dataCDS-9600bps.
	DataCDS9600bps3 = "\x1e"

	// GeneralDataCDS3 is the octet string constant for general-dataCDS.
	GeneralDataCDS3 = "\x1f"

	// AllPadAccessCAServices3 is the octet string constant for allPadAccessCA-Services.
	AllPadAccessCAServices3 = "\x20"

	// PadAccessCA300bps3 is the octet string constant for padAccessCA-300bps.
	PadAccessCA300bps3 = "\x21"

	// PadAccessCA1200bps3 is the octet string constant for padAccessCA-1200bps.
	PadAccessCA1200bps3 = "\x22"

	// PadAccessCA120075bps3 is the octet string constant for padAccessCA-1200-75bps.
	PadAccessCA120075bps3 = "\x23"

	// PadAccessCA2400bps3 is the octet string constant for padAccessCA-2400bps.
	PadAccessCA2400bps3 = "\x24"

	// PadAccessCA4800bps3 is the octet string constant for padAccessCA-4800bps.
	PadAccessCA4800bps3 = "\x25"

	// PadAccessCA9600bps3 is the octet string constant for padAccessCA-9600bps.
	PadAccessCA9600bps3 = "\x26"

	// GeneralPadAccessCA3 is the octet string constant for general-padAccessCA.
	GeneralPadAccessCA3 = "\x27"

	// AllDataPDSServices3 is the octet string constant for allDataPDS-Services.
	AllDataPDSServices3 = "\x28"

	// DataPDS2400bps3 is the octet string constant for dataPDS-2400bps.
	DataPDS2400bps3 = "\x2c"

	// DataPDS4800bps3 is the octet string constant for dataPDS-4800bps.
	DataPDS4800bps3 = "\x2d"

	// DataPDS9600bps3 is the octet string constant for dataPDS-9600bps.
	DataPDS9600bps3 = "\x2e"

	// GeneralDataPDS3 is the octet string constant for general-dataPDS.
	GeneralDataPDS3 = "\x2f"

	// AllAlternateSpeechDataCDA3 is the octet string constant for allAlternateSpeech-DataCDA.
	AllAlternateSpeechDataCDA3 = "\x30"

	// AllAlternateSpeechDataCDS3 is the octet string constant for allAlternateSpeech-DataCDS.
	AllAlternateSpeechDataCDS3 = "\x38"

	// AllSpeechFollowedByDataCDA3 is the octet string constant for allSpeechFollowedByDataCDA.
	AllSpeechFollowedByDataCDA3 = "\x40"

	// AllSpeechFollowedByDataCDS3 is the octet string constant for allSpeechFollowedByDataCDS.
	AllSpeechFollowedByDataCDS3 = "\x48"

	// AllDataCircuitAsynchronous3 is the octet string constant for allDataCircuitAsynchronous.
	AllDataCircuitAsynchronous3 = "\x50"

	// AllAsynchronousServices3 is the octet string constant for allAsynchronousServices.
	AllAsynchronousServices3 = "\x60"

	// AllDataCircuitSynchronous3 is the octet string constant for allDataCircuitSynchronous.
	AllDataCircuitSynchronous3 = "\x58"

	// AllSynchronousServices3 is the octet string constant for allSynchronousServices.
	AllSynchronousServices3 = "\x68"

	// AllPLMNSpecificBS3 is the octet string constant for allPLMN-specificBS.
	AllPLMNSpecificBS3 = "\xd0"

	// PlmnSpecificBS13 is the octet string constant for plmn-specificBS-1.
	PlmnSpecificBS13 = "\xd1"

	// PlmnSpecificBS23 is the octet string constant for plmn-specificBS-2.
	PlmnSpecificBS23 = "\xd2"

	// PlmnSpecificBS33 is the octet string constant for plmn-specificBS-3.
	PlmnSpecificBS33 = "\xd3"

	// PlmnSpecificBS43 is the octet string constant for plmn-specificBS-4.
	PlmnSpecificBS43 = "\xd4"

	// PlmnSpecificBS53 is the octet string constant for plmn-specificBS-5.
	PlmnSpecificBS53 = "\xd5"

	// PlmnSpecificBS63 is the octet string constant for plmn-specificBS-6.
	PlmnSpecificBS63 = "\xd6"

	// PlmnSpecificBS73 is the octet string constant for plmn-specificBS-7.
	PlmnSpecificBS73 = "\xd7"

	// PlmnSpecificBS83 is the octet string constant for plmn-specificBS-8.
	PlmnSpecificBS83 = "\xd8"

	// PlmnSpecificBS93 is the octet string constant for plmn-specificBS-9.
	PlmnSpecificBS93 = "\xd9"

	// PlmnSpecificBSA3 is the octet string constant for plmn-specificBS-A.
	PlmnSpecificBSA3 = "\xda"

	// PlmnSpecificBSB3 is the octet string constant for plmn-specificBS-B.
	PlmnSpecificBSB3 = "\xdb"

	// PlmnSpecificBSC3 is the octet string constant for plmn-specificBS-C.
	PlmnSpecificBSC3 = "\xdc"

	// PlmnSpecificBSD3 is the octet string constant for plmn-specificBS-D.
	PlmnSpecificBSD3 = "\xdd"

	// PlmnSpecificBSE3 is the octet string constant for plmn-specificBS-E.
	PlmnSpecificBSE3 = "\xde"

	// PlmnSpecificBSF3 is the octet string constant for plmn-specificBS-F.
	PlmnSpecificBSF3 = "\xdf"
)

// BearerServiceCode3 represents the ASN.1 type BearerServiceCode (OCTET_STRING).
type BearerServiceCode3 = []byte

// ExtBearerServiceCode3 represents the ASN.1 type Ext-BearerServiceCode (OCTET_STRING).
type ExtBearerServiceCode3 = []byte
