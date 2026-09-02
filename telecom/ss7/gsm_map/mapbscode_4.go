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

	// AllBearerServices4 is the octet string constant for allBearerServices.
	AllBearerServices4 = "\x00"

	// AllDataCDAServices4 is the octet string constant for allDataCDA-Services.
	AllDataCDAServices4 = "\x10"

	// DataCDA300bps4 is the octet string constant for dataCDA-300bps.
	DataCDA300bps4 = "\x11"

	// DataCDA1200bps4 is the octet string constant for dataCDA-1200bps.
	DataCDA1200bps4 = "\x12"

	// DataCDA120075bps4 is the octet string constant for dataCDA-1200-75bps.
	DataCDA120075bps4 = "\x13"

	// DataCDA2400bps4 is the octet string constant for dataCDA-2400bps.
	DataCDA2400bps4 = "\x14"

	// DataCDA4800bps4 is the octet string constant for dataCDA-4800bps.
	DataCDA4800bps4 = "\x15"

	// DataCDA9600bps4 is the octet string constant for dataCDA-9600bps.
	DataCDA9600bps4 = "\x16"

	// GeneralDataCDA4 is the octet string constant for general-dataCDA.
	GeneralDataCDA4 = "\x17"

	// AllDataCDSServices4 is the octet string constant for allDataCDS-Services.
	AllDataCDSServices4 = "\x18"

	// DataCDS1200bps4 is the octet string constant for dataCDS-1200bps.
	DataCDS1200bps4 = "\x1a"

	// DataCDS2400bps4 is the octet string constant for dataCDS-2400bps.
	DataCDS2400bps4 = "\x1c"

	// DataCDS4800bps4 is the octet string constant for dataCDS-4800bps.
	DataCDS4800bps4 = "\x1d"

	// DataCDS9600bps4 is the octet string constant for dataCDS-9600bps.
	DataCDS9600bps4 = "\x1e"

	// GeneralDataCDS4 is the octet string constant for general-dataCDS.
	GeneralDataCDS4 = "\x1f"

	// AllPadAccessCAServices4 is the octet string constant for allPadAccessCA-Services.
	AllPadAccessCAServices4 = "\x20"

	// PadAccessCA300bps4 is the octet string constant for padAccessCA-300bps.
	PadAccessCA300bps4 = "\x21"

	// PadAccessCA1200bps4 is the octet string constant for padAccessCA-1200bps.
	PadAccessCA1200bps4 = "\x22"

	// PadAccessCA120075bps4 is the octet string constant for padAccessCA-1200-75bps.
	PadAccessCA120075bps4 = "\x23"

	// PadAccessCA2400bps4 is the octet string constant for padAccessCA-2400bps.
	PadAccessCA2400bps4 = "\x24"

	// PadAccessCA4800bps4 is the octet string constant for padAccessCA-4800bps.
	PadAccessCA4800bps4 = "\x25"

	// PadAccessCA9600bps4 is the octet string constant for padAccessCA-9600bps.
	PadAccessCA9600bps4 = "\x26"

	// GeneralPadAccessCA4 is the octet string constant for general-padAccessCA.
	GeneralPadAccessCA4 = "\x27"

	// AllDataPDSServices4 is the octet string constant for allDataPDS-Services.
	AllDataPDSServices4 = "\x28"

	// DataPDS2400bps4 is the octet string constant for dataPDS-2400bps.
	DataPDS2400bps4 = "\x2c"

	// DataPDS4800bps4 is the octet string constant for dataPDS-4800bps.
	DataPDS4800bps4 = "\x2d"

	// DataPDS9600bps4 is the octet string constant for dataPDS-9600bps.
	DataPDS9600bps4 = "\x2e"

	// GeneralDataPDS4 is the octet string constant for general-dataPDS.
	GeneralDataPDS4 = "\x2f"

	// AllAlternateSpeechDataCDA4 is the octet string constant for allAlternateSpeech-DataCDA.
	AllAlternateSpeechDataCDA4 = "\x30"

	// AllAlternateSpeechDataCDS4 is the octet string constant for allAlternateSpeech-DataCDS.
	AllAlternateSpeechDataCDS4 = "\x38"

	// AllSpeechFollowedByDataCDA4 is the octet string constant for allSpeechFollowedByDataCDA.
	AllSpeechFollowedByDataCDA4 = "\x40"

	// AllSpeechFollowedByDataCDS4 is the octet string constant for allSpeechFollowedByDataCDS.
	AllSpeechFollowedByDataCDS4 = "\x48"

	// AllDataCircuitAsynchronous4 is the octet string constant for allDataCircuitAsynchronous.
	AllDataCircuitAsynchronous4 = "\x50"

	// AllAsynchronousServices4 is the octet string constant for allAsynchronousServices.
	AllAsynchronousServices4 = "\x60"

	// AllDataCircuitSynchronous4 is the octet string constant for allDataCircuitSynchronous.
	AllDataCircuitSynchronous4 = "\x58"

	// AllSynchronousServices4 is the octet string constant for allSynchronousServices.
	AllSynchronousServices4 = "\x68"

	// AllPLMNSpecificBS4 is the octet string constant for allPLMN-specificBS.
	AllPLMNSpecificBS4 = "\xd0"

	// PlmnSpecificBS14 is the octet string constant for plmn-specificBS-1.
	PlmnSpecificBS14 = "\xd1"

	// PlmnSpecificBS24 is the octet string constant for plmn-specificBS-2.
	PlmnSpecificBS24 = "\xd2"

	// PlmnSpecificBS34 is the octet string constant for plmn-specificBS-3.
	PlmnSpecificBS34 = "\xd3"

	// PlmnSpecificBS44 is the octet string constant for plmn-specificBS-4.
	PlmnSpecificBS44 = "\xd4"

	// PlmnSpecificBS54 is the octet string constant for plmn-specificBS-5.
	PlmnSpecificBS54 = "\xd5"

	// PlmnSpecificBS64 is the octet string constant for plmn-specificBS-6.
	PlmnSpecificBS64 = "\xd6"

	// PlmnSpecificBS74 is the octet string constant for plmn-specificBS-7.
	PlmnSpecificBS74 = "\xd7"

	// PlmnSpecificBS84 is the octet string constant for plmn-specificBS-8.
	PlmnSpecificBS84 = "\xd8"

	// PlmnSpecificBS94 is the octet string constant for plmn-specificBS-9.
	PlmnSpecificBS94 = "\xd9"

	// PlmnSpecificBSA4 is the octet string constant for plmn-specificBS-A.
	PlmnSpecificBSA4 = "\xda"

	// PlmnSpecificBSB4 is the octet string constant for plmn-specificBS-B.
	PlmnSpecificBSB4 = "\xdb"

	// PlmnSpecificBSC4 is the octet string constant for plmn-specificBS-C.
	PlmnSpecificBSC4 = "\xdc"

	// PlmnSpecificBSD4 is the octet string constant for plmn-specificBS-D.
	PlmnSpecificBSD4 = "\xdd"

	// PlmnSpecificBSE4 is the octet string constant for plmn-specificBS-E.
	PlmnSpecificBSE4 = "\xde"

	// PlmnSpecificBSF4 is the octet string constant for plmn-specificBS-F.
	PlmnSpecificBSF4 = "\xdf"
)

// BearerServiceCode4 represents the ASN.1 type BearerServiceCode (OCTET_STRING).
type BearerServiceCode4 = []byte

// ExtBearerServiceCode4 represents the ASN.1 type Ext-BearerServiceCode (OCTET_STRING).
type ExtBearerServiceCode4 = []byte
