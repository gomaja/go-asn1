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

	// AllBearerServices6 is the octet string constant for allBearerServices.
	AllBearerServices6 = "\x00"

	// AllDataCDAServices6 is the octet string constant for allDataCDA-Services.
	AllDataCDAServices6 = "\x10"

	// DataCDA300bps6 is the octet string constant for dataCDA-300bps.
	DataCDA300bps6 = "\x11"

	// DataCDA1200bps6 is the octet string constant for dataCDA-1200bps.
	DataCDA1200bps6 = "\x12"

	// DataCDA120075bps6 is the octet string constant for dataCDA-1200-75bps.
	DataCDA120075bps6 = "\x13"

	// DataCDA2400bps6 is the octet string constant for dataCDA-2400bps.
	DataCDA2400bps6 = "\x14"

	// DataCDA4800bps6 is the octet string constant for dataCDA-4800bps.
	DataCDA4800bps6 = "\x15"

	// DataCDA9600bps6 is the octet string constant for dataCDA-9600bps.
	DataCDA9600bps6 = "\x16"

	// GeneralDataCDA6 is the octet string constant for general-dataCDA.
	GeneralDataCDA6 = "\x17"

	// AllDataCDSServices6 is the octet string constant for allDataCDS-Services.
	AllDataCDSServices6 = "\x18"

	// DataCDS1200bps6 is the octet string constant for dataCDS-1200bps.
	DataCDS1200bps6 = "\x1a"

	// DataCDS2400bps6 is the octet string constant for dataCDS-2400bps.
	DataCDS2400bps6 = "\x1c"

	// DataCDS4800bps6 is the octet string constant for dataCDS-4800bps.
	DataCDS4800bps6 = "\x1d"

	// DataCDS9600bps6 is the octet string constant for dataCDS-9600bps.
	DataCDS9600bps6 = "\x1e"

	// GeneralDataCDS6 is the octet string constant for general-dataCDS.
	GeneralDataCDS6 = "\x1f"

	// AllPadAccessCAServices6 is the octet string constant for allPadAccessCA-Services.
	AllPadAccessCAServices6 = "\x20"

	// PadAccessCA300bps6 is the octet string constant for padAccessCA-300bps.
	PadAccessCA300bps6 = "\x21"

	// PadAccessCA1200bps6 is the octet string constant for padAccessCA-1200bps.
	PadAccessCA1200bps6 = "\x22"

	// PadAccessCA120075bps6 is the octet string constant for padAccessCA-1200-75bps.
	PadAccessCA120075bps6 = "\x23"

	// PadAccessCA2400bps6 is the octet string constant for padAccessCA-2400bps.
	PadAccessCA2400bps6 = "\x24"

	// PadAccessCA4800bps6 is the octet string constant for padAccessCA-4800bps.
	PadAccessCA4800bps6 = "\x25"

	// PadAccessCA9600bps6 is the octet string constant for padAccessCA-9600bps.
	PadAccessCA9600bps6 = "\x26"

	// GeneralPadAccessCA6 is the octet string constant for general-padAccessCA.
	GeneralPadAccessCA6 = "\x27"

	// AllDataPDSServices6 is the octet string constant for allDataPDS-Services.
	AllDataPDSServices6 = "\x28"

	// DataPDS2400bps6 is the octet string constant for dataPDS-2400bps.
	DataPDS2400bps6 = "\x2c"

	// DataPDS4800bps6 is the octet string constant for dataPDS-4800bps.
	DataPDS4800bps6 = "\x2d"

	// DataPDS9600bps6 is the octet string constant for dataPDS-9600bps.
	DataPDS9600bps6 = "\x2e"

	// GeneralDataPDS6 is the octet string constant for general-dataPDS.
	GeneralDataPDS6 = "\x2f"

	// AllAlternateSpeechDataCDA6 is the octet string constant for allAlternateSpeech-DataCDA.
	AllAlternateSpeechDataCDA6 = "\x30"

	// AllAlternateSpeechDataCDS6 is the octet string constant for allAlternateSpeech-DataCDS.
	AllAlternateSpeechDataCDS6 = "\x38"

	// AllSpeechFollowedByDataCDA6 is the octet string constant for allSpeechFollowedByDataCDA.
	AllSpeechFollowedByDataCDA6 = "\x40"

	// AllSpeechFollowedByDataCDS6 is the octet string constant for allSpeechFollowedByDataCDS.
	AllSpeechFollowedByDataCDS6 = "\x48"

	// AllDataCircuitAsynchronous6 is the octet string constant for allDataCircuitAsynchronous.
	AllDataCircuitAsynchronous6 = "\x50"

	// AllAsynchronousServices6 is the octet string constant for allAsynchronousServices.
	AllAsynchronousServices6 = "\x60"

	// AllDataCircuitSynchronous6 is the octet string constant for allDataCircuitSynchronous.
	AllDataCircuitSynchronous6 = "\x58"

	// AllSynchronousServices6 is the octet string constant for allSynchronousServices.
	AllSynchronousServices6 = "\x68"

	// AllPLMNSpecificBS6 is the octet string constant for allPLMN-specificBS.
	AllPLMNSpecificBS6 = "\xd0"

	// PlmnSpecificBS16 is the octet string constant for plmn-specificBS-1.
	PlmnSpecificBS16 = "\xd1"

	// PlmnSpecificBS26 is the octet string constant for plmn-specificBS-2.
	PlmnSpecificBS26 = "\xd2"

	// PlmnSpecificBS36 is the octet string constant for plmn-specificBS-3.
	PlmnSpecificBS36 = "\xd3"

	// PlmnSpecificBS46 is the octet string constant for plmn-specificBS-4.
	PlmnSpecificBS46 = "\xd4"

	// PlmnSpecificBS56 is the octet string constant for plmn-specificBS-5.
	PlmnSpecificBS56 = "\xd5"

	// PlmnSpecificBS66 is the octet string constant for plmn-specificBS-6.
	PlmnSpecificBS66 = "\xd6"

	// PlmnSpecificBS76 is the octet string constant for plmn-specificBS-7.
	PlmnSpecificBS76 = "\xd7"

	// PlmnSpecificBS86 is the octet string constant for plmn-specificBS-8.
	PlmnSpecificBS86 = "\xd8"

	// PlmnSpecificBS96 is the octet string constant for plmn-specificBS-9.
	PlmnSpecificBS96 = "\xd9"

	// PlmnSpecificBSA6 is the octet string constant for plmn-specificBS-A.
	PlmnSpecificBSA6 = "\xda"

	// PlmnSpecificBSB6 is the octet string constant for plmn-specificBS-B.
	PlmnSpecificBSB6 = "\xdb"

	// PlmnSpecificBSC6 is the octet string constant for plmn-specificBS-C.
	PlmnSpecificBSC6 = "\xdc"

	// PlmnSpecificBSD6 is the octet string constant for plmn-specificBS-D.
	PlmnSpecificBSD6 = "\xdd"

	// PlmnSpecificBSE6 is the octet string constant for plmn-specificBS-E.
	PlmnSpecificBSE6 = "\xde"

	// PlmnSpecificBSF6 is the octet string constant for plmn-specificBS-F.
	PlmnSpecificBSF6 = "\xdf"
)

// BearerServiceCode6 represents the ASN.1 type BearerServiceCode (OCTET_STRING).
type BearerServiceCode6 = []byte

// ExtBearerServiceCode6 represents the ASN.1 type Ext-BearerServiceCode (OCTET_STRING).
type ExtBearerServiceCode6 = []byte
