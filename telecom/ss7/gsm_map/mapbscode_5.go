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

	// AllBearerServices5 is the octet string constant for allBearerServices.
	AllBearerServices5 = "\x00"

	// AllDataCDAServices5 is the octet string constant for allDataCDA-Services.
	AllDataCDAServices5 = "\x10"

	// DataCDA300bps5 is the octet string constant for dataCDA-300bps.
	DataCDA300bps5 = "\x11"

	// DataCDA1200bps5 is the octet string constant for dataCDA-1200bps.
	DataCDA1200bps5 = "\x12"

	// DataCDA120075bps5 is the octet string constant for dataCDA-1200-75bps.
	DataCDA120075bps5 = "\x13"

	// DataCDA2400bps5 is the octet string constant for dataCDA-2400bps.
	DataCDA2400bps5 = "\x14"

	// DataCDA4800bps5 is the octet string constant for dataCDA-4800bps.
	DataCDA4800bps5 = "\x15"

	// DataCDA9600bps5 is the octet string constant for dataCDA-9600bps.
	DataCDA9600bps5 = "\x16"

	// GeneralDataCDA5 is the octet string constant for general-dataCDA.
	GeneralDataCDA5 = "\x17"

	// AllDataCDSServices5 is the octet string constant for allDataCDS-Services.
	AllDataCDSServices5 = "\x18"

	// DataCDS1200bps5 is the octet string constant for dataCDS-1200bps.
	DataCDS1200bps5 = "\x1a"

	// DataCDS2400bps5 is the octet string constant for dataCDS-2400bps.
	DataCDS2400bps5 = "\x1c"

	// DataCDS4800bps5 is the octet string constant for dataCDS-4800bps.
	DataCDS4800bps5 = "\x1d"

	// DataCDS9600bps5 is the octet string constant for dataCDS-9600bps.
	DataCDS9600bps5 = "\x1e"

	// GeneralDataCDS5 is the octet string constant for general-dataCDS.
	GeneralDataCDS5 = "\x1f"

	// AllPadAccessCAServices5 is the octet string constant for allPadAccessCA-Services.
	AllPadAccessCAServices5 = "\x20"

	// PadAccessCA300bps5 is the octet string constant for padAccessCA-300bps.
	PadAccessCA300bps5 = "\x21"

	// PadAccessCA1200bps5 is the octet string constant for padAccessCA-1200bps.
	PadAccessCA1200bps5 = "\x22"

	// PadAccessCA120075bps5 is the octet string constant for padAccessCA-1200-75bps.
	PadAccessCA120075bps5 = "\x23"

	// PadAccessCA2400bps5 is the octet string constant for padAccessCA-2400bps.
	PadAccessCA2400bps5 = "\x24"

	// PadAccessCA4800bps5 is the octet string constant for padAccessCA-4800bps.
	PadAccessCA4800bps5 = "\x25"

	// PadAccessCA9600bps5 is the octet string constant for padAccessCA-9600bps.
	PadAccessCA9600bps5 = "\x26"

	// GeneralPadAccessCA5 is the octet string constant for general-padAccessCA.
	GeneralPadAccessCA5 = "\x27"

	// AllDataPDSServices5 is the octet string constant for allDataPDS-Services.
	AllDataPDSServices5 = "\x28"

	// DataPDS2400bps5 is the octet string constant for dataPDS-2400bps.
	DataPDS2400bps5 = "\x2c"

	// DataPDS4800bps5 is the octet string constant for dataPDS-4800bps.
	DataPDS4800bps5 = "\x2d"

	// DataPDS9600bps5 is the octet string constant for dataPDS-9600bps.
	DataPDS9600bps5 = "\x2e"

	// GeneralDataPDS5 is the octet string constant for general-dataPDS.
	GeneralDataPDS5 = "\x2f"

	// AllAlternateSpeechDataCDA5 is the octet string constant for allAlternateSpeech-DataCDA.
	AllAlternateSpeechDataCDA5 = "\x30"

	// AllAlternateSpeechDataCDS5 is the octet string constant for allAlternateSpeech-DataCDS.
	AllAlternateSpeechDataCDS5 = "\x38"

	// AllSpeechFollowedByDataCDA5 is the octet string constant for allSpeechFollowedByDataCDA.
	AllSpeechFollowedByDataCDA5 = "\x40"

	// AllSpeechFollowedByDataCDS5 is the octet string constant for allSpeechFollowedByDataCDS.
	AllSpeechFollowedByDataCDS5 = "\x48"

	// AllDataCircuitAsynchronous5 is the octet string constant for allDataCircuitAsynchronous.
	AllDataCircuitAsynchronous5 = "\x50"

	// AllAsynchronousServices5 is the octet string constant for allAsynchronousServices.
	AllAsynchronousServices5 = "\x60"

	// AllDataCircuitSynchronous5 is the octet string constant for allDataCircuitSynchronous.
	AllDataCircuitSynchronous5 = "\x58"

	// AllSynchronousServices5 is the octet string constant for allSynchronousServices.
	AllSynchronousServices5 = "\x68"

	// AllPLMNSpecificBS5 is the octet string constant for allPLMN-specificBS.
	AllPLMNSpecificBS5 = "\xd0"

	// PlmnSpecificBS15 is the octet string constant for plmn-specificBS-1.
	PlmnSpecificBS15 = "\xd1"

	// PlmnSpecificBS25 is the octet string constant for plmn-specificBS-2.
	PlmnSpecificBS25 = "\xd2"

	// PlmnSpecificBS35 is the octet string constant for plmn-specificBS-3.
	PlmnSpecificBS35 = "\xd3"

	// PlmnSpecificBS45 is the octet string constant for plmn-specificBS-4.
	PlmnSpecificBS45 = "\xd4"

	// PlmnSpecificBS55 is the octet string constant for plmn-specificBS-5.
	PlmnSpecificBS55 = "\xd5"

	// PlmnSpecificBS65 is the octet string constant for plmn-specificBS-6.
	PlmnSpecificBS65 = "\xd6"

	// PlmnSpecificBS75 is the octet string constant for plmn-specificBS-7.
	PlmnSpecificBS75 = "\xd7"

	// PlmnSpecificBS85 is the octet string constant for plmn-specificBS-8.
	PlmnSpecificBS85 = "\xd8"

	// PlmnSpecificBS95 is the octet string constant for plmn-specificBS-9.
	PlmnSpecificBS95 = "\xd9"

	// PlmnSpecificBSA5 is the octet string constant for plmn-specificBS-A.
	PlmnSpecificBSA5 = "\xda"

	// PlmnSpecificBSB5 is the octet string constant for plmn-specificBS-B.
	PlmnSpecificBSB5 = "\xdb"

	// PlmnSpecificBSC5 is the octet string constant for plmn-specificBS-C.
	PlmnSpecificBSC5 = "\xdc"

	// PlmnSpecificBSD5 is the octet string constant for plmn-specificBS-D.
	PlmnSpecificBSD5 = "\xdd"

	// PlmnSpecificBSE5 is the octet string constant for plmn-specificBS-E.
	PlmnSpecificBSE5 = "\xde"

	// PlmnSpecificBSF5 is the octet string constant for plmn-specificBS-F.
	PlmnSpecificBSF5 = "\xdf"
)

// BearerServiceCode5 represents the ASN.1 type BearerServiceCode (OCTET_STRING).
type BearerServiceCode5 = []byte

// ExtBearerServiceCode5 represents the ASN.1 type Ext-BearerServiceCode (OCTET_STRING).
type ExtBearerServiceCode5 = []byte
