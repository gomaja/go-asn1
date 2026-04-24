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

	// AllAlternateSpeechDataCDA is the octet string constant for allAlternateSpeech-DataCDA.
	AllAlternateSpeechDataCDA = "\x30"

	// AllAlternateSpeechDataCDS is the octet string constant for allAlternateSpeech-DataCDS.
	AllAlternateSpeechDataCDS = "\x38"

	// AllAsynchronousServices is the octet string constant for allAsynchronousServices.
	AllAsynchronousServices = "\x60"

	// AllBearerServices is the octet string constant for allBearerServices.
	AllBearerServices = "\x00"

	// AllDataCDAServices is the octet string constant for allDataCDA-Services.
	AllDataCDAServices = "\x10"

	// AllDataCDSServices is the octet string constant for allDataCDS-Services.
	AllDataCDSServices = "\x18"

	// AllDataCircuitAsynchronous is the octet string constant for allDataCircuitAsynchronous.
	AllDataCircuitAsynchronous = "\x50"

	// AllDataCircuitSynchronous is the octet string constant for allDataCircuitSynchronous.
	AllDataCircuitSynchronous = "\x58"

	// AllDataPDSServices is the octet string constant for allDataPDS-Services.
	AllDataPDSServices = "\x28"

	// AllPLMNSpecificBS is the octet string constant for allPLMN-specificBS.
	AllPLMNSpecificBS = "\xd0"

	// AllPadAccessCAServices is the octet string constant for allPadAccessCA-Services.
	AllPadAccessCAServices = "\x20"

	// AllSpeechFollowedByDataCDA is the octet string constant for allSpeechFollowedByDataCDA.
	AllSpeechFollowedByDataCDA = "\x40"

	// AllSpeechFollowedByDataCDS is the octet string constant for allSpeechFollowedByDataCDS.
	AllSpeechFollowedByDataCDS = "\x48"

	// AllSynchronousServices is the octet string constant for allSynchronousServices.
	AllSynchronousServices = "\x68"

	// DataCDA120075bps is the octet string constant for dataCDA-1200-75bps.
	DataCDA120075bps = "\x13"

	// DataCDA1200bps is the octet string constant for dataCDA-1200bps.
	DataCDA1200bps = "\x12"

	// DataCDA2400bps is the octet string constant for dataCDA-2400bps.
	DataCDA2400bps = "\x14"

	// DataCDA300bps is the octet string constant for dataCDA-300bps.
	DataCDA300bps = "\x11"

	// DataCDA4800bps is the octet string constant for dataCDA-4800bps.
	DataCDA4800bps = "\x15"

	// DataCDA9600bps is the octet string constant for dataCDA-9600bps.
	DataCDA9600bps = "\x16"

	// DataCDS1200bps is the octet string constant for dataCDS-1200bps.
	DataCDS1200bps = "\x1a"

	// DataCDS2400bps is the octet string constant for dataCDS-2400bps.
	DataCDS2400bps = "\x1c"

	// DataCDS4800bps is the octet string constant for dataCDS-4800bps.
	DataCDS4800bps = "\x1d"

	// DataCDS9600bps is the octet string constant for dataCDS-9600bps.
	DataCDS9600bps = "\x1e"

	// DataPDS2400bps is the octet string constant for dataPDS-2400bps.
	DataPDS2400bps = "\x2c"

	// DataPDS4800bps is the octet string constant for dataPDS-4800bps.
	DataPDS4800bps = "\x2d"

	// DataPDS9600bps is the octet string constant for dataPDS-9600bps.
	DataPDS9600bps = "\x2e"

	// GeneralDataCDA is the octet string constant for general-dataCDA.
	GeneralDataCDA = "\x17"

	// GeneralDataCDS is the octet string constant for general-dataCDS.
	GeneralDataCDS = "\x1f"

	// GeneralDataPDS is the octet string constant for general-dataPDS.
	GeneralDataPDS = "\x2f"

	// GeneralPadAccessCA is the octet string constant for general-padAccessCA.
	GeneralPadAccessCA = "\x27"

	// PadAccessCA120075bps is the octet string constant for padAccessCA-1200-75bps.
	PadAccessCA120075bps = "\x23"

	// PadAccessCA1200bps is the octet string constant for padAccessCA-1200bps.
	PadAccessCA1200bps = "\x22"

	// PadAccessCA2400bps is the octet string constant for padAccessCA-2400bps.
	PadAccessCA2400bps = "\x24"

	// PadAccessCA300bps is the octet string constant for padAccessCA-300bps.
	PadAccessCA300bps = "\x21"

	// PadAccessCA4800bps is the octet string constant for padAccessCA-4800bps.
	PadAccessCA4800bps = "\x25"

	// PadAccessCA9600bps is the octet string constant for padAccessCA-9600bps.
	PadAccessCA9600bps = "\x26"

	// PlmnSpecificBS1 is the octet string constant for plmn-specificBS-1.
	PlmnSpecificBS1 = "\xd1"

	// PlmnSpecificBS2 is the octet string constant for plmn-specificBS-2.
	PlmnSpecificBS2 = "\xd2"

	// PlmnSpecificBS3 is the octet string constant for plmn-specificBS-3.
	PlmnSpecificBS3 = "\xd3"

	// PlmnSpecificBS4 is the octet string constant for plmn-specificBS-4.
	PlmnSpecificBS4 = "\xd4"

	// PlmnSpecificBS5 is the octet string constant for plmn-specificBS-5.
	PlmnSpecificBS5 = "\xd5"

	// PlmnSpecificBS6 is the octet string constant for plmn-specificBS-6.
	PlmnSpecificBS6 = "\xd6"

	// PlmnSpecificBS7 is the octet string constant for plmn-specificBS-7.
	PlmnSpecificBS7 = "\xd7"

	// PlmnSpecificBS8 is the octet string constant for plmn-specificBS-8.
	PlmnSpecificBS8 = "\xd8"

	// PlmnSpecificBS9 is the octet string constant for plmn-specificBS-9.
	PlmnSpecificBS9 = "\xd9"

	// PlmnSpecificBSA is the octet string constant for plmn-specificBS-A.
	PlmnSpecificBSA = "\xda"

	// PlmnSpecificBSB is the octet string constant for plmn-specificBS-B.
	PlmnSpecificBSB = "\xdb"

	// PlmnSpecificBSC is the octet string constant for plmn-specificBS-C.
	PlmnSpecificBSC = "\xdc"

	// PlmnSpecificBSD is the octet string constant for plmn-specificBS-D.
	PlmnSpecificBSD = "\xdd"

	// PlmnSpecificBSE is the octet string constant for plmn-specificBS-E.
	PlmnSpecificBSE = "\xde"

	// PlmnSpecificBSF is the octet string constant for plmn-specificBS-F.
	PlmnSpecificBSF = "\xdf"
)

// BearerServiceCode represents the ASN.1 type BearerServiceCode (OCTET_STRING).
type BearerServiceCode = []byte

// ExtBearerServiceCode represents the ASN.1 type Ext-BearerServiceCode (OCTET_STRING).
type ExtBearerServiceCode = []byte
