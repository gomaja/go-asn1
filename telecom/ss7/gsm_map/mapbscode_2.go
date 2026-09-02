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

	// BSAllBearerServices is the octet string constant for allBearerServices.
	BSAllBearerServices = "\x00"

	// BSAllDataCDAServices is the octet string constant for allDataCDA-Services.
	BSAllDataCDAServices = "\x10"

	// BSDataCDA300bps is the octet string constant for dataCDA-300bps.
	BSDataCDA300bps = "\x11"

	// BSDataCDA1200bps is the octet string constant for dataCDA-1200bps.
	BSDataCDA1200bps = "\x12"

	// BSDataCDA120075bps is the octet string constant for dataCDA-1200-75bps.
	BSDataCDA120075bps = "\x13"

	// BSDataCDA2400bps is the octet string constant for dataCDA-2400bps.
	BSDataCDA2400bps = "\x14"

	// BSDataCDA4800bps is the octet string constant for dataCDA-4800bps.
	BSDataCDA4800bps = "\x15"

	// BSDataCDA9600bps is the octet string constant for dataCDA-9600bps.
	BSDataCDA9600bps = "\x16"

	// BSGeneralDataCDA is the octet string constant for general-dataCDA.
	BSGeneralDataCDA = "\x17"

	// BSAllDataCDSServices is the octet string constant for allDataCDS-Services.
	BSAllDataCDSServices = "\x18"

	// BSDataCDS1200bps is the octet string constant for dataCDS-1200bps.
	BSDataCDS1200bps = "\x1a"

	// BSDataCDS2400bps is the octet string constant for dataCDS-2400bps.
	BSDataCDS2400bps = "\x1c"

	// BSDataCDS4800bps is the octet string constant for dataCDS-4800bps.
	BSDataCDS4800bps = "\x1d"

	// BSDataCDS9600bps is the octet string constant for dataCDS-9600bps.
	BSDataCDS9600bps = "\x1e"

	// BSGeneralDataCDS is the octet string constant for general-dataCDS.
	BSGeneralDataCDS = "\x1f"

	// BSAllPadAccessCAServices is the octet string constant for allPadAccessCA-Services.
	BSAllPadAccessCAServices = "\x20"

	// BSPadAccessCA300bps is the octet string constant for padAccessCA-300bps.
	BSPadAccessCA300bps = "\x21"

	// BSPadAccessCA1200bps is the octet string constant for padAccessCA-1200bps.
	BSPadAccessCA1200bps = "\x22"

	// BSPadAccessCA120075bps is the octet string constant for padAccessCA-1200-75bps.
	BSPadAccessCA120075bps = "\x23"

	// BSPadAccessCA2400bps is the octet string constant for padAccessCA-2400bps.
	BSPadAccessCA2400bps = "\x24"

	// BSPadAccessCA4800bps is the octet string constant for padAccessCA-4800bps.
	BSPadAccessCA4800bps = "\x25"

	// BSPadAccessCA9600bps is the octet string constant for padAccessCA-9600bps.
	BSPadAccessCA9600bps = "\x26"

	// BSGeneralPadAccessCA is the octet string constant for general-padAccessCA.
	BSGeneralPadAccessCA = "\x27"

	// BSAllDataPDSServices is the octet string constant for allDataPDS-Services.
	BSAllDataPDSServices = "\x28"

	// BSDataPDS2400bps is the octet string constant for dataPDS-2400bps.
	BSDataPDS2400bps = "\x2c"

	// BSDataPDS4800bps is the octet string constant for dataPDS-4800bps.
	BSDataPDS4800bps = "\x2d"

	// BSDataPDS9600bps is the octet string constant for dataPDS-9600bps.
	BSDataPDS9600bps = "\x2e"

	// BSGeneralDataPDS is the octet string constant for general-dataPDS.
	BSGeneralDataPDS = "\x2f"

	// BSAllAlternateSpeechDataCDA is the octet string constant for allAlternateSpeech-DataCDA.
	BSAllAlternateSpeechDataCDA = "\x30"

	// BSAllAlternateSpeechDataCDS is the octet string constant for allAlternateSpeech-DataCDS.
	BSAllAlternateSpeechDataCDS = "\x38"

	// BSAllSpeechFollowedByDataCDA is the octet string constant for allSpeechFollowedByDataCDA.
	BSAllSpeechFollowedByDataCDA = "\x40"

	// BSAllSpeechFollowedByDataCDS is the octet string constant for allSpeechFollowedByDataCDS.
	BSAllSpeechFollowedByDataCDS = "\x48"

	// BSAllDataCircuitAsynchronous is the octet string constant for allDataCircuitAsynchronous.
	BSAllDataCircuitAsynchronous = "\x50"

	// BSAllAsynchronousServices is the octet string constant for allAsynchronousServices.
	BSAllAsynchronousServices = "\x60"

	// BSAllDataCircuitSynchronous is the octet string constant for allDataCircuitSynchronous.
	BSAllDataCircuitSynchronous = "\x58"

	// BSAllSynchronousServices is the octet string constant for allSynchronousServices.
	BSAllSynchronousServices = "\x68"

	// BSAllPLMNSpecificBS is the octet string constant for allPLMN-specificBS.
	BSAllPLMNSpecificBS = "\xd0"

	// BSPlmnSpecificBS1 is the octet string constant for plmn-specificBS-1.
	BSPlmnSpecificBS1 = "\xd1"

	// BSPlmnSpecificBS2 is the octet string constant for plmn-specificBS-2.
	BSPlmnSpecificBS2 = "\xd2"

	// BSPlmnSpecificBS3 is the octet string constant for plmn-specificBS-3.
	BSPlmnSpecificBS3 = "\xd3"

	// BSPlmnSpecificBS4 is the octet string constant for plmn-specificBS-4.
	BSPlmnSpecificBS4 = "\xd4"

	// BSPlmnSpecificBS5 is the octet string constant for plmn-specificBS-5.
	BSPlmnSpecificBS5 = "\xd5"

	// BSPlmnSpecificBS6 is the octet string constant for plmn-specificBS-6.
	BSPlmnSpecificBS6 = "\xd6"

	// BSPlmnSpecificBS7 is the octet string constant for plmn-specificBS-7.
	BSPlmnSpecificBS7 = "\xd7"

	// BSPlmnSpecificBS8 is the octet string constant for plmn-specificBS-8.
	BSPlmnSpecificBS8 = "\xd8"

	// BSPlmnSpecificBS9 is the octet string constant for plmn-specificBS-9.
	BSPlmnSpecificBS9 = "\xd9"

	// BSPlmnSpecificBSA is the octet string constant for plmn-specificBS-A.
	BSPlmnSpecificBSA = "\xda"

	// BSPlmnSpecificBSB is the octet string constant for plmn-specificBS-B.
	BSPlmnSpecificBSB = "\xdb"

	// BSPlmnSpecificBSC is the octet string constant for plmn-specificBS-C.
	BSPlmnSpecificBSC = "\xdc"

	// BSPlmnSpecificBSD is the octet string constant for plmn-specificBS-D.
	BSPlmnSpecificBSD = "\xdd"

	// BSPlmnSpecificBSE is the octet string constant for plmn-specificBS-E.
	BSPlmnSpecificBSE = "\xde"

	// BSPlmnSpecificBSF is the octet string constant for plmn-specificBS-F.
	BSPlmnSpecificBSF = "\xdf"
)

// BSBearerServiceCode represents the ASN.1 type BearerServiceCode (OCTET_STRING).
type BSBearerServiceCode = []byte

// BSExtBearerServiceCode represents the ASN.1 type Ext-BearerServiceCode (OCTET_STRING).
type BSExtBearerServiceCode = []byte
