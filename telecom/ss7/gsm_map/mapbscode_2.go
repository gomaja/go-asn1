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

	// BSAllBearerServices is the octet string constant for BSAllBearerServices.
	BSAllBearerServices = "\x00"

	// BSAllDataCDAServices is the octet string constant for BSAllDataCDAServices.
	BSAllDataCDAServices = "\x10"

	// BSDataCDA300bps is the octet string constant for BSDataCDA300bps.
	BSDataCDA300bps = "\x11"

	// BSDataCDA1200bps is the octet string constant for BSDataCDA1200bps.
	BSDataCDA1200bps = "\x12"

	// BSDataCDA120075bps is the octet string constant for BSDataCDA120075bps.
	BSDataCDA120075bps = "\x13"

	// BSDataCDA2400bps is the octet string constant for BSDataCDA2400bps.
	BSDataCDA2400bps = "\x14"

	// BSDataCDA4800bps is the octet string constant for BSDataCDA4800bps.
	BSDataCDA4800bps = "\x15"

	// BSDataCDA9600bps is the octet string constant for BSDataCDA9600bps.
	BSDataCDA9600bps = "\x16"

	// BSGeneralDataCDA is the octet string constant for BSGeneralDataCDA.
	BSGeneralDataCDA = "\x17"

	// BSAllDataCDSServices is the octet string constant for BSAllDataCDSServices.
	BSAllDataCDSServices = "\x18"

	// BSDataCDS1200bps is the octet string constant for BSDataCDS1200bps.
	BSDataCDS1200bps = "\x1a"

	// BSDataCDS2400bps is the octet string constant for BSDataCDS2400bps.
	BSDataCDS2400bps = "\x1c"

	// BSDataCDS4800bps is the octet string constant for BSDataCDS4800bps.
	BSDataCDS4800bps = "\x1d"

	// BSDataCDS9600bps is the octet string constant for BSDataCDS9600bps.
	BSDataCDS9600bps = "\x1e"

	// BSGeneralDataCDS is the octet string constant for BSGeneralDataCDS.
	BSGeneralDataCDS = "\x1f"

	// BSAllPadAccessCAServices is the octet string constant for BSAllPadAccessCAServices.
	BSAllPadAccessCAServices = "\x20"

	// BSPadAccessCA300bps is the octet string constant for BSPadAccessCA300bps.
	BSPadAccessCA300bps = "\x21"

	// BSPadAccessCA1200bps is the octet string constant for BSPadAccessCA1200bps.
	BSPadAccessCA1200bps = "\x22"

	// BSPadAccessCA120075bps is the octet string constant for BSPadAccessCA120075bps.
	BSPadAccessCA120075bps = "\x23"

	// BSPadAccessCA2400bps is the octet string constant for BSPadAccessCA2400bps.
	BSPadAccessCA2400bps = "\x24"

	// BSPadAccessCA4800bps is the octet string constant for BSPadAccessCA4800bps.
	BSPadAccessCA4800bps = "\x25"

	// BSPadAccessCA9600bps is the octet string constant for BSPadAccessCA9600bps.
	BSPadAccessCA9600bps = "\x26"

	// BSGeneralPadAccessCA is the octet string constant for BSGeneralPadAccessCA.
	BSGeneralPadAccessCA = "\x27"

	// BSAllDataPDSServices is the octet string constant for BSAllDataPDSServices.
	BSAllDataPDSServices = "\x28"

	// BSDataPDS2400bps is the octet string constant for BSDataPDS2400bps.
	BSDataPDS2400bps = "\x2c"

	// BSDataPDS4800bps is the octet string constant for BSDataPDS4800bps.
	BSDataPDS4800bps = "\x2d"

	// BSDataPDS9600bps is the octet string constant for BSDataPDS9600bps.
	BSDataPDS9600bps = "\x2e"

	// BSGeneralDataPDS is the octet string constant for BSGeneralDataPDS.
	BSGeneralDataPDS = "\x2f"

	// BSAllAlternateSpeechDataCDA is the octet string constant for BSAllAlternateSpeechDataCDA.
	BSAllAlternateSpeechDataCDA = "\x30"

	// BSAllAlternateSpeechDataCDS is the octet string constant for BSAllAlternateSpeechDataCDS.
	BSAllAlternateSpeechDataCDS = "\x38"

	// BSAllSpeechFollowedByDataCDA is the octet string constant for BSAllSpeechFollowedByDataCDA.
	BSAllSpeechFollowedByDataCDA = "\x40"

	// BSAllSpeechFollowedByDataCDS is the octet string constant for BSAllSpeechFollowedByDataCDS.
	BSAllSpeechFollowedByDataCDS = "\x48"

	// BSAllDataCircuitAsynchronous is the octet string constant for BSAllDataCircuitAsynchronous.
	BSAllDataCircuitAsynchronous = "\x50"

	// BSAllAsynchronousServices is the octet string constant for BSAllAsynchronousServices.
	BSAllAsynchronousServices = "\x60"

	// BSAllDataCircuitSynchronous is the octet string constant for BSAllDataCircuitSynchronous.
	BSAllDataCircuitSynchronous = "\x58"

	// BSAllSynchronousServices is the octet string constant for BSAllSynchronousServices.
	BSAllSynchronousServices = "\x68"

	// BSAllPLMNSpecificBS is the octet string constant for BSAllPLMNSpecificBS.
	BSAllPLMNSpecificBS = "\xd0"

	// BSPlmnSpecificBS1 is the octet string constant for BSPlmnSpecificBS1.
	BSPlmnSpecificBS1 = "\xd1"

	// BSPlmnSpecificBS2 is the octet string constant for BSPlmnSpecificBS2.
	BSPlmnSpecificBS2 = "\xd2"

	// BSPlmnSpecificBS3 is the octet string constant for BSPlmnSpecificBS3.
	BSPlmnSpecificBS3 = "\xd3"

	// BSPlmnSpecificBS4 is the octet string constant for BSPlmnSpecificBS4.
	BSPlmnSpecificBS4 = "\xd4"

	// BSPlmnSpecificBS5 is the octet string constant for BSPlmnSpecificBS5.
	BSPlmnSpecificBS5 = "\xd5"

	// BSPlmnSpecificBS6 is the octet string constant for BSPlmnSpecificBS6.
	BSPlmnSpecificBS6 = "\xd6"

	// BSPlmnSpecificBS7 is the octet string constant for BSPlmnSpecificBS7.
	BSPlmnSpecificBS7 = "\xd7"

	// BSPlmnSpecificBS8 is the octet string constant for BSPlmnSpecificBS8.
	BSPlmnSpecificBS8 = "\xd8"

	// BSPlmnSpecificBS9 is the octet string constant for BSPlmnSpecificBS9.
	BSPlmnSpecificBS9 = "\xd9"

	// BSPlmnSpecificBSA is the octet string constant for BSPlmnSpecificBSA.
	BSPlmnSpecificBSA = "\xda"

	// BSPlmnSpecificBSB is the octet string constant for BSPlmnSpecificBSB.
	BSPlmnSpecificBSB = "\xdb"

	// BSPlmnSpecificBSC is the octet string constant for BSPlmnSpecificBSC.
	BSPlmnSpecificBSC = "\xdc"

	// BSPlmnSpecificBSD is the octet string constant for BSPlmnSpecificBSD.
	BSPlmnSpecificBSD = "\xdd"

	// BSPlmnSpecificBSE is the octet string constant for BSPlmnSpecificBSE.
	BSPlmnSpecificBSE = "\xde"

	// BSPlmnSpecificBSF is the octet string constant for BSPlmnSpecificBSF.
	BSPlmnSpecificBSF = "\xdf"
)

// BSBearerServiceCode represents the ASN.1 type BearerServiceCode (OCTET_STRING).
type BSBearerServiceCode = []byte

// BSExtBearerServiceCode represents the ASN.1 type Ext-BearerServiceCode (OCTET_STRING).
type BSExtBearerServiceCode = []byte
