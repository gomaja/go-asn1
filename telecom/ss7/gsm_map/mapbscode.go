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

	// AllBearerServices is the octet string constant for AllBearerServices.
	AllBearerServices = "\x00"

	// AllDataCDAServices is the octet string constant for AllDataCDAServices.
	AllDataCDAServices = "\x10"

	// DataCDA300bps is the octet string constant for DataCDA300bps.
	DataCDA300bps = "\x11"

	// DataCDA1200bps is the octet string constant for DataCDA1200bps.
	DataCDA1200bps = "\x12"

	// DataCDA120075bps is the octet string constant for DataCDA120075bps.
	DataCDA120075bps = "\x13"

	// DataCDA2400bps is the octet string constant for DataCDA2400bps.
	DataCDA2400bps = "\x14"

	// DataCDA4800bps is the octet string constant for DataCDA4800bps.
	DataCDA4800bps = "\x15"

	// DataCDA9600bps is the octet string constant for DataCDA9600bps.
	DataCDA9600bps = "\x16"

	// GeneralDataCDA is the octet string constant for GeneralDataCDA.
	GeneralDataCDA = "\x17"

	// AllDataCDSServices is the octet string constant for AllDataCDSServices.
	AllDataCDSServices = "\x18"

	// DataCDS1200bps is the octet string constant for DataCDS1200bps.
	DataCDS1200bps = "\x1a"

	// DataCDS2400bps is the octet string constant for DataCDS2400bps.
	DataCDS2400bps = "\x1c"

	// DataCDS4800bps is the octet string constant for DataCDS4800bps.
	DataCDS4800bps = "\x1d"

	// DataCDS9600bps is the octet string constant for DataCDS9600bps.
	DataCDS9600bps = "\x1e"

	// GeneralDataCDS is the octet string constant for GeneralDataCDS.
	GeneralDataCDS = "\x1f"

	// AllPadAccessCAServices is the octet string constant for AllPadAccessCAServices.
	AllPadAccessCAServices = "\x20"

	// PadAccessCA300bps is the octet string constant for PadAccessCA300bps.
	PadAccessCA300bps = "\x21"

	// PadAccessCA1200bps is the octet string constant for PadAccessCA1200bps.
	PadAccessCA1200bps = "\x22"

	// PadAccessCA120075bps is the octet string constant for PadAccessCA120075bps.
	PadAccessCA120075bps = "\x23"

	// PadAccessCA2400bps is the octet string constant for PadAccessCA2400bps.
	PadAccessCA2400bps = "\x24"

	// PadAccessCA4800bps is the octet string constant for PadAccessCA4800bps.
	PadAccessCA4800bps = "\x25"

	// PadAccessCA9600bps is the octet string constant for PadAccessCA9600bps.
	PadAccessCA9600bps = "\x26"

	// GeneralPadAccessCA is the octet string constant for GeneralPadAccessCA.
	GeneralPadAccessCA = "\x27"

	// AllDataPDSServices is the octet string constant for AllDataPDSServices.
	AllDataPDSServices = "\x28"

	// DataPDS2400bps is the octet string constant for DataPDS2400bps.
	DataPDS2400bps = "\x2c"

	// DataPDS4800bps is the octet string constant for DataPDS4800bps.
	DataPDS4800bps = "\x2d"

	// DataPDS9600bps is the octet string constant for DataPDS9600bps.
	DataPDS9600bps = "\x2e"

	// GeneralDataPDS is the octet string constant for GeneralDataPDS.
	GeneralDataPDS = "\x2f"

	// AllAlternateSpeechDataCDA is the octet string constant for AllAlternateSpeechDataCDA.
	AllAlternateSpeechDataCDA = "\x30"

	// AllAlternateSpeechDataCDS is the octet string constant for AllAlternateSpeechDataCDS.
	AllAlternateSpeechDataCDS = "\x38"

	// AllSpeechFollowedByDataCDA is the octet string constant for AllSpeechFollowedByDataCDA.
	AllSpeechFollowedByDataCDA = "\x40"

	// AllSpeechFollowedByDataCDS is the octet string constant for AllSpeechFollowedByDataCDS.
	AllSpeechFollowedByDataCDS = "\x48"

	// AllDataCircuitAsynchronous is the octet string constant for AllDataCircuitAsynchronous.
	AllDataCircuitAsynchronous = "\x50"

	// AllAsynchronousServices is the octet string constant for AllAsynchronousServices.
	AllAsynchronousServices = "\x60"

	// AllDataCircuitSynchronous is the octet string constant for AllDataCircuitSynchronous.
	AllDataCircuitSynchronous = "\x58"

	// AllSynchronousServices is the octet string constant for AllSynchronousServices.
	AllSynchronousServices = "\x68"

	// AllPLMNSpecificBS is the octet string constant for AllPLMNSpecificBS.
	AllPLMNSpecificBS = "\xd0"

	// PlmnSpecificBS1 is the octet string constant for PlmnSpecificBS1.
	PlmnSpecificBS1 = "\xd1"

	// PlmnSpecificBS2 is the octet string constant for PlmnSpecificBS2.
	PlmnSpecificBS2 = "\xd2"

	// PlmnSpecificBS3 is the octet string constant for PlmnSpecificBS3.
	PlmnSpecificBS3 = "\xd3"

	// PlmnSpecificBS4 is the octet string constant for PlmnSpecificBS4.
	PlmnSpecificBS4 = "\xd4"

	// PlmnSpecificBS5 is the octet string constant for PlmnSpecificBS5.
	PlmnSpecificBS5 = "\xd5"

	// PlmnSpecificBS6 is the octet string constant for PlmnSpecificBS6.
	PlmnSpecificBS6 = "\xd6"

	// PlmnSpecificBS7 is the octet string constant for PlmnSpecificBS7.
	PlmnSpecificBS7 = "\xd7"

	// PlmnSpecificBS8 is the octet string constant for PlmnSpecificBS8.
	PlmnSpecificBS8 = "\xd8"

	// PlmnSpecificBS9 is the octet string constant for PlmnSpecificBS9.
	PlmnSpecificBS9 = "\xd9"

	// PlmnSpecificBSA is the octet string constant for PlmnSpecificBSA.
	PlmnSpecificBSA = "\xda"

	// PlmnSpecificBSB is the octet string constant for PlmnSpecificBSB.
	PlmnSpecificBSB = "\xdb"

	// PlmnSpecificBSC is the octet string constant for PlmnSpecificBSC.
	PlmnSpecificBSC = "\xdc"

	// PlmnSpecificBSD is the octet string constant for PlmnSpecificBSD.
	PlmnSpecificBSD = "\xdd"

	// PlmnSpecificBSE is the octet string constant for PlmnSpecificBSE.
	PlmnSpecificBSE = "\xde"

	// PlmnSpecificBSF is the octet string constant for PlmnSpecificBSF.
	PlmnSpecificBSF = "\xdf"
)

// BearerServiceCode represents the ASN.1 type BearerServiceCode (OCTET_STRING).
type BearerServiceCode = []byte

// ExtBearerServiceCode represents the ASN.1 type ExtBearerServiceCode (OCTET_STRING).
type ExtBearerServiceCode = []byte
