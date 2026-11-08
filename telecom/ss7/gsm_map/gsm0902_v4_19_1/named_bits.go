// Code generated from ASN.1. DO NOT EDIT.

package gsm0902_v4_19_1

import (
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// NewODBGeneralData constructs ASN.1 MAP-MS-DataTypes.ODB-GeneralData (X.208 (11/1988) §§17.10, 37.4.3–37.4.4; X.209 (11/1988) §11.2).
func NewODBGeneralData(set ...int) (ODBGeneralData, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 6, Max: 6}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.ODB-GeneralData")
}

// NewODBHPLMNData constructs ASN.1 MAP-MS-DataTypes.ODB-HPLMN-Data (X.208 (11/1988) §§17.10, 37.4.3–37.4.4; X.209 (11/1988) §11.2).
func NewODBHPLMNData(set ...int) (ODBHPLMNData, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 4}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.ODB-HPLMN-Data")
}

// NewMWStatus constructs ASN.1 MAP-SM-DataTypes.MW-Status (X.208 (11/1988) §§17.10, 37.4.3–37.4.4; X.209 (11/1988) §11.2).
func NewMWStatus(set ...int) (MWStatus, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 6, Max: 6}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-SM-DataTypes.MW-Status")
}
