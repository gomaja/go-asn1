// Code generated from ASN.1. DO NOT EDIT.

package v21_map_ss_datatypes

import (
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// NewSSServiceIndicator constructs ASN.1 MAP-SS-DataTypes.ServiceIndicator (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSSServiceIndicator(set ...int) (SSServiceIndicator, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 32}}}, set...)
}
