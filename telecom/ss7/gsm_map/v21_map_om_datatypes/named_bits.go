// Code generated from ASN.1. DO NOT EDIT.

package v21_map_om_datatypes

import (
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// NewOMTraceNETypeList constructs ASN.1 MAP-OM-DataTypes.TraceNE-TypeList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMTraceNETypeList(set ...int) (OMTraceNETypeList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 6, Max: 16}}}, set...)
}

// NewOMMSCSInterfaceList constructs ASN.1 MAP-OM-DataTypes.MSC-S-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMMSCSInterfaceList(set ...int) (OMMSCSInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 10, Max: 16}}}, set...)
}

// NewOMMGWInterfaceList constructs ASN.1 MAP-OM-DataTypes.MGW-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMMGWInterfaceList(set ...int) (OMMGWInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewOMSGSNInterfaceList constructs ASN.1 MAP-OM-DataTypes.SGSN-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMSGSNInterfaceList(set ...int) (OMSGSNInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 8, Max: 16}}}, set...)
}

// NewOMGGSNInterfaceList constructs ASN.1 MAP-OM-DataTypes.GGSN-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMGGSNInterfaceList(set ...int) (OMGGSNInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewOMRNCInterfaceList constructs ASN.1 MAP-OM-DataTypes.RNC-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMRNCInterfaceList(set ...int) (OMRNCInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 8}}}, set...)
}

// NewOMBMSCInterfaceList constructs ASN.1 MAP-OM-DataTypes.BMSC-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMBMSCInterfaceList(set ...int) (OMBMSCInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
}

// NewOMMMEInterfaceList constructs ASN.1 MAP-OM-DataTypes.MME-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMMMEInterfaceList(set ...int) (OMMMEInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 5, Max: 8}}}, set...)
}

// NewOMSGWInterfaceList constructs ASN.1 MAP-OM-DataTypes.SGW-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMSGWInterfaceList(set ...int) (OMSGWInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 5, Max: 8}}}, set...)
}

// NewOMPGWInterfaceList constructs ASN.1 MAP-OM-DataTypes.PGW-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMPGWInterfaceList(set ...int) (OMPGWInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 8, Max: 16}}}, set...)
}

// NewOMENBInterfaceList constructs ASN.1 MAP-OM-DataTypes.ENB-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMENBInterfaceList(set ...int) (OMENBInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewOMMSCSEventList constructs ASN.1 MAP-OM-DataTypes.MSC-S-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMMSCSEventList(set ...int) (OMMSCSEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 5, Max: 16}}}, set...)
}

// NewOMMGWEventList constructs ASN.1 MAP-OM-DataTypes.MGW-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMMGWEventList(set ...int) (OMMGWEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
}

// NewOMSGSNEventList constructs ASN.1 MAP-OM-DataTypes.SGSN-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMSGSNEventList(set ...int) (OMSGSNEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 16}}}, set...)
}

// NewOMGGSNEventList constructs ASN.1 MAP-OM-DataTypes.GGSN-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMGGSNEventList(set ...int) (OMGGSNEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewOMBMSCEventList constructs ASN.1 MAP-OM-DataTypes.BMSC-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMBMSCEventList(set ...int) (OMBMSCEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
}

// NewOMMMEEventList constructs ASN.1 MAP-OM-DataTypes.MME-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMMMEEventList(set ...int) (OMMMEEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 6, Max: 8}}}, set...)
}

// NewOMSGWEventList constructs ASN.1 MAP-OM-DataTypes.SGW-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMSGWEventList(set ...int) (OMSGWEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewOMPGWEventList constructs ASN.1 MAP-OM-DataTypes.PGW-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOMPGWEventList(set ...int) (OMPGWEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}
