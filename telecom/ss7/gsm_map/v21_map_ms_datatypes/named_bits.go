// Code generated from ASN.1. DO NOT EDIT.

package v21_map_ms_datatypes

import (
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// NewMSSupportedRATTypes constructs ASN.1 MAP-MS-DataTypes.SupportedRAT-Types (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSSupportedRATTypes(set ...int) (MSSupportedRATTypes, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewMSSupportedLCSCapabilitySets constructs ASN.1 MAP-MS-DataTypes.SupportedLCS-CapabilitySets (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSSupportedLCSCapabilitySets(set ...int) (MSSupportedLCSCapabilitySets, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 16}}}, set...)
}

// NewMSISRInformation constructs ASN.1 MAP-MS-DataTypes.ISR-Information (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSISRInformation(set ...int) (MSISRInformation, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewMSSupportedFeatures constructs ASN.1 MAP-MS-DataTypes.SupportedFeatures (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSSupportedFeatures(set ...int) (MSSupportedFeatures, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 26, Max: 40}}}, set...)
}

// NewMSExtSupportedFeatures constructs ASN.1 MAP-MS-DataTypes.Ext-SupportedFeatures (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSExtSupportedFeatures(set ...int) (MSExtSupportedFeatures, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 40}}}, set...)
}

// NewMSLCLSNegotiation constructs ASN.1 MAP-MS-DataTypes.LCLS-Negotiation (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSLCLSNegotiation(set ...int) (MSLCLSNegotiation, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewMSLCLSConfigurationPreference constructs ASN.1 MAP-MS-DataTypes.LCLS-ConfigurationPreference (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSLCLSConfigurationPreference(set ...int) (MSLCLSConfigurationPreference, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 8}}}, set...)
}

// NewMSRequestedEquipmentInfo constructs ASN.1 MAP-MS-DataTypes.RequestedEquipmentInfo (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSRequestedEquipmentInfo(set ...int) (MSRequestedEquipmentInfo, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewMSAccessRestrictionData constructs ASN.1 MAP-MS-DataTypes.AccessRestrictionData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSAccessRestrictionData(set ...int) (MSAccessRestrictionData, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewMSExtAccessRestrictionData constructs ASN.1 MAP-MS-DataTypes.Ext-AccessRestrictionData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSExtAccessRestrictionData(set ...int) (MSExtAccessRestrictionData, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 32}}}, set...)
}

// NewMSODBGeneralData constructs ASN.1 MAP-MS-DataTypes.ODB-GeneralData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSODBGeneralData(set ...int) (MSODBGeneralData, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 15, Max: 32}}}, set...)
}

// NewMSODBHPLMNData constructs ASN.1 MAP-MS-DataTypes.ODB-HPLMN-Data (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSODBHPLMNData(set ...int) (MSODBHPLMNData, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 32}}}, set...)
}

// NewMSSpecificCSIWithdraw constructs ASN.1 MAP-MS-DataTypes.SpecificCSI-Withdraw (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSSpecificCSIWithdraw(set ...int) (MSSpecificCSIWithdraw, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 8, Max: 32}}}, set...)
}

// NewMSSupportedCamelPhases constructs ASN.1 MAP-MS-DataTypes.SupportedCamelPhases (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSSupportedCamelPhases(set ...int) (MSSupportedCamelPhases, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
}

// NewMSOfferedCamel4CSIs constructs ASN.1 MAP-MS-DataTypes.OfferedCamel4CSIs (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSOfferedCamel4CSIs(set ...int) (MSOfferedCamel4CSIs, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, set...)
}

// NewMSOfferedCamel4Functionalities constructs ASN.1 MAP-MS-DataTypes.OfferedCamel4Functionalities (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSOfferedCamel4Functionalities(set ...int) (MSOfferedCamel4Functionalities, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 15, Max: 64}}}, set...)
}

// NewMSAdditionalSubscriptions constructs ASN.1 MAP-MS-DataTypes.AdditionalSubscriptions (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSAdditionalSubscriptions(set ...int) (MSAdditionalSubscriptions, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewMSRequestedNodes constructs ASN.1 MAP-MS-DataTypes.RequestedNodes (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSRequestedNodes(set ...int) (MSRequestedNodes, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
}

// NewMSRequestedServingNode constructs ASN.1 MAP-MS-DataTypes.RequestedServingNode (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSRequestedServingNode(set ...int) (MSRequestedServingNode, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
}

// NewMSServingNode constructs ASN.1 MAP-MS-DataTypes.ServingNode (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSServingNode(set ...int) (MSServingNode, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}
