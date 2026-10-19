// Code generated from ASN.1. DO NOT EDIT.

package v21_map_ms_datatypes

import (
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// NewMSSupportedRATTypes constructs ASN.1 MAP-MS-DataTypes.SupportedRAT-Types (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSSupportedRATTypes(set ...int) (MSSupportedRATTypes, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.SupportedRAT-Types")
}

// NewMSSupportedLCSCapabilitySets constructs ASN.1 MAP-MS-DataTypes.SupportedLCS-CapabilitySets (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSSupportedLCSCapabilitySets(set ...int) (MSSupportedLCSCapabilitySets, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.SupportedLCS-CapabilitySets")
}

// NewMSISRInformation constructs ASN.1 MAP-MS-DataTypes.ISR-Information (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSISRInformation(set ...int) (MSISRInformation, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.ISR-Information")
}

// NewMSSupportedFeatures constructs ASN.1 MAP-MS-DataTypes.SupportedFeatures (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSSupportedFeatures(set ...int) (MSSupportedFeatures, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 26, Max: 40}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.SupportedFeatures")
}

// NewMSExtSupportedFeatures constructs ASN.1 MAP-MS-DataTypes.Ext-SupportedFeatures (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSExtSupportedFeatures(set ...int) (MSExtSupportedFeatures, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 40}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.Ext-SupportedFeatures")
}

// NewMSLCLSNegotiation constructs ASN.1 MAP-MS-DataTypes.LCLS-Negotiation (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSLCLSNegotiation(set ...int) (MSLCLSNegotiation, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.LCLS-Negotiation")
}

// NewMSLCLSConfigurationPreference constructs ASN.1 MAP-MS-DataTypes.LCLS-ConfigurationPreference (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSLCLSConfigurationPreference(set ...int) (MSLCLSConfigurationPreference, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.LCLS-ConfigurationPreference")
}

// NewMSRequestedEquipmentInfo constructs ASN.1 MAP-MS-DataTypes.RequestedEquipmentInfo (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSRequestedEquipmentInfo(set ...int) (MSRequestedEquipmentInfo, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.RequestedEquipmentInfo")
}

// NewMSAccessRestrictionData constructs ASN.1 MAP-MS-DataTypes.AccessRestrictionData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSAccessRestrictionData(set ...int) (MSAccessRestrictionData, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.AccessRestrictionData")
}

// NewMSExtAccessRestrictionData constructs ASN.1 MAP-MS-DataTypes.Ext-AccessRestrictionData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSExtAccessRestrictionData(set ...int) (MSExtAccessRestrictionData, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 32}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.Ext-AccessRestrictionData")
}

// NewMSODBGeneralData constructs ASN.1 MAP-MS-DataTypes.ODB-GeneralData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSODBGeneralData(set ...int) (MSODBGeneralData, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 15, Max: 32}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.ODB-GeneralData")
}

// NewMSODBHPLMNData constructs ASN.1 MAP-MS-DataTypes.ODB-HPLMN-Data (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSODBHPLMNData(set ...int) (MSODBHPLMNData, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 32}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.ODB-HPLMN-Data")
}

// NewMSSpecificCSIWithdraw constructs ASN.1 MAP-MS-DataTypes.SpecificCSI-Withdraw (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSSpecificCSIWithdraw(set ...int) (MSSpecificCSIWithdraw, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 8, Max: 32}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.SpecificCSI-Withdraw")
}

// NewMSSupportedCamelPhases constructs ASN.1 MAP-MS-DataTypes.SupportedCamelPhases (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSSupportedCamelPhases(set ...int) (MSSupportedCamelPhases, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.SupportedCamelPhases")
}

// NewMSOfferedCamel4CSIs constructs ASN.1 MAP-MS-DataTypes.OfferedCamel4CSIs (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSOfferedCamel4CSIs(set ...int) (MSOfferedCamel4CSIs, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.OfferedCamel4CSIs")
}

// NewMSOfferedCamel4Functionalities constructs ASN.1 MAP-MS-DataTypes.OfferedCamel4Functionalities (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSOfferedCamel4Functionalities(set ...int) (MSOfferedCamel4Functionalities, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 15, Max: 64}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.OfferedCamel4Functionalities")
}

// NewMSAdditionalSubscriptions constructs ASN.1 MAP-MS-DataTypes.AdditionalSubscriptions (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSAdditionalSubscriptions(set ...int) (MSAdditionalSubscriptions, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.AdditionalSubscriptions")
}

// NewMSRequestedNodes constructs ASN.1 MAP-MS-DataTypes.RequestedNodes (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSRequestedNodes(set ...int) (MSRequestedNodes, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.RequestedNodes")
}

// NewMSRequestedServingNode constructs ASN.1 MAP-MS-DataTypes.RequestedServingNode (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSRequestedServingNode(set ...int) (MSRequestedServingNode, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.RequestedServingNode")
}

// NewMSServingNode constructs ASN.1 MAP-MS-DataTypes.ServingNode (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSServingNode(set ...int) (MSServingNode, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.ServingNode")
}
