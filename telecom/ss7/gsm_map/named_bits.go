// Code generated from ASN.1. DO NOT EDIT.

package gsm_map

import (
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// NewServiceIndicator constructs ASN.1 MAP-SS-DataTypes.ServiceIndicator (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewServiceIndicator(set ...int) (ServiceIndicator, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 32}}}, set...)
}

// NewTraceNETypeList constructs ASN.1 MAP-OM-DataTypes.TraceNE-TypeList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewTraceNETypeList(set ...int) (TraceNETypeList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 6, Max: 16}}}, set...)
}

// NewMSCSInterfaceList constructs ASN.1 MAP-OM-DataTypes.MSC-S-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSCSInterfaceList(set ...int) (MSCSInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 10, Max: 16}}}, set...)
}

// NewMGWInterfaceList constructs ASN.1 MAP-OM-DataTypes.MGW-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMGWInterfaceList(set ...int) (MGWInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewSGSNInterfaceList constructs ASN.1 MAP-OM-DataTypes.SGSN-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSGSNInterfaceList(set ...int) (SGSNInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 8, Max: 16}}}, set...)
}

// NewGGSNInterfaceList constructs ASN.1 MAP-OM-DataTypes.GGSN-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewGGSNInterfaceList(set ...int) (GGSNInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewRNCInterfaceList constructs ASN.1 MAP-OM-DataTypes.RNC-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewRNCInterfaceList(set ...int) (RNCInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 8}}}, set...)
}

// NewBMSCInterfaceList constructs ASN.1 MAP-OM-DataTypes.BMSC-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewBMSCInterfaceList(set ...int) (BMSCInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
}

// NewMMEInterfaceList constructs ASN.1 MAP-OM-DataTypes.MME-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMMEInterfaceList(set ...int) (MMEInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 5, Max: 8}}}, set...)
}

// NewSGWInterfaceList constructs ASN.1 MAP-OM-DataTypes.SGW-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSGWInterfaceList(set ...int) (SGWInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 5, Max: 8}}}, set...)
}

// NewPGWInterfaceList constructs ASN.1 MAP-OM-DataTypes.PGW-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewPGWInterfaceList(set ...int) (PGWInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 8, Max: 16}}}, set...)
}

// NewENBInterfaceList constructs ASN.1 MAP-OM-DataTypes.ENB-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewENBInterfaceList(set ...int) (ENBInterfaceList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewMSCSEventList constructs ASN.1 MAP-OM-DataTypes.MSC-S-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSCSEventList(set ...int) (MSCSEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 5, Max: 16}}}, set...)
}

// NewMGWEventList constructs ASN.1 MAP-OM-DataTypes.MGW-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMGWEventList(set ...int) (MGWEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
}

// NewSGSNEventList constructs ASN.1 MAP-OM-DataTypes.SGSN-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSGSNEventList(set ...int) (SGSNEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 16}}}, set...)
}

// NewGGSNEventList constructs ASN.1 MAP-OM-DataTypes.GGSN-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewGGSNEventList(set ...int) (GGSNEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewBMSCEventList constructs ASN.1 MAP-OM-DataTypes.BMSC-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewBMSCEventList(set ...int) (BMSCEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
}

// NewMMEEventList constructs ASN.1 MAP-OM-DataTypes.MME-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMMEEventList(set ...int) (MMEEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 6, Max: 8}}}, set...)
}

// NewSGWEventList constructs ASN.1 MAP-OM-DataTypes.SGW-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSGWEventList(set ...int) (SGWEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewPGWEventList constructs ASN.1 MAP-OM-DataTypes.PGW-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewPGWEventList(set ...int) (PGWEventList, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewSupportedRATTypes constructs ASN.1 MAP-MS-DataTypes.SupportedRAT-Types (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSupportedRATTypes(set ...int) (SupportedRATTypes, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewSupportedLCSCapabilitySets constructs ASN.1 MAP-MS-DataTypes.SupportedLCS-CapabilitySets (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSupportedLCSCapabilitySets(set ...int) (SupportedLCSCapabilitySets, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 16}}}, set...)
}

// NewISRInformation constructs ASN.1 MAP-MS-DataTypes.ISR-Information (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewISRInformation(set ...int) (ISRInformation, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewSupportedFeatures constructs ASN.1 MAP-MS-DataTypes.SupportedFeatures (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSupportedFeatures(set ...int) (SupportedFeatures, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 26, Max: 40}}}, set...)
}

// NewExtSupportedFeatures constructs ASN.1 MAP-MS-DataTypes.Ext-SupportedFeatures (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewExtSupportedFeatures(set ...int) (ExtSupportedFeatures, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 40}}}, set...)
}

// NewLCLSNegotiation constructs ASN.1 MAP-MS-DataTypes.LCLS-Negotiation (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewLCLSNegotiation(set ...int) (LCLSNegotiation, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewLCLSConfigurationPreference constructs ASN.1 MAP-MS-DataTypes.LCLS-ConfigurationPreference (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewLCLSConfigurationPreference(set ...int) (LCLSConfigurationPreference, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 8}}}, set...)
}

// NewRequestedEquipmentInfo constructs ASN.1 MAP-MS-DataTypes.RequestedEquipmentInfo (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewRequestedEquipmentInfo(set ...int) (RequestedEquipmentInfo, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewAccessRestrictionData constructs ASN.1 MAP-MS-DataTypes.AccessRestrictionData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewAccessRestrictionData(set ...int) (AccessRestrictionData, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewExtAccessRestrictionData constructs ASN.1 MAP-MS-DataTypes.Ext-AccessRestrictionData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewExtAccessRestrictionData(set ...int) (ExtAccessRestrictionData, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 32}}}, set...)
}

// NewODBGeneralData constructs ASN.1 MAP-MS-DataTypes.ODB-GeneralData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewODBGeneralData(set ...int) (ODBGeneralData, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 15, Max: 32}}}, set...)
}

// NewODBHPLMNData constructs ASN.1 MAP-MS-DataTypes.ODB-HPLMN-Data (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewODBHPLMNData(set ...int) (ODBHPLMNData, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 32}}}, set...)
}

// NewSpecificCSIWithdraw constructs ASN.1 MAP-MS-DataTypes.SpecificCSI-Withdraw (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSpecificCSIWithdraw(set ...int) (SpecificCSIWithdraw, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 8, Max: 32}}}, set...)
}

// NewSupportedCamelPhases constructs ASN.1 MAP-MS-DataTypes.SupportedCamelPhases (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSupportedCamelPhases(set ...int) (SupportedCamelPhases, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
}

// NewOfferedCamel4CSIs constructs ASN.1 MAP-MS-DataTypes.OfferedCamel4CSIs (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOfferedCamel4CSIs(set ...int) (OfferedCamel4CSIs, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, set...)
}

// NewOfferedCamel4Functionalities constructs ASN.1 MAP-MS-DataTypes.OfferedCamel4Functionalities (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOfferedCamel4Functionalities(set ...int) (OfferedCamel4Functionalities, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 15, Max: 64}}}, set...)
}

// NewAdditionalSubscriptions constructs ASN.1 MAP-MS-DataTypes.AdditionalSubscriptions (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewAdditionalSubscriptions(set ...int) (AdditionalSubscriptions, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
}

// NewRequestedNodes constructs ASN.1 MAP-MS-DataTypes.RequestedNodes (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewRequestedNodes(set ...int) (RequestedNodes, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
}

// NewRequestedServingNode constructs ASN.1 MAP-MS-DataTypes.RequestedServingNode (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewRequestedServingNode(set ...int) (RequestedServingNode, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
}

// NewServingNode constructs ASN.1 MAP-MS-DataTypes.ServingNode (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewServingNode(set ...int) (ServingNode, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewSuppressMTSS constructs ASN.1 MAP-CH-DataTypes.SuppressMTSS (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSuppressMTSS(set ...int) (SuppressMTSS, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 16}}}, set...)
}

// NewAllowedServices constructs ASN.1 MAP-CH-DataTypes.AllowedServices (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewAllowedServices(set ...int) (AllowedServices, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
}

// NewMWStatus constructs ASN.1 MAP-SM-DataTypes.MW-Status (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMWStatus(set ...int) (MWStatus, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 6, Max: 16}}}, set...)
}

// NewDeferredLocationEventType constructs ASN.1 MAP-LCS-DataTypes.DeferredLocationEventType (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewDeferredLocationEventType(set ...int) (DeferredLocationEventType, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
}

// NewSupportedGADShapes constructs ASN.1 MAP-LCS-DataTypes.SupportedGADShapes (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSupportedGADShapes(set ...int) (SupportedGADShapes, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, set...)
}

// NewDeferredLocationExt constructs ASN.1 SS-DataTypes.DeferredLocationExt (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewDeferredLocationExt(set ...int) (DeferredLocationExt, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
}

// NewRangingSlExt constructs ASN.1 SS-DataTypes.RangingSlExt (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewRangingSlExt(set ...int) (RangingSlExt, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
}

// NewLocationInfo constructs ASN.1 SS-DataTypes.LocationInfo (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewLocationInfo(set ...int) (LocationInfo, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 32}}}, set...)
}

// NewReportingAccessTypes constructs ASN.1 SS-DataTypes.ReportingAccessTypes (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewReportingAccessTypes(set ...int) (ReportingAccessTypes, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
}

// NewLCSPruUpdateTrigger constructs ASN.1 SS-DataTypes.LCS-PruUpdateTrigger (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewLCSPruUpdateTrigger(set ...int) (LCSPruUpdateTrigger, error) {
	return ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
}
