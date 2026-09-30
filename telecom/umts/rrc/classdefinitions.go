// Code generated from ASN.1 module "Class-definitions". DO NOT EDIT.

package rrc

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = per.NewBitBuffer
)

// DLDCCHMessage represents the ASN.1 type DL-DCCH-Message (SEQUENCE).
type DLDCCHMessage struct {
	IntegrityCheckInfo   *IntegrityCheckInfo            `asn1:"tag:0,context,implicit,optional" json:"IntegrityCheckInfo,omitempty"`
	Message              DLDCCHMessageType              `asn1:"tag:1,context,explicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// DLDCCHMessageType choice constants.
const (
	DLDCCHMessageTypeChoiceActiveSetUpdate                     = 1
	DLDCCHMessageTypeChoiceAssistanceDataDelivery              = 2
	DLDCCHMessageTypeChoiceCellChangeOrderFromUTRAN            = 3
	DLDCCHMessageTypeChoiceCellUpdateConfirm                   = 4
	DLDCCHMessageTypeChoiceCounterCheck                        = 5
	DLDCCHMessageTypeChoiceDownlinkDirectTransfer              = 6
	DLDCCHMessageTypeChoiceHandoverFromUTRANCommandGSM         = 7
	DLDCCHMessageTypeChoiceHandoverFromUTRANCommandCDMA2000    = 8
	DLDCCHMessageTypeChoiceMeasurementControl                  = 9
	DLDCCHMessageTypeChoicePagingType2                         = 10
	DLDCCHMessageTypeChoicePhysicalChannelReconfiguration      = 11
	DLDCCHMessageTypeChoicePhysicalSharedChannelAllocation     = 12
	DLDCCHMessageTypeChoiceRadioBearerReconfiguration          = 13
	DLDCCHMessageTypeChoiceRadioBearerRelease                  = 14
	DLDCCHMessageTypeChoiceRadioBearerSetup                    = 15
	DLDCCHMessageTypeChoiceRrcConnectionRelease                = 16
	DLDCCHMessageTypeChoiceSecurityModeCommand                 = 17
	DLDCCHMessageTypeChoiceSignallingConnectionRelease         = 18
	DLDCCHMessageTypeChoiceTransportChannelReconfiguration     = 19
	DLDCCHMessageTypeChoiceTransportFormatCombinationControl   = 20
	DLDCCHMessageTypeChoiceUeCapabilityEnquiry                 = 21
	DLDCCHMessageTypeChoiceUeCapabilityInformationConfirm      = 22
	DLDCCHMessageTypeChoiceUplinkPhysicalChannelControl        = 23
	DLDCCHMessageTypeChoiceUraUpdateConfirm                    = 24
	DLDCCHMessageTypeChoiceUtranMobilityInformation            = 25
	DLDCCHMessageTypeChoiceHandoverFromUTRANCommandGERANIu     = 26
	DLDCCHMessageTypeChoiceMbmsModifiedServicesInformation     = 27
	DLDCCHMessageTypeChoiceEtwsPrimaryNotificationWithSecurity = 28
	DLDCCHMessageTypeChoiceHandoverFromUTRANCommandEUTRA       = 29
	DLDCCHMessageTypeChoiceUeInformationRequest                = 30
	DLDCCHMessageTypeChoiceLoggingMeasurementConfiguration     = 31
	DLDCCHMessageTypeChoiceSpare1                              = 32
)

// DLDCCHMessageType represents the ASN.1 CHOICE type DL-DCCH-MessageType.
type DLDCCHMessageType struct {
	Choice                              int
	PERPadding_                         per.CompletePadding                  `json:"-"`
	PERExtraBits_                       per.TrailingBits                     `json:"-"`
	PEROpenTypePadding_                 per.CompletePadding                  `json:"-"`
	ActiveSetUpdate                     *ActiveSetUpdate                     `json:"ActiveSetUpdate,omitempty"`
	AssistanceDataDelivery              *AssistanceDataDelivery              `json:"AssistanceDataDelivery,omitempty"`
	CellChangeOrderFromUTRAN            *CellChangeOrderFromUTRAN            `json:"CellChangeOrderFromUTRAN,omitempty"`
	CellUpdateConfirm                   *CellUpdateConfirm                   `json:"CellUpdateConfirm,omitempty"`
	CounterCheck                        *CounterCheck                        `json:"CounterCheck,omitempty"`
	DownlinkDirectTransfer              *DownlinkDirectTransfer              `json:"DownlinkDirectTransfer,omitempty"`
	HandoverFromUTRANCommandGSM         *HandoverFromUTRANCommandGSM         `json:"HandoverFromUTRANCommandGSM,omitempty"`
	HandoverFromUTRANCommandCDMA2000    *HandoverFromUTRANCommandCDMA2000    `json:"HandoverFromUTRANCommandCDMA2000,omitempty"`
	MeasurementControl                  *MeasurementControl                  `json:"MeasurementControl,omitempty"`
	PagingType2                         *PagingType2                         `json:"PagingType2,omitempty"`
	PhysicalChannelReconfiguration      *PhysicalChannelReconfiguration      `json:"PhysicalChannelReconfiguration,omitempty"`
	PhysicalSharedChannelAllocation     *PhysicalSharedChannelAllocation     `json:"PhysicalSharedChannelAllocation,omitempty"`
	RadioBearerReconfiguration          *RadioBearerReconfiguration          `json:"RadioBearerReconfiguration,omitempty"`
	RadioBearerRelease                  *RadioBearerRelease                  `json:"RadioBearerRelease,omitempty"`
	RadioBearerSetup                    *RadioBearerSetup                    `json:"RadioBearerSetup,omitempty"`
	RrcConnectionRelease                *RRCConnectionRelease                `json:"RrcConnectionRelease,omitempty"`
	SecurityModeCommand                 *SecurityModeCommand                 `json:"SecurityModeCommand,omitempty"`
	SignallingConnectionRelease         *SignallingConnectionRelease         `json:"SignallingConnectionRelease,omitempty"`
	TransportChannelReconfiguration     *TransportChannelReconfiguration     `json:"TransportChannelReconfiguration,omitempty"`
	TransportFormatCombinationControl   *TransportFormatCombinationControl   `json:"TransportFormatCombinationControl,omitempty"`
	UeCapabilityEnquiry                 *UECapabilityEnquiry                 `json:"UeCapabilityEnquiry,omitempty"`
	UeCapabilityInformationConfirm      *UECapabilityInformationConfirm      `json:"UeCapabilityInformationConfirm,omitempty"`
	UplinkPhysicalChannelControl        *UplinkPhysicalChannelControl        `json:"UplinkPhysicalChannelControl,omitempty"`
	UraUpdateConfirm                    *URAUpdateConfirm                    `json:"UraUpdateConfirm,omitempty"`
	UtranMobilityInformation            *UTRANMobilityInformation            `json:"UtranMobilityInformation,omitempty"`
	HandoverFromUTRANCommandGERANIu     *HandoverFromUTRANCommandGERANIu     `json:"HandoverFromUTRANCommandGERANIu,omitempty"`
	MbmsModifiedServicesInformation     *MBMSModifiedServicesInformation     `json:"MbmsModifiedServicesInformation,omitempty"`
	EtwsPrimaryNotificationWithSecurity *ETWSPrimaryNotificationWithSecurity `json:"EtwsPrimaryNotificationWithSecurity,omitempty"`
	HandoverFromUTRANCommandEUTRA       *HandoverFromUTRANCommandEUTRA       `json:"HandoverFromUTRANCommandEUTRA,omitempty"`
	UeInformationRequest                *UEInformationRequest                `json:"UeInformationRequest,omitempty"`
	LoggingMeasurementConfiguration     *LoggingMeasurementConfiguration     `json:"LoggingMeasurementConfiguration,omitempty"`
	Spare1                              *struct{}                            `json:"Spare1,omitempty"`
}

// NewDLDCCHMessageTypeActiveSetUpdate creates a DLDCCHMessageType with the activeSetUpdate alternative.
func NewDLDCCHMessageTypeActiveSetUpdate(v ActiveSetUpdate) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:          DLDCCHMessageTypeChoiceActiveSetUpdate,
		ActiveSetUpdate: &v,
	}
}

// NewDLDCCHMessageTypeAssistanceDataDelivery creates a DLDCCHMessageType with the assistanceDataDelivery alternative.
func NewDLDCCHMessageTypeAssistanceDataDelivery(v AssistanceDataDelivery) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                 DLDCCHMessageTypeChoiceAssistanceDataDelivery,
		AssistanceDataDelivery: &v,
	}
}

// NewDLDCCHMessageTypeCellChangeOrderFromUTRAN creates a DLDCCHMessageType with the cellChangeOrderFromUTRAN alternative.
func NewDLDCCHMessageTypeCellChangeOrderFromUTRAN(v CellChangeOrderFromUTRAN) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                   DLDCCHMessageTypeChoiceCellChangeOrderFromUTRAN,
		CellChangeOrderFromUTRAN: &v,
	}
}

// NewDLDCCHMessageTypeCellUpdateConfirm creates a DLDCCHMessageType with the cellUpdateConfirm alternative.
func NewDLDCCHMessageTypeCellUpdateConfirm(v CellUpdateConfirm) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:            DLDCCHMessageTypeChoiceCellUpdateConfirm,
		CellUpdateConfirm: &v,
	}
}

// NewDLDCCHMessageTypeCounterCheck creates a DLDCCHMessageType with the counterCheck alternative.
func NewDLDCCHMessageTypeCounterCheck(v CounterCheck) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:       DLDCCHMessageTypeChoiceCounterCheck,
		CounterCheck: &v,
	}
}

// NewDLDCCHMessageTypeDownlinkDirectTransfer creates a DLDCCHMessageType with the downlinkDirectTransfer alternative.
func NewDLDCCHMessageTypeDownlinkDirectTransfer(v DownlinkDirectTransfer) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                 DLDCCHMessageTypeChoiceDownlinkDirectTransfer,
		DownlinkDirectTransfer: &v,
	}
}

// NewDLDCCHMessageTypeHandoverFromUTRANCommandGSM creates a DLDCCHMessageType with the handoverFromUTRANCommand-GSM alternative.
func NewDLDCCHMessageTypeHandoverFromUTRANCommandGSM(v HandoverFromUTRANCommandGSM) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                      DLDCCHMessageTypeChoiceHandoverFromUTRANCommandGSM,
		HandoverFromUTRANCommandGSM: &v,
	}
}

// NewDLDCCHMessageTypeHandoverFromUTRANCommandCDMA2000 creates a DLDCCHMessageType with the handoverFromUTRANCommand-CDMA2000 alternative.
func NewDLDCCHMessageTypeHandoverFromUTRANCommandCDMA2000(v HandoverFromUTRANCommandCDMA2000) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                           DLDCCHMessageTypeChoiceHandoverFromUTRANCommandCDMA2000,
		HandoverFromUTRANCommandCDMA2000: &v,
	}
}

// NewDLDCCHMessageTypeMeasurementControl creates a DLDCCHMessageType with the measurementControl alternative.
func NewDLDCCHMessageTypeMeasurementControl(v MeasurementControl) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:             DLDCCHMessageTypeChoiceMeasurementControl,
		MeasurementControl: &v,
	}
}

// NewDLDCCHMessageTypePagingType2 creates a DLDCCHMessageType with the pagingType2 alternative.
func NewDLDCCHMessageTypePagingType2(v PagingType2) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:      DLDCCHMessageTypeChoicePagingType2,
		PagingType2: &v,
	}
}

// NewDLDCCHMessageTypePhysicalChannelReconfiguration creates a DLDCCHMessageType with the physicalChannelReconfiguration alternative.
func NewDLDCCHMessageTypePhysicalChannelReconfiguration(v PhysicalChannelReconfiguration) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                         DLDCCHMessageTypeChoicePhysicalChannelReconfiguration,
		PhysicalChannelReconfiguration: &v,
	}
}

// NewDLDCCHMessageTypePhysicalSharedChannelAllocation creates a DLDCCHMessageType with the physicalSharedChannelAllocation alternative.
func NewDLDCCHMessageTypePhysicalSharedChannelAllocation(v PhysicalSharedChannelAllocation) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                          DLDCCHMessageTypeChoicePhysicalSharedChannelAllocation,
		PhysicalSharedChannelAllocation: &v,
	}
}

// NewDLDCCHMessageTypeRadioBearerReconfiguration creates a DLDCCHMessageType with the radioBearerReconfiguration alternative.
func NewDLDCCHMessageTypeRadioBearerReconfiguration(v RadioBearerReconfiguration) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                     DLDCCHMessageTypeChoiceRadioBearerReconfiguration,
		RadioBearerReconfiguration: &v,
	}
}

// NewDLDCCHMessageTypeRadioBearerRelease creates a DLDCCHMessageType with the radioBearerRelease alternative.
func NewDLDCCHMessageTypeRadioBearerRelease(v RadioBearerRelease) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:             DLDCCHMessageTypeChoiceRadioBearerRelease,
		RadioBearerRelease: &v,
	}
}

// NewDLDCCHMessageTypeRadioBearerSetup creates a DLDCCHMessageType with the radioBearerSetup alternative.
func NewDLDCCHMessageTypeRadioBearerSetup(v RadioBearerSetup) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:           DLDCCHMessageTypeChoiceRadioBearerSetup,
		RadioBearerSetup: &v,
	}
}

// NewDLDCCHMessageTypeRrcConnectionRelease creates a DLDCCHMessageType with the rrcConnectionRelease alternative.
func NewDLDCCHMessageTypeRrcConnectionRelease(v RRCConnectionRelease) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:               DLDCCHMessageTypeChoiceRrcConnectionRelease,
		RrcConnectionRelease: &v,
	}
}

// NewDLDCCHMessageTypeSecurityModeCommand creates a DLDCCHMessageType with the securityModeCommand alternative.
func NewDLDCCHMessageTypeSecurityModeCommand(v SecurityModeCommand) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:              DLDCCHMessageTypeChoiceSecurityModeCommand,
		SecurityModeCommand: &v,
	}
}

// NewDLDCCHMessageTypeSignallingConnectionRelease creates a DLDCCHMessageType with the signallingConnectionRelease alternative.
func NewDLDCCHMessageTypeSignallingConnectionRelease(v SignallingConnectionRelease) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                      DLDCCHMessageTypeChoiceSignallingConnectionRelease,
		SignallingConnectionRelease: &v,
	}
}

// NewDLDCCHMessageTypeTransportChannelReconfiguration creates a DLDCCHMessageType with the transportChannelReconfiguration alternative.
func NewDLDCCHMessageTypeTransportChannelReconfiguration(v TransportChannelReconfiguration) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                          DLDCCHMessageTypeChoiceTransportChannelReconfiguration,
		TransportChannelReconfiguration: &v,
	}
}

// NewDLDCCHMessageTypeTransportFormatCombinationControl creates a DLDCCHMessageType with the transportFormatCombinationControl alternative.
func NewDLDCCHMessageTypeTransportFormatCombinationControl(v TransportFormatCombinationControl) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                            DLDCCHMessageTypeChoiceTransportFormatCombinationControl,
		TransportFormatCombinationControl: &v,
	}
}

// NewDLDCCHMessageTypeUeCapabilityEnquiry creates a DLDCCHMessageType with the ueCapabilityEnquiry alternative.
func NewDLDCCHMessageTypeUeCapabilityEnquiry(v UECapabilityEnquiry) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:              DLDCCHMessageTypeChoiceUeCapabilityEnquiry,
		UeCapabilityEnquiry: &v,
	}
}

// NewDLDCCHMessageTypeUeCapabilityInformationConfirm creates a DLDCCHMessageType with the ueCapabilityInformationConfirm alternative.
func NewDLDCCHMessageTypeUeCapabilityInformationConfirm(v UECapabilityInformationConfirm) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                         DLDCCHMessageTypeChoiceUeCapabilityInformationConfirm,
		UeCapabilityInformationConfirm: &v,
	}
}

// NewDLDCCHMessageTypeUplinkPhysicalChannelControl creates a DLDCCHMessageType with the uplinkPhysicalChannelControl alternative.
func NewDLDCCHMessageTypeUplinkPhysicalChannelControl(v UplinkPhysicalChannelControl) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                       DLDCCHMessageTypeChoiceUplinkPhysicalChannelControl,
		UplinkPhysicalChannelControl: &v,
	}
}

// NewDLDCCHMessageTypeUraUpdateConfirm creates a DLDCCHMessageType with the uraUpdateConfirm alternative.
func NewDLDCCHMessageTypeUraUpdateConfirm(v URAUpdateConfirm) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:           DLDCCHMessageTypeChoiceUraUpdateConfirm,
		UraUpdateConfirm: &v,
	}
}

// NewDLDCCHMessageTypeUtranMobilityInformation creates a DLDCCHMessageType with the utranMobilityInformation alternative.
func NewDLDCCHMessageTypeUtranMobilityInformation(v UTRANMobilityInformation) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                   DLDCCHMessageTypeChoiceUtranMobilityInformation,
		UtranMobilityInformation: &v,
	}
}

// NewDLDCCHMessageTypeHandoverFromUTRANCommandGERANIu creates a DLDCCHMessageType with the handoverFromUTRANCommand-GERANIu alternative.
func NewDLDCCHMessageTypeHandoverFromUTRANCommandGERANIu(v HandoverFromUTRANCommandGERANIu) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                          DLDCCHMessageTypeChoiceHandoverFromUTRANCommandGERANIu,
		HandoverFromUTRANCommandGERANIu: &v,
	}
}

// NewDLDCCHMessageTypeMbmsModifiedServicesInformation creates a DLDCCHMessageType with the mbmsModifiedServicesInformation alternative.
func NewDLDCCHMessageTypeMbmsModifiedServicesInformation(v MBMSModifiedServicesInformation) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                          DLDCCHMessageTypeChoiceMbmsModifiedServicesInformation,
		MbmsModifiedServicesInformation: &v,
	}
}

// NewDLDCCHMessageTypeEtwsPrimaryNotificationWithSecurity creates a DLDCCHMessageType with the etwsPrimaryNotificationWithSecurity alternative.
func NewDLDCCHMessageTypeEtwsPrimaryNotificationWithSecurity(v ETWSPrimaryNotificationWithSecurity) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                              DLDCCHMessageTypeChoiceEtwsPrimaryNotificationWithSecurity,
		EtwsPrimaryNotificationWithSecurity: &v,
	}
}

// NewDLDCCHMessageTypeHandoverFromUTRANCommandEUTRA creates a DLDCCHMessageType with the handoverFromUTRANCommand-EUTRA alternative.
func NewDLDCCHMessageTypeHandoverFromUTRANCommandEUTRA(v HandoverFromUTRANCommandEUTRA) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                        DLDCCHMessageTypeChoiceHandoverFromUTRANCommandEUTRA,
		HandoverFromUTRANCommandEUTRA: &v,
	}
}

// NewDLDCCHMessageTypeUeInformationRequest creates a DLDCCHMessageType with the ueInformationRequest alternative.
func NewDLDCCHMessageTypeUeInformationRequest(v UEInformationRequest) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:               DLDCCHMessageTypeChoiceUeInformationRequest,
		UeInformationRequest: &v,
	}
}

// NewDLDCCHMessageTypeLoggingMeasurementConfiguration creates a DLDCCHMessageType with the loggingMeasurementConfiguration alternative.
func NewDLDCCHMessageTypeLoggingMeasurementConfiguration(v LoggingMeasurementConfiguration) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice:                          DLDCCHMessageTypeChoiceLoggingMeasurementConfiguration,
		LoggingMeasurementConfiguration: &v,
	}
}

// NewDLDCCHMessageTypeSpare1 creates a DLDCCHMessageType with the spare1 alternative.
func NewDLDCCHMessageTypeSpare1(v struct{}) DLDCCHMessageType {
	return DLDCCHMessageType{
		Choice: DLDCCHMessageTypeChoiceSpare1,
		Spare1: &v,
	}
}

// ULDCCHMessage represents the ASN.1 type UL-DCCH-Message (SEQUENCE).
type ULDCCHMessage struct {
	IntegrityCheckInfo   *IntegrityCheckInfo            `asn1:"tag:0,context,implicit,optional" json:"IntegrityCheckInfo,omitempty"`
	Message              ULDCCHMessageType              `asn1:"tag:1,context,explicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// ULDCCHMessageType choice constants.
const (
	ULDCCHMessageTypeChoiceActiveSetUpdateComplete                  = 1
	ULDCCHMessageTypeChoiceActiveSetUpdateFailure                   = 2
	ULDCCHMessageTypeChoiceCellChangeOrderFromUTRANFailure          = 3
	ULDCCHMessageTypeChoiceCounterCheckResponse                     = 4
	ULDCCHMessageTypeChoiceHandoverToUTRANComplete                  = 5
	ULDCCHMessageTypeChoiceInitialDirectTransfer                    = 6
	ULDCCHMessageTypeChoiceHandoverFromUTRANFailure                 = 7
	ULDCCHMessageTypeChoiceMeasurementControlFailure                = 8
	ULDCCHMessageTypeChoiceMeasurementReport                        = 9
	ULDCCHMessageTypeChoicePhysicalChannelReconfigurationComplete   = 10
	ULDCCHMessageTypeChoicePhysicalChannelReconfigurationFailure    = 11
	ULDCCHMessageTypeChoiceRadioBearerReconfigurationComplete       = 12
	ULDCCHMessageTypeChoiceRadioBearerReconfigurationFailure        = 13
	ULDCCHMessageTypeChoiceRadioBearerReleaseComplete               = 14
	ULDCCHMessageTypeChoiceRadioBearerReleaseFailure                = 15
	ULDCCHMessageTypeChoiceRadioBearerSetupComplete                 = 16
	ULDCCHMessageTypeChoiceRadioBearerSetupFailure                  = 17
	ULDCCHMessageTypeChoiceRrcConnectionReleaseComplete             = 18
	ULDCCHMessageTypeChoiceRrcConnectionSetupComplete               = 19
	ULDCCHMessageTypeChoiceRrcStatus                                = 20
	ULDCCHMessageTypeChoiceSecurityModeComplete                     = 21
	ULDCCHMessageTypeChoiceSecurityModeFailure                      = 22
	ULDCCHMessageTypeChoiceSignallingConnectionReleaseIndication    = 23
	ULDCCHMessageTypeChoiceTransportChannelReconfigurationComplete  = 24
	ULDCCHMessageTypeChoiceTransportChannelReconfigurationFailure   = 25
	ULDCCHMessageTypeChoiceTransportFormatCombinationControlFailure = 26
	ULDCCHMessageTypeChoiceUeCapabilityInformation                  = 27
	ULDCCHMessageTypeChoiceUplinkDirectTransfer                     = 28
	ULDCCHMessageTypeChoiceUtranMobilityInformationConfirm          = 29
	ULDCCHMessageTypeChoiceUtranMobilityInformationFailure          = 30
	ULDCCHMessageTypeChoiceMbmsModificationRequest                  = 31
	ULDCCHMessageTypeChoiceUlDCCHMessageTypeExt                     = 32
)

// ULDCCHMessageType represents the ASN.1 CHOICE type UL-DCCH-MessageType.
type ULDCCHMessageType struct {
	Choice                                   int
	PERPadding_                              per.CompletePadding                       `json:"-"`
	PERExtraBits_                            per.TrailingBits                          `json:"-"`
	PEROpenTypePadding_                      per.CompletePadding                       `json:"-"`
	ActiveSetUpdateComplete                  *ActiveSetUpdateComplete                  `json:"ActiveSetUpdateComplete,omitempty"`
	ActiveSetUpdateFailure                   *ActiveSetUpdateFailure                   `json:"ActiveSetUpdateFailure,omitempty"`
	CellChangeOrderFromUTRANFailure          *CellChangeOrderFromUTRANFailure          `json:"CellChangeOrderFromUTRANFailure,omitempty"`
	CounterCheckResponse                     *CounterCheckResponse                     `json:"CounterCheckResponse,omitempty"`
	HandoverToUTRANComplete                  *HandoverToUTRANComplete                  `json:"HandoverToUTRANComplete,omitempty"`
	InitialDirectTransfer                    *InitialDirectTransfer                    `json:"InitialDirectTransfer,omitempty"`
	HandoverFromUTRANFailure                 *HandoverFromUTRANFailure                 `json:"HandoverFromUTRANFailure,omitempty"`
	MeasurementControlFailure                *MeasurementControlFailure                `json:"MeasurementControlFailure,omitempty"`
	MeasurementReport                        *MeasurementReport                        `json:"MeasurementReport,omitempty"`
	PhysicalChannelReconfigurationComplete   *PhysicalChannelReconfigurationComplete   `json:"PhysicalChannelReconfigurationComplete,omitempty"`
	PhysicalChannelReconfigurationFailure    *PhysicalChannelReconfigurationFailure    `json:"PhysicalChannelReconfigurationFailure,omitempty"`
	RadioBearerReconfigurationComplete       *RadioBearerReconfigurationComplete       `json:"RadioBearerReconfigurationComplete,omitempty"`
	RadioBearerReconfigurationFailure        *RadioBearerReconfigurationFailure        `json:"RadioBearerReconfigurationFailure,omitempty"`
	RadioBearerReleaseComplete               *RadioBearerReleaseComplete               `json:"RadioBearerReleaseComplete,omitempty"`
	RadioBearerReleaseFailure                *RadioBearerReleaseFailure                `json:"RadioBearerReleaseFailure,omitempty"`
	RadioBearerSetupComplete                 *RadioBearerSetupComplete                 `json:"RadioBearerSetupComplete,omitempty"`
	RadioBearerSetupFailure                  *RadioBearerSetupFailure                  `json:"RadioBearerSetupFailure,omitempty"`
	RrcConnectionReleaseComplete             *RRCConnectionReleaseComplete             `json:"RrcConnectionReleaseComplete,omitempty"`
	RrcConnectionSetupComplete               *RRCConnectionSetupComplete               `json:"RrcConnectionSetupComplete,omitempty"`
	RrcStatus                                *RRCStatus                                `json:"RrcStatus,omitempty"`
	SecurityModeComplete                     *SecurityModeComplete                     `json:"SecurityModeComplete,omitempty"`
	SecurityModeFailure                      *SecurityModeFailure                      `json:"SecurityModeFailure,omitempty"`
	SignallingConnectionReleaseIndication    *SignallingConnectionReleaseIndication    `json:"SignallingConnectionReleaseIndication,omitempty"`
	TransportChannelReconfigurationComplete  *TransportChannelReconfigurationComplete  `json:"TransportChannelReconfigurationComplete,omitempty"`
	TransportChannelReconfigurationFailure   *TransportChannelReconfigurationFailure   `json:"TransportChannelReconfigurationFailure,omitempty"`
	TransportFormatCombinationControlFailure *TransportFormatCombinationControlFailure `json:"TransportFormatCombinationControlFailure,omitempty"`
	UeCapabilityInformation                  *UECapabilityInformation                  `json:"UeCapabilityInformation,omitempty"`
	UplinkDirectTransfer                     *UplinkDirectTransfer                     `json:"UplinkDirectTransfer,omitempty"`
	UtranMobilityInformationConfirm          *UTRANMobilityInformationConfirm          `json:"UtranMobilityInformationConfirm,omitempty"`
	UtranMobilityInformationFailure          *UTRANMobilityInformationFailure          `json:"UtranMobilityInformationFailure,omitempty"`
	MbmsModificationRequest                  *MBMSModificationRequest                  `json:"MbmsModificationRequest,omitempty"`
	UlDCCHMessageTypeExt                     *ULDCCHMessageTypeExt                     `json:"UlDCCHMessageTypeExt,omitempty"`
}

// NewULDCCHMessageTypeActiveSetUpdateComplete creates a ULDCCHMessageType with the activeSetUpdateComplete alternative.
func NewULDCCHMessageTypeActiveSetUpdateComplete(v ActiveSetUpdateComplete) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                  ULDCCHMessageTypeChoiceActiveSetUpdateComplete,
		ActiveSetUpdateComplete: &v,
	}
}

// NewULDCCHMessageTypeActiveSetUpdateFailure creates a ULDCCHMessageType with the activeSetUpdateFailure alternative.
func NewULDCCHMessageTypeActiveSetUpdateFailure(v ActiveSetUpdateFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                 ULDCCHMessageTypeChoiceActiveSetUpdateFailure,
		ActiveSetUpdateFailure: &v,
	}
}

// NewULDCCHMessageTypeCellChangeOrderFromUTRANFailure creates a ULDCCHMessageType with the cellChangeOrderFromUTRANFailure alternative.
func NewULDCCHMessageTypeCellChangeOrderFromUTRANFailure(v CellChangeOrderFromUTRANFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                          ULDCCHMessageTypeChoiceCellChangeOrderFromUTRANFailure,
		CellChangeOrderFromUTRANFailure: &v,
	}
}

// NewULDCCHMessageTypeCounterCheckResponse creates a ULDCCHMessageType with the counterCheckResponse alternative.
func NewULDCCHMessageTypeCounterCheckResponse(v CounterCheckResponse) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:               ULDCCHMessageTypeChoiceCounterCheckResponse,
		CounterCheckResponse: &v,
	}
}

// NewULDCCHMessageTypeHandoverToUTRANComplete creates a ULDCCHMessageType with the handoverToUTRANComplete alternative.
func NewULDCCHMessageTypeHandoverToUTRANComplete(v HandoverToUTRANComplete) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                  ULDCCHMessageTypeChoiceHandoverToUTRANComplete,
		HandoverToUTRANComplete: &v,
	}
}

// NewULDCCHMessageTypeInitialDirectTransfer creates a ULDCCHMessageType with the initialDirectTransfer alternative.
func NewULDCCHMessageTypeInitialDirectTransfer(v InitialDirectTransfer) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                ULDCCHMessageTypeChoiceInitialDirectTransfer,
		InitialDirectTransfer: &v,
	}
}

// NewULDCCHMessageTypeHandoverFromUTRANFailure creates a ULDCCHMessageType with the handoverFromUTRANFailure alternative.
func NewULDCCHMessageTypeHandoverFromUTRANFailure(v HandoverFromUTRANFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                   ULDCCHMessageTypeChoiceHandoverFromUTRANFailure,
		HandoverFromUTRANFailure: &v,
	}
}

// NewULDCCHMessageTypeMeasurementControlFailure creates a ULDCCHMessageType with the measurementControlFailure alternative.
func NewULDCCHMessageTypeMeasurementControlFailure(v MeasurementControlFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                    ULDCCHMessageTypeChoiceMeasurementControlFailure,
		MeasurementControlFailure: &v,
	}
}

// NewULDCCHMessageTypeMeasurementReport creates a ULDCCHMessageType with the measurementReport alternative.
func NewULDCCHMessageTypeMeasurementReport(v MeasurementReport) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:            ULDCCHMessageTypeChoiceMeasurementReport,
		MeasurementReport: &v,
	}
}

// NewULDCCHMessageTypePhysicalChannelReconfigurationComplete creates a ULDCCHMessageType with the physicalChannelReconfigurationComplete alternative.
func NewULDCCHMessageTypePhysicalChannelReconfigurationComplete(v PhysicalChannelReconfigurationComplete) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                                 ULDCCHMessageTypeChoicePhysicalChannelReconfigurationComplete,
		PhysicalChannelReconfigurationComplete: &v,
	}
}

// NewULDCCHMessageTypePhysicalChannelReconfigurationFailure creates a ULDCCHMessageType with the physicalChannelReconfigurationFailure alternative.
func NewULDCCHMessageTypePhysicalChannelReconfigurationFailure(v PhysicalChannelReconfigurationFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                                ULDCCHMessageTypeChoicePhysicalChannelReconfigurationFailure,
		PhysicalChannelReconfigurationFailure: &v,
	}
}

// NewULDCCHMessageTypeRadioBearerReconfigurationComplete creates a ULDCCHMessageType with the radioBearerReconfigurationComplete alternative.
func NewULDCCHMessageTypeRadioBearerReconfigurationComplete(v RadioBearerReconfigurationComplete) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                             ULDCCHMessageTypeChoiceRadioBearerReconfigurationComplete,
		RadioBearerReconfigurationComplete: &v,
	}
}

// NewULDCCHMessageTypeRadioBearerReconfigurationFailure creates a ULDCCHMessageType with the radioBearerReconfigurationFailure alternative.
func NewULDCCHMessageTypeRadioBearerReconfigurationFailure(v RadioBearerReconfigurationFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                            ULDCCHMessageTypeChoiceRadioBearerReconfigurationFailure,
		RadioBearerReconfigurationFailure: &v,
	}
}

// NewULDCCHMessageTypeRadioBearerReleaseComplete creates a ULDCCHMessageType with the radioBearerReleaseComplete alternative.
func NewULDCCHMessageTypeRadioBearerReleaseComplete(v RadioBearerReleaseComplete) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                     ULDCCHMessageTypeChoiceRadioBearerReleaseComplete,
		RadioBearerReleaseComplete: &v,
	}
}

// NewULDCCHMessageTypeRadioBearerReleaseFailure creates a ULDCCHMessageType with the radioBearerReleaseFailure alternative.
func NewULDCCHMessageTypeRadioBearerReleaseFailure(v RadioBearerReleaseFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                    ULDCCHMessageTypeChoiceRadioBearerReleaseFailure,
		RadioBearerReleaseFailure: &v,
	}
}

// NewULDCCHMessageTypeRadioBearerSetupComplete creates a ULDCCHMessageType with the radioBearerSetupComplete alternative.
func NewULDCCHMessageTypeRadioBearerSetupComplete(v RadioBearerSetupComplete) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                   ULDCCHMessageTypeChoiceRadioBearerSetupComplete,
		RadioBearerSetupComplete: &v,
	}
}

// NewULDCCHMessageTypeRadioBearerSetupFailure creates a ULDCCHMessageType with the radioBearerSetupFailure alternative.
func NewULDCCHMessageTypeRadioBearerSetupFailure(v RadioBearerSetupFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                  ULDCCHMessageTypeChoiceRadioBearerSetupFailure,
		RadioBearerSetupFailure: &v,
	}
}

// NewULDCCHMessageTypeRrcConnectionReleaseComplete creates a ULDCCHMessageType with the rrcConnectionReleaseComplete alternative.
func NewULDCCHMessageTypeRrcConnectionReleaseComplete(v RRCConnectionReleaseComplete) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                       ULDCCHMessageTypeChoiceRrcConnectionReleaseComplete,
		RrcConnectionReleaseComplete: &v,
	}
}

// NewULDCCHMessageTypeRrcConnectionSetupComplete creates a ULDCCHMessageType with the rrcConnectionSetupComplete alternative.
func NewULDCCHMessageTypeRrcConnectionSetupComplete(v RRCConnectionSetupComplete) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                     ULDCCHMessageTypeChoiceRrcConnectionSetupComplete,
		RrcConnectionSetupComplete: &v,
	}
}

// NewULDCCHMessageTypeRrcStatus creates a ULDCCHMessageType with the rrcStatus alternative.
func NewULDCCHMessageTypeRrcStatus(v RRCStatus) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:    ULDCCHMessageTypeChoiceRrcStatus,
		RrcStatus: &v,
	}
}

// NewULDCCHMessageTypeSecurityModeComplete creates a ULDCCHMessageType with the securityModeComplete alternative.
func NewULDCCHMessageTypeSecurityModeComplete(v SecurityModeComplete) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:               ULDCCHMessageTypeChoiceSecurityModeComplete,
		SecurityModeComplete: &v,
	}
}

// NewULDCCHMessageTypeSecurityModeFailure creates a ULDCCHMessageType with the securityModeFailure alternative.
func NewULDCCHMessageTypeSecurityModeFailure(v SecurityModeFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:              ULDCCHMessageTypeChoiceSecurityModeFailure,
		SecurityModeFailure: &v,
	}
}

// NewULDCCHMessageTypeSignallingConnectionReleaseIndication creates a ULDCCHMessageType with the signallingConnectionReleaseIndication alternative.
func NewULDCCHMessageTypeSignallingConnectionReleaseIndication(v SignallingConnectionReleaseIndication) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                                ULDCCHMessageTypeChoiceSignallingConnectionReleaseIndication,
		SignallingConnectionReleaseIndication: &v,
	}
}

// NewULDCCHMessageTypeTransportChannelReconfigurationComplete creates a ULDCCHMessageType with the transportChannelReconfigurationComplete alternative.
func NewULDCCHMessageTypeTransportChannelReconfigurationComplete(v TransportChannelReconfigurationComplete) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                                  ULDCCHMessageTypeChoiceTransportChannelReconfigurationComplete,
		TransportChannelReconfigurationComplete: &v,
	}
}

// NewULDCCHMessageTypeTransportChannelReconfigurationFailure creates a ULDCCHMessageType with the transportChannelReconfigurationFailure alternative.
func NewULDCCHMessageTypeTransportChannelReconfigurationFailure(v TransportChannelReconfigurationFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                                 ULDCCHMessageTypeChoiceTransportChannelReconfigurationFailure,
		TransportChannelReconfigurationFailure: &v,
	}
}

// NewULDCCHMessageTypeTransportFormatCombinationControlFailure creates a ULDCCHMessageType with the transportFormatCombinationControlFailure alternative.
func NewULDCCHMessageTypeTransportFormatCombinationControlFailure(v TransportFormatCombinationControlFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                                   ULDCCHMessageTypeChoiceTransportFormatCombinationControlFailure,
		TransportFormatCombinationControlFailure: &v,
	}
}

// NewULDCCHMessageTypeUeCapabilityInformation creates a ULDCCHMessageType with the ueCapabilityInformation alternative.
func NewULDCCHMessageTypeUeCapabilityInformation(v UECapabilityInformation) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                  ULDCCHMessageTypeChoiceUeCapabilityInformation,
		UeCapabilityInformation: &v,
	}
}

// NewULDCCHMessageTypeUplinkDirectTransfer creates a ULDCCHMessageType with the uplinkDirectTransfer alternative.
func NewULDCCHMessageTypeUplinkDirectTransfer(v UplinkDirectTransfer) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:               ULDCCHMessageTypeChoiceUplinkDirectTransfer,
		UplinkDirectTransfer: &v,
	}
}

// NewULDCCHMessageTypeUtranMobilityInformationConfirm creates a ULDCCHMessageType with the utranMobilityInformationConfirm alternative.
func NewULDCCHMessageTypeUtranMobilityInformationConfirm(v UTRANMobilityInformationConfirm) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                          ULDCCHMessageTypeChoiceUtranMobilityInformationConfirm,
		UtranMobilityInformationConfirm: &v,
	}
}

// NewULDCCHMessageTypeUtranMobilityInformationFailure creates a ULDCCHMessageType with the utranMobilityInformationFailure alternative.
func NewULDCCHMessageTypeUtranMobilityInformationFailure(v UTRANMobilityInformationFailure) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                          ULDCCHMessageTypeChoiceUtranMobilityInformationFailure,
		UtranMobilityInformationFailure: &v,
	}
}

// NewULDCCHMessageTypeMbmsModificationRequest creates a ULDCCHMessageType with the mbmsModificationRequest alternative.
func NewULDCCHMessageTypeMbmsModificationRequest(v MBMSModificationRequest) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:                  ULDCCHMessageTypeChoiceMbmsModificationRequest,
		MbmsModificationRequest: &v,
	}
}

// NewULDCCHMessageTypeUlDCCHMessageTypeExt creates a ULDCCHMessageType with the ul-DCCH-MessageType-ext alternative.
func NewULDCCHMessageTypeUlDCCHMessageTypeExt(v ULDCCHMessageTypeExt) ULDCCHMessageType {
	return ULDCCHMessageType{
		Choice:               ULDCCHMessageTypeChoiceUlDCCHMessageTypeExt,
		UlDCCHMessageTypeExt: &v,
	}
}

// ULDCCHMessageTypeExt choice constants.
const (
	ULDCCHMessageTypeExtChoiceUeInformationResponse = 1
	ULDCCHMessageTypeExtChoiceSpare15               = 2
	ULDCCHMessageTypeExtChoiceSpare14               = 3
	ULDCCHMessageTypeExtChoiceSpare13               = 4
	ULDCCHMessageTypeExtChoiceSpare12               = 5
	ULDCCHMessageTypeExtChoiceSpare11               = 6
	ULDCCHMessageTypeExtChoiceSpare10               = 7
	ULDCCHMessageTypeExtChoiceSpare9                = 8
	ULDCCHMessageTypeExtChoiceSpare8                = 9
	ULDCCHMessageTypeExtChoiceSpare7                = 10
	ULDCCHMessageTypeExtChoiceSpare6                = 11
	ULDCCHMessageTypeExtChoiceSpare5                = 12
	ULDCCHMessageTypeExtChoiceSpare4                = 13
	ULDCCHMessageTypeExtChoiceSpare3                = 14
	ULDCCHMessageTypeExtChoiceSpare2                = 15
	ULDCCHMessageTypeExtChoiceSpare1                = 16
)

// ULDCCHMessageTypeExt represents the ASN.1 CHOICE type UL-DCCH-MessageType-ext.
type ULDCCHMessageTypeExt struct {
	Choice                int
	PERPadding_           per.CompletePadding    `json:"-"`
	PERExtraBits_         per.TrailingBits       `json:"-"`
	PEROpenTypePadding_   per.CompletePadding    `json:"-"`
	UeInformationResponse *UEInformationResponse `json:"UeInformationResponse,omitempty"`
	Spare15               *struct{}              `json:"Spare15,omitempty"`
	Spare14               *struct{}              `json:"Spare14,omitempty"`
	Spare13               *struct{}              `json:"Spare13,omitempty"`
	Spare12               *struct{}              `json:"Spare12,omitempty"`
	Spare11               *struct{}              `json:"Spare11,omitempty"`
	Spare10               *struct{}              `json:"Spare10,omitempty"`
	Spare9                *struct{}              `json:"Spare9,omitempty"`
	Spare8                *struct{}              `json:"Spare8,omitempty"`
	Spare7                *struct{}              `json:"Spare7,omitempty"`
	Spare6                *struct{}              `json:"Spare6,omitempty"`
	Spare5                *struct{}              `json:"Spare5,omitempty"`
	Spare4                *struct{}              `json:"Spare4,omitempty"`
	Spare3                *struct{}              `json:"Spare3,omitempty"`
	Spare2                *struct{}              `json:"Spare2,omitempty"`
	Spare1                *struct{}              `json:"Spare1,omitempty"`
}

// NewULDCCHMessageTypeExtUeInformationResponse creates a ULDCCHMessageTypeExt with the ueInformationResponse alternative.
func NewULDCCHMessageTypeExtUeInformationResponse(v UEInformationResponse) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice:                ULDCCHMessageTypeExtChoiceUeInformationResponse,
		UeInformationResponse: &v,
	}
}

// NewULDCCHMessageTypeExtSpare15 creates a ULDCCHMessageTypeExt with the spare15 alternative.
func NewULDCCHMessageTypeExtSpare15(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice:  ULDCCHMessageTypeExtChoiceSpare15,
		Spare15: &v,
	}
}

// NewULDCCHMessageTypeExtSpare14 creates a ULDCCHMessageTypeExt with the spare14 alternative.
func NewULDCCHMessageTypeExtSpare14(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice:  ULDCCHMessageTypeExtChoiceSpare14,
		Spare14: &v,
	}
}

// NewULDCCHMessageTypeExtSpare13 creates a ULDCCHMessageTypeExt with the spare13 alternative.
func NewULDCCHMessageTypeExtSpare13(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice:  ULDCCHMessageTypeExtChoiceSpare13,
		Spare13: &v,
	}
}

// NewULDCCHMessageTypeExtSpare12 creates a ULDCCHMessageTypeExt with the spare12 alternative.
func NewULDCCHMessageTypeExtSpare12(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice:  ULDCCHMessageTypeExtChoiceSpare12,
		Spare12: &v,
	}
}

// NewULDCCHMessageTypeExtSpare11 creates a ULDCCHMessageTypeExt with the spare11 alternative.
func NewULDCCHMessageTypeExtSpare11(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice:  ULDCCHMessageTypeExtChoiceSpare11,
		Spare11: &v,
	}
}

// NewULDCCHMessageTypeExtSpare10 creates a ULDCCHMessageTypeExt with the spare10 alternative.
func NewULDCCHMessageTypeExtSpare10(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice:  ULDCCHMessageTypeExtChoiceSpare10,
		Spare10: &v,
	}
}

// NewULDCCHMessageTypeExtSpare9 creates a ULDCCHMessageTypeExt with the spare9 alternative.
func NewULDCCHMessageTypeExtSpare9(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice: ULDCCHMessageTypeExtChoiceSpare9,
		Spare9: &v,
	}
}

// NewULDCCHMessageTypeExtSpare8 creates a ULDCCHMessageTypeExt with the spare8 alternative.
func NewULDCCHMessageTypeExtSpare8(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice: ULDCCHMessageTypeExtChoiceSpare8,
		Spare8: &v,
	}
}

// NewULDCCHMessageTypeExtSpare7 creates a ULDCCHMessageTypeExt with the spare7 alternative.
func NewULDCCHMessageTypeExtSpare7(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice: ULDCCHMessageTypeExtChoiceSpare7,
		Spare7: &v,
	}
}

// NewULDCCHMessageTypeExtSpare6 creates a ULDCCHMessageTypeExt with the spare6 alternative.
func NewULDCCHMessageTypeExtSpare6(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice: ULDCCHMessageTypeExtChoiceSpare6,
		Spare6: &v,
	}
}

// NewULDCCHMessageTypeExtSpare5 creates a ULDCCHMessageTypeExt with the spare5 alternative.
func NewULDCCHMessageTypeExtSpare5(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice: ULDCCHMessageTypeExtChoiceSpare5,
		Spare5: &v,
	}
}

// NewULDCCHMessageTypeExtSpare4 creates a ULDCCHMessageTypeExt with the spare4 alternative.
func NewULDCCHMessageTypeExtSpare4(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice: ULDCCHMessageTypeExtChoiceSpare4,
		Spare4: &v,
	}
}

// NewULDCCHMessageTypeExtSpare3 creates a ULDCCHMessageTypeExt with the spare3 alternative.
func NewULDCCHMessageTypeExtSpare3(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice: ULDCCHMessageTypeExtChoiceSpare3,
		Spare3: &v,
	}
}

// NewULDCCHMessageTypeExtSpare2 creates a ULDCCHMessageTypeExt with the spare2 alternative.
func NewULDCCHMessageTypeExtSpare2(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice: ULDCCHMessageTypeExtChoiceSpare2,
		Spare2: &v,
	}
}

// NewULDCCHMessageTypeExtSpare1 creates a ULDCCHMessageTypeExt with the spare1 alternative.
func NewULDCCHMessageTypeExtSpare1(v struct{}) ULDCCHMessageTypeExt {
	return ULDCCHMessageTypeExt{
		Choice: ULDCCHMessageTypeExtChoiceSpare1,
		Spare1: &v,
	}
}

// DLCCCHMessage represents the ASN.1 type DL-CCCH-Message (SEQUENCE).
type DLCCCHMessage struct {
	IntegrityCheckInfo   *IntegrityCheckInfo            `asn1:"tag:0,context,implicit,optional" json:"IntegrityCheckInfo,omitempty"`
	Message              DLCCCHMessageType              `asn1:"tag:1,context,explicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// DLCCCHMessageType choice constants.
const (
	DLCCCHMessageTypeChoiceCellUpdateConfirm    = 1
	DLCCCHMessageTypeChoiceRrcConnectionReject  = 2
	DLCCCHMessageTypeChoiceRrcConnectionRelease = 3
	DLCCCHMessageTypeChoiceRrcConnectionSetup   = 4
	DLCCCHMessageTypeChoiceUraUpdateConfirm     = 5
	DLCCCHMessageTypeChoiceDummy                = 6
	DLCCCHMessageTypeChoiceSpare2               = 7
	DLCCCHMessageTypeChoiceSpare1               = 8
)

// DLCCCHMessageType represents the ASN.1 CHOICE type DL-CCCH-MessageType.
type DLCCCHMessageType struct {
	Choice               int
	PERPadding_          per.CompletePadding                  `json:"-"`
	PERExtraBits_        per.TrailingBits                     `json:"-"`
	PEROpenTypePadding_  per.CompletePadding                  `json:"-"`
	CellUpdateConfirm    *CellUpdateConfirmCCCH               `json:"CellUpdateConfirm,omitempty"`
	RrcConnectionReject  *RRCConnectionReject                 `json:"RrcConnectionReject,omitempty"`
	RrcConnectionRelease *RRCConnectionReleaseCCCH            `json:"RrcConnectionRelease,omitempty"`
	RrcConnectionSetup   *RRCConnectionSetup                  `json:"RrcConnectionSetup,omitempty"`
	UraUpdateConfirm     *URAUpdateConfirmCCCH                `json:"UraUpdateConfirm,omitempty"`
	Dummy                *ETWSPrimaryNotificationWithSecurity `json:"Dummy,omitempty"`
	Spare2               *struct{}                            `json:"Spare2,omitempty"`
	Spare1               *struct{}                            `json:"Spare1,omitempty"`
}

// NewDLCCCHMessageTypeCellUpdateConfirm creates a DLCCCHMessageType with the cellUpdateConfirm alternative.
func NewDLCCCHMessageTypeCellUpdateConfirm(v CellUpdateConfirmCCCH) DLCCCHMessageType {
	return DLCCCHMessageType{
		Choice:            DLCCCHMessageTypeChoiceCellUpdateConfirm,
		CellUpdateConfirm: &v,
	}
}

// NewDLCCCHMessageTypeRrcConnectionReject creates a DLCCCHMessageType with the rrcConnectionReject alternative.
func NewDLCCCHMessageTypeRrcConnectionReject(v RRCConnectionReject) DLCCCHMessageType {
	return DLCCCHMessageType{
		Choice:              DLCCCHMessageTypeChoiceRrcConnectionReject,
		RrcConnectionReject: &v,
	}
}

// NewDLCCCHMessageTypeRrcConnectionRelease creates a DLCCCHMessageType with the rrcConnectionRelease alternative.
func NewDLCCCHMessageTypeRrcConnectionRelease(v RRCConnectionReleaseCCCH) DLCCCHMessageType {
	return DLCCCHMessageType{
		Choice:               DLCCCHMessageTypeChoiceRrcConnectionRelease,
		RrcConnectionRelease: &v,
	}
}

// NewDLCCCHMessageTypeRrcConnectionSetup creates a DLCCCHMessageType with the rrcConnectionSetup alternative.
func NewDLCCCHMessageTypeRrcConnectionSetup(v RRCConnectionSetup) DLCCCHMessageType {
	return DLCCCHMessageType{
		Choice:             DLCCCHMessageTypeChoiceRrcConnectionSetup,
		RrcConnectionSetup: &v,
	}
}

// NewDLCCCHMessageTypeUraUpdateConfirm creates a DLCCCHMessageType with the uraUpdateConfirm alternative.
func NewDLCCCHMessageTypeUraUpdateConfirm(v URAUpdateConfirmCCCH) DLCCCHMessageType {
	return DLCCCHMessageType{
		Choice:           DLCCCHMessageTypeChoiceUraUpdateConfirm,
		UraUpdateConfirm: &v,
	}
}

// NewDLCCCHMessageTypeDummy creates a DLCCCHMessageType with the dummy alternative.
func NewDLCCCHMessageTypeDummy(v ETWSPrimaryNotificationWithSecurity) DLCCCHMessageType {
	return DLCCCHMessageType{
		Choice: DLCCCHMessageTypeChoiceDummy,
		Dummy:  &v,
	}
}

// NewDLCCCHMessageTypeSpare2 creates a DLCCCHMessageType with the spare2 alternative.
func NewDLCCCHMessageTypeSpare2(v struct{}) DLCCCHMessageType {
	return DLCCCHMessageType{
		Choice: DLCCCHMessageTypeChoiceSpare2,
		Spare2: &v,
	}
}

// NewDLCCCHMessageTypeSpare1 creates a DLCCCHMessageType with the spare1 alternative.
func NewDLCCCHMessageTypeSpare1(v struct{}) DLCCCHMessageType {
	return DLCCCHMessageType{
		Choice: DLCCCHMessageTypeChoiceSpare1,
		Spare1: &v,
	}
}

// ULCCCHMessage represents the ASN.1 type UL-CCCH-Message (SEQUENCE).
type ULCCCHMessage struct {
	IntegrityCheckInfo   *IntegrityCheckInfo            `asn1:"tag:0,context,implicit,optional" json:"IntegrityCheckInfo,omitempty"`
	Message              ULCCCHMessageType              `asn1:"tag:1,context,explicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// ULCCCHMessageType choice constants.
const (
	ULCCCHMessageTypeChoiceCellUpdate           = 1
	ULCCCHMessageTypeChoiceRrcConnectionRequest = 2
	ULCCCHMessageTypeChoiceUraUpdate            = 3
	ULCCCHMessageTypeChoiceULCCCHMessageTypeR11 = 4
)

// ULCCCHMessageType represents the ASN.1 CHOICE type UL-CCCH-MessageType.
type ULCCCHMessageType struct {
	Choice               int
	PERPadding_          per.CompletePadding   `json:"-"`
	PERExtraBits_        per.TrailingBits      `json:"-"`
	PEROpenTypePadding_  per.CompletePadding   `json:"-"`
	CellUpdate           *CellUpdate           `json:"CellUpdate,omitempty"`
	RrcConnectionRequest *RRCConnectionRequest `json:"RrcConnectionRequest,omitempty"`
	UraUpdate            *URAUpdate            `json:"UraUpdate,omitempty"`
	ULCCCHMessageTypeR11 *ULCCCHMessageTypeR11 `json:"ULCCCHMessageTypeR11,omitempty"`
}

// NewULCCCHMessageTypeCellUpdate creates a ULCCCHMessageType with the cellUpdate alternative.
func NewULCCCHMessageTypeCellUpdate(v CellUpdate) ULCCCHMessageType {
	return ULCCCHMessageType{
		Choice:     ULCCCHMessageTypeChoiceCellUpdate,
		CellUpdate: &v,
	}
}

// NewULCCCHMessageTypeRrcConnectionRequest creates a ULCCCHMessageType with the rrcConnectionRequest alternative.
func NewULCCCHMessageTypeRrcConnectionRequest(v RRCConnectionRequest) ULCCCHMessageType {
	return ULCCCHMessageType{
		Choice:               ULCCCHMessageTypeChoiceRrcConnectionRequest,
		RrcConnectionRequest: &v,
	}
}

// NewULCCCHMessageTypeUraUpdate creates a ULCCCHMessageType with the uraUpdate alternative.
func NewULCCCHMessageTypeUraUpdate(v URAUpdate) ULCCCHMessageType {
	return ULCCCHMessageType{
		Choice:    ULCCCHMessageTypeChoiceUraUpdate,
		UraUpdate: &v,
	}
}

// NewULCCCHMessageTypeULCCCHMessageTypeR11 creates a ULCCCHMessageType with the uL-CCCH-MessageType-r11 alternative.
func NewULCCCHMessageTypeULCCCHMessageTypeR11(v ULCCCHMessageTypeR11) ULCCCHMessageType {
	return ULCCCHMessageType{
		Choice:               ULCCCHMessageTypeChoiceULCCCHMessageTypeR11,
		ULCCCHMessageTypeR11: &v,
	}
}

// ULCCCHMessageTypeR11 choice constants.
const (
	ULCCCHMessageTypeR11ChoiceCellUpdate = 1
	ULCCCHMessageTypeR11ChoiceSpare3     = 2
	ULCCCHMessageTypeR11ChoiceSpare2     = 3
	ULCCCHMessageTypeR11ChoiceSpare1     = 4
)

// ULCCCHMessageTypeR11 represents the ASN.1 CHOICE type UL-CCCH-MessageType-r11.
type ULCCCHMessageTypeR11 struct {
	Choice              int
	PERPadding_         per.CompletePadding `json:"-"`
	PERExtraBits_       per.TrailingBits    `json:"-"`
	PEROpenTypePadding_ per.CompletePadding `json:"-"`
	CellUpdate          *CellUpdateFDDR11   `json:"CellUpdate,omitempty"`
	Spare3              *struct{}           `json:"Spare3,omitempty"`
	Spare2              *struct{}           `json:"Spare2,omitempty"`
	Spare1              *struct{}           `json:"Spare1,omitempty"`
}

// NewULCCCHMessageTypeR11CellUpdate creates a ULCCCHMessageTypeR11 with the cellUpdate alternative.
func NewULCCCHMessageTypeR11CellUpdate(v CellUpdateFDDR11) ULCCCHMessageTypeR11 {
	return ULCCCHMessageTypeR11{
		Choice:     ULCCCHMessageTypeR11ChoiceCellUpdate,
		CellUpdate: &v,
	}
}

// NewULCCCHMessageTypeR11Spare3 creates a ULCCCHMessageTypeR11 with the spare3 alternative.
func NewULCCCHMessageTypeR11Spare3(v struct{}) ULCCCHMessageTypeR11 {
	return ULCCCHMessageTypeR11{
		Choice: ULCCCHMessageTypeR11ChoiceSpare3,
		Spare3: &v,
	}
}

// NewULCCCHMessageTypeR11Spare2 creates a ULCCCHMessageTypeR11 with the spare2 alternative.
func NewULCCCHMessageTypeR11Spare2(v struct{}) ULCCCHMessageTypeR11 {
	return ULCCCHMessageTypeR11{
		Choice: ULCCCHMessageTypeR11ChoiceSpare2,
		Spare2: &v,
	}
}

// NewULCCCHMessageTypeR11Spare1 creates a ULCCCHMessageTypeR11 with the spare1 alternative.
func NewULCCCHMessageTypeR11Spare1(v struct{}) ULCCCHMessageTypeR11 {
	return ULCCCHMessageTypeR11{
		Choice: ULCCCHMessageTypeR11ChoiceSpare1,
		Spare1: &v,
	}
}

// PCCHMessage represents the ASN.1 type PCCH-Message (SEQUENCE).
type PCCHMessage struct {
	Message              PCCHMessageType                `asn1:"tag:0,context,explicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// PCCHMessageType choice constants.
const (
	PCCHMessageTypeChoicePagingType1 = 1
	PCCHMessageTypeChoiceSpare       = 2
)

// PCCHMessageType represents the ASN.1 CHOICE type PCCH-MessageType.
type PCCHMessageType struct {
	Choice              int
	PERPadding_         per.CompletePadding `json:"-"`
	PERExtraBits_       per.TrailingBits    `json:"-"`
	PEROpenTypePadding_ per.CompletePadding `json:"-"`
	PagingType1         *PagingType1        `json:"PagingType1,omitempty"`
	Spare               *struct{}           `json:"Spare,omitempty"`
}

// NewPCCHMessageTypePagingType1 creates a PCCHMessageType with the pagingType1 alternative.
func NewPCCHMessageTypePagingType1(v PagingType1) PCCHMessageType {
	return PCCHMessageType{
		Choice:      PCCHMessageTypeChoicePagingType1,
		PagingType1: &v,
	}
}

// NewPCCHMessageTypeSpare creates a PCCHMessageType with the spare alternative.
func NewPCCHMessageTypeSpare(v struct{}) PCCHMessageType {
	return PCCHMessageType{
		Choice: PCCHMessageTypeChoiceSpare,
		Spare:  &v,
	}
}

// DLSHCCHMessage represents the ASN.1 type DL-SHCCH-Message (SEQUENCE).
type DLSHCCHMessage struct {
	Message              DLSHCCHMessageType             `asn1:"tag:0,context,explicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// DLSHCCHMessageType choice constants.
const (
	DLSHCCHMessageTypeChoicePhysicalSharedChannelAllocation = 1
	DLSHCCHMessageTypeChoiceSpare                           = 2
)

// DLSHCCHMessageType represents the ASN.1 CHOICE type DL-SHCCH-MessageType.
type DLSHCCHMessageType struct {
	Choice                          int
	PERPadding_                     per.CompletePadding              `json:"-"`
	PERExtraBits_                   per.TrailingBits                 `json:"-"`
	PEROpenTypePadding_             per.CompletePadding              `json:"-"`
	PhysicalSharedChannelAllocation *PhysicalSharedChannelAllocation `json:"PhysicalSharedChannelAllocation,omitempty"`
	Spare                           *struct{}                        `json:"Spare,omitempty"`
}

// NewDLSHCCHMessageTypePhysicalSharedChannelAllocation creates a DLSHCCHMessageType with the physicalSharedChannelAllocation alternative.
func NewDLSHCCHMessageTypePhysicalSharedChannelAllocation(v PhysicalSharedChannelAllocation) DLSHCCHMessageType {
	return DLSHCCHMessageType{
		Choice:                          DLSHCCHMessageTypeChoicePhysicalSharedChannelAllocation,
		PhysicalSharedChannelAllocation: &v,
	}
}

// NewDLSHCCHMessageTypeSpare creates a DLSHCCHMessageType with the spare alternative.
func NewDLSHCCHMessageTypeSpare(v struct{}) DLSHCCHMessageType {
	return DLSHCCHMessageType{
		Choice: DLSHCCHMessageTypeChoiceSpare,
		Spare:  &v,
	}
}

// ULSHCCHMessage represents the ASN.1 type UL-SHCCH-Message (SEQUENCE).
type ULSHCCHMessage struct {
	Message              ULSHCCHMessageType             `asn1:"tag:0,context,explicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// ULSHCCHMessageType choice constants.
const (
	ULSHCCHMessageTypeChoicePuschCapacityRequest = 1
	ULSHCCHMessageTypeChoiceSpare                = 2
)

// ULSHCCHMessageType represents the ASN.1 CHOICE type UL-SHCCH-MessageType.
type ULSHCCHMessageType struct {
	Choice               int
	PERPadding_          per.CompletePadding   `json:"-"`
	PERExtraBits_        per.TrailingBits      `json:"-"`
	PEROpenTypePadding_  per.CompletePadding   `json:"-"`
	PuschCapacityRequest *PUSCHCapacityRequest `json:"PuschCapacityRequest,omitempty"`
	Spare                *struct{}             `json:"Spare,omitempty"`
}

// NewULSHCCHMessageTypePuschCapacityRequest creates a ULSHCCHMessageType with the puschCapacityRequest alternative.
func NewULSHCCHMessageTypePuschCapacityRequest(v PUSCHCapacityRequest) ULSHCCHMessageType {
	return ULSHCCHMessageType{
		Choice:               ULSHCCHMessageTypeChoicePuschCapacityRequest,
		PuschCapacityRequest: &v,
	}
}

// NewULSHCCHMessageTypeSpare creates a ULSHCCHMessageType with the spare alternative.
func NewULSHCCHMessageTypeSpare(v struct{}) ULSHCCHMessageType {
	return ULSHCCHMessageType{
		Choice: ULSHCCHMessageTypeChoiceSpare,
		Spare:  &v,
	}
}

// BCCHFACHMessage represents the ASN.1 type BCCH-FACH-Message (SEQUENCE).
type BCCHFACHMessage struct {
	Message              BCCHFACHMessageType            `asn1:"tag:0,context,explicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// BCCHFACHMessageType choice constants.
const (
	BCCHFACHMessageTypeChoiceDummy                             = 1
	BCCHFACHMessageTypeChoiceSystemInformationChangeIndication = 2
	BCCHFACHMessageTypeChoiceSpare2                            = 3
	BCCHFACHMessageTypeChoiceSpare1                            = 4
)

// BCCHFACHMessageType represents the ASN.1 CHOICE type BCCH-FACH-MessageType.
type BCCHFACHMessageType struct {
	Choice                            int
	PERPadding_                       per.CompletePadding                `json:"-"`
	PERExtraBits_                     per.TrailingBits                   `json:"-"`
	PEROpenTypePadding_               per.CompletePadding                `json:"-"`
	Dummy                             *SystemInformationFACH             `json:"Dummy,omitempty"`
	SystemInformationChangeIndication *SystemInformationChangeIndication `json:"SystemInformationChangeIndication,omitempty"`
	Spare2                            *struct{}                          `json:"Spare2,omitempty"`
	Spare1                            *struct{}                          `json:"Spare1,omitempty"`
}

// NewBCCHFACHMessageTypeDummy creates a BCCHFACHMessageType with the dummy alternative.
func NewBCCHFACHMessageTypeDummy(v SystemInformationFACH) BCCHFACHMessageType {
	return BCCHFACHMessageType{
		Choice: BCCHFACHMessageTypeChoiceDummy,
		Dummy:  &v,
	}
}

// NewBCCHFACHMessageTypeSystemInformationChangeIndication creates a BCCHFACHMessageType with the systemInformationChangeIndication alternative.
func NewBCCHFACHMessageTypeSystemInformationChangeIndication(v SystemInformationChangeIndication) BCCHFACHMessageType {
	return BCCHFACHMessageType{
		Choice:                            BCCHFACHMessageTypeChoiceSystemInformationChangeIndication,
		SystemInformationChangeIndication: &v,
	}
}

// NewBCCHFACHMessageTypeSpare2 creates a BCCHFACHMessageType with the spare2 alternative.
func NewBCCHFACHMessageTypeSpare2(v struct{}) BCCHFACHMessageType {
	return BCCHFACHMessageType{
		Choice: BCCHFACHMessageTypeChoiceSpare2,
		Spare2: &v,
	}
}

// NewBCCHFACHMessageTypeSpare1 creates a BCCHFACHMessageType with the spare1 alternative.
func NewBCCHFACHMessageTypeSpare1(v struct{}) BCCHFACHMessageType {
	return BCCHFACHMessageType{
		Choice: BCCHFACHMessageTypeChoiceSpare1,
		Spare1: &v,
	}
}

// BCCHBCHMessage represents the ASN.1 type BCCH-BCH-Message (SEQUENCE).
type BCCHBCHMessage struct {
	Message              SystemInformationBCH           `asn1:"tag:0,context,implicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// BCCHBCH2Message represents the ASN.1 type BCCH-BCH2-Message (SEQUENCE).
type BCCHBCH2Message struct {
	Message              SystemInformation2BCH          `asn1:"tag:0,context,implicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// MCCHMessage represents the ASN.1 type MCCH-Message (SEQUENCE).
type MCCHMessage struct {
	Message              MCCHMessageType                `asn1:"tag:0,context,explicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// MCCHMessageType choice constants.
const (
	MCCHMessageTypeChoiceMbmsAccessInformation                = 1
	MCCHMessageTypeChoiceMbmsCommonPTMRBInformation           = 2
	MCCHMessageTypeChoiceMbmsCurrentCellPTMRBInformation      = 3
	MCCHMessageTypeChoiceMbmsGeneralInformation               = 4
	MCCHMessageTypeChoiceMbmsModifiedServicesInformation      = 5
	MCCHMessageTypeChoiceMbmsNeighbouringCellPTMRBInformation = 6
	MCCHMessageTypeChoiceMbmsUnmodifiedServicesInformation    = 7
	MCCHMessageTypeChoiceSpare9                               = 8
	MCCHMessageTypeChoiceSpare8                               = 9
	MCCHMessageTypeChoiceSpare7                               = 10
	MCCHMessageTypeChoiceSpare6                               = 11
	MCCHMessageTypeChoiceSpare5                               = 12
	MCCHMessageTypeChoiceSpare4                               = 13
	MCCHMessageTypeChoiceSpare3                               = 14
	MCCHMessageTypeChoiceSpare2                               = 15
	MCCHMessageTypeChoiceSpare1                               = 16
)

// MCCHMessageType represents the ASN.1 CHOICE type MCCH-MessageType.
type MCCHMessageType struct {
	Choice                               int
	PERPadding_                          per.CompletePadding                   `json:"-"`
	PERExtraBits_                        per.TrailingBits                      `json:"-"`
	PEROpenTypePadding_                  per.CompletePadding                   `json:"-"`
	MbmsAccessInformation                *MBMSAccessInformation                `json:"MbmsAccessInformation,omitempty"`
	MbmsCommonPTMRBInformation           *MBMSCommonPTMRBInformation           `json:"MbmsCommonPTMRBInformation,omitempty"`
	MbmsCurrentCellPTMRBInformation      *MBMSCurrentCellPTMRBInformation      `json:"MbmsCurrentCellPTMRBInformation,omitempty"`
	MbmsGeneralInformation               *MBMSGeneralInformation               `json:"MbmsGeneralInformation,omitempty"`
	MbmsModifiedServicesInformation      *MBMSModifiedServicesInformation      `json:"MbmsModifiedServicesInformation,omitempty"`
	MbmsNeighbouringCellPTMRBInformation *MBMSNeighbouringCellPTMRBInformation `json:"MbmsNeighbouringCellPTMRBInformation,omitempty"`
	MbmsUnmodifiedServicesInformation    *MBMSUnmodifiedServicesInformation    `json:"MbmsUnmodifiedServicesInformation,omitempty"`
	Spare9                               *struct{}                             `json:"Spare9,omitempty"`
	Spare8                               *struct{}                             `json:"Spare8,omitempty"`
	Spare7                               *struct{}                             `json:"Spare7,omitempty"`
	Spare6                               *struct{}                             `json:"Spare6,omitempty"`
	Spare5                               *struct{}                             `json:"Spare5,omitempty"`
	Spare4                               *struct{}                             `json:"Spare4,omitempty"`
	Spare3                               *struct{}                             `json:"Spare3,omitempty"`
	Spare2                               *struct{}                             `json:"Spare2,omitempty"`
	Spare1                               *struct{}                             `json:"Spare1,omitempty"`
}

// NewMCCHMessageTypeMbmsAccessInformation creates a MCCHMessageType with the mbmsAccessInformation alternative.
func NewMCCHMessageTypeMbmsAccessInformation(v MBMSAccessInformation) MCCHMessageType {
	return MCCHMessageType{
		Choice:                MCCHMessageTypeChoiceMbmsAccessInformation,
		MbmsAccessInformation: &v,
	}
}

// NewMCCHMessageTypeMbmsCommonPTMRBInformation creates a MCCHMessageType with the mbmsCommonPTMRBInformation alternative.
func NewMCCHMessageTypeMbmsCommonPTMRBInformation(v MBMSCommonPTMRBInformation) MCCHMessageType {
	return MCCHMessageType{
		Choice:                     MCCHMessageTypeChoiceMbmsCommonPTMRBInformation,
		MbmsCommonPTMRBInformation: &v,
	}
}

// NewMCCHMessageTypeMbmsCurrentCellPTMRBInformation creates a MCCHMessageType with the mbmsCurrentCellPTMRBInformation alternative.
func NewMCCHMessageTypeMbmsCurrentCellPTMRBInformation(v MBMSCurrentCellPTMRBInformation) MCCHMessageType {
	return MCCHMessageType{
		Choice:                          MCCHMessageTypeChoiceMbmsCurrentCellPTMRBInformation,
		MbmsCurrentCellPTMRBInformation: &v,
	}
}

// NewMCCHMessageTypeMbmsGeneralInformation creates a MCCHMessageType with the mbmsGeneralInformation alternative.
func NewMCCHMessageTypeMbmsGeneralInformation(v MBMSGeneralInformation) MCCHMessageType {
	return MCCHMessageType{
		Choice:                 MCCHMessageTypeChoiceMbmsGeneralInformation,
		MbmsGeneralInformation: &v,
	}
}

// NewMCCHMessageTypeMbmsModifiedServicesInformation creates a MCCHMessageType with the mbmsModifiedServicesInformation alternative.
func NewMCCHMessageTypeMbmsModifiedServicesInformation(v MBMSModifiedServicesInformation) MCCHMessageType {
	return MCCHMessageType{
		Choice:                          MCCHMessageTypeChoiceMbmsModifiedServicesInformation,
		MbmsModifiedServicesInformation: &v,
	}
}

// NewMCCHMessageTypeMbmsNeighbouringCellPTMRBInformation creates a MCCHMessageType with the mbmsNeighbouringCellPTMRBInformation alternative.
func NewMCCHMessageTypeMbmsNeighbouringCellPTMRBInformation(v MBMSNeighbouringCellPTMRBInformation) MCCHMessageType {
	return MCCHMessageType{
		Choice:                               MCCHMessageTypeChoiceMbmsNeighbouringCellPTMRBInformation,
		MbmsNeighbouringCellPTMRBInformation: &v,
	}
}

// NewMCCHMessageTypeMbmsUnmodifiedServicesInformation creates a MCCHMessageType with the mbmsUnmodifiedServicesInformation alternative.
func NewMCCHMessageTypeMbmsUnmodifiedServicesInformation(v MBMSUnmodifiedServicesInformation) MCCHMessageType {
	return MCCHMessageType{
		Choice:                            MCCHMessageTypeChoiceMbmsUnmodifiedServicesInformation,
		MbmsUnmodifiedServicesInformation: &v,
	}
}

// NewMCCHMessageTypeSpare9 creates a MCCHMessageType with the spare9 alternative.
func NewMCCHMessageTypeSpare9(v struct{}) MCCHMessageType {
	return MCCHMessageType{
		Choice: MCCHMessageTypeChoiceSpare9,
		Spare9: &v,
	}
}

// NewMCCHMessageTypeSpare8 creates a MCCHMessageType with the spare8 alternative.
func NewMCCHMessageTypeSpare8(v struct{}) MCCHMessageType {
	return MCCHMessageType{
		Choice: MCCHMessageTypeChoiceSpare8,
		Spare8: &v,
	}
}

// NewMCCHMessageTypeSpare7 creates a MCCHMessageType with the spare7 alternative.
func NewMCCHMessageTypeSpare7(v struct{}) MCCHMessageType {
	return MCCHMessageType{
		Choice: MCCHMessageTypeChoiceSpare7,
		Spare7: &v,
	}
}

// NewMCCHMessageTypeSpare6 creates a MCCHMessageType with the spare6 alternative.
func NewMCCHMessageTypeSpare6(v struct{}) MCCHMessageType {
	return MCCHMessageType{
		Choice: MCCHMessageTypeChoiceSpare6,
		Spare6: &v,
	}
}

// NewMCCHMessageTypeSpare5 creates a MCCHMessageType with the spare5 alternative.
func NewMCCHMessageTypeSpare5(v struct{}) MCCHMessageType {
	return MCCHMessageType{
		Choice: MCCHMessageTypeChoiceSpare5,
		Spare5: &v,
	}
}

// NewMCCHMessageTypeSpare4 creates a MCCHMessageType with the spare4 alternative.
func NewMCCHMessageTypeSpare4(v struct{}) MCCHMessageType {
	return MCCHMessageType{
		Choice: MCCHMessageTypeChoiceSpare4,
		Spare4: &v,
	}
}

// NewMCCHMessageTypeSpare3 creates a MCCHMessageType with the spare3 alternative.
func NewMCCHMessageTypeSpare3(v struct{}) MCCHMessageType {
	return MCCHMessageType{
		Choice: MCCHMessageTypeChoiceSpare3,
		Spare3: &v,
	}
}

// NewMCCHMessageTypeSpare2 creates a MCCHMessageType with the spare2 alternative.
func NewMCCHMessageTypeSpare2(v struct{}) MCCHMessageType {
	return MCCHMessageType{
		Choice: MCCHMessageTypeChoiceSpare2,
		Spare2: &v,
	}
}

// NewMCCHMessageTypeSpare1 creates a MCCHMessageType with the spare1 alternative.
func NewMCCHMessageTypeSpare1(v struct{}) MCCHMessageType {
	return MCCHMessageType{
		Choice: MCCHMessageTypeChoiceSpare1,
		Spare1: &v,
	}
}

// MSCHMessage represents the ASN.1 type MSCH-Message (SEQUENCE).
type MSCHMessage struct {
	Message              MSCHMessageType                `asn1:"tag:0,context,explicit"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// MSCHMessageType choice constants.
const (
	MSCHMessageTypeChoiceMbmsSchedulingInformation = 1
	MSCHMessageTypeChoiceSpare3                    = 2
	MSCHMessageTypeChoiceSpare2                    = 3
	MSCHMessageTypeChoiceSpare1                    = 4
)

// MSCHMessageType represents the ASN.1 CHOICE type MSCH-MessageType.
type MSCHMessageType struct {
	Choice                    int
	PERPadding_               per.CompletePadding        `json:"-"`
	PERExtraBits_             per.TrailingBits           `json:"-"`
	PEROpenTypePadding_       per.CompletePadding        `json:"-"`
	MbmsSchedulingInformation *MBMSSchedulingInformation `json:"MbmsSchedulingInformation,omitempty"`
	Spare3                    *struct{}                  `json:"Spare3,omitempty"`
	Spare2                    *struct{}                  `json:"Spare2,omitempty"`
	Spare1                    *struct{}                  `json:"Spare1,omitempty"`
}

// NewMSCHMessageTypeMbmsSchedulingInformation creates a MSCHMessageType with the mbmsSchedulingInformation alternative.
func NewMSCHMessageTypeMbmsSchedulingInformation(v MBMSSchedulingInformation) MSCHMessageType {
	return MSCHMessageType{
		Choice:                    MSCHMessageTypeChoiceMbmsSchedulingInformation,
		MbmsSchedulingInformation: &v,
	}
}

// NewMSCHMessageTypeSpare3 creates a MSCHMessageType with the spare3 alternative.
func NewMSCHMessageTypeSpare3(v struct{}) MSCHMessageType {
	return MSCHMessageType{
		Choice: MSCHMessageTypeChoiceSpare3,
		Spare3: &v,
	}
}

// NewMSCHMessageTypeSpare2 creates a MSCHMessageType with the spare2 alternative.
func NewMSCHMessageTypeSpare2(v struct{}) MSCHMessageType {
	return MSCHMessageType{
		Choice: MSCHMessageTypeChoiceSpare2,
		Spare2: &v,
	}
}

// NewMSCHMessageTypeSpare1 creates a MSCHMessageType with the spare1 alternative.
func NewMSCHMessageTypeSpare1(v struct{}) MSCHMessageType {
	return MSCHMessageType{
		Choice: MSCHMessageTypeChoiceSpare1,
		Spare1: &v,
	}
}

// MarshalUPER encodes DLDCCHMessage to UPER format.
func (v *DLDCCHMessage) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *DLDCCHMessage) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IntegrityCheckInfo != nil); err != nil {
		return err
	}
	if v.IntegrityCheckInfo != nil {
		if err := v.IntegrityCheckInfo.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding integrityCheckInfo: %w", err)
		}
	}
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes DLDCCHMessage from UPER format.
func (v *DLDCCHMessage) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes DLDCCHMessage with explicit receiver options.
func (v *DLDCCHMessage) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLDCCHMessage")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "DLDCCHMessage")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *DLDCCHMessage) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = DLDCCHMessage{}
	// Read preamble bitmap for optional root fields
	opt_integritycheckinfo, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_integritycheckinfo {
		var dec_integritycheckinfo IntegrityCheckInfo
		if err := dec_integritycheckinfo.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "IntegrityCheckInfo")
		}
		v.IntegrityCheckInfo = &dec_integritycheckinfo
	}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes DLDCCHMessageType to UPER format.
func (v *DLDCCHMessageType) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *DLDCCHMessageType) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("DLDCCHMessageType: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 31); err != nil {
		return err
	}
	switch v.Choice {
	case DLDCCHMessageTypeChoiceActiveSetUpdate:
		if v.ActiveSetUpdate == nil {
			return fmt.Errorf("choice alternative activeSetUpdate is nil")
		}
		if err := v.ActiveSetUpdate.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding activeSetUpdate: %w", err)
		}
	case DLDCCHMessageTypeChoiceAssistanceDataDelivery:
		if v.AssistanceDataDelivery == nil {
			return fmt.Errorf("choice alternative assistanceDataDelivery is nil")
		}
		if err := v.AssistanceDataDelivery.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding assistanceDataDelivery: %w", err)
		}
	case DLDCCHMessageTypeChoiceCellChangeOrderFromUTRAN:
		if v.CellChangeOrderFromUTRAN == nil {
			return fmt.Errorf("choice alternative cellChangeOrderFromUTRAN is nil")
		}
		if err := v.CellChangeOrderFromUTRAN.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding cellChangeOrderFromUTRAN: %w", err)
		}
	case DLDCCHMessageTypeChoiceCellUpdateConfirm:
		if v.CellUpdateConfirm == nil {
			return fmt.Errorf("choice alternative cellUpdateConfirm is nil")
		}
		if err := v.CellUpdateConfirm.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding cellUpdateConfirm: %w", err)
		}
	case DLDCCHMessageTypeChoiceCounterCheck:
		if v.CounterCheck == nil {
			return fmt.Errorf("choice alternative counterCheck is nil")
		}
		if err := v.CounterCheck.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding counterCheck: %w", err)
		}
	case DLDCCHMessageTypeChoiceDownlinkDirectTransfer:
		if v.DownlinkDirectTransfer == nil {
			return fmt.Errorf("choice alternative downlinkDirectTransfer is nil")
		}
		if err := v.DownlinkDirectTransfer.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding downlinkDirectTransfer: %w", err)
		}
	case DLDCCHMessageTypeChoiceHandoverFromUTRANCommandGSM:
		if v.HandoverFromUTRANCommandGSM == nil {
			return fmt.Errorf("choice alternative handoverFromUTRANCommand-GSM is nil")
		}
		if err := v.HandoverFromUTRANCommandGSM.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding handoverFromUTRANCommand-GSM: %w", err)
		}
	case DLDCCHMessageTypeChoiceHandoverFromUTRANCommandCDMA2000:
		if v.HandoverFromUTRANCommandCDMA2000 == nil {
			return fmt.Errorf("choice alternative handoverFromUTRANCommand-CDMA2000 is nil")
		}
		if err := v.HandoverFromUTRANCommandCDMA2000.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding handoverFromUTRANCommand-CDMA2000: %w", err)
		}
	case DLDCCHMessageTypeChoiceMeasurementControl:
		if v.MeasurementControl == nil {
			return fmt.Errorf("choice alternative measurementControl is nil")
		}
		if err := v.MeasurementControl.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding measurementControl: %w", err)
		}
	case DLDCCHMessageTypeChoicePagingType2:
		if v.PagingType2 == nil {
			return fmt.Errorf("choice alternative pagingType2 is nil")
		}
		if err := v.PagingType2.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding pagingType2: %w", err)
		}
	case DLDCCHMessageTypeChoicePhysicalChannelReconfiguration:
		if v.PhysicalChannelReconfiguration == nil {
			return fmt.Errorf("choice alternative physicalChannelReconfiguration is nil")
		}
		if err := v.PhysicalChannelReconfiguration.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding physicalChannelReconfiguration: %w", err)
		}
	case DLDCCHMessageTypeChoicePhysicalSharedChannelAllocation:
		if v.PhysicalSharedChannelAllocation == nil {
			return fmt.Errorf("choice alternative physicalSharedChannelAllocation is nil")
		}
		if err := v.PhysicalSharedChannelAllocation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding physicalSharedChannelAllocation: %w", err)
		}
	case DLDCCHMessageTypeChoiceRadioBearerReconfiguration:
		if v.RadioBearerReconfiguration == nil {
			return fmt.Errorf("choice alternative radioBearerReconfiguration is nil")
		}
		if err := v.RadioBearerReconfiguration.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioBearerReconfiguration: %w", err)
		}
	case DLDCCHMessageTypeChoiceRadioBearerRelease:
		if v.RadioBearerRelease == nil {
			return fmt.Errorf("choice alternative radioBearerRelease is nil")
		}
		if err := v.RadioBearerRelease.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioBearerRelease: %w", err)
		}
	case DLDCCHMessageTypeChoiceRadioBearerSetup:
		if v.RadioBearerSetup == nil {
			return fmt.Errorf("choice alternative radioBearerSetup is nil")
		}
		if err := v.RadioBearerSetup.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioBearerSetup: %w", err)
		}
	case DLDCCHMessageTypeChoiceRrcConnectionRelease:
		if v.RrcConnectionRelease == nil {
			return fmt.Errorf("choice alternative rrcConnectionRelease is nil")
		}
		if err := v.RrcConnectionRelease.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding rrcConnectionRelease: %w", err)
		}
	case DLDCCHMessageTypeChoiceSecurityModeCommand:
		if v.SecurityModeCommand == nil {
			return fmt.Errorf("choice alternative securityModeCommand is nil")
		}
		if err := v.SecurityModeCommand.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding securityModeCommand: %w", err)
		}
	case DLDCCHMessageTypeChoiceSignallingConnectionRelease:
		if v.SignallingConnectionRelease == nil {
			return fmt.Errorf("choice alternative signallingConnectionRelease is nil")
		}
		if err := v.SignallingConnectionRelease.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding signallingConnectionRelease: %w", err)
		}
	case DLDCCHMessageTypeChoiceTransportChannelReconfiguration:
		if v.TransportChannelReconfiguration == nil {
			return fmt.Errorf("choice alternative transportChannelReconfiguration is nil")
		}
		if err := v.TransportChannelReconfiguration.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding transportChannelReconfiguration: %w", err)
		}
	case DLDCCHMessageTypeChoiceTransportFormatCombinationControl:
		if v.TransportFormatCombinationControl == nil {
			return fmt.Errorf("choice alternative transportFormatCombinationControl is nil")
		}
		if err := v.TransportFormatCombinationControl.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding transportFormatCombinationControl: %w", err)
		}
	case DLDCCHMessageTypeChoiceUeCapabilityEnquiry:
		if v.UeCapabilityEnquiry == nil {
			return fmt.Errorf("choice alternative ueCapabilityEnquiry is nil")
		}
		if err := v.UeCapabilityEnquiry.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding ueCapabilityEnquiry: %w", err)
		}
	case DLDCCHMessageTypeChoiceUeCapabilityInformationConfirm:
		if v.UeCapabilityInformationConfirm == nil {
			return fmt.Errorf("choice alternative ueCapabilityInformationConfirm is nil")
		}
		if err := v.UeCapabilityInformationConfirm.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding ueCapabilityInformationConfirm: %w", err)
		}
	case DLDCCHMessageTypeChoiceUplinkPhysicalChannelControl:
		if v.UplinkPhysicalChannelControl == nil {
			return fmt.Errorf("choice alternative uplinkPhysicalChannelControl is nil")
		}
		if err := v.UplinkPhysicalChannelControl.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding uplinkPhysicalChannelControl: %w", err)
		}
	case DLDCCHMessageTypeChoiceUraUpdateConfirm:
		if v.UraUpdateConfirm == nil {
			return fmt.Errorf("choice alternative uraUpdateConfirm is nil")
		}
		if err := v.UraUpdateConfirm.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding uraUpdateConfirm: %w", err)
		}
	case DLDCCHMessageTypeChoiceUtranMobilityInformation:
		if v.UtranMobilityInformation == nil {
			return fmt.Errorf("choice alternative utranMobilityInformation is nil")
		}
		if err := v.UtranMobilityInformation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding utranMobilityInformation: %w", err)
		}
	case DLDCCHMessageTypeChoiceHandoverFromUTRANCommandGERANIu:
		if v.HandoverFromUTRANCommandGERANIu == nil {
			return fmt.Errorf("choice alternative handoverFromUTRANCommand-GERANIu is nil")
		}
		if err := v.HandoverFromUTRANCommandGERANIu.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding handoverFromUTRANCommand-GERANIu: %w", err)
		}
	case DLDCCHMessageTypeChoiceMbmsModifiedServicesInformation:
		if v.MbmsModifiedServicesInformation == nil {
			return fmt.Errorf("choice alternative mbmsModifiedServicesInformation is nil")
		}
		if err := v.MbmsModifiedServicesInformation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding mbmsModifiedServicesInformation: %w", err)
		}
	case DLDCCHMessageTypeChoiceEtwsPrimaryNotificationWithSecurity:
		if v.EtwsPrimaryNotificationWithSecurity == nil {
			return fmt.Errorf("choice alternative etwsPrimaryNotificationWithSecurity is nil")
		}
		if err := v.EtwsPrimaryNotificationWithSecurity.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding etwsPrimaryNotificationWithSecurity: %w", err)
		}
	case DLDCCHMessageTypeChoiceHandoverFromUTRANCommandEUTRA:
		if v.HandoverFromUTRANCommandEUTRA == nil {
			return fmt.Errorf("choice alternative handoverFromUTRANCommand-EUTRA is nil")
		}
		if err := v.HandoverFromUTRANCommandEUTRA.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding handoverFromUTRANCommand-EUTRA: %w", err)
		}
	case DLDCCHMessageTypeChoiceUeInformationRequest:
		if v.UeInformationRequest == nil {
			return fmt.Errorf("choice alternative ueInformationRequest is nil")
		}
		if err := v.UeInformationRequest.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding ueInformationRequest: %w", err)
		}
	case DLDCCHMessageTypeChoiceLoggingMeasurementConfiguration:
		if v.LoggingMeasurementConfiguration == nil {
			return fmt.Errorf("choice alternative loggingMeasurementConfiguration is nil")
		}
		if err := v.LoggingMeasurementConfiguration.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding loggingMeasurementConfiguration: %w", err)
		}
	case DLDCCHMessageTypeChoiceSpare1:
	default:
		return fmt.Errorf("unknown DLDCCHMessageType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes DLDCCHMessageType from UPER format.
func (v *DLDCCHMessageType) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes DLDCCHMessageType with explicit receiver options.
func (v *DLDCCHMessageType) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLDCCHMessageType")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "DLDCCHMessageType")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *DLDCCHMessageType) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = DLDCCHMessageType{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 31)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case DLDCCHMessageTypeChoiceActiveSetUpdate:
		var dec_activesetupdate ActiveSetUpdate
		if err := dec_activesetupdate.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "ActiveSetUpdate")
		}
		v.ActiveSetUpdate = &dec_activesetupdate
	case DLDCCHMessageTypeChoiceAssistanceDataDelivery:
		var dec_assistancedatadelivery AssistanceDataDelivery
		if err := dec_assistancedatadelivery.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AssistanceDataDelivery")
		}
		v.AssistanceDataDelivery = &dec_assistancedatadelivery
	case DLDCCHMessageTypeChoiceCellChangeOrderFromUTRAN:
		var dec_cellchangeorderfromutran CellChangeOrderFromUTRAN
		if err := dec_cellchangeorderfromutran.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CellChangeOrderFromUTRAN")
		}
		v.CellChangeOrderFromUTRAN = &dec_cellchangeorderfromutran
	case DLDCCHMessageTypeChoiceCellUpdateConfirm:
		var dec_cellupdateconfirm CellUpdateConfirm
		if err := dec_cellupdateconfirm.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CellUpdateConfirm")
		}
		v.CellUpdateConfirm = &dec_cellupdateconfirm
	case DLDCCHMessageTypeChoiceCounterCheck:
		var dec_countercheck CounterCheck
		if err := dec_countercheck.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CounterCheck")
		}
		v.CounterCheck = &dec_countercheck
	case DLDCCHMessageTypeChoiceDownlinkDirectTransfer:
		var dec_downlinkdirecttransfer DownlinkDirectTransfer
		if err := dec_downlinkdirecttransfer.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "DownlinkDirectTransfer")
		}
		v.DownlinkDirectTransfer = &dec_downlinkdirecttransfer
	case DLDCCHMessageTypeChoiceHandoverFromUTRANCommandGSM:
		var dec_handoverfromutrancommandgsm HandoverFromUTRANCommandGSM
		if err := dec_handoverfromutrancommandgsm.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "HandoverFromUTRANCommandGSM")
		}
		v.HandoverFromUTRANCommandGSM = &dec_handoverfromutrancommandgsm
	case DLDCCHMessageTypeChoiceHandoverFromUTRANCommandCDMA2000:
		var dec_handoverfromutrancommandcdma2000 HandoverFromUTRANCommandCDMA2000
		if err := dec_handoverfromutrancommandcdma2000.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "HandoverFromUTRANCommandCDMA2000")
		}
		v.HandoverFromUTRANCommandCDMA2000 = &dec_handoverfromutrancommandcdma2000
	case DLDCCHMessageTypeChoiceMeasurementControl:
		var dec_measurementcontrol MeasurementControl
		if err := dec_measurementcontrol.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MeasurementControl")
		}
		v.MeasurementControl = &dec_measurementcontrol
	case DLDCCHMessageTypeChoicePagingType2:
		var dec_pagingtype2 PagingType2
		if err := dec_pagingtype2.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PagingType2")
		}
		v.PagingType2 = &dec_pagingtype2
	case DLDCCHMessageTypeChoicePhysicalChannelReconfiguration:
		var dec_physicalchannelreconfiguration PhysicalChannelReconfiguration
		if err := dec_physicalchannelreconfiguration.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PhysicalChannelReconfiguration")
		}
		v.PhysicalChannelReconfiguration = &dec_physicalchannelreconfiguration
	case DLDCCHMessageTypeChoicePhysicalSharedChannelAllocation:
		var dec_physicalsharedchannelallocation PhysicalSharedChannelAllocation
		if err := dec_physicalsharedchannelallocation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PhysicalSharedChannelAllocation")
		}
		v.PhysicalSharedChannelAllocation = &dec_physicalsharedchannelallocation
	case DLDCCHMessageTypeChoiceRadioBearerReconfiguration:
		var dec_radiobearerreconfiguration RadioBearerReconfiguration
		if err := dec_radiobearerreconfiguration.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RadioBearerReconfiguration")
		}
		v.RadioBearerReconfiguration = &dec_radiobearerreconfiguration
	case DLDCCHMessageTypeChoiceRadioBearerRelease:
		var dec_radiobearerrelease RadioBearerRelease
		if err := dec_radiobearerrelease.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RadioBearerRelease")
		}
		v.RadioBearerRelease = &dec_radiobearerrelease
	case DLDCCHMessageTypeChoiceRadioBearerSetup:
		var dec_radiobearersetup RadioBearerSetup
		if err := dec_radiobearersetup.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RadioBearerSetup")
		}
		v.RadioBearerSetup = &dec_radiobearersetup
	case DLDCCHMessageTypeChoiceRrcConnectionRelease:
		var dec_rrcconnectionrelease RRCConnectionRelease
		if err := dec_rrcconnectionrelease.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RrcConnectionRelease")
		}
		v.RrcConnectionRelease = &dec_rrcconnectionrelease
	case DLDCCHMessageTypeChoiceSecurityModeCommand:
		var dec_securitymodecommand SecurityModeCommand
		if err := dec_securitymodecommand.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SecurityModeCommand")
		}
		v.SecurityModeCommand = &dec_securitymodecommand
	case DLDCCHMessageTypeChoiceSignallingConnectionRelease:
		var dec_signallingconnectionrelease SignallingConnectionRelease
		if err := dec_signallingconnectionrelease.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SignallingConnectionRelease")
		}
		v.SignallingConnectionRelease = &dec_signallingconnectionrelease
	case DLDCCHMessageTypeChoiceTransportChannelReconfiguration:
		var dec_transportchannelreconfiguration TransportChannelReconfiguration
		if err := dec_transportchannelreconfiguration.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TransportChannelReconfiguration")
		}
		v.TransportChannelReconfiguration = &dec_transportchannelreconfiguration
	case DLDCCHMessageTypeChoiceTransportFormatCombinationControl:
		var dec_transportformatcombinationcontrol TransportFormatCombinationControl
		if err := dec_transportformatcombinationcontrol.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TransportFormatCombinationControl")
		}
		v.TransportFormatCombinationControl = &dec_transportformatcombinationcontrol
	case DLDCCHMessageTypeChoiceUeCapabilityEnquiry:
		var dec_uecapabilityenquiry UECapabilityEnquiry
		if err := dec_uecapabilityenquiry.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UeCapabilityEnquiry")
		}
		v.UeCapabilityEnquiry = &dec_uecapabilityenquiry
	case DLDCCHMessageTypeChoiceUeCapabilityInformationConfirm:
		var dec_uecapabilityinformationconfirm UECapabilityInformationConfirm
		if err := dec_uecapabilityinformationconfirm.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UeCapabilityInformationConfirm")
		}
		v.UeCapabilityInformationConfirm = &dec_uecapabilityinformationconfirm
	case DLDCCHMessageTypeChoiceUplinkPhysicalChannelControl:
		var dec_uplinkphysicalchannelcontrol UplinkPhysicalChannelControl
		if err := dec_uplinkphysicalchannelcontrol.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UplinkPhysicalChannelControl")
		}
		v.UplinkPhysicalChannelControl = &dec_uplinkphysicalchannelcontrol
	case DLDCCHMessageTypeChoiceUraUpdateConfirm:
		var dec_uraupdateconfirm URAUpdateConfirm
		if err := dec_uraupdateconfirm.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UraUpdateConfirm")
		}
		v.UraUpdateConfirm = &dec_uraupdateconfirm
	case DLDCCHMessageTypeChoiceUtranMobilityInformation:
		var dec_utranmobilityinformation UTRANMobilityInformation
		if err := dec_utranmobilityinformation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UtranMobilityInformation")
		}
		v.UtranMobilityInformation = &dec_utranmobilityinformation
	case DLDCCHMessageTypeChoiceHandoverFromUTRANCommandGERANIu:
		var dec_handoverfromutrancommandgeraniu HandoverFromUTRANCommandGERANIu
		if err := dec_handoverfromutrancommandgeraniu.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "HandoverFromUTRANCommandGERANIu")
		}
		v.HandoverFromUTRANCommandGERANIu = &dec_handoverfromutrancommandgeraniu
	case DLDCCHMessageTypeChoiceMbmsModifiedServicesInformation:
		var dec_mbmsmodifiedservicesinformation MBMSModifiedServicesInformation
		if err := dec_mbmsmodifiedservicesinformation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MbmsModifiedServicesInformation")
		}
		v.MbmsModifiedServicesInformation = &dec_mbmsmodifiedservicesinformation
	case DLDCCHMessageTypeChoiceEtwsPrimaryNotificationWithSecurity:
		var dec_etwsprimarynotificationwithsecurity ETWSPrimaryNotificationWithSecurity
		if err := dec_etwsprimarynotificationwithsecurity.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "EtwsPrimaryNotificationWithSecurity")
		}
		v.EtwsPrimaryNotificationWithSecurity = &dec_etwsprimarynotificationwithsecurity
	case DLDCCHMessageTypeChoiceHandoverFromUTRANCommandEUTRA:
		var dec_handoverfromutrancommandeutra HandoverFromUTRANCommandEUTRA
		if err := dec_handoverfromutrancommandeutra.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "HandoverFromUTRANCommandEUTRA")
		}
		v.HandoverFromUTRANCommandEUTRA = &dec_handoverfromutrancommandeutra
	case DLDCCHMessageTypeChoiceUeInformationRequest:
		var dec_ueinformationrequest UEInformationRequest
		if err := dec_ueinformationrequest.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UeInformationRequest")
		}
		v.UeInformationRequest = &dec_ueinformationrequest
	case DLDCCHMessageTypeChoiceLoggingMeasurementConfiguration:
		var dec_loggingmeasurementconfiguration LoggingMeasurementConfiguration
		if err := dec_loggingmeasurementconfiguration.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "LoggingMeasurementConfiguration")
		}
		v.LoggingMeasurementConfiguration = &dec_loggingmeasurementconfiguration
	case DLDCCHMessageTypeChoiceSpare1:
		v.Spare1 = new(struct{})
	}
	return nil
}

// MarshalUPER encodes ULDCCHMessage to UPER format.
func (v *ULDCCHMessage) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *ULDCCHMessage) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IntegrityCheckInfo != nil); err != nil {
		return err
	}
	if v.IntegrityCheckInfo != nil {
		if err := v.IntegrityCheckInfo.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding integrityCheckInfo: %w", err)
		}
	}
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes ULDCCHMessage from UPER format.
func (v *ULDCCHMessage) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes ULDCCHMessage with explicit receiver options.
func (v *ULDCCHMessage) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULDCCHMessage")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULDCCHMessage")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *ULDCCHMessage) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ULDCCHMessage{}
	// Read preamble bitmap for optional root fields
	opt_integritycheckinfo, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_integritycheckinfo {
		var dec_integritycheckinfo IntegrityCheckInfo
		if err := dec_integritycheckinfo.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "IntegrityCheckInfo")
		}
		v.IntegrityCheckInfo = &dec_integritycheckinfo
	}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes ULDCCHMessageType to UPER format.
func (v *ULDCCHMessageType) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *ULDCCHMessageType) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("ULDCCHMessageType: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 31); err != nil {
		return err
	}
	switch v.Choice {
	case ULDCCHMessageTypeChoiceActiveSetUpdateComplete:
		if v.ActiveSetUpdateComplete == nil {
			return fmt.Errorf("choice alternative activeSetUpdateComplete is nil")
		}
		if err := v.ActiveSetUpdateComplete.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding activeSetUpdateComplete: %w", err)
		}
	case ULDCCHMessageTypeChoiceActiveSetUpdateFailure:
		if v.ActiveSetUpdateFailure == nil {
			return fmt.Errorf("choice alternative activeSetUpdateFailure is nil")
		}
		if err := v.ActiveSetUpdateFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding activeSetUpdateFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceCellChangeOrderFromUTRANFailure:
		if v.CellChangeOrderFromUTRANFailure == nil {
			return fmt.Errorf("choice alternative cellChangeOrderFromUTRANFailure is nil")
		}
		if err := v.CellChangeOrderFromUTRANFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding cellChangeOrderFromUTRANFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceCounterCheckResponse:
		if v.CounterCheckResponse == nil {
			return fmt.Errorf("choice alternative counterCheckResponse is nil")
		}
		if err := v.CounterCheckResponse.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding counterCheckResponse: %w", err)
		}
	case ULDCCHMessageTypeChoiceHandoverToUTRANComplete:
		if v.HandoverToUTRANComplete == nil {
			return fmt.Errorf("choice alternative handoverToUTRANComplete is nil")
		}
		if err := v.HandoverToUTRANComplete.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding handoverToUTRANComplete: %w", err)
		}
	case ULDCCHMessageTypeChoiceInitialDirectTransfer:
		if v.InitialDirectTransfer == nil {
			return fmt.Errorf("choice alternative initialDirectTransfer is nil")
		}
		if err := v.InitialDirectTransfer.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding initialDirectTransfer: %w", err)
		}
	case ULDCCHMessageTypeChoiceHandoverFromUTRANFailure:
		if v.HandoverFromUTRANFailure == nil {
			return fmt.Errorf("choice alternative handoverFromUTRANFailure is nil")
		}
		if err := v.HandoverFromUTRANFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding handoverFromUTRANFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceMeasurementControlFailure:
		if v.MeasurementControlFailure == nil {
			return fmt.Errorf("choice alternative measurementControlFailure is nil")
		}
		if err := v.MeasurementControlFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding measurementControlFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceMeasurementReport:
		if v.MeasurementReport == nil {
			return fmt.Errorf("choice alternative measurementReport is nil")
		}
		if err := v.MeasurementReport.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding measurementReport: %w", err)
		}
	case ULDCCHMessageTypeChoicePhysicalChannelReconfigurationComplete:
		if v.PhysicalChannelReconfigurationComplete == nil {
			return fmt.Errorf("choice alternative physicalChannelReconfigurationComplete is nil")
		}
		if err := v.PhysicalChannelReconfigurationComplete.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding physicalChannelReconfigurationComplete: %w", err)
		}
	case ULDCCHMessageTypeChoicePhysicalChannelReconfigurationFailure:
		if v.PhysicalChannelReconfigurationFailure == nil {
			return fmt.Errorf("choice alternative physicalChannelReconfigurationFailure is nil")
		}
		if err := v.PhysicalChannelReconfigurationFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding physicalChannelReconfigurationFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceRadioBearerReconfigurationComplete:
		if v.RadioBearerReconfigurationComplete == nil {
			return fmt.Errorf("choice alternative radioBearerReconfigurationComplete is nil")
		}
		if err := v.RadioBearerReconfigurationComplete.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioBearerReconfigurationComplete: %w", err)
		}
	case ULDCCHMessageTypeChoiceRadioBearerReconfigurationFailure:
		if v.RadioBearerReconfigurationFailure == nil {
			return fmt.Errorf("choice alternative radioBearerReconfigurationFailure is nil")
		}
		if err := v.RadioBearerReconfigurationFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioBearerReconfigurationFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceRadioBearerReleaseComplete:
		if v.RadioBearerReleaseComplete == nil {
			return fmt.Errorf("choice alternative radioBearerReleaseComplete is nil")
		}
		if err := v.RadioBearerReleaseComplete.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioBearerReleaseComplete: %w", err)
		}
	case ULDCCHMessageTypeChoiceRadioBearerReleaseFailure:
		if v.RadioBearerReleaseFailure == nil {
			return fmt.Errorf("choice alternative radioBearerReleaseFailure is nil")
		}
		if err := v.RadioBearerReleaseFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioBearerReleaseFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceRadioBearerSetupComplete:
		if v.RadioBearerSetupComplete == nil {
			return fmt.Errorf("choice alternative radioBearerSetupComplete is nil")
		}
		if err := v.RadioBearerSetupComplete.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioBearerSetupComplete: %w", err)
		}
	case ULDCCHMessageTypeChoiceRadioBearerSetupFailure:
		if v.RadioBearerSetupFailure == nil {
			return fmt.Errorf("choice alternative radioBearerSetupFailure is nil")
		}
		if err := v.RadioBearerSetupFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioBearerSetupFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceRrcConnectionReleaseComplete:
		if v.RrcConnectionReleaseComplete == nil {
			return fmt.Errorf("choice alternative rrcConnectionReleaseComplete is nil")
		}
		if err := v.RrcConnectionReleaseComplete.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding rrcConnectionReleaseComplete: %w", err)
		}
	case ULDCCHMessageTypeChoiceRrcConnectionSetupComplete:
		if v.RrcConnectionSetupComplete == nil {
			return fmt.Errorf("choice alternative rrcConnectionSetupComplete is nil")
		}
		if err := v.RrcConnectionSetupComplete.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding rrcConnectionSetupComplete: %w", err)
		}
	case ULDCCHMessageTypeChoiceRrcStatus:
		if v.RrcStatus == nil {
			return fmt.Errorf("choice alternative rrcStatus is nil")
		}
		if err := v.RrcStatus.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding rrcStatus: %w", err)
		}
	case ULDCCHMessageTypeChoiceSecurityModeComplete:
		if v.SecurityModeComplete == nil {
			return fmt.Errorf("choice alternative securityModeComplete is nil")
		}
		if err := v.SecurityModeComplete.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding securityModeComplete: %w", err)
		}
	case ULDCCHMessageTypeChoiceSecurityModeFailure:
		if v.SecurityModeFailure == nil {
			return fmt.Errorf("choice alternative securityModeFailure is nil")
		}
		if err := v.SecurityModeFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding securityModeFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceSignallingConnectionReleaseIndication:
		if v.SignallingConnectionReleaseIndication == nil {
			return fmt.Errorf("choice alternative signallingConnectionReleaseIndication is nil")
		}
		if err := v.SignallingConnectionReleaseIndication.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding signallingConnectionReleaseIndication: %w", err)
		}
	case ULDCCHMessageTypeChoiceTransportChannelReconfigurationComplete:
		if v.TransportChannelReconfigurationComplete == nil {
			return fmt.Errorf("choice alternative transportChannelReconfigurationComplete is nil")
		}
		if err := v.TransportChannelReconfigurationComplete.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding transportChannelReconfigurationComplete: %w", err)
		}
	case ULDCCHMessageTypeChoiceTransportChannelReconfigurationFailure:
		if v.TransportChannelReconfigurationFailure == nil {
			return fmt.Errorf("choice alternative transportChannelReconfigurationFailure is nil")
		}
		if err := v.TransportChannelReconfigurationFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding transportChannelReconfigurationFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceTransportFormatCombinationControlFailure:
		if v.TransportFormatCombinationControlFailure == nil {
			return fmt.Errorf("choice alternative transportFormatCombinationControlFailure is nil")
		}
		if err := v.TransportFormatCombinationControlFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding transportFormatCombinationControlFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceUeCapabilityInformation:
		if v.UeCapabilityInformation == nil {
			return fmt.Errorf("choice alternative ueCapabilityInformation is nil")
		}
		if err := v.UeCapabilityInformation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding ueCapabilityInformation: %w", err)
		}
	case ULDCCHMessageTypeChoiceUplinkDirectTransfer:
		if v.UplinkDirectTransfer == nil {
			return fmt.Errorf("choice alternative uplinkDirectTransfer is nil")
		}
		if err := v.UplinkDirectTransfer.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding uplinkDirectTransfer: %w", err)
		}
	case ULDCCHMessageTypeChoiceUtranMobilityInformationConfirm:
		if v.UtranMobilityInformationConfirm == nil {
			return fmt.Errorf("choice alternative utranMobilityInformationConfirm is nil")
		}
		if err := v.UtranMobilityInformationConfirm.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding utranMobilityInformationConfirm: %w", err)
		}
	case ULDCCHMessageTypeChoiceUtranMobilityInformationFailure:
		if v.UtranMobilityInformationFailure == nil {
			return fmt.Errorf("choice alternative utranMobilityInformationFailure is nil")
		}
		if err := v.UtranMobilityInformationFailure.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding utranMobilityInformationFailure: %w", err)
		}
	case ULDCCHMessageTypeChoiceMbmsModificationRequest:
		if v.MbmsModificationRequest == nil {
			return fmt.Errorf("choice alternative mbmsModificationRequest is nil")
		}
		if err := v.MbmsModificationRequest.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding mbmsModificationRequest: %w", err)
		}
	case ULDCCHMessageTypeChoiceUlDCCHMessageTypeExt:
		if v.UlDCCHMessageTypeExt == nil {
			return fmt.Errorf("choice alternative ul-DCCH-MessageType-ext is nil")
		}
		if err := v.UlDCCHMessageTypeExt.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding ul-DCCH-MessageType-ext: %w", err)
		}
	default:
		return fmt.Errorf("unknown ULDCCHMessageType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes ULDCCHMessageType from UPER format.
func (v *ULDCCHMessageType) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes ULDCCHMessageType with explicit receiver options.
func (v *ULDCCHMessageType) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULDCCHMessageType")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULDCCHMessageType")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *ULDCCHMessageType) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ULDCCHMessageType{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 31)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case ULDCCHMessageTypeChoiceActiveSetUpdateComplete:
		var dec_activesetupdatecomplete ActiveSetUpdateComplete
		if err := dec_activesetupdatecomplete.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "ActiveSetUpdateComplete")
		}
		v.ActiveSetUpdateComplete = &dec_activesetupdatecomplete
	case ULDCCHMessageTypeChoiceActiveSetUpdateFailure:
		var dec_activesetupdatefailure ActiveSetUpdateFailure
		if err := dec_activesetupdatefailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "ActiveSetUpdateFailure")
		}
		v.ActiveSetUpdateFailure = &dec_activesetupdatefailure
	case ULDCCHMessageTypeChoiceCellChangeOrderFromUTRANFailure:
		var dec_cellchangeorderfromutranfailure CellChangeOrderFromUTRANFailure
		if err := dec_cellchangeorderfromutranfailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CellChangeOrderFromUTRANFailure")
		}
		v.CellChangeOrderFromUTRANFailure = &dec_cellchangeorderfromutranfailure
	case ULDCCHMessageTypeChoiceCounterCheckResponse:
		var dec_countercheckresponse CounterCheckResponse
		if err := dec_countercheckresponse.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CounterCheckResponse")
		}
		v.CounterCheckResponse = &dec_countercheckresponse
	case ULDCCHMessageTypeChoiceHandoverToUTRANComplete:
		var dec_handovertoutrancomplete HandoverToUTRANComplete
		if err := dec_handovertoutrancomplete.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "HandoverToUTRANComplete")
		}
		v.HandoverToUTRANComplete = &dec_handovertoutrancomplete
	case ULDCCHMessageTypeChoiceInitialDirectTransfer:
		var dec_initialdirecttransfer InitialDirectTransfer
		if err := dec_initialdirecttransfer.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "InitialDirectTransfer")
		}
		v.InitialDirectTransfer = &dec_initialdirecttransfer
	case ULDCCHMessageTypeChoiceHandoverFromUTRANFailure:
		var dec_handoverfromutranfailure HandoverFromUTRANFailure
		if err := dec_handoverfromutranfailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "HandoverFromUTRANFailure")
		}
		v.HandoverFromUTRANFailure = &dec_handoverfromutranfailure
	case ULDCCHMessageTypeChoiceMeasurementControlFailure:
		var dec_measurementcontrolfailure MeasurementControlFailure
		if err := dec_measurementcontrolfailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MeasurementControlFailure")
		}
		v.MeasurementControlFailure = &dec_measurementcontrolfailure
	case ULDCCHMessageTypeChoiceMeasurementReport:
		var dec_measurementreport MeasurementReport
		if err := dec_measurementreport.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MeasurementReport")
		}
		v.MeasurementReport = &dec_measurementreport
	case ULDCCHMessageTypeChoicePhysicalChannelReconfigurationComplete:
		var dec_physicalchannelreconfigurationcomplete PhysicalChannelReconfigurationComplete
		if err := dec_physicalchannelreconfigurationcomplete.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PhysicalChannelReconfigurationComplete")
		}
		v.PhysicalChannelReconfigurationComplete = &dec_physicalchannelreconfigurationcomplete
	case ULDCCHMessageTypeChoicePhysicalChannelReconfigurationFailure:
		var dec_physicalchannelreconfigurationfailure PhysicalChannelReconfigurationFailure
		if err := dec_physicalchannelreconfigurationfailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PhysicalChannelReconfigurationFailure")
		}
		v.PhysicalChannelReconfigurationFailure = &dec_physicalchannelreconfigurationfailure
	case ULDCCHMessageTypeChoiceRadioBearerReconfigurationComplete:
		var dec_radiobearerreconfigurationcomplete RadioBearerReconfigurationComplete
		if err := dec_radiobearerreconfigurationcomplete.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RadioBearerReconfigurationComplete")
		}
		v.RadioBearerReconfigurationComplete = &dec_radiobearerreconfigurationcomplete
	case ULDCCHMessageTypeChoiceRadioBearerReconfigurationFailure:
		var dec_radiobearerreconfigurationfailure RadioBearerReconfigurationFailure
		if err := dec_radiobearerreconfigurationfailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RadioBearerReconfigurationFailure")
		}
		v.RadioBearerReconfigurationFailure = &dec_radiobearerreconfigurationfailure
	case ULDCCHMessageTypeChoiceRadioBearerReleaseComplete:
		var dec_radiobearerreleasecomplete RadioBearerReleaseComplete
		if err := dec_radiobearerreleasecomplete.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RadioBearerReleaseComplete")
		}
		v.RadioBearerReleaseComplete = &dec_radiobearerreleasecomplete
	case ULDCCHMessageTypeChoiceRadioBearerReleaseFailure:
		var dec_radiobearerreleasefailure RadioBearerReleaseFailure
		if err := dec_radiobearerreleasefailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RadioBearerReleaseFailure")
		}
		v.RadioBearerReleaseFailure = &dec_radiobearerreleasefailure
	case ULDCCHMessageTypeChoiceRadioBearerSetupComplete:
		var dec_radiobearersetupcomplete RadioBearerSetupComplete
		if err := dec_radiobearersetupcomplete.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RadioBearerSetupComplete")
		}
		v.RadioBearerSetupComplete = &dec_radiobearersetupcomplete
	case ULDCCHMessageTypeChoiceRadioBearerSetupFailure:
		var dec_radiobearersetupfailure RadioBearerSetupFailure
		if err := dec_radiobearersetupfailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RadioBearerSetupFailure")
		}
		v.RadioBearerSetupFailure = &dec_radiobearersetupfailure
	case ULDCCHMessageTypeChoiceRrcConnectionReleaseComplete:
		var dec_rrcconnectionreleasecomplete RRCConnectionReleaseComplete
		if err := dec_rrcconnectionreleasecomplete.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RrcConnectionReleaseComplete")
		}
		v.RrcConnectionReleaseComplete = &dec_rrcconnectionreleasecomplete
	case ULDCCHMessageTypeChoiceRrcConnectionSetupComplete:
		var dec_rrcconnectionsetupcomplete RRCConnectionSetupComplete
		if err := dec_rrcconnectionsetupcomplete.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RrcConnectionSetupComplete")
		}
		v.RrcConnectionSetupComplete = &dec_rrcconnectionsetupcomplete
	case ULDCCHMessageTypeChoiceRrcStatus:
		var dec_rrcstatus RRCStatus
		if err := dec_rrcstatus.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RrcStatus")
		}
		v.RrcStatus = &dec_rrcstatus
	case ULDCCHMessageTypeChoiceSecurityModeComplete:
		var dec_securitymodecomplete SecurityModeComplete
		if err := dec_securitymodecomplete.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SecurityModeComplete")
		}
		v.SecurityModeComplete = &dec_securitymodecomplete
	case ULDCCHMessageTypeChoiceSecurityModeFailure:
		var dec_securitymodefailure SecurityModeFailure
		if err := dec_securitymodefailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SecurityModeFailure")
		}
		v.SecurityModeFailure = &dec_securitymodefailure
	case ULDCCHMessageTypeChoiceSignallingConnectionReleaseIndication:
		var dec_signallingconnectionreleaseindication SignallingConnectionReleaseIndication
		if err := dec_signallingconnectionreleaseindication.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SignallingConnectionReleaseIndication")
		}
		v.SignallingConnectionReleaseIndication = &dec_signallingconnectionreleaseindication
	case ULDCCHMessageTypeChoiceTransportChannelReconfigurationComplete:
		var dec_transportchannelreconfigurationcomplete TransportChannelReconfigurationComplete
		if err := dec_transportchannelreconfigurationcomplete.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TransportChannelReconfigurationComplete")
		}
		v.TransportChannelReconfigurationComplete = &dec_transportchannelreconfigurationcomplete
	case ULDCCHMessageTypeChoiceTransportChannelReconfigurationFailure:
		var dec_transportchannelreconfigurationfailure TransportChannelReconfigurationFailure
		if err := dec_transportchannelreconfigurationfailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TransportChannelReconfigurationFailure")
		}
		v.TransportChannelReconfigurationFailure = &dec_transportchannelreconfigurationfailure
	case ULDCCHMessageTypeChoiceTransportFormatCombinationControlFailure:
		var dec_transportformatcombinationcontrolfailure TransportFormatCombinationControlFailure
		if err := dec_transportformatcombinationcontrolfailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TransportFormatCombinationControlFailure")
		}
		v.TransportFormatCombinationControlFailure = &dec_transportformatcombinationcontrolfailure
	case ULDCCHMessageTypeChoiceUeCapabilityInformation:
		var dec_uecapabilityinformation UECapabilityInformation
		if err := dec_uecapabilityinformation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UeCapabilityInformation")
		}
		v.UeCapabilityInformation = &dec_uecapabilityinformation
	case ULDCCHMessageTypeChoiceUplinkDirectTransfer:
		var dec_uplinkdirecttransfer UplinkDirectTransfer
		if err := dec_uplinkdirecttransfer.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UplinkDirectTransfer")
		}
		v.UplinkDirectTransfer = &dec_uplinkdirecttransfer
	case ULDCCHMessageTypeChoiceUtranMobilityInformationConfirm:
		var dec_utranmobilityinformationconfirm UTRANMobilityInformationConfirm
		if err := dec_utranmobilityinformationconfirm.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UtranMobilityInformationConfirm")
		}
		v.UtranMobilityInformationConfirm = &dec_utranmobilityinformationconfirm
	case ULDCCHMessageTypeChoiceUtranMobilityInformationFailure:
		var dec_utranmobilityinformationfailure UTRANMobilityInformationFailure
		if err := dec_utranmobilityinformationfailure.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UtranMobilityInformationFailure")
		}
		v.UtranMobilityInformationFailure = &dec_utranmobilityinformationfailure
	case ULDCCHMessageTypeChoiceMbmsModificationRequest:
		var dec_mbmsmodificationrequest MBMSModificationRequest
		if err := dec_mbmsmodificationrequest.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MbmsModificationRequest")
		}
		v.MbmsModificationRequest = &dec_mbmsmodificationrequest
	case ULDCCHMessageTypeChoiceUlDCCHMessageTypeExt:
		var dec_uldcchmessagetypeext ULDCCHMessageTypeExt
		if err := dec_uldcchmessagetypeext.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UlDCCHMessageTypeExt")
		}
		v.UlDCCHMessageTypeExt = &dec_uldcchmessagetypeext
	}
	return nil
}

// MarshalUPER encodes ULDCCHMessageTypeExt to UPER format.
func (v *ULDCCHMessageTypeExt) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *ULDCCHMessageTypeExt) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("ULDCCHMessageTypeExt: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 15); err != nil {
		return err
	}
	switch v.Choice {
	case ULDCCHMessageTypeExtChoiceUeInformationResponse:
		if v.UeInformationResponse == nil {
			return fmt.Errorf("choice alternative ueInformationResponse is nil")
		}
		if err := v.UeInformationResponse.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding ueInformationResponse: %w", err)
		}
	case ULDCCHMessageTypeExtChoiceSpare15:
	case ULDCCHMessageTypeExtChoiceSpare14:
	case ULDCCHMessageTypeExtChoiceSpare13:
	case ULDCCHMessageTypeExtChoiceSpare12:
	case ULDCCHMessageTypeExtChoiceSpare11:
	case ULDCCHMessageTypeExtChoiceSpare10:
	case ULDCCHMessageTypeExtChoiceSpare9:
	case ULDCCHMessageTypeExtChoiceSpare8:
	case ULDCCHMessageTypeExtChoiceSpare7:
	case ULDCCHMessageTypeExtChoiceSpare6:
	case ULDCCHMessageTypeExtChoiceSpare5:
	case ULDCCHMessageTypeExtChoiceSpare4:
	case ULDCCHMessageTypeExtChoiceSpare3:
	case ULDCCHMessageTypeExtChoiceSpare2:
	case ULDCCHMessageTypeExtChoiceSpare1:
	default:
		return fmt.Errorf("unknown ULDCCHMessageTypeExt choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes ULDCCHMessageTypeExt from UPER format.
func (v *ULDCCHMessageTypeExt) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes ULDCCHMessageTypeExt with explicit receiver options.
func (v *ULDCCHMessageTypeExt) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULDCCHMessageTypeExt")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULDCCHMessageTypeExt")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *ULDCCHMessageTypeExt) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ULDCCHMessageTypeExt{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 15)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case ULDCCHMessageTypeExtChoiceUeInformationResponse:
		var dec_ueinformationresponse UEInformationResponse
		if err := dec_ueinformationresponse.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UeInformationResponse")
		}
		v.UeInformationResponse = &dec_ueinformationresponse
	case ULDCCHMessageTypeExtChoiceSpare15:
		v.Spare15 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare14:
		v.Spare14 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare13:
		v.Spare13 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare12:
		v.Spare12 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare11:
		v.Spare11 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare10:
		v.Spare10 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare9:
		v.Spare9 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare8:
		v.Spare8 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare7:
		v.Spare7 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare6:
		v.Spare6 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare5:
		v.Spare5 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare4:
		v.Spare4 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare3:
		v.Spare3 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare2:
		v.Spare2 = new(struct{})
	case ULDCCHMessageTypeExtChoiceSpare1:
		v.Spare1 = new(struct{})
	}
	return nil
}

// MarshalUPER encodes DLCCCHMessage to UPER format.
func (v *DLCCCHMessage) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *DLCCCHMessage) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IntegrityCheckInfo != nil); err != nil {
		return err
	}
	if v.IntegrityCheckInfo != nil {
		if err := v.IntegrityCheckInfo.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding integrityCheckInfo: %w", err)
		}
	}
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes DLCCCHMessage from UPER format.
func (v *DLCCCHMessage) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes DLCCCHMessage with explicit receiver options.
func (v *DLCCCHMessage) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLCCCHMessage")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "DLCCCHMessage")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *DLCCCHMessage) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = DLCCCHMessage{}
	// Read preamble bitmap for optional root fields
	opt_integritycheckinfo, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_integritycheckinfo {
		var dec_integritycheckinfo IntegrityCheckInfo
		if err := dec_integritycheckinfo.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "IntegrityCheckInfo")
		}
		v.IntegrityCheckInfo = &dec_integritycheckinfo
	}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes DLCCCHMessageType to UPER format.
func (v *DLCCCHMessageType) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *DLCCCHMessageType) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("DLCCCHMessageType: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 7); err != nil {
		return err
	}
	switch v.Choice {
	case DLCCCHMessageTypeChoiceCellUpdateConfirm:
		if v.CellUpdateConfirm == nil {
			return fmt.Errorf("choice alternative cellUpdateConfirm is nil")
		}
		if err := v.CellUpdateConfirm.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding cellUpdateConfirm: %w", err)
		}
	case DLCCCHMessageTypeChoiceRrcConnectionReject:
		if v.RrcConnectionReject == nil {
			return fmt.Errorf("choice alternative rrcConnectionReject is nil")
		}
		if err := v.RrcConnectionReject.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding rrcConnectionReject: %w", err)
		}
	case DLCCCHMessageTypeChoiceRrcConnectionRelease:
		if v.RrcConnectionRelease == nil {
			return fmt.Errorf("choice alternative rrcConnectionRelease is nil")
		}
		if err := v.RrcConnectionRelease.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding rrcConnectionRelease: %w", err)
		}
	case DLCCCHMessageTypeChoiceRrcConnectionSetup:
		if v.RrcConnectionSetup == nil {
			return fmt.Errorf("choice alternative rrcConnectionSetup is nil")
		}
		if err := v.RrcConnectionSetup.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding rrcConnectionSetup: %w", err)
		}
	case DLCCCHMessageTypeChoiceUraUpdateConfirm:
		if v.UraUpdateConfirm == nil {
			return fmt.Errorf("choice alternative uraUpdateConfirm is nil")
		}
		if err := v.UraUpdateConfirm.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding uraUpdateConfirm: %w", err)
		}
	case DLCCCHMessageTypeChoiceDummy:
		if v.Dummy == nil {
			return fmt.Errorf("choice alternative dummy is nil")
		}
		if err := v.Dummy.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding dummy: %w", err)
		}
	case DLCCCHMessageTypeChoiceSpare2:
	case DLCCCHMessageTypeChoiceSpare1:
	default:
		return fmt.Errorf("unknown DLCCCHMessageType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes DLCCCHMessageType from UPER format.
func (v *DLCCCHMessageType) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes DLCCCHMessageType with explicit receiver options.
func (v *DLCCCHMessageType) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLCCCHMessageType")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "DLCCCHMessageType")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *DLCCCHMessageType) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = DLCCCHMessageType{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 7)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case DLCCCHMessageTypeChoiceCellUpdateConfirm:
		var dec_cellupdateconfirm CellUpdateConfirmCCCH
		if err := dec_cellupdateconfirm.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CellUpdateConfirm")
		}
		v.CellUpdateConfirm = &dec_cellupdateconfirm
	case DLCCCHMessageTypeChoiceRrcConnectionReject:
		var dec_rrcconnectionreject RRCConnectionReject
		if err := dec_rrcconnectionreject.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RrcConnectionReject")
		}
		v.RrcConnectionReject = &dec_rrcconnectionreject
	case DLCCCHMessageTypeChoiceRrcConnectionRelease:
		var dec_rrcconnectionrelease RRCConnectionReleaseCCCH
		if err := dec_rrcconnectionrelease.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RrcConnectionRelease")
		}
		v.RrcConnectionRelease = &dec_rrcconnectionrelease
	case DLCCCHMessageTypeChoiceRrcConnectionSetup:
		var dec_rrcconnectionsetup RRCConnectionSetup
		if err := dec_rrcconnectionsetup.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RrcConnectionSetup")
		}
		v.RrcConnectionSetup = &dec_rrcconnectionsetup
	case DLCCCHMessageTypeChoiceUraUpdateConfirm:
		var dec_uraupdateconfirm URAUpdateConfirmCCCH
		if err := dec_uraupdateconfirm.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UraUpdateConfirm")
		}
		v.UraUpdateConfirm = &dec_uraupdateconfirm
	case DLCCCHMessageTypeChoiceDummy:
		var dec_dummy ETWSPrimaryNotificationWithSecurity
		if err := dec_dummy.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "Dummy")
		}
		v.Dummy = &dec_dummy
	case DLCCCHMessageTypeChoiceSpare2:
		v.Spare2 = new(struct{})
	case DLCCCHMessageTypeChoiceSpare1:
		v.Spare1 = new(struct{})
	}
	return nil
}

// MarshalUPER encodes ULCCCHMessage to UPER format.
func (v *ULCCCHMessage) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *ULCCCHMessage) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IntegrityCheckInfo != nil); err != nil {
		return err
	}
	if v.IntegrityCheckInfo != nil {
		if err := v.IntegrityCheckInfo.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding integrityCheckInfo: %w", err)
		}
	}
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes ULCCCHMessage from UPER format.
func (v *ULCCCHMessage) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes ULCCCHMessage with explicit receiver options.
func (v *ULCCCHMessage) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULCCCHMessage")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULCCCHMessage")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *ULCCCHMessage) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ULCCCHMessage{}
	// Read preamble bitmap for optional root fields
	opt_integritycheckinfo, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_integritycheckinfo {
		var dec_integritycheckinfo IntegrityCheckInfo
		if err := dec_integritycheckinfo.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "IntegrityCheckInfo")
		}
		v.IntegrityCheckInfo = &dec_integritycheckinfo
	}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes ULCCCHMessageType to UPER format.
func (v *ULCCCHMessageType) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *ULCCCHMessageType) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("ULCCCHMessageType: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case ULCCCHMessageTypeChoiceCellUpdate:
		if v.CellUpdate == nil {
			return fmt.Errorf("choice alternative cellUpdate is nil")
		}
		if err := v.CellUpdate.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding cellUpdate: %w", err)
		}
	case ULCCCHMessageTypeChoiceRrcConnectionRequest:
		if v.RrcConnectionRequest == nil {
			return fmt.Errorf("choice alternative rrcConnectionRequest is nil")
		}
		if err := v.RrcConnectionRequest.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding rrcConnectionRequest: %w", err)
		}
	case ULCCCHMessageTypeChoiceUraUpdate:
		if v.UraUpdate == nil {
			return fmt.Errorf("choice alternative uraUpdate is nil")
		}
		if err := v.UraUpdate.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding uraUpdate: %w", err)
		}
	case ULCCCHMessageTypeChoiceULCCCHMessageTypeR11:
		if v.ULCCCHMessageTypeR11 == nil {
			return fmt.Errorf("choice alternative uL-CCCH-MessageType-r11 is nil")
		}
		if err := v.ULCCCHMessageTypeR11.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding uL-CCCH-MessageType-r11: %w", err)
		}
	default:
		return fmt.Errorf("unknown ULCCCHMessageType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes ULCCCHMessageType from UPER format.
func (v *ULCCCHMessageType) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes ULCCCHMessageType with explicit receiver options.
func (v *ULCCCHMessageType) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULCCCHMessageType")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULCCCHMessageType")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *ULCCCHMessageType) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ULCCCHMessageType{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 3)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case ULCCCHMessageTypeChoiceCellUpdate:
		var dec_cellupdate CellUpdate
		if err := dec_cellupdate.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CellUpdate")
		}
		v.CellUpdate = &dec_cellupdate
	case ULCCCHMessageTypeChoiceRrcConnectionRequest:
		var dec_rrcconnectionrequest RRCConnectionRequest
		if err := dec_rrcconnectionrequest.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RrcConnectionRequest")
		}
		v.RrcConnectionRequest = &dec_rrcconnectionrequest
	case ULCCCHMessageTypeChoiceUraUpdate:
		var dec_uraupdate URAUpdate
		if err := dec_uraupdate.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UraUpdate")
		}
		v.UraUpdate = &dec_uraupdate
	case ULCCCHMessageTypeChoiceULCCCHMessageTypeR11:
		var dec_ulccchmessagetyper11 ULCCCHMessageTypeR11
		if err := dec_ulccchmessagetyper11.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "ULCCCHMessageTypeR11")
		}
		v.ULCCCHMessageTypeR11 = &dec_ulccchmessagetyper11
	}
	return nil
}

// MarshalUPER encodes ULCCCHMessageTypeR11 to UPER format.
func (v *ULCCCHMessageTypeR11) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *ULCCCHMessageTypeR11) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("ULCCCHMessageTypeR11: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case ULCCCHMessageTypeR11ChoiceCellUpdate:
		if v.CellUpdate == nil {
			return fmt.Errorf("choice alternative cellUpdate is nil")
		}
		if err := v.CellUpdate.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding cellUpdate: %w", err)
		}
	case ULCCCHMessageTypeR11ChoiceSpare3:
	case ULCCCHMessageTypeR11ChoiceSpare2:
	case ULCCCHMessageTypeR11ChoiceSpare1:
	default:
		return fmt.Errorf("unknown ULCCCHMessageTypeR11 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes ULCCCHMessageTypeR11 from UPER format.
func (v *ULCCCHMessageTypeR11) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes ULCCCHMessageTypeR11 with explicit receiver options.
func (v *ULCCCHMessageTypeR11) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULCCCHMessageTypeR11")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULCCCHMessageTypeR11")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *ULCCCHMessageTypeR11) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ULCCCHMessageTypeR11{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 3)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case ULCCCHMessageTypeR11ChoiceCellUpdate:
		var dec_cellupdate CellUpdateFDDR11
		if err := dec_cellupdate.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CellUpdate")
		}
		v.CellUpdate = &dec_cellupdate
	case ULCCCHMessageTypeR11ChoiceSpare3:
		v.Spare3 = new(struct{})
	case ULCCCHMessageTypeR11ChoiceSpare2:
		v.Spare2 = new(struct{})
	case ULCCCHMessageTypeR11ChoiceSpare1:
		v.Spare1 = new(struct{})
	}
	return nil
}

// MarshalUPER encodes PCCHMessage to UPER format.
func (v *PCCHMessage) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *PCCHMessage) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes PCCHMessage from UPER format.
func (v *PCCHMessage) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes PCCHMessage with explicit receiver options.
func (v *PCCHMessage) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PCCHMessage")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PCCHMessage")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *PCCHMessage) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = PCCHMessage{}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes PCCHMessageType to UPER format.
func (v *PCCHMessageType) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *PCCHMessageType) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("PCCHMessageType: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case PCCHMessageTypeChoicePagingType1:
		if v.PagingType1 == nil {
			return fmt.Errorf("choice alternative pagingType1 is nil")
		}
		if err := v.PagingType1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding pagingType1: %w", err)
		}
	case PCCHMessageTypeChoiceSpare:
	default:
		return fmt.Errorf("unknown PCCHMessageType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes PCCHMessageType from UPER format.
func (v *PCCHMessageType) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes PCCHMessageType with explicit receiver options.
func (v *PCCHMessageType) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PCCHMessageType")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PCCHMessageType")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *PCCHMessageType) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = PCCHMessageType{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case PCCHMessageTypeChoicePagingType1:
		var dec_pagingtype1 PagingType1
		if err := dec_pagingtype1.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PagingType1")
		}
		v.PagingType1 = &dec_pagingtype1
	case PCCHMessageTypeChoiceSpare:
		v.Spare = new(struct{})
	}
	return nil
}

// MarshalUPER encodes DLSHCCHMessage to UPER format.
func (v *DLSHCCHMessage) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *DLSHCCHMessage) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes DLSHCCHMessage from UPER format.
func (v *DLSHCCHMessage) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes DLSHCCHMessage with explicit receiver options.
func (v *DLSHCCHMessage) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLSHCCHMessage")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "DLSHCCHMessage")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *DLSHCCHMessage) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = DLSHCCHMessage{}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes DLSHCCHMessageType to UPER format.
func (v *DLSHCCHMessageType) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *DLSHCCHMessageType) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("DLSHCCHMessageType: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case DLSHCCHMessageTypeChoicePhysicalSharedChannelAllocation:
		if v.PhysicalSharedChannelAllocation == nil {
			return fmt.Errorf("choice alternative physicalSharedChannelAllocation is nil")
		}
		if err := v.PhysicalSharedChannelAllocation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding physicalSharedChannelAllocation: %w", err)
		}
	case DLSHCCHMessageTypeChoiceSpare:
	default:
		return fmt.Errorf("unknown DLSHCCHMessageType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes DLSHCCHMessageType from UPER format.
func (v *DLSHCCHMessageType) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes DLSHCCHMessageType with explicit receiver options.
func (v *DLSHCCHMessageType) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLSHCCHMessageType")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "DLSHCCHMessageType")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *DLSHCCHMessageType) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = DLSHCCHMessageType{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case DLSHCCHMessageTypeChoicePhysicalSharedChannelAllocation:
		var dec_physicalsharedchannelallocation PhysicalSharedChannelAllocation
		if err := dec_physicalsharedchannelallocation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PhysicalSharedChannelAllocation")
		}
		v.PhysicalSharedChannelAllocation = &dec_physicalsharedchannelallocation
	case DLSHCCHMessageTypeChoiceSpare:
		v.Spare = new(struct{})
	}
	return nil
}

// MarshalUPER encodes ULSHCCHMessage to UPER format.
func (v *ULSHCCHMessage) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *ULSHCCHMessage) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes ULSHCCHMessage from UPER format.
func (v *ULSHCCHMessage) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes ULSHCCHMessage with explicit receiver options.
func (v *ULSHCCHMessage) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULSHCCHMessage")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULSHCCHMessage")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *ULSHCCHMessage) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ULSHCCHMessage{}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes ULSHCCHMessageType to UPER format.
func (v *ULSHCCHMessageType) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *ULSHCCHMessageType) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("ULSHCCHMessageType: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case ULSHCCHMessageTypeChoicePuschCapacityRequest:
		if v.PuschCapacityRequest == nil {
			return fmt.Errorf("choice alternative puschCapacityRequest is nil")
		}
		if err := v.PuschCapacityRequest.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding puschCapacityRequest: %w", err)
		}
	case ULSHCCHMessageTypeChoiceSpare:
	default:
		return fmt.Errorf("unknown ULSHCCHMessageType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes ULSHCCHMessageType from UPER format.
func (v *ULSHCCHMessageType) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes ULSHCCHMessageType with explicit receiver options.
func (v *ULSHCCHMessageType) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULSHCCHMessageType")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULSHCCHMessageType")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *ULSHCCHMessageType) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ULSHCCHMessageType{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case ULSHCCHMessageTypeChoicePuschCapacityRequest:
		var dec_puschcapacityrequest PUSCHCapacityRequest
		if err := dec_puschcapacityrequest.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PuschCapacityRequest")
		}
		v.PuschCapacityRequest = &dec_puschcapacityrequest
	case ULSHCCHMessageTypeChoiceSpare:
		v.Spare = new(struct{})
	}
	return nil
}

// MarshalUPER encodes BCCHFACHMessage to UPER format.
func (v *BCCHFACHMessage) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *BCCHFACHMessage) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes BCCHFACHMessage from UPER format.
func (v *BCCHFACHMessage) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes BCCHFACHMessage with explicit receiver options.
func (v *BCCHFACHMessage) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BCCHFACHMessage")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BCCHFACHMessage")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *BCCHFACHMessage) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = BCCHFACHMessage{}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes BCCHFACHMessageType to UPER format.
func (v *BCCHFACHMessageType) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *BCCHFACHMessageType) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("BCCHFACHMessageType: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case BCCHFACHMessageTypeChoiceDummy:
		if v.Dummy == nil {
			return fmt.Errorf("choice alternative dummy is nil")
		}
		if err := v.Dummy.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding dummy: %w", err)
		}
	case BCCHFACHMessageTypeChoiceSystemInformationChangeIndication:
		if v.SystemInformationChangeIndication == nil {
			return fmt.Errorf("choice alternative systemInformationChangeIndication is nil")
		}
		if err := v.SystemInformationChangeIndication.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding systemInformationChangeIndication: %w", err)
		}
	case BCCHFACHMessageTypeChoiceSpare2:
	case BCCHFACHMessageTypeChoiceSpare1:
	default:
		return fmt.Errorf("unknown BCCHFACHMessageType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes BCCHFACHMessageType from UPER format.
func (v *BCCHFACHMessageType) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes BCCHFACHMessageType with explicit receiver options.
func (v *BCCHFACHMessageType) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BCCHFACHMessageType")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BCCHFACHMessageType")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *BCCHFACHMessageType) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = BCCHFACHMessageType{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 3)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case BCCHFACHMessageTypeChoiceDummy:
		var dec_dummy SystemInformationFACH
		if err := dec_dummy.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "Dummy")
		}
		v.Dummy = &dec_dummy
	case BCCHFACHMessageTypeChoiceSystemInformationChangeIndication:
		var dec_systeminformationchangeindication SystemInformationChangeIndication
		if err := dec_systeminformationchangeindication.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SystemInformationChangeIndication")
		}
		v.SystemInformationChangeIndication = &dec_systeminformationchangeindication
	case BCCHFACHMessageTypeChoiceSpare2:
		v.Spare2 = new(struct{})
	case BCCHFACHMessageTypeChoiceSpare1:
		v.Spare1 = new(struct{})
	}
	return nil
}

// MarshalUPER encodes BCCHBCHMessage to UPER format.
func (v *BCCHBCHMessage) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *BCCHBCHMessage) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes BCCHBCHMessage from UPER format.
func (v *BCCHBCHMessage) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes BCCHBCHMessage with explicit receiver options.
func (v *BCCHBCHMessage) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BCCHBCHMessage")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BCCHBCHMessage")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *BCCHBCHMessage) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = BCCHBCHMessage{}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes BCCHBCH2Message to UPER format.
func (v *BCCHBCH2Message) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *BCCHBCH2Message) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes BCCHBCH2Message from UPER format.
func (v *BCCHBCH2Message) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes BCCHBCH2Message with explicit receiver options.
func (v *BCCHBCH2Message) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BCCHBCH2Message")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BCCHBCH2Message")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *BCCHBCH2Message) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = BCCHBCH2Message{}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes MCCHMessage to UPER format.
func (v *MCCHMessage) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *MCCHMessage) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes MCCHMessage from UPER format.
func (v *MCCHMessage) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes MCCHMessage with explicit receiver options.
func (v *MCCHMessage) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MCCHMessage")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MCCHMessage")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *MCCHMessage) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = MCCHMessage{}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes MCCHMessageType to UPER format.
func (v *MCCHMessageType) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *MCCHMessageType) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("MCCHMessageType: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 15); err != nil {
		return err
	}
	switch v.Choice {
	case MCCHMessageTypeChoiceMbmsAccessInformation:
		if v.MbmsAccessInformation == nil {
			return fmt.Errorf("choice alternative mbmsAccessInformation is nil")
		}
		if err := v.MbmsAccessInformation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding mbmsAccessInformation: %w", err)
		}
	case MCCHMessageTypeChoiceMbmsCommonPTMRBInformation:
		if v.MbmsCommonPTMRBInformation == nil {
			return fmt.Errorf("choice alternative mbmsCommonPTMRBInformation is nil")
		}
		if err := v.MbmsCommonPTMRBInformation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding mbmsCommonPTMRBInformation: %w", err)
		}
	case MCCHMessageTypeChoiceMbmsCurrentCellPTMRBInformation:
		if v.MbmsCurrentCellPTMRBInformation == nil {
			return fmt.Errorf("choice alternative mbmsCurrentCellPTMRBInformation is nil")
		}
		if err := v.MbmsCurrentCellPTMRBInformation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding mbmsCurrentCellPTMRBInformation: %w", err)
		}
	case MCCHMessageTypeChoiceMbmsGeneralInformation:
		if v.MbmsGeneralInformation == nil {
			return fmt.Errorf("choice alternative mbmsGeneralInformation is nil")
		}
		if err := v.MbmsGeneralInformation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding mbmsGeneralInformation: %w", err)
		}
	case MCCHMessageTypeChoiceMbmsModifiedServicesInformation:
		if v.MbmsModifiedServicesInformation == nil {
			return fmt.Errorf("choice alternative mbmsModifiedServicesInformation is nil")
		}
		if err := v.MbmsModifiedServicesInformation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding mbmsModifiedServicesInformation: %w", err)
		}
	case MCCHMessageTypeChoiceMbmsNeighbouringCellPTMRBInformation:
		if v.MbmsNeighbouringCellPTMRBInformation == nil {
			return fmt.Errorf("choice alternative mbmsNeighbouringCellPTMRBInformation is nil")
		}
		if err := v.MbmsNeighbouringCellPTMRBInformation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding mbmsNeighbouringCellPTMRBInformation: %w", err)
		}
	case MCCHMessageTypeChoiceMbmsUnmodifiedServicesInformation:
		if v.MbmsUnmodifiedServicesInformation == nil {
			return fmt.Errorf("choice alternative mbmsUnmodifiedServicesInformation is nil")
		}
		if err := v.MbmsUnmodifiedServicesInformation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding mbmsUnmodifiedServicesInformation: %w", err)
		}
	case MCCHMessageTypeChoiceSpare9:
	case MCCHMessageTypeChoiceSpare8:
	case MCCHMessageTypeChoiceSpare7:
	case MCCHMessageTypeChoiceSpare6:
	case MCCHMessageTypeChoiceSpare5:
	case MCCHMessageTypeChoiceSpare4:
	case MCCHMessageTypeChoiceSpare3:
	case MCCHMessageTypeChoiceSpare2:
	case MCCHMessageTypeChoiceSpare1:
	default:
		return fmt.Errorf("unknown MCCHMessageType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes MCCHMessageType from UPER format.
func (v *MCCHMessageType) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes MCCHMessageType with explicit receiver options.
func (v *MCCHMessageType) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MCCHMessageType")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MCCHMessageType")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *MCCHMessageType) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = MCCHMessageType{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 15)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case MCCHMessageTypeChoiceMbmsAccessInformation:
		var dec_mbmsaccessinformation MBMSAccessInformation
		if err := dec_mbmsaccessinformation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MbmsAccessInformation")
		}
		v.MbmsAccessInformation = &dec_mbmsaccessinformation
	case MCCHMessageTypeChoiceMbmsCommonPTMRBInformation:
		var dec_mbmscommonptmrbinformation MBMSCommonPTMRBInformation
		if err := dec_mbmscommonptmrbinformation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MbmsCommonPTMRBInformation")
		}
		v.MbmsCommonPTMRBInformation = &dec_mbmscommonptmrbinformation
	case MCCHMessageTypeChoiceMbmsCurrentCellPTMRBInformation:
		var dec_mbmscurrentcellptmrbinformation MBMSCurrentCellPTMRBInformation
		if err := dec_mbmscurrentcellptmrbinformation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MbmsCurrentCellPTMRBInformation")
		}
		v.MbmsCurrentCellPTMRBInformation = &dec_mbmscurrentcellptmrbinformation
	case MCCHMessageTypeChoiceMbmsGeneralInformation:
		var dec_mbmsgeneralinformation MBMSGeneralInformation
		if err := dec_mbmsgeneralinformation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MbmsGeneralInformation")
		}
		v.MbmsGeneralInformation = &dec_mbmsgeneralinformation
	case MCCHMessageTypeChoiceMbmsModifiedServicesInformation:
		var dec_mbmsmodifiedservicesinformation MBMSModifiedServicesInformation
		if err := dec_mbmsmodifiedservicesinformation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MbmsModifiedServicesInformation")
		}
		v.MbmsModifiedServicesInformation = &dec_mbmsmodifiedservicesinformation
	case MCCHMessageTypeChoiceMbmsNeighbouringCellPTMRBInformation:
		var dec_mbmsneighbouringcellptmrbinformation MBMSNeighbouringCellPTMRBInformation
		if err := dec_mbmsneighbouringcellptmrbinformation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MbmsNeighbouringCellPTMRBInformation")
		}
		v.MbmsNeighbouringCellPTMRBInformation = &dec_mbmsneighbouringcellptmrbinformation
	case MCCHMessageTypeChoiceMbmsUnmodifiedServicesInformation:
		var dec_mbmsunmodifiedservicesinformation MBMSUnmodifiedServicesInformation
		if err := dec_mbmsunmodifiedservicesinformation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MbmsUnmodifiedServicesInformation")
		}
		v.MbmsUnmodifiedServicesInformation = &dec_mbmsunmodifiedservicesinformation
	case MCCHMessageTypeChoiceSpare9:
		v.Spare9 = new(struct{})
	case MCCHMessageTypeChoiceSpare8:
		v.Spare8 = new(struct{})
	case MCCHMessageTypeChoiceSpare7:
		v.Spare7 = new(struct{})
	case MCCHMessageTypeChoiceSpare6:
		v.Spare6 = new(struct{})
	case MCCHMessageTypeChoiceSpare5:
		v.Spare5 = new(struct{})
	case MCCHMessageTypeChoiceSpare4:
		v.Spare4 = new(struct{})
	case MCCHMessageTypeChoiceSpare3:
		v.Spare3 = new(struct{})
	case MCCHMessageTypeChoiceSpare2:
		v.Spare2 = new(struct{})
	case MCCHMessageTypeChoiceSpare1:
		v.Spare1 = new(struct{})
	}
	return nil
}

// MarshalUPER encodes MSCHMessage to UPER format.
func (v *MSCHMessage) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *MSCHMessage) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.Message.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes MSCHMessage from UPER format.
func (v *MSCHMessage) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes MSCHMessage with explicit receiver options.
func (v *MSCHMessage) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MSCHMessage")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MSCHMessage")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *MSCHMessage) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = MSCHMessage{}
	if err := v.Message.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Message")
	}
	return nil
}

// MarshalUPER encodes MSCHMessageType to UPER format.
func (v *MSCHMessageType) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithTrailing(v.PERPadding_, v.PERExtraBits_)
}

func (v *MSCHMessageType) MarshalUPERTo(bb *per.BitBuffer) error {
	if v.Choice < 1 {
		return fmt.Errorf("MSCHMessageType: choice %d must be positive", v.Choice)
	}
	// arithmetic pattern UPER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_uper.go:152
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case MSCHMessageTypeChoiceMbmsSchedulingInformation:
		if v.MbmsSchedulingInformation == nil {
			return fmt.Errorf("choice alternative mbmsSchedulingInformation is nil")
		}
		if err := v.MbmsSchedulingInformation.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding mbmsSchedulingInformation: %w", err)
		}
	case MSCHMessageTypeChoiceSpare3:
	case MSCHMessageTypeChoiceSpare2:
	case MSCHMessageTypeChoiceSpare1:
	default:
		return fmt.Errorf("unknown MSCHMessageType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes MSCHMessageType from UPER format.
func (v *MSCHMessageType) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes MSCHMessageType with explicit receiver options.
func (v *MSCHMessageType) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MSCHMessageType")
	}
	padding, extra, err := per.CaptureFinalPaddingWithOptions(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MSCHMessageType")
	}
	v.PERPadding_, v.PERExtraBits_ = padding, extra
	return nil
}

func (v *MSCHMessageType) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = MSCHMessageType{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 3)
	if err != nil {
		return err
	}
	// arithmetic pattern UPER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_uper.go:241
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case MSCHMessageTypeChoiceMbmsSchedulingInformation:
		var dec_mbmsschedulinginformation MBMSSchedulingInformation
		if err := dec_mbmsschedulinginformation.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "MbmsSchedulingInformation")
		}
		v.MbmsSchedulingInformation = &dec_mbmsschedulinginformation
	case MSCHMessageTypeChoiceSpare3:
		v.Spare3 = new(struct{})
	case MSCHMessageTypeChoiceSpare2:
		v.Spare2 = new(struct{})
	case MSCHMessageTypeChoiceSpare1:
		v.Spare1 = new(struct{})
	}
	return nil
}
