// Code generated from ASN.1. DO NOT EDIT.

package bindings

import (
	mapvalues "github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

func pointerValueCodec[T any](decode func([]byte, ...ber.DecodeOption) (*T, error), encode func(*T, ...ber.EncodeOption) ([]byte, error), der func(*T) ([]byte, error)) mapvalues.ValueCodec[T] {
	return mapvalues.NewValueCodec(
		func(data []byte, opts ...ber.DecodeOption) (T, error) {
			v, err := decode(data, opts...)
			if err != nil {
				var zero T
				return zero, err
			}
			return *v, nil
		},
		func(v T, opts ...ber.EncodeOption) ([]byte, error) { return encode(&v, opts...) },
		func(v T) ([]byte, error) { return der(&v) },
	)
}

type compositeCodecPointer[T any] interface {
	*T
	UnmarshalBER([]byte, ...ber.DecodeOption) error
	MarshalBER(...ber.EncodeOption) ([]byte, error)
	MarshalDER() ([]byte, error)
}

func compositeValueCodec[T any, P compositeCodecPointer[T]]() mapvalues.ValueCodec[T] {
	return mapvalues.NewValueCodec(
		func(data []byte, opts ...ber.DecodeOption) (T, error) {
			var v T
			if err := P(&v).UnmarshalBER(data, opts...); err != nil {
				var zero T
				return zero, err
			}
			return v, nil
		},
		func(v T, opts ...ber.EncodeOption) ([]byte, error) { return P(&v).MarshalBER(opts...) },
		func(v T) ([]byte, error) { return P(&v).MarshalDER() },
	)
}

// ExtensionContainerCodec binds MAP-ExtensionDataTypes.ExtensionContainer.
func ExtensionContainerCodec() mapvalues.ValueCodec[mapvalues.ExtensionContainer] {
	return compositeValueCodec[mapvalues.ExtensionContainer, *mapvalues.ExtensionContainer]()
}

// SLRArgExtensionContainerCodec binds MAP-ExtensionDataTypes.SLR-ArgExtensionContainer.
func SLRArgExtensionContainerCodec() mapvalues.ValueCodec[mapvalues.SLRArgExtensionContainer] {
	return compositeValueCodec[mapvalues.SLRArgExtensionContainer, *mapvalues.SLRArgExtensionContainer]()
}

// PrivateExtensionListCodec binds MAP-ExtensionDataTypes.PrivateExtensionList.
func PrivateExtensionListCodec() mapvalues.ValueCodec[mapvalues.PrivateExtensionList] {
	return pointerValueCodec(mapvalues.UnmarshalBERPrivateExtensionList, mapvalues.MarshalBERPrivateExtensionList, mapvalues.MarshalDERPrivateExtensionList)
}

// PrivateExtensionCodec binds MAP-ExtensionDataTypes.PrivateExtension.
func PrivateExtensionCodec() mapvalues.ValueCodec[mapvalues.PrivateExtension] {
	return compositeValueCodec[mapvalues.PrivateExtension, *mapvalues.PrivateExtension]()
}

// PCSExtensionsCodec binds MAP-ExtensionDataTypes.PCS-Extensions.
func PCSExtensionsCodec() mapvalues.ValueCodec[mapvalues.PCSExtensions] {
	return compositeValueCodec[mapvalues.PCSExtensions, *mapvalues.PCSExtensions]()
}

// SLRArgPCSExtensionsCodec binds MAP-ExtensionDataTypes.SLR-Arg-PCS-Extensions.
func SLRArgPCSExtensionsCodec() mapvalues.ValueCodec[mapvalues.SLRArgPCSExtensions] {
	return compositeValueCodec[mapvalues.SLRArgPCSExtensions, *mapvalues.SLRArgPCSExtensions]()
}

// SSCodeCodec binds MAP-SS-Code.SS-Code.
func SSCodeCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.SSCode]] {
	return pointerValueCodec(mapvalues.UnmarshalBERSSCode, mapvalues.MarshalBERSSCode, mapvalues.MarshalDERSSCode)
}

// ISDNAddressStringCodec binds MAP-CommonDataTypes.ISDN-AddressString.
func ISDNAddressStringCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.ISDNAddressString]] {
	return pointerValueCodec(mapvalues.UnmarshalBERISDNAddressString, mapvalues.MarshalBERISDNAddressString, mapvalues.MarshalDERISDNAddressString)
}

// FTNAddressStringCodec binds MAP-CommonDataTypes.FTN-AddressString.
func FTNAddressStringCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.FTNAddressString]] {
	return pointerValueCodec(mapvalues.UnmarshalBERFTNAddressString, mapvalues.MarshalBERFTNAddressString, mapvalues.MarshalDERFTNAddressString)
}

// ExternalSignalInfoCodec binds MAP-CommonDataTypes.ExternalSignalInfo.
func ExternalSignalInfoCodec() mapvalues.ValueCodec[mapvalues.ExternalSignalInfo] {
	return compositeValueCodec[mapvalues.ExternalSignalInfo, *mapvalues.ExternalSignalInfo]()
}

// ExtExternalSignalInfoCodec binds MAP-CommonDataTypes.Ext-ExternalSignalInfo.
func ExtExternalSignalInfoCodec() mapvalues.ValueCodec[mapvalues.ExtExternalSignalInfo] {
	return compositeValueCodec[mapvalues.ExtExternalSignalInfo, *mapvalues.ExtExternalSignalInfo]()
}

// AccessNetworkSignalInfoCodec binds MAP-CommonDataTypes.AccessNetworkSignalInfo.
func AccessNetworkSignalInfoCodec() mapvalues.ValueCodec[mapvalues.AccessNetworkSignalInfo] {
	return compositeValueCodec[mapvalues.AccessNetworkSignalInfo, *mapvalues.AccessNetworkSignalInfo]()
}

// IMSICodec binds MAP-CommonDataTypes.IMSI.
func IMSICodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.IMSI]] {
	return pointerValueCodec(mapvalues.UnmarshalBERIMSI, mapvalues.MarshalBERIMSI, mapvalues.MarshalDERIMSI)
}

// IdentityCodec binds MAP-CommonDataTypes.Identity.
func IdentityCodec() mapvalues.ValueCodec[mapvalues.Identity] {
	return compositeValueCodec[mapvalues.Identity, *mapvalues.Identity]()
}

// IMSIWithLMSICodec binds MAP-CommonDataTypes.IMSI-WithLMSI.
func IMSIWithLMSICodec() mapvalues.ValueCodec[mapvalues.IMSIWithLMSI] {
	return compositeValueCodec[mapvalues.IMSIWithLMSI, *mapvalues.IMSIWithLMSI]()
}

// ASCICallReferenceCodec binds MAP-CommonDataTypes.ASCI-CallReference.
func ASCICallReferenceCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.ASCICallReference]] {
	return pointerValueCodec(mapvalues.UnmarshalBERASCICallReference, mapvalues.MarshalBERASCICallReference, mapvalues.MarshalDERASCICallReference)
}

// SubscriberIdCodec binds MAP-CommonDataTypes.SubscriberId.
func SubscriberIdCodec() mapvalues.ValueCodec[mapvalues.SubscriberId] {
	return compositeValueCodec[mapvalues.SubscriberId, *mapvalues.SubscriberId]()
}

// IMEICodec binds MAP-CommonDataTypes.IMEI.
func IMEICodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.IMEI]] {
	return pointerValueCodec(mapvalues.UnmarshalBERIMEI, mapvalues.MarshalBERIMEI, mapvalues.MarshalDERIMEI)
}

// HLRIdCodec binds MAP-CommonDataTypes.HLR-Id.
func HLRIdCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.HLRId]] {
	return pointerValueCodec(mapvalues.UnmarshalBERHLRId, mapvalues.MarshalBERHLRId, mapvalues.MarshalDERHLRId)
}

// HLRListCodec binds MAP-CommonDataTypes.HLR-List.
func HLRListCodec() mapvalues.ValueCodec[mapvalues.HLRList] {
	return pointerValueCodec(mapvalues.UnmarshalBERHLRList, mapvalues.MarshalBERHLRList, mapvalues.MarshalDERHLRList)
}

// NAEAPreferredCICodec binds MAP-CommonDataTypes.NAEA-PreferredCI.
func NAEAPreferredCICodec() mapvalues.ValueCodec[mapvalues.NAEAPreferredCI] {
	return compositeValueCodec[mapvalues.NAEAPreferredCI, *mapvalues.NAEAPreferredCI]()
}

// SubscriberIdentityCodec binds MAP-CommonDataTypes.SubscriberIdentity.
func SubscriberIdentityCodec() mapvalues.ValueCodec[mapvalues.SubscriberIdentity] {
	return compositeValueCodec[mapvalues.SubscriberIdentity, *mapvalues.SubscriberIdentity]()
}

// LCSClientExternalIDCodec binds MAP-CommonDataTypes.LCSClientExternalID.
func LCSClientExternalIDCodec() mapvalues.ValueCodec[mapvalues.LCSClientExternalID] {
	return compositeValueCodec[mapvalues.LCSClientExternalID, *mapvalues.LCSClientExternalID]()
}

// NetworkNodeDiameterAddressCodec binds MAP-CommonDataTypes.NetworkNodeDiameterAddress.
func NetworkNodeDiameterAddressCodec() mapvalues.ValueCodec[mapvalues.NetworkNodeDiameterAddress] {
	return compositeValueCodec[mapvalues.NetworkNodeDiameterAddress, *mapvalues.NetworkNodeDiameterAddress]()
}

// CellGlobalIdOrServiceAreaIdOrLAICodec binds MAP-CommonDataTypes.CellGlobalIdOrServiceAreaIdOrLAI.
func CellGlobalIdOrServiceAreaIdOrLAICodec() mapvalues.ValueCodec[mapvalues.CellGlobalIdOrServiceAreaIdOrLAI] {
	return compositeValueCodec[mapvalues.CellGlobalIdOrServiceAreaIdOrLAI, *mapvalues.CellGlobalIdOrServiceAreaIdOrLAI]()
}

// BasicServiceCodeCodec binds MAP-CommonDataTypes.BasicServiceCode.
func BasicServiceCodeCodec() mapvalues.ValueCodec[mapvalues.BasicServiceCode] {
	return compositeValueCodec[mapvalues.BasicServiceCode, *mapvalues.BasicServiceCode]()
}

// ExtBasicServiceCodeCodec binds MAP-CommonDataTypes.Ext-BasicServiceCode.
func ExtBasicServiceCodeCodec() mapvalues.ValueCodec[mapvalues.ExtBasicServiceCode] {
	return compositeValueCodec[mapvalues.ExtBasicServiceCode, *mapvalues.ExtBasicServiceCode]()
}

// EMLPPInfoCodec binds MAP-CommonDataTypes.EMLPP-Info.
func EMLPPInfoCodec() mapvalues.ValueCodec[mapvalues.EMLPPInfo] {
	return compositeValueCodec[mapvalues.EMLPPInfo, *mapvalues.EMLPPInfo]()
}

// MCSSInfoCodec binds MAP-CommonDataTypes.MC-SS-Info.
func MCSSInfoCodec() mapvalues.ValueCodec[mapvalues.MCSSInfo] {
	return compositeValueCodec[mapvalues.MCSSInfo, *mapvalues.MCSSInfo]()
}

// RegisterSSArgCodec binds MAP-SS-DataTypes.RegisterSS-Arg.
func RegisterSSArgCodec() mapvalues.ValueCodec[mapvalues.RegisterSSArg] {
	return compositeValueCodec[mapvalues.RegisterSSArg, *mapvalues.RegisterSSArg]()
}

// SSInfoCodec binds MAP-SS-DataTypes.SS-Info.
func SSInfoCodec() mapvalues.ValueCodec[mapvalues.SSInfo] {
	return compositeValueCodec[mapvalues.SSInfo, *mapvalues.SSInfo]()
}

// ForwardingInfoCodec binds MAP-SS-DataTypes.ForwardingInfo.
func ForwardingInfoCodec() mapvalues.ValueCodec[mapvalues.ForwardingInfo] {
	return compositeValueCodec[mapvalues.ForwardingInfo, *mapvalues.ForwardingInfo]()
}

// ForwardingFeatureListCodec binds MAP-SS-DataTypes.ForwardingFeatureList.
func ForwardingFeatureListCodec() mapvalues.ValueCodec[mapvalues.ForwardingFeatureList] {
	return pointerValueCodec(mapvalues.UnmarshalBERForwardingFeatureList, mapvalues.MarshalBERForwardingFeatureList, mapvalues.MarshalDERForwardingFeatureList)
}

// ForwardingFeatureCodec binds MAP-SS-DataTypes.ForwardingFeature.
func ForwardingFeatureCodec() mapvalues.ValueCodec[mapvalues.ForwardingFeature] {
	return compositeValueCodec[mapvalues.ForwardingFeature, *mapvalues.ForwardingFeature]()
}

// SSStatusCodec binds MAP-SS-DataTypes.SS-Status.
func SSStatusCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.SSStatus]] {
	return pointerValueCodec(mapvalues.UnmarshalBERSSStatus, mapvalues.MarshalBERSSStatus, mapvalues.MarshalDERSSStatus)
}

// CallBarringInfoCodec binds MAP-SS-DataTypes.CallBarringInfo.
func CallBarringInfoCodec() mapvalues.ValueCodec[mapvalues.CallBarringInfo] {
	return compositeValueCodec[mapvalues.CallBarringInfo, *mapvalues.CallBarringInfo]()
}

// CallBarringFeatureListCodec binds MAP-SS-DataTypes.CallBarringFeatureList.
func CallBarringFeatureListCodec() mapvalues.ValueCodec[mapvalues.CallBarringFeatureList] {
	return pointerValueCodec(mapvalues.UnmarshalBERCallBarringFeatureList, mapvalues.MarshalBERCallBarringFeatureList, mapvalues.MarshalDERCallBarringFeatureList)
}

// CallBarringFeatureCodec binds MAP-SS-DataTypes.CallBarringFeature.
func CallBarringFeatureCodec() mapvalues.ValueCodec[mapvalues.CallBarringFeature] {
	return compositeValueCodec[mapvalues.CallBarringFeature, *mapvalues.CallBarringFeature]()
}

// SSDataCodec binds MAP-SS-DataTypes.SS-Data.
func SSDataCodec() mapvalues.ValueCodec[mapvalues.SSData] {
	return compositeValueCodec[mapvalues.SSData, *mapvalues.SSData]()
}

// SSSubscriptionOptionCodec binds MAP-SS-DataTypes.SS-SubscriptionOption.
func SSSubscriptionOptionCodec() mapvalues.ValueCodec[mapvalues.SSSubscriptionOption] {
	return compositeValueCodec[mapvalues.SSSubscriptionOption, *mapvalues.SSSubscriptionOption]()
}

// SSForBSCodeCodec binds MAP-SS-DataTypes.SS-ForBS-Code.
func SSForBSCodeCodec() mapvalues.ValueCodec[mapvalues.SSForBSCode] {
	return compositeValueCodec[mapvalues.SSForBSCode, *mapvalues.SSForBSCode]()
}

// GenericServiceInfoCodec binds MAP-SS-DataTypes.GenericServiceInfo.
func GenericServiceInfoCodec() mapvalues.ValueCodec[mapvalues.GenericServiceInfo] {
	return compositeValueCodec[mapvalues.GenericServiceInfo, *mapvalues.GenericServiceInfo]()
}

// CCBSFeatureListCodec binds MAP-SS-DataTypes.CCBS-FeatureList.
func CCBSFeatureListCodec() mapvalues.ValueCodec[mapvalues.CCBSFeatureList] {
	return pointerValueCodec(mapvalues.UnmarshalBERCCBSFeatureList, mapvalues.MarshalBERCCBSFeatureList, mapvalues.MarshalDERCCBSFeatureList)
}

// CCBSFeatureCodec binds MAP-SS-DataTypes.CCBS-Feature.
func CCBSFeatureCodec() mapvalues.ValueCodec[mapvalues.CCBSFeature] {
	return compositeValueCodec[mapvalues.CCBSFeature, *mapvalues.CCBSFeature]()
}

// InterrogateSSResCodec binds MAP-SS-DataTypes.InterrogateSS-Res.
func InterrogateSSResCodec() mapvalues.ValueCodec[mapvalues.InterrogateSSRes] {
	return compositeValueCodec[mapvalues.InterrogateSSRes, *mapvalues.InterrogateSSRes]()
}

// USSDArgCodec binds MAP-SS-DataTypes.USSD-Arg.
func USSDArgCodec() mapvalues.ValueCodec[mapvalues.USSDArg] {
	return compositeValueCodec[mapvalues.USSDArg, *mapvalues.USSDArg]()
}

// USSDResCodec binds MAP-SS-DataTypes.USSD-Res.
func USSDResCodec() mapvalues.ValueCodec[mapvalues.USSDRes] {
	return compositeValueCodec[mapvalues.USSDRes, *mapvalues.USSDRes]()
}

// PasswordCodec binds MAP-SS-DataTypes.Password.
func PasswordCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.Password]] {
	return pointerValueCodec(mapvalues.UnmarshalBERPassword, mapvalues.MarshalBERPassword, mapvalues.MarshalDERPassword)
}

// GuidanceInfoCodec binds MAP-SS-DataTypes.GuidanceInfo.
func GuidanceInfoCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.GuidanceInfo]] {
	return pointerValueCodec(mapvalues.UnmarshalBERGuidanceInfo, mapvalues.MarshalBERGuidanceInfo, mapvalues.MarshalDERGuidanceInfo)
}

// SSListCodec binds MAP-SS-DataTypes.SS-List.
func SSListCodec() mapvalues.ValueCodec[mapvalues.SSList] {
	return pointerValueCodec(mapvalues.UnmarshalBERSSList, mapvalues.MarshalBERSSList, mapvalues.MarshalDERSSList)
}

// SSInfoListCodec binds MAP-SS-DataTypes.SS-InfoList.
func SSInfoListCodec() mapvalues.ValueCodec[mapvalues.SSInfoList] {
	return pointerValueCodec(mapvalues.UnmarshalBERSSInfoList, mapvalues.MarshalBERSSInfoList, mapvalues.MarshalDERSSInfoList)
}

// BasicServiceGroupListCodec binds MAP-SS-DataTypes.BasicServiceGroupList.
func BasicServiceGroupListCodec() mapvalues.ValueCodec[mapvalues.BasicServiceGroupList] {
	return pointerValueCodec(mapvalues.UnmarshalBERBasicServiceGroupList, mapvalues.MarshalBERBasicServiceGroupList, mapvalues.MarshalDERBasicServiceGroupList)
}

// SSInvocationNotificationArgCodec binds MAP-SS-DataTypes.SS-InvocationNotificationArg.
func SSInvocationNotificationArgCodec() mapvalues.ValueCodec[mapvalues.SSInvocationNotificationArg] {
	return compositeValueCodec[mapvalues.SSInvocationNotificationArg, *mapvalues.SSInvocationNotificationArg]()
}

// SSInvocationNotificationResCodec binds MAP-SS-DataTypes.SS-InvocationNotificationRes.
func SSInvocationNotificationResCodec() mapvalues.ValueCodec[mapvalues.SSInvocationNotificationRes] {
	return compositeValueCodec[mapvalues.SSInvocationNotificationRes, *mapvalues.SSInvocationNotificationRes]()
}

// SSEventSpecificationCodec binds MAP-SS-DataTypes.SS-EventSpecification.
func SSEventSpecificationCodec() mapvalues.ValueCodec[mapvalues.SSEventSpecification] {
	return pointerValueCodec(mapvalues.UnmarshalBERSSEventSpecification, mapvalues.MarshalBERSSEventSpecification, mapvalues.MarshalDERSSEventSpecification)
}

// RegisterCCEntryArgCodec binds MAP-SS-DataTypes.RegisterCC-EntryArg.
func RegisterCCEntryArgCodec() mapvalues.ValueCodec[mapvalues.RegisterCCEntryArg] {
	return compositeValueCodec[mapvalues.RegisterCCEntryArg, *mapvalues.RegisterCCEntryArg]()
}

// CCBSDataCodec binds MAP-SS-DataTypes.CCBS-Data.
func CCBSDataCodec() mapvalues.ValueCodec[mapvalues.CCBSData] {
	return compositeValueCodec[mapvalues.CCBSData, *mapvalues.CCBSData]()
}

// RegisterCCEntryResCodec binds MAP-SS-DataTypes.RegisterCC-EntryRes.
func RegisterCCEntryResCodec() mapvalues.ValueCodec[mapvalues.RegisterCCEntryRes] {
	return compositeValueCodec[mapvalues.RegisterCCEntryRes, *mapvalues.RegisterCCEntryRes]()
}

// EraseCCEntryArgCodec binds MAP-SS-DataTypes.EraseCC-EntryArg.
func EraseCCEntryArgCodec() mapvalues.ValueCodec[mapvalues.EraseCCEntryArg] {
	return compositeValueCodec[mapvalues.EraseCCEntryArg, *mapvalues.EraseCCEntryArg]()
}

// EraseCCEntryResCodec binds MAP-SS-DataTypes.EraseCC-EntryRes.
func EraseCCEntryResCodec() mapvalues.ValueCodec[mapvalues.EraseCCEntryRes] {
	return compositeValueCodec[mapvalues.EraseCCEntryRes, *mapvalues.EraseCCEntryRes]()
}

// RoamingNotAllowedParamCodec binds MAP-ER-DataTypes.RoamingNotAllowedParam.
func RoamingNotAllowedParamCodec() mapvalues.ValueCodec[mapvalues.RoamingNotAllowedParam] {
	return compositeValueCodec[mapvalues.RoamingNotAllowedParam, *mapvalues.RoamingNotAllowedParam]()
}

// CallBarredParamCodec binds MAP-ER-DataTypes.CallBarredParam.
func CallBarredParamCodec() mapvalues.ValueCodec[mapvalues.CallBarredParam] {
	return compositeValueCodec[mapvalues.CallBarredParam, *mapvalues.CallBarredParam]()
}

// ExtensibleCallBarredParamCodec binds MAP-ER-DataTypes.ExtensibleCallBarredParam.
func ExtensibleCallBarredParamCodec() mapvalues.ValueCodec[mapvalues.ExtensibleCallBarredParam] {
	return compositeValueCodec[mapvalues.ExtensibleCallBarredParam, *mapvalues.ExtensibleCallBarredParam]()
}

// CUGRejectParamCodec binds MAP-ER-DataTypes.CUG-RejectParam.
func CUGRejectParamCodec() mapvalues.ValueCodec[mapvalues.CUGRejectParam] {
	return compositeValueCodec[mapvalues.CUGRejectParam, *mapvalues.CUGRejectParam]()
}

// SSIncompatibilityCauseCodec binds MAP-ER-DataTypes.SS-IncompatibilityCause.
func SSIncompatibilityCauseCodec() mapvalues.ValueCodec[mapvalues.SSIncompatibilityCause] {
	return compositeValueCodec[mapvalues.SSIncompatibilityCause, *mapvalues.SSIncompatibilityCause]()
}

// PWRegistrationFailureCauseCodec binds MAP-ER-DataTypes.PW-RegistrationFailureCause.
func PWRegistrationFailureCauseCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.PWRegistrationFailureCause]] {
	return pointerValueCodec(mapvalues.UnmarshalBERPWRegistrationFailureCause, mapvalues.MarshalBERPWRegistrationFailureCause, mapvalues.MarshalDERPWRegistrationFailureCause)
}

// SMDeliveryFailureCauseCodec binds MAP-ER-DataTypes.SM-DeliveryFailureCause.
func SMDeliveryFailureCauseCodec() mapvalues.ValueCodec[mapvalues.SMDeliveryFailureCause] {
	return compositeValueCodec[mapvalues.SMDeliveryFailureCause, *mapvalues.SMDeliveryFailureCause]()
}

// AbsentSubscriberSMParamCodec binds MAP-ER-DataTypes.AbsentSubscriberSM-Param.
func AbsentSubscriberSMParamCodec() mapvalues.ValueCodec[mapvalues.AbsentSubscriberSMParam] {
	return compositeValueCodec[mapvalues.AbsentSubscriberSMParam, *mapvalues.AbsentSubscriberSMParam]()
}

// SystemFailureParamCodec binds MAP-ER-DataTypes.SystemFailureParam.
func SystemFailureParamCodec() mapvalues.ValueCodec[mapvalues.SystemFailureParam] {
	return compositeValueCodec[mapvalues.SystemFailureParam, *mapvalues.SystemFailureParam]()
}

// ExtensibleSystemFailureParamCodec binds MAP-ER-DataTypes.ExtensibleSystemFailureParam.
func ExtensibleSystemFailureParamCodec() mapvalues.ValueCodec[mapvalues.ExtensibleSystemFailureParam] {
	return compositeValueCodec[mapvalues.ExtensibleSystemFailureParam, *mapvalues.ExtensibleSystemFailureParam]()
}

// DataMissingParamCodec binds MAP-ER-DataTypes.DataMissingParam.
func DataMissingParamCodec() mapvalues.ValueCodec[mapvalues.DataMissingParam] {
	return compositeValueCodec[mapvalues.DataMissingParam, *mapvalues.DataMissingParam]()
}

// UnexpectedDataParamCodec binds MAP-ER-DataTypes.UnexpectedDataParam.
func UnexpectedDataParamCodec() mapvalues.ValueCodec[mapvalues.UnexpectedDataParam] {
	return compositeValueCodec[mapvalues.UnexpectedDataParam, *mapvalues.UnexpectedDataParam]()
}

// FacilityNotSupParamCodec binds MAP-ER-DataTypes.FacilityNotSupParam.
func FacilityNotSupParamCodec() mapvalues.ValueCodec[mapvalues.FacilityNotSupParam] {
	return compositeValueCodec[mapvalues.FacilityNotSupParam, *mapvalues.FacilityNotSupParam]()
}

// ORNotAllowedParamCodec binds MAP-ER-DataTypes.OR-NotAllowedParam.
func ORNotAllowedParamCodec() mapvalues.ValueCodec[mapvalues.ORNotAllowedParam] {
	return compositeValueCodec[mapvalues.ORNotAllowedParam, *mapvalues.ORNotAllowedParam]()
}

// UnknownSubscriberParamCodec binds MAP-ER-DataTypes.UnknownSubscriberParam.
func UnknownSubscriberParamCodec() mapvalues.ValueCodec[mapvalues.UnknownSubscriberParam] {
	return compositeValueCodec[mapvalues.UnknownSubscriberParam, *mapvalues.UnknownSubscriberParam]()
}

// NumberChangedParamCodec binds MAP-ER-DataTypes.NumberChangedParam.
func NumberChangedParamCodec() mapvalues.ValueCodec[mapvalues.NumberChangedParam] {
	return compositeValueCodec[mapvalues.NumberChangedParam, *mapvalues.NumberChangedParam]()
}

// UnidentifiedSubParamCodec binds MAP-ER-DataTypes.UnidentifiedSubParam.
func UnidentifiedSubParamCodec() mapvalues.ValueCodec[mapvalues.UnidentifiedSubParam] {
	return compositeValueCodec[mapvalues.UnidentifiedSubParam, *mapvalues.UnidentifiedSubParam]()
}

// IllegalSubscriberParamCodec binds MAP-ER-DataTypes.IllegalSubscriberParam.
func IllegalSubscriberParamCodec() mapvalues.ValueCodec[mapvalues.IllegalSubscriberParam] {
	return compositeValueCodec[mapvalues.IllegalSubscriberParam, *mapvalues.IllegalSubscriberParam]()
}

// IllegalEquipmentParamCodec binds MAP-ER-DataTypes.IllegalEquipmentParam.
func IllegalEquipmentParamCodec() mapvalues.ValueCodec[mapvalues.IllegalEquipmentParam] {
	return compositeValueCodec[mapvalues.IllegalEquipmentParam, *mapvalues.IllegalEquipmentParam]()
}

// BearerServNotProvParamCodec binds MAP-ER-DataTypes.BearerServNotProvParam.
func BearerServNotProvParamCodec() mapvalues.ValueCodec[mapvalues.BearerServNotProvParam] {
	return compositeValueCodec[mapvalues.BearerServNotProvParam, *mapvalues.BearerServNotProvParam]()
}

// TeleservNotProvParamCodec binds MAP-ER-DataTypes.TeleservNotProvParam.
func TeleservNotProvParamCodec() mapvalues.ValueCodec[mapvalues.TeleservNotProvParam] {
	return compositeValueCodec[mapvalues.TeleservNotProvParam, *mapvalues.TeleservNotProvParam]()
}

// TracingBufferFullParamCodec binds MAP-ER-DataTypes.TracingBufferFullParam.
func TracingBufferFullParamCodec() mapvalues.ValueCodec[mapvalues.TracingBufferFullParam] {
	return compositeValueCodec[mapvalues.TracingBufferFullParam, *mapvalues.TracingBufferFullParam]()
}

// NoRoamingNbParamCodec binds MAP-ER-DataTypes.NoRoamingNbParam.
func NoRoamingNbParamCodec() mapvalues.ValueCodec[mapvalues.NoRoamingNbParam] {
	return compositeValueCodec[mapvalues.NoRoamingNbParam, *mapvalues.NoRoamingNbParam]()
}

// AbsentSubscriberParamCodec binds MAP-ER-DataTypes.AbsentSubscriberParam.
func AbsentSubscriberParamCodec() mapvalues.ValueCodec[mapvalues.AbsentSubscriberParam] {
	return compositeValueCodec[mapvalues.AbsentSubscriberParam, *mapvalues.AbsentSubscriberParam]()
}

// BusySubscriberParamCodec binds MAP-ER-DataTypes.BusySubscriberParam.
func BusySubscriberParamCodec() mapvalues.ValueCodec[mapvalues.BusySubscriberParam] {
	return compositeValueCodec[mapvalues.BusySubscriberParam, *mapvalues.BusySubscriberParam]()
}

// NoSubscriberReplyParamCodec binds MAP-ER-DataTypes.NoSubscriberReplyParam.
func NoSubscriberReplyParamCodec() mapvalues.ValueCodec[mapvalues.NoSubscriberReplyParam] {
	return compositeValueCodec[mapvalues.NoSubscriberReplyParam, *mapvalues.NoSubscriberReplyParam]()
}

// ForwardingViolationParamCodec binds MAP-ER-DataTypes.ForwardingViolationParam.
func ForwardingViolationParamCodec() mapvalues.ValueCodec[mapvalues.ForwardingViolationParam] {
	return compositeValueCodec[mapvalues.ForwardingViolationParam, *mapvalues.ForwardingViolationParam]()
}

// ForwardingFailedParamCodec binds MAP-ER-DataTypes.ForwardingFailedParam.
func ForwardingFailedParamCodec() mapvalues.ValueCodec[mapvalues.ForwardingFailedParam] {
	return compositeValueCodec[mapvalues.ForwardingFailedParam, *mapvalues.ForwardingFailedParam]()
}

// ATINotAllowedParamCodec binds MAP-ER-DataTypes.ATI-NotAllowedParam.
func ATINotAllowedParamCodec() mapvalues.ValueCodec[mapvalues.ATINotAllowedParam] {
	return compositeValueCodec[mapvalues.ATINotAllowedParam, *mapvalues.ATINotAllowedParam]()
}

// ATSINotAllowedParamCodec binds MAP-ER-DataTypes.ATSI-NotAllowedParam.
func ATSINotAllowedParamCodec() mapvalues.ValueCodec[mapvalues.ATSINotAllowedParam] {
	return compositeValueCodec[mapvalues.ATSINotAllowedParam, *mapvalues.ATSINotAllowedParam]()
}

// ATMNotAllowedParamCodec binds MAP-ER-DataTypes.ATM-NotAllowedParam.
func ATMNotAllowedParamCodec() mapvalues.ValueCodec[mapvalues.ATMNotAllowedParam] {
	return compositeValueCodec[mapvalues.ATMNotAllowedParam, *mapvalues.ATMNotAllowedParam]()
}

// IllegalSSOperationParamCodec binds MAP-ER-DataTypes.IllegalSS-OperationParam.
func IllegalSSOperationParamCodec() mapvalues.ValueCodec[mapvalues.IllegalSSOperationParam] {
	return compositeValueCodec[mapvalues.IllegalSSOperationParam, *mapvalues.IllegalSSOperationParam]()
}

// SSNotAvailableParamCodec binds MAP-ER-DataTypes.SS-NotAvailableParam.
func SSNotAvailableParamCodec() mapvalues.ValueCodec[mapvalues.SSNotAvailableParam] {
	return compositeValueCodec[mapvalues.SSNotAvailableParam, *mapvalues.SSNotAvailableParam]()
}

// SSSubscriptionViolationParamCodec binds MAP-ER-DataTypes.SS-SubscriptionViolationParam.
func SSSubscriptionViolationParamCodec() mapvalues.ValueCodec[mapvalues.SSSubscriptionViolationParam] {
	return compositeValueCodec[mapvalues.SSSubscriptionViolationParam, *mapvalues.SSSubscriptionViolationParam]()
}

// InformationNotAvailableParamCodec binds MAP-ER-DataTypes.InformationNotAvailableParam.
func InformationNotAvailableParamCodec() mapvalues.ValueCodec[mapvalues.InformationNotAvailableParam] {
	return compositeValueCodec[mapvalues.InformationNotAvailableParam, *mapvalues.InformationNotAvailableParam]()
}

// SubBusyForMTSMSParamCodec binds MAP-ER-DataTypes.SubBusyForMT-SMS-Param.
func SubBusyForMTSMSParamCodec() mapvalues.ValueCodec[mapvalues.SubBusyForMTSMSParam] {
	return compositeValueCodec[mapvalues.SubBusyForMTSMSParam, *mapvalues.SubBusyForMTSMSParam]()
}

// MessageWaitListFullParamCodec binds MAP-ER-DataTypes.MessageWaitListFullParam.
func MessageWaitListFullParamCodec() mapvalues.ValueCodec[mapvalues.MessageWaitListFullParam] {
	return compositeValueCodec[mapvalues.MessageWaitListFullParam, *mapvalues.MessageWaitListFullParam]()
}

// ResourceLimitationParamCodec binds MAP-ER-DataTypes.ResourceLimitationParam.
func ResourceLimitationParamCodec() mapvalues.ValueCodec[mapvalues.ResourceLimitationParam] {
	return compositeValueCodec[mapvalues.ResourceLimitationParam, *mapvalues.ResourceLimitationParam]()
}

// NoGroupCallNbParamCodec binds MAP-ER-DataTypes.NoGroupCallNbParam.
func NoGroupCallNbParamCodec() mapvalues.ValueCodec[mapvalues.NoGroupCallNbParam] {
	return compositeValueCodec[mapvalues.NoGroupCallNbParam, *mapvalues.NoGroupCallNbParam]()
}

// IncompatibleTerminalParamCodec binds MAP-ER-DataTypes.IncompatibleTerminalParam.
func IncompatibleTerminalParamCodec() mapvalues.ValueCodec[mapvalues.IncompatibleTerminalParam] {
	return compositeValueCodec[mapvalues.IncompatibleTerminalParam, *mapvalues.IncompatibleTerminalParam]()
}

// ShortTermDenialParamCodec binds MAP-ER-DataTypes.ShortTermDenialParam.
func ShortTermDenialParamCodec() mapvalues.ValueCodec[mapvalues.ShortTermDenialParam] {
	return compositeValueCodec[mapvalues.ShortTermDenialParam, *mapvalues.ShortTermDenialParam]()
}

// LongTermDenialParamCodec binds MAP-ER-DataTypes.LongTermDenialParam.
func LongTermDenialParamCodec() mapvalues.ValueCodec[mapvalues.LongTermDenialParam] {
	return compositeValueCodec[mapvalues.LongTermDenialParam, *mapvalues.LongTermDenialParam]()
}

// UnauthorizedRequestingNetworkParamCodec binds MAP-ER-DataTypes.UnauthorizedRequestingNetwork-Param.
func UnauthorizedRequestingNetworkParamCodec() mapvalues.ValueCodec[mapvalues.UnauthorizedRequestingNetworkParam] {
	return compositeValueCodec[mapvalues.UnauthorizedRequestingNetworkParam, *mapvalues.UnauthorizedRequestingNetworkParam]()
}

// UnauthorizedLCSClientParamCodec binds MAP-ER-DataTypes.UnauthorizedLCSClient-Param.
func UnauthorizedLCSClientParamCodec() mapvalues.ValueCodec[mapvalues.UnauthorizedLCSClientParam] {
	return compositeValueCodec[mapvalues.UnauthorizedLCSClientParam, *mapvalues.UnauthorizedLCSClientParam]()
}

// PositionMethodFailureParamCodec binds MAP-ER-DataTypes.PositionMethodFailure-Param.
func PositionMethodFailureParamCodec() mapvalues.ValueCodec[mapvalues.PositionMethodFailureParam] {
	return compositeValueCodec[mapvalues.PositionMethodFailureParam, *mapvalues.PositionMethodFailureParam]()
}

// UnknownOrUnreachableLCSClientParamCodec binds MAP-ER-DataTypes.UnknownOrUnreachableLCSClient-Param.
func UnknownOrUnreachableLCSClientParamCodec() mapvalues.ValueCodec[mapvalues.UnknownOrUnreachableLCSClientParam] {
	return compositeValueCodec[mapvalues.UnknownOrUnreachableLCSClientParam, *mapvalues.UnknownOrUnreachableLCSClientParam]()
}

// MMEventNotSupportedParamCodec binds MAP-ER-DataTypes.MM-EventNotSupported-Param.
func MMEventNotSupportedParamCodec() mapvalues.ValueCodec[mapvalues.MMEventNotSupportedParam] {
	return compositeValueCodec[mapvalues.MMEventNotSupportedParam, *mapvalues.MMEventNotSupportedParam]()
}

// TargetCellOutsideGCAParamCodec binds MAP-ER-DataTypes.TargetCellOutsideGCA-Param.
func TargetCellOutsideGCAParamCodec() mapvalues.ValueCodec[mapvalues.TargetCellOutsideGCAParam] {
	return compositeValueCodec[mapvalues.TargetCellOutsideGCAParam, *mapvalues.TargetCellOutsideGCAParam]()
}

// OngoingGroupCallParamCodec binds MAP-ER-DataTypes.OngoingGroupCallParam.
func OngoingGroupCallParamCodec() mapvalues.ValueCodec[mapvalues.OngoingGroupCallParam] {
	return compositeValueCodec[mapvalues.OngoingGroupCallParam, *mapvalues.OngoingGroupCallParam]()
}

// ActivateTraceModeArgCodec binds MAP-OM-DataTypes.ActivateTraceModeArg.
func ActivateTraceModeArgCodec() mapvalues.ValueCodec[mapvalues.ActivateTraceModeArg] {
	return compositeValueCodec[mapvalues.ActivateTraceModeArg, *mapvalues.ActivateTraceModeArg]()
}

// MDTConfigurationCodec binds MAP-OM-DataTypes.MDT-Configuration.
func MDTConfigurationCodec() mapvalues.ValueCodec[mapvalues.MDTConfiguration] {
	return compositeValueCodec[mapvalues.MDTConfiguration, *mapvalues.MDTConfiguration]()
}

// MDTAllowedPLMNIdListCodec binds MAP-OM-DataTypes.MDT-Allowed-PLMNId-List.
func MDTAllowedPLMNIdListCodec() mapvalues.ValueCodec[mapvalues.MDTAllowedPLMNIdList] {
	return pointerValueCodec(mapvalues.UnmarshalBERMDTAllowedPLMNIdList, mapvalues.MarshalBERMDTAllowedPLMNIdList, mapvalues.MarshalDERMDTAllowedPLMNIdList)
}

// AreaScopeCodec binds MAP-OM-DataTypes.AreaScope.
func AreaScopeCodec() mapvalues.ValueCodec[mapvalues.AreaScope] {
	return compositeValueCodec[mapvalues.AreaScope, *mapvalues.AreaScope]()
}

// CGIListCodec binds MAP-OM-DataTypes.CGI-List.
func CGIListCodec() mapvalues.ValueCodec[mapvalues.CGIList] {
	return pointerValueCodec(mapvalues.UnmarshalBERCGIList, mapvalues.MarshalBERCGIList, mapvalues.MarshalDERCGIList)
}

// EUTRANCGIListCodec binds MAP-OM-DataTypes.E-UTRAN-CGI-List.
func EUTRANCGIListCodec() mapvalues.ValueCodec[mapvalues.EUTRANCGIList] {
	return pointerValueCodec(mapvalues.UnmarshalBEREUTRANCGIList, mapvalues.MarshalBEREUTRANCGIList, mapvalues.MarshalDEREUTRANCGIList)
}

// RoutingAreaIdListCodec binds MAP-OM-DataTypes.RoutingAreaId-List.
func RoutingAreaIdListCodec() mapvalues.ValueCodec[mapvalues.RoutingAreaIdList] {
	return pointerValueCodec(mapvalues.UnmarshalBERRoutingAreaIdList, mapvalues.MarshalBERRoutingAreaIdList, mapvalues.MarshalDERRoutingAreaIdList)
}

// LocationAreaIdListCodec binds MAP-OM-DataTypes.LocationAreaId-List.
func LocationAreaIdListCodec() mapvalues.ValueCodec[mapvalues.LocationAreaIdList] {
	return pointerValueCodec(mapvalues.UnmarshalBERLocationAreaIdList, mapvalues.MarshalBERLocationAreaIdList, mapvalues.MarshalDERLocationAreaIdList)
}

// TrackingAreaIdListCodec binds MAP-OM-DataTypes.TrackingAreaId-List.
func TrackingAreaIdListCodec() mapvalues.ValueCodec[mapvalues.TrackingAreaIdList] {
	return pointerValueCodec(mapvalues.UnmarshalBERTrackingAreaIdList, mapvalues.MarshalBERTrackingAreaIdList, mapvalues.MarshalDERTrackingAreaIdList)
}

// TraceDepthListCodec binds MAP-OM-DataTypes.TraceDepthList.
func TraceDepthListCodec() mapvalues.ValueCodec[mapvalues.TraceDepthList] {
	return compositeValueCodec[mapvalues.TraceDepthList, *mapvalues.TraceDepthList]()
}

// TraceInterfaceListCodec binds MAP-OM-DataTypes.TraceInterfaceList.
func TraceInterfaceListCodec() mapvalues.ValueCodec[mapvalues.TraceInterfaceList] {
	return compositeValueCodec[mapvalues.TraceInterfaceList, *mapvalues.TraceInterfaceList]()
}

// TraceEventListCodec binds MAP-OM-DataTypes.TraceEventList.
func TraceEventListCodec() mapvalues.ValueCodec[mapvalues.TraceEventList] {
	return compositeValueCodec[mapvalues.TraceEventList, *mapvalues.TraceEventList]()
}

// TracePropagationListCodec binds MAP-OM-DataTypes.TracePropagationList.
func TracePropagationListCodec() mapvalues.ValueCodec[mapvalues.TracePropagationList] {
	return compositeValueCodec[mapvalues.TracePropagationList, *mapvalues.TracePropagationList]()
}

// ActivateTraceModeResCodec binds MAP-OM-DataTypes.ActivateTraceModeRes.
func ActivateTraceModeResCodec() mapvalues.ValueCodec[mapvalues.ActivateTraceModeRes] {
	return compositeValueCodec[mapvalues.ActivateTraceModeRes, *mapvalues.ActivateTraceModeRes]()
}

// DeactivateTraceModeArgCodec binds MAP-OM-DataTypes.DeactivateTraceModeArg.
func DeactivateTraceModeArgCodec() mapvalues.ValueCodec[mapvalues.DeactivateTraceModeArg] {
	return compositeValueCodec[mapvalues.DeactivateTraceModeArg, *mapvalues.DeactivateTraceModeArg]()
}

// DeactivateTraceModeResCodec binds MAP-OM-DataTypes.DeactivateTraceModeRes.
func DeactivateTraceModeResCodec() mapvalues.ValueCodec[mapvalues.DeactivateTraceModeRes] {
	return compositeValueCodec[mapvalues.DeactivateTraceModeRes, *mapvalues.DeactivateTraceModeRes]()
}

// UpdateLocationArgCodec binds MAP-MS-DataTypes.UpdateLocationArg.
func UpdateLocationArgCodec() mapvalues.ValueCodec[mapvalues.UpdateLocationArg] {
	return compositeValueCodec[mapvalues.UpdateLocationArg, *mapvalues.UpdateLocationArg]()
}

// VLRCapabilityCodec binds MAP-MS-DataTypes.VLR-Capability.
func VLRCapabilityCodec() mapvalues.ValueCodec[mapvalues.VLRCapability] {
	return compositeValueCodec[mapvalues.VLRCapability, *mapvalues.VLRCapability]()
}

// SuperChargerInfoCodec binds MAP-MS-DataTypes.SuperChargerInfo.
func SuperChargerInfoCodec() mapvalues.ValueCodec[mapvalues.SuperChargerInfo] {
	return compositeValueCodec[mapvalues.SuperChargerInfo, *mapvalues.SuperChargerInfo]()
}

// UpdateLocationResCodec binds MAP-MS-DataTypes.UpdateLocationRes.
func UpdateLocationResCodec() mapvalues.ValueCodec[mapvalues.UpdateLocationRes] {
	return compositeValueCodec[mapvalues.UpdateLocationRes, *mapvalues.UpdateLocationRes]()
}

// ADDInfoCodec binds MAP-MS-DataTypes.ADD-Info.
func ADDInfoCodec() mapvalues.ValueCodec[mapvalues.ADDInfo] {
	return compositeValueCodec[mapvalues.ADDInfo, *mapvalues.ADDInfo]()
}

// PagingAreaCodec binds MAP-MS-DataTypes.PagingArea.
func PagingAreaCodec() mapvalues.ValueCodec[mapvalues.PagingArea] {
	return pointerValueCodec(mapvalues.UnmarshalBERPagingArea, mapvalues.MarshalBERPagingArea, mapvalues.MarshalDERPagingArea)
}

// LocationAreaCodec binds MAP-MS-DataTypes.LocationArea.
func LocationAreaCodec() mapvalues.ValueCodec[mapvalues.LocationArea] {
	return compositeValueCodec[mapvalues.LocationArea, *mapvalues.LocationArea]()
}

// CancelLocationArgCodec binds MAP-MS-DataTypes.CancelLocationArg.
func CancelLocationArgCodec() mapvalues.ValueCodec[mapvalues.CancelLocationArg] {
	return compositeValueCodec[mapvalues.CancelLocationArg, *mapvalues.CancelLocationArg]()
}

// CancelLocationResCodec binds MAP-MS-DataTypes.CancelLocationRes.
func CancelLocationResCodec() mapvalues.ValueCodec[mapvalues.CancelLocationRes] {
	return compositeValueCodec[mapvalues.CancelLocationRes, *mapvalues.CancelLocationRes]()
}

// PurgeMSArgCodec binds MAP-MS-DataTypes.PurgeMS-Arg.
func PurgeMSArgCodec() mapvalues.ValueCodec[mapvalues.PurgeMSArg] {
	return compositeValueCodec[mapvalues.PurgeMSArg, *mapvalues.PurgeMSArg]()
}

// PurgeMSResCodec binds MAP-MS-DataTypes.PurgeMS-Res.
func PurgeMSResCodec() mapvalues.ValueCodec[mapvalues.PurgeMSRes] {
	return compositeValueCodec[mapvalues.PurgeMSRes, *mapvalues.PurgeMSRes]()
}

// SendIdentificationArgCodec binds MAP-MS-DataTypes.SendIdentificationArg.
func SendIdentificationArgCodec() mapvalues.ValueCodec[mapvalues.SendIdentificationArg] {
	return compositeValueCodec[mapvalues.SendIdentificationArg, *mapvalues.SendIdentificationArg]()
}

// SendIdentificationResCodec binds MAP-MS-DataTypes.SendIdentificationRes.
func SendIdentificationResCodec() mapvalues.ValueCodec[mapvalues.SendIdentificationRes] {
	return compositeValueCodec[mapvalues.SendIdentificationRes, *mapvalues.SendIdentificationRes]()
}

// AuthenticationSetListCodec binds MAP-MS-DataTypes.AuthenticationSetList.
func AuthenticationSetListCodec() mapvalues.ValueCodec[mapvalues.AuthenticationSetList] {
	return compositeValueCodec[mapvalues.AuthenticationSetList, *mapvalues.AuthenticationSetList]()
}

// TripletListCodec binds MAP-MS-DataTypes.TripletList.
func TripletListCodec() mapvalues.ValueCodec[mapvalues.TripletList] {
	return pointerValueCodec(mapvalues.UnmarshalBERTripletList, mapvalues.MarshalBERTripletList, mapvalues.MarshalDERTripletList)
}

// QuintupletListCodec binds MAP-MS-DataTypes.QuintupletList.
func QuintupletListCodec() mapvalues.ValueCodec[mapvalues.QuintupletList] {
	return pointerValueCodec(mapvalues.UnmarshalBERQuintupletList, mapvalues.MarshalBERQuintupletList, mapvalues.MarshalDERQuintupletList)
}

// AuthenticationTripletCodec binds MAP-MS-DataTypes.AuthenticationTriplet.
func AuthenticationTripletCodec() mapvalues.ValueCodec[mapvalues.AuthenticationTriplet] {
	return compositeValueCodec[mapvalues.AuthenticationTriplet, *mapvalues.AuthenticationTriplet]()
}

// AuthenticationQuintupletCodec binds MAP-MS-DataTypes.AuthenticationQuintuplet.
func AuthenticationQuintupletCodec() mapvalues.ValueCodec[mapvalues.AuthenticationQuintuplet] {
	return compositeValueCodec[mapvalues.AuthenticationQuintuplet, *mapvalues.AuthenticationQuintuplet]()
}

// CurrentSecurityContextCodec binds MAP-MS-DataTypes.CurrentSecurityContext.
func CurrentSecurityContextCodec() mapvalues.ValueCodec[mapvalues.CurrentSecurityContext] {
	return compositeValueCodec[mapvalues.CurrentSecurityContext, *mapvalues.CurrentSecurityContext]()
}

// GSMSecurityContextDataCodec binds MAP-MS-DataTypes.GSM-SecurityContextData.
func GSMSecurityContextDataCodec() mapvalues.ValueCodec[mapvalues.GSMSecurityContextData] {
	return compositeValueCodec[mapvalues.GSMSecurityContextData, *mapvalues.GSMSecurityContextData]()
}

// UMTSSecurityContextDataCodec binds MAP-MS-DataTypes.UMTS-SecurityContextData.
func UMTSSecurityContextDataCodec() mapvalues.ValueCodec[mapvalues.UMTSSecurityContextData] {
	return compositeValueCodec[mapvalues.UMTSSecurityContextData, *mapvalues.UMTSSecurityContextData]()
}

// AuthenticationFailureReportArgCodec binds MAP-MS-DataTypes.AuthenticationFailureReportArg.
func AuthenticationFailureReportArgCodec() mapvalues.ValueCodec[mapvalues.AuthenticationFailureReportArg] {
	return compositeValueCodec[mapvalues.AuthenticationFailureReportArg, *mapvalues.AuthenticationFailureReportArg]()
}

// AuthenticationFailureReportResCodec binds MAP-MS-DataTypes.AuthenticationFailureReportRes.
func AuthenticationFailureReportResCodec() mapvalues.ValueCodec[mapvalues.AuthenticationFailureReportRes] {
	return compositeValueCodec[mapvalues.AuthenticationFailureReportRes, *mapvalues.AuthenticationFailureReportRes]()
}

// UpdateGprsLocationArgCodec binds MAP-MS-DataTypes.UpdateGprsLocationArg.
func UpdateGprsLocationArgCodec() mapvalues.ValueCodec[mapvalues.UpdateGprsLocationArg] {
	return compositeValueCodec[mapvalues.UpdateGprsLocationArg, *mapvalues.UpdateGprsLocationArg]()
}

// EPSInfoCodec binds MAP-MS-DataTypes.EPS-Info.
func EPSInfoCodec() mapvalues.ValueCodec[mapvalues.EPSInfo] {
	return compositeValueCodec[mapvalues.EPSInfo, *mapvalues.EPSInfo]()
}

// PDNGWUpdateCodec binds MAP-MS-DataTypes.PDN-GW-Update.
func PDNGWUpdateCodec() mapvalues.ValueCodec[mapvalues.PDNGWUpdate] {
	return compositeValueCodec[mapvalues.PDNGWUpdate, *mapvalues.PDNGWUpdate]()
}

// SGSNCapabilityCodec binds MAP-MS-DataTypes.SGSN-Capability.
func SGSNCapabilityCodec() mapvalues.ValueCodec[mapvalues.SGSNCapability] {
	return compositeValueCodec[mapvalues.SGSNCapability, *mapvalues.SGSNCapability]()
}

// UpdateGprsLocationResCodec binds MAP-MS-DataTypes.UpdateGprsLocationRes.
func UpdateGprsLocationResCodec() mapvalues.ValueCodec[mapvalues.UpdateGprsLocationRes] {
	return compositeValueCodec[mapvalues.UpdateGprsLocationRes, *mapvalues.UpdateGprsLocationRes]()
}

// EPLMNListCodec binds MAP-MS-DataTypes.EPLMN-List.
func EPLMNListCodec() mapvalues.ValueCodec[mapvalues.EPLMNList] {
	return pointerValueCodec(mapvalues.UnmarshalBEREPLMNList, mapvalues.MarshalBEREPLMNList, mapvalues.MarshalDEREPLMNList)
}

// AdjacentPLMNListCodec binds MAP-MS-DataTypes.AdjacentPLMN-List.
func AdjacentPLMNListCodec() mapvalues.ValueCodec[mapvalues.AdjacentPLMNList] {
	return pointerValueCodec(mapvalues.UnmarshalBERAdjacentPLMNList, mapvalues.MarshalBERAdjacentPLMNList, mapvalues.MarshalDERAdjacentPLMNList)
}

// ForwardAccessSignallingArgCodec binds MAP-MS-DataTypes.ForwardAccessSignalling-Arg.
func ForwardAccessSignallingArgCodec() mapvalues.ValueCodec[mapvalues.ForwardAccessSignallingArg] {
	return compositeValueCodec[mapvalues.ForwardAccessSignallingArg, *mapvalues.ForwardAccessSignallingArg]()
}

// AllowedUMTSAlgorithmsCodec binds MAP-MS-DataTypes.AllowedUMTS-Algorithms.
func AllowedUMTSAlgorithmsCodec() mapvalues.ValueCodec[mapvalues.AllowedUMTSAlgorithms] {
	return compositeValueCodec[mapvalues.AllowedUMTSAlgorithms, *mapvalues.AllowedUMTSAlgorithms]()
}

// PrepareHOArgCodec binds MAP-MS-DataTypes.PrepareHO-Arg.
func PrepareHOArgCodec() mapvalues.ValueCodec[mapvalues.PrepareHOArg] {
	return compositeValueCodec[mapvalues.PrepareHOArg, *mapvalues.PrepareHOArg]()
}

// BSSMAPServiceHandoverListCodec binds MAP-MS-DataTypes.BSSMAP-ServiceHandoverList.
func BSSMAPServiceHandoverListCodec() mapvalues.ValueCodec[mapvalues.BSSMAPServiceHandoverList] {
	return pointerValueCodec(mapvalues.UnmarshalBERBSSMAPServiceHandoverList, mapvalues.MarshalBERBSSMAPServiceHandoverList, mapvalues.MarshalDERBSSMAPServiceHandoverList)
}

// BSSMAPServiceHandoverInfoCodec binds MAP-MS-DataTypes.BSSMAP-ServiceHandoverInfo.
func BSSMAPServiceHandoverInfoCodec() mapvalues.ValueCodec[mapvalues.BSSMAPServiceHandoverInfo] {
	return compositeValueCodec[mapvalues.BSSMAPServiceHandoverInfo, *mapvalues.BSSMAPServiceHandoverInfo]()
}

// RadioResourceListCodec binds MAP-MS-DataTypes.RadioResourceList.
func RadioResourceListCodec() mapvalues.ValueCodec[mapvalues.RadioResourceList] {
	return pointerValueCodec(mapvalues.UnmarshalBERRadioResourceList, mapvalues.MarshalBERRadioResourceList, mapvalues.MarshalDERRadioResourceList)
}

// RadioResourceCodec binds MAP-MS-DataTypes.RadioResource.
func RadioResourceCodec() mapvalues.ValueCodec[mapvalues.RadioResource] {
	return compositeValueCodec[mapvalues.RadioResource, *mapvalues.RadioResource]()
}

// PrepareHOResCodec binds MAP-MS-DataTypes.PrepareHO-Res.
func PrepareHOResCodec() mapvalues.ValueCodec[mapvalues.PrepareHORes] {
	return compositeValueCodec[mapvalues.PrepareHORes, *mapvalues.PrepareHORes]()
}

// SelectedUMTSAlgorithmsCodec binds MAP-MS-DataTypes.SelectedUMTS-Algorithms.
func SelectedUMTSAlgorithmsCodec() mapvalues.ValueCodec[mapvalues.SelectedUMTSAlgorithms] {
	return compositeValueCodec[mapvalues.SelectedUMTSAlgorithms, *mapvalues.SelectedUMTSAlgorithms]()
}

// ChosenRadioResourceInformationCodec binds MAP-MS-DataTypes.ChosenRadioResourceInformation.
func ChosenRadioResourceInformationCodec() mapvalues.ValueCodec[mapvalues.ChosenRadioResourceInformation] {
	return compositeValueCodec[mapvalues.ChosenRadioResourceInformation, *mapvalues.ChosenRadioResourceInformation]()
}

// PrepareSubsequentHOArgCodec binds MAP-MS-DataTypes.PrepareSubsequentHO-Arg.
func PrepareSubsequentHOArgCodec() mapvalues.ValueCodec[mapvalues.PrepareSubsequentHOArg] {
	return compositeValueCodec[mapvalues.PrepareSubsequentHOArg, *mapvalues.PrepareSubsequentHOArg]()
}

// PrepareSubsequentHOResCodec binds MAP-MS-DataTypes.PrepareSubsequentHO-Res.
func PrepareSubsequentHOResCodec() mapvalues.ValueCodec[mapvalues.PrepareSubsequentHORes] {
	return compositeValueCodec[mapvalues.PrepareSubsequentHORes, *mapvalues.PrepareSubsequentHORes]()
}

// ProcessAccessSignallingArgCodec binds MAP-MS-DataTypes.ProcessAccessSignalling-Arg.
func ProcessAccessSignallingArgCodec() mapvalues.ValueCodec[mapvalues.ProcessAccessSignallingArg] {
	return compositeValueCodec[mapvalues.ProcessAccessSignallingArg, *mapvalues.ProcessAccessSignallingArg]()
}

// AoIPCodecsListCodec binds MAP-MS-DataTypes.AoIPCodecsList.
func AoIPCodecsListCodec() mapvalues.ValueCodec[mapvalues.AoIPCodecsList] {
	return compositeValueCodec[mapvalues.AoIPCodecsList, *mapvalues.AoIPCodecsList]()
}

// SupportedCodecsListCodec binds MAP-MS-DataTypes.SupportedCodecsList.
func SupportedCodecsListCodec() mapvalues.ValueCodec[mapvalues.SupportedCodecsList] {
	return compositeValueCodec[mapvalues.SupportedCodecsList, *mapvalues.SupportedCodecsList]()
}

// CodecListCodec binds MAP-MS-DataTypes.CodecList.
func CodecListCodec() mapvalues.ValueCodec[mapvalues.CodecList] {
	return compositeValueCodec[mapvalues.CodecList, *mapvalues.CodecList]()
}

// SendEndSignalArgCodec binds MAP-MS-DataTypes.SendEndSignal-Arg.
func SendEndSignalArgCodec() mapvalues.ValueCodec[mapvalues.SendEndSignalArg] {
	return compositeValueCodec[mapvalues.SendEndSignalArg, *mapvalues.SendEndSignalArg]()
}

// SendEndSignalResCodec binds MAP-MS-DataTypes.SendEndSignal-Res.
func SendEndSignalResCodec() mapvalues.ValueCodec[mapvalues.SendEndSignalRes] {
	return compositeValueCodec[mapvalues.SendEndSignalRes, *mapvalues.SendEndSignalRes]()
}

// RelocationNumberListCodec binds MAP-MS-DataTypes.RelocationNumberList.
func RelocationNumberListCodec() mapvalues.ValueCodec[mapvalues.RelocationNumberList] {
	return pointerValueCodec(mapvalues.UnmarshalBERRelocationNumberList, mapvalues.MarshalBERRelocationNumberList, mapvalues.MarshalDERRelocationNumberList)
}

// RelocationNumberCodec binds MAP-MS-DataTypes.RelocationNumber.
func RelocationNumberCodec() mapvalues.ValueCodec[mapvalues.RelocationNumber] {
	return compositeValueCodec[mapvalues.RelocationNumber, *mapvalues.RelocationNumber]()
}

// SendAuthenticationInfoArgCodec binds MAP-MS-DataTypes.SendAuthenticationInfoArg.
func SendAuthenticationInfoArgCodec() mapvalues.ValueCodec[mapvalues.SendAuthenticationInfoArg] {
	return compositeValueCodec[mapvalues.SendAuthenticationInfoArg, *mapvalues.SendAuthenticationInfoArg]()
}

// ReSynchronisationInfoCodec binds MAP-MS-DataTypes.Re-synchronisationInfo.
func ReSynchronisationInfoCodec() mapvalues.ValueCodec[mapvalues.ReSynchronisationInfo] {
	return compositeValueCodec[mapvalues.ReSynchronisationInfo, *mapvalues.ReSynchronisationInfo]()
}

// SendAuthenticationInfoResCodec binds MAP-MS-DataTypes.SendAuthenticationInfoRes.
func SendAuthenticationInfoResCodec() mapvalues.ValueCodec[mapvalues.SendAuthenticationInfoRes] {
	return compositeValueCodec[mapvalues.SendAuthenticationInfoRes, *mapvalues.SendAuthenticationInfoRes]()
}

// EPSAuthenticationSetListCodec binds MAP-MS-DataTypes.EPS-AuthenticationSetList.
func EPSAuthenticationSetListCodec() mapvalues.ValueCodec[mapvalues.EPSAuthenticationSetList] {
	return pointerValueCodec(mapvalues.UnmarshalBEREPSAuthenticationSetList, mapvalues.MarshalBEREPSAuthenticationSetList, mapvalues.MarshalDEREPSAuthenticationSetList)
}

// EPCAVCodec binds MAP-MS-DataTypes.EPC-AV.
func EPCAVCodec() mapvalues.ValueCodec[mapvalues.EPCAV] {
	return compositeValueCodec[mapvalues.EPCAV, *mapvalues.EPCAV]()
}

// CheckIMEIArgCodec binds MAP-MS-DataTypes.CheckIMEI-Arg.
func CheckIMEIArgCodec() mapvalues.ValueCodec[mapvalues.CheckIMEIArg] {
	return compositeValueCodec[mapvalues.CheckIMEIArg, *mapvalues.CheckIMEIArg]()
}

// CheckIMEIResCodec binds MAP-MS-DataTypes.CheckIMEI-Res.
func CheckIMEIResCodec() mapvalues.ValueCodec[mapvalues.CheckIMEIRes] {
	return compositeValueCodec[mapvalues.CheckIMEIRes, *mapvalues.CheckIMEIRes]()
}

// UESBIIuCodec binds MAP-MS-DataTypes.UESBI-Iu.
func UESBIIuCodec() mapvalues.ValueCodec[mapvalues.UESBIIu] {
	return compositeValueCodec[mapvalues.UESBIIu, *mapvalues.UESBIIu]()
}

// InsertSubscriberDataArgCodec binds MAP-MS-DataTypes.InsertSubscriberDataArg.
func InsertSubscriberDataArgCodec() mapvalues.ValueCodec[mapvalues.InsertSubscriberDataArg] {
	return compositeValueCodec[mapvalues.InsertSubscriberDataArg, *mapvalues.InsertSubscriberDataArg]()
}

// EDRXCycleLengthListCodec binds MAP-MS-DataTypes.EDRX-Cycle-Length-List.
func EDRXCycleLengthListCodec() mapvalues.ValueCodec[mapvalues.EDRXCycleLengthList] {
	return pointerValueCodec(mapvalues.UnmarshalBEREDRXCycleLengthList, mapvalues.MarshalBEREDRXCycleLengthList, mapvalues.MarshalDEREDRXCycleLengthList)
}

// EDRXCycleLengthCodec binds MAP-MS-DataTypes.EDRX-Cycle-Length.
func EDRXCycleLengthCodec() mapvalues.ValueCodec[mapvalues.EDRXCycleLength] {
	return compositeValueCodec[mapvalues.EDRXCycleLength, *mapvalues.EDRXCycleLength]()
}

// ResetIdListCodec binds MAP-MS-DataTypes.Reset-Id-List.
func ResetIdListCodec() mapvalues.ValueCodec[mapvalues.ResetIdList] {
	return pointerValueCodec(mapvalues.UnmarshalBERResetIdList, mapvalues.MarshalBERResetIdList, mapvalues.MarshalDERResetIdList)
}

// IMSIGroupIdListCodec binds MAP-MS-DataTypes.IMSI-GroupIdList.
func IMSIGroupIdListCodec() mapvalues.ValueCodec[mapvalues.IMSIGroupIdList] {
	return pointerValueCodec(mapvalues.UnmarshalBERIMSIGroupIdList, mapvalues.MarshalBERIMSIGroupIdList, mapvalues.MarshalDERIMSIGroupIdList)
}

// IMSIGroupIdCodec binds MAP-MS-DataTypes.IMSI-GroupId.
func IMSIGroupIdCodec() mapvalues.ValueCodec[mapvalues.IMSIGroupId] {
	return compositeValueCodec[mapvalues.IMSIGroupId, *mapvalues.IMSIGroupId]()
}

// CSGSubscriptionDataListCodec binds MAP-MS-DataTypes.CSG-SubscriptionDataList.
func CSGSubscriptionDataListCodec() mapvalues.ValueCodec[mapvalues.CSGSubscriptionDataList] {
	return pointerValueCodec(mapvalues.UnmarshalBERCSGSubscriptionDataList, mapvalues.MarshalBERCSGSubscriptionDataList, mapvalues.MarshalDERCSGSubscriptionDataList)
}

// CSGSubscriptionDataCodec binds MAP-MS-DataTypes.CSG-SubscriptionData.
func CSGSubscriptionDataCodec() mapvalues.ValueCodec[mapvalues.CSGSubscriptionData] {
	return compositeValueCodec[mapvalues.CSGSubscriptionData, *mapvalues.CSGSubscriptionData]()
}

// VPLMNCSGSubscriptionDataListCodec binds MAP-MS-DataTypes.VPLMN-CSG-SubscriptionDataList.
func VPLMNCSGSubscriptionDataListCodec() mapvalues.ValueCodec[mapvalues.VPLMNCSGSubscriptionDataList] {
	return pointerValueCodec(mapvalues.UnmarshalBERVPLMNCSGSubscriptionDataList, mapvalues.MarshalBERVPLMNCSGSubscriptionDataList, mapvalues.MarshalDERVPLMNCSGSubscriptionDataList)
}

// LIPAAllowedAPNListCodec binds MAP-MS-DataTypes.LIPA-AllowedAPNList.
func LIPAAllowedAPNListCodec() mapvalues.ValueCodec[mapvalues.LIPAAllowedAPNList] {
	return pointerValueCodec(mapvalues.UnmarshalBERLIPAAllowedAPNList, mapvalues.MarshalBERLIPAAllowedAPNList, mapvalues.MarshalDERLIPAAllowedAPNList)
}

// EPSSubscriptionDataCodec binds MAP-MS-DataTypes.EPS-SubscriptionData.
func EPSSubscriptionDataCodec() mapvalues.ValueCodec[mapvalues.EPSSubscriptionData] {
	return compositeValueCodec[mapvalues.EPSSubscriptionData, *mapvalues.EPSSubscriptionData]()
}

// APNConfigurationProfileCodec binds MAP-MS-DataTypes.APN-ConfigurationProfile.
func APNConfigurationProfileCodec() mapvalues.ValueCodec[mapvalues.APNConfigurationProfile] {
	return compositeValueCodec[mapvalues.APNConfigurationProfile, *mapvalues.APNConfigurationProfile]()
}

// EPSDataListCodec binds MAP-MS-DataTypes.EPS-DataList.
func EPSDataListCodec() mapvalues.ValueCodec[mapvalues.EPSDataList] {
	return pointerValueCodec(mapvalues.UnmarshalBEREPSDataList, mapvalues.MarshalBEREPSDataList, mapvalues.MarshalDEREPSDataList)
}

// APNConfigurationCodec binds MAP-MS-DataTypes.APN-Configuration.
func APNConfigurationCodec() mapvalues.ValueCodec[mapvalues.APNConfiguration] {
	return compositeValueCodec[mapvalues.APNConfiguration, *mapvalues.APNConfiguration]()
}

// EPSQoSSubscribedCodec binds MAP-MS-DataTypes.EPS-QoS-Subscribed.
func EPSQoSSubscribedCodec() mapvalues.ValueCodec[mapvalues.EPSQoSSubscribed] {
	return compositeValueCodec[mapvalues.EPSQoSSubscribed, *mapvalues.EPSQoSSubscribed]()
}

// AMBRCodec binds MAP-MS-DataTypes.AMBR.
func AMBRCodec() mapvalues.ValueCodec[mapvalues.AMBR] {
	return compositeValueCodec[mapvalues.AMBR, *mapvalues.AMBR]()
}

// SpecificAPNInfoListCodec binds MAP-MS-DataTypes.SpecificAPNInfoList.
func SpecificAPNInfoListCodec() mapvalues.ValueCodec[mapvalues.SpecificAPNInfoList] {
	return pointerValueCodec(mapvalues.UnmarshalBERSpecificAPNInfoList, mapvalues.MarshalBERSpecificAPNInfoList, mapvalues.MarshalDERSpecificAPNInfoList)
}

// SpecificAPNInfoCodec binds MAP-MS-DataTypes.SpecificAPNInfo.
func SpecificAPNInfoCodec() mapvalues.ValueCodec[mapvalues.SpecificAPNInfo] {
	return compositeValueCodec[mapvalues.SpecificAPNInfo, *mapvalues.SpecificAPNInfo]()
}

// AllocationRetentionPriorityCodec binds MAP-MS-DataTypes.Allocation-Retention-Priority.
func AllocationRetentionPriorityCodec() mapvalues.ValueCodec[mapvalues.AllocationRetentionPriority] {
	return compositeValueCodec[mapvalues.AllocationRetentionPriority, *mapvalues.AllocationRetentionPriority]()
}

// PDNGWIdentityCodec binds MAP-MS-DataTypes.PDN-GW-Identity.
func PDNGWIdentityCodec() mapvalues.ValueCodec[mapvalues.PDNGWIdentity] {
	return compositeValueCodec[mapvalues.PDNGWIdentity, *mapvalues.PDNGWIdentity]()
}

// WLANOffloadabilityCodec binds MAP-MS-DataTypes.WLAN-Offloadability.
func WLANOffloadabilityCodec() mapvalues.ValueCodec[mapvalues.WLANOffloadability] {
	return compositeValueCodec[mapvalues.WLANOffloadability, *mapvalues.WLANOffloadability]()
}

// AdjacentAccessRestrictionDataListCodec binds MAP-MS-DataTypes.AdjacentAccessRestrictionDataList.
func AdjacentAccessRestrictionDataListCodec() mapvalues.ValueCodec[mapvalues.AdjacentAccessRestrictionDataList] {
	return pointerValueCodec(mapvalues.UnmarshalBERAdjacentAccessRestrictionDataList, mapvalues.MarshalBERAdjacentAccessRestrictionDataList, mapvalues.MarshalDERAdjacentAccessRestrictionDataList)
}

// AdjacentAccessRestrictionDataCodec binds MAP-MS-DataTypes.AdjacentAccessRestrictionData.
func AdjacentAccessRestrictionDataCodec() mapvalues.ValueCodec[mapvalues.AdjacentAccessRestrictionData] {
	return compositeValueCodec[mapvalues.AdjacentAccessRestrictionData, *mapvalues.AdjacentAccessRestrictionData]()
}

// LCSInformationCodec binds MAP-MS-DataTypes.LCSInformation.
func LCSInformationCodec() mapvalues.ValueCodec[mapvalues.LCSInformation] {
	return compositeValueCodec[mapvalues.LCSInformation, *mapvalues.LCSInformation]()
}

// GMLCListCodec binds MAP-MS-DataTypes.GMLC-List.
func GMLCListCodec() mapvalues.ValueCodec[mapvalues.GMLCList] {
	return pointerValueCodec(mapvalues.UnmarshalBERGMLCList, mapvalues.MarshalBERGMLCList, mapvalues.MarshalDERGMLCList)
}

// GPRSDataListCodec binds MAP-MS-DataTypes.GPRSDataList.
func GPRSDataListCodec() mapvalues.ValueCodec[mapvalues.GPRSDataList] {
	return pointerValueCodec(mapvalues.UnmarshalBERGPRSDataList, mapvalues.MarshalBERGPRSDataList, mapvalues.MarshalDERGPRSDataList)
}

// PDPContextCodec binds MAP-MS-DataTypes.PDP-Context.
func PDPContextCodec() mapvalues.ValueCodec[mapvalues.PDPContext] {
	return compositeValueCodec[mapvalues.PDPContext, *mapvalues.PDPContext]()
}

// GPRSSubscriptionDataCodec binds MAP-MS-DataTypes.GPRSSubscriptionData.
func GPRSSubscriptionDataCodec() mapvalues.ValueCodec[mapvalues.GPRSSubscriptionData] {
	return compositeValueCodec[mapvalues.GPRSSubscriptionData, *mapvalues.GPRSSubscriptionData]()
}

// SGSNCAMELSubscriptionInfoCodec binds MAP-MS-DataTypes.SGSN-CAMEL-SubscriptionInfo.
func SGSNCAMELSubscriptionInfoCodec() mapvalues.ValueCodec[mapvalues.SGSNCAMELSubscriptionInfo] {
	return compositeValueCodec[mapvalues.SGSNCAMELSubscriptionInfo, *mapvalues.SGSNCAMELSubscriptionInfo]()
}

// GPRSCSICodec binds MAP-MS-DataTypes.GPRS-CSI.
func GPRSCSICodec() mapvalues.ValueCodec[mapvalues.GPRSCSI] {
	return compositeValueCodec[mapvalues.GPRSCSI, *mapvalues.GPRSCSI]()
}

// GPRSCamelTDPDataListCodec binds MAP-MS-DataTypes.GPRS-CamelTDPDataList.
func GPRSCamelTDPDataListCodec() mapvalues.ValueCodec[mapvalues.GPRSCamelTDPDataList] {
	return pointerValueCodec(mapvalues.UnmarshalBERGPRSCamelTDPDataList, mapvalues.MarshalBERGPRSCamelTDPDataList, mapvalues.MarshalDERGPRSCamelTDPDataList)
}

// GPRSCamelTDPDataCodec binds MAP-MS-DataTypes.GPRS-CamelTDPData.
func GPRSCamelTDPDataCodec() mapvalues.ValueCodec[mapvalues.GPRSCamelTDPData] {
	return compositeValueCodec[mapvalues.GPRSCamelTDPData, *mapvalues.GPRSCamelTDPData]()
}

// LSADataListCodec binds MAP-MS-DataTypes.LSADataList.
func LSADataListCodec() mapvalues.ValueCodec[mapvalues.LSADataList] {
	return pointerValueCodec(mapvalues.UnmarshalBERLSADataList, mapvalues.MarshalBERLSADataList, mapvalues.MarshalDERLSADataList)
}

// LSADataCodec binds MAP-MS-DataTypes.LSAData.
func LSADataCodec() mapvalues.ValueCodec[mapvalues.LSAData] {
	return compositeValueCodec[mapvalues.LSAData, *mapvalues.LSAData]()
}

// LSAInformationCodec binds MAP-MS-DataTypes.LSAInformation.
func LSAInformationCodec() mapvalues.ValueCodec[mapvalues.LSAInformation] {
	return compositeValueCodec[mapvalues.LSAInformation, *mapvalues.LSAInformation]()
}

// SubscriberDataCodec binds MAP-MS-DataTypes.SubscriberData.
func SubscriberDataCodec() mapvalues.ValueCodec[mapvalues.SubscriberData] {
	return compositeValueCodec[mapvalues.SubscriberData, *mapvalues.SubscriberData]()
}

// BearerServiceListCodec binds MAP-MS-DataTypes.BearerServiceList.
func BearerServiceListCodec() mapvalues.ValueCodec[mapvalues.BearerServiceList] {
	return pointerValueCodec(mapvalues.UnmarshalBERBearerServiceList, mapvalues.MarshalBERBearerServiceList, mapvalues.MarshalDERBearerServiceList)
}

// TeleserviceListCodec binds MAP-MS-DataTypes.TeleserviceList.
func TeleserviceListCodec() mapvalues.ValueCodec[mapvalues.TeleserviceList] {
	return pointerValueCodec(mapvalues.UnmarshalBERTeleserviceList, mapvalues.MarshalBERTeleserviceList, mapvalues.MarshalDERTeleserviceList)
}

// ODBDataCodec binds MAP-MS-DataTypes.ODB-Data.
func ODBDataCodec() mapvalues.ValueCodec[mapvalues.ODBData] {
	return compositeValueCodec[mapvalues.ODBData, *mapvalues.ODBData]()
}

// ExtSSInfoListCodec binds MAP-MS-DataTypes.Ext-SS-InfoList.
func ExtSSInfoListCodec() mapvalues.ValueCodec[mapvalues.ExtSSInfoList] {
	return pointerValueCodec(mapvalues.UnmarshalBERExtSSInfoList, mapvalues.MarshalBERExtSSInfoList, mapvalues.MarshalDERExtSSInfoList)
}

// ExtSSInfoCodec binds MAP-MS-DataTypes.Ext-SS-Info.
func ExtSSInfoCodec() mapvalues.ValueCodec[mapvalues.ExtSSInfo] {
	return compositeValueCodec[mapvalues.ExtSSInfo, *mapvalues.ExtSSInfo]()
}

// ExtForwInfoCodec binds MAP-MS-DataTypes.Ext-ForwInfo.
func ExtForwInfoCodec() mapvalues.ValueCodec[mapvalues.ExtForwInfo] {
	return compositeValueCodec[mapvalues.ExtForwInfo, *mapvalues.ExtForwInfo]()
}

// ExtForwFeatureListCodec binds MAP-MS-DataTypes.Ext-ForwFeatureList.
func ExtForwFeatureListCodec() mapvalues.ValueCodec[mapvalues.ExtForwFeatureList] {
	return pointerValueCodec(mapvalues.UnmarshalBERExtForwFeatureList, mapvalues.MarshalBERExtForwFeatureList, mapvalues.MarshalDERExtForwFeatureList)
}

// ExtForwFeatureCodec binds MAP-MS-DataTypes.Ext-ForwFeature.
func ExtForwFeatureCodec() mapvalues.ValueCodec[mapvalues.ExtForwFeature] {
	return compositeValueCodec[mapvalues.ExtForwFeature, *mapvalues.ExtForwFeature]()
}

// ExtCallBarInfoCodec binds MAP-MS-DataTypes.Ext-CallBarInfo.
func ExtCallBarInfoCodec() mapvalues.ValueCodec[mapvalues.ExtCallBarInfo] {
	return compositeValueCodec[mapvalues.ExtCallBarInfo, *mapvalues.ExtCallBarInfo]()
}

// ExtCallBarFeatureListCodec binds MAP-MS-DataTypes.Ext-CallBarFeatureList.
func ExtCallBarFeatureListCodec() mapvalues.ValueCodec[mapvalues.ExtCallBarFeatureList] {
	return pointerValueCodec(mapvalues.UnmarshalBERExtCallBarFeatureList, mapvalues.MarshalBERExtCallBarFeatureList, mapvalues.MarshalDERExtCallBarFeatureList)
}

// ExtCallBarringFeatureCodec binds MAP-MS-DataTypes.Ext-CallBarringFeature.
func ExtCallBarringFeatureCodec() mapvalues.ValueCodec[mapvalues.ExtCallBarringFeature] {
	return compositeValueCodec[mapvalues.ExtCallBarringFeature, *mapvalues.ExtCallBarringFeature]()
}

// CUGInfoCodec binds MAP-MS-DataTypes.CUG-Info.
func CUGInfoCodec() mapvalues.ValueCodec[mapvalues.CUGInfo] {
	return compositeValueCodec[mapvalues.CUGInfo, *mapvalues.CUGInfo]()
}

// CUGSubscriptionListCodec binds MAP-MS-DataTypes.CUG-SubscriptionList.
func CUGSubscriptionListCodec() mapvalues.ValueCodec[mapvalues.CUGSubscriptionList] {
	return pointerValueCodec(mapvalues.UnmarshalBERCUGSubscriptionList, mapvalues.MarshalBERCUGSubscriptionList, mapvalues.MarshalDERCUGSubscriptionList)
}

// CUGSubscriptionCodec binds MAP-MS-DataTypes.CUG-Subscription.
func CUGSubscriptionCodec() mapvalues.ValueCodec[mapvalues.CUGSubscription] {
	return compositeValueCodec[mapvalues.CUGSubscription, *mapvalues.CUGSubscription]()
}

// CUGFeatureListCodec binds MAP-MS-DataTypes.CUG-FeatureList.
func CUGFeatureListCodec() mapvalues.ValueCodec[mapvalues.CUGFeatureList] {
	return pointerValueCodec(mapvalues.UnmarshalBERCUGFeatureList, mapvalues.MarshalBERCUGFeatureList, mapvalues.MarshalDERCUGFeatureList)
}

// ExtBasicServiceGroupListCodec binds MAP-MS-DataTypes.Ext-BasicServiceGroupList.
func ExtBasicServiceGroupListCodec() mapvalues.ValueCodec[mapvalues.ExtBasicServiceGroupList] {
	return pointerValueCodec(mapvalues.UnmarshalBERExtBasicServiceGroupList, mapvalues.MarshalBERExtBasicServiceGroupList, mapvalues.MarshalDERExtBasicServiceGroupList)
}

// CUGFeatureCodec binds MAP-MS-DataTypes.CUG-Feature.
func CUGFeatureCodec() mapvalues.ValueCodec[mapvalues.CUGFeature] {
	return compositeValueCodec[mapvalues.CUGFeature, *mapvalues.CUGFeature]()
}

// ExtSSDataCodec binds MAP-MS-DataTypes.Ext-SS-Data.
func ExtSSDataCodec() mapvalues.ValueCodec[mapvalues.ExtSSData] {
	return compositeValueCodec[mapvalues.ExtSSData, *mapvalues.ExtSSData]()
}

// LCSPrivacyExceptionListCodec binds MAP-MS-DataTypes.LCS-PrivacyExceptionList.
func LCSPrivacyExceptionListCodec() mapvalues.ValueCodec[mapvalues.LCSPrivacyExceptionList] {
	return pointerValueCodec(mapvalues.UnmarshalBERLCSPrivacyExceptionList, mapvalues.MarshalBERLCSPrivacyExceptionList, mapvalues.MarshalDERLCSPrivacyExceptionList)
}

// LCSPrivacyClassCodec binds MAP-MS-DataTypes.LCS-PrivacyClass.
func LCSPrivacyClassCodec() mapvalues.ValueCodec[mapvalues.LCSPrivacyClass] {
	return compositeValueCodec[mapvalues.LCSPrivacyClass, *mapvalues.LCSPrivacyClass]()
}

// ExternalClientListCodec binds MAP-MS-DataTypes.ExternalClientList.
func ExternalClientListCodec() mapvalues.ValueCodec[mapvalues.ExternalClientList] {
	return pointerValueCodec(mapvalues.UnmarshalBERExternalClientList, mapvalues.MarshalBERExternalClientList, mapvalues.MarshalDERExternalClientList)
}

// PLMNClientListCodec binds MAP-MS-DataTypes.PLMNClientList.
func PLMNClientListCodec() mapvalues.ValueCodec[mapvalues.PLMNClientList] {
	return pointerValueCodec(mapvalues.UnmarshalBERPLMNClientList, mapvalues.MarshalBERPLMNClientList, mapvalues.MarshalDERPLMNClientList)
}

// ExtExternalClientListCodec binds MAP-MS-DataTypes.Ext-ExternalClientList.
func ExtExternalClientListCodec() mapvalues.ValueCodec[mapvalues.ExtExternalClientList] {
	return pointerValueCodec(mapvalues.UnmarshalBERExtExternalClientList, mapvalues.MarshalBERExtExternalClientList, mapvalues.MarshalDERExtExternalClientList)
}

// ExternalClientCodec binds MAP-MS-DataTypes.ExternalClient.
func ExternalClientCodec() mapvalues.ValueCodec[mapvalues.ExternalClient] {
	return compositeValueCodec[mapvalues.ExternalClient, *mapvalues.ExternalClient]()
}

// ServiceTypeListCodec binds MAP-MS-DataTypes.ServiceTypeList.
func ServiceTypeListCodec() mapvalues.ValueCodec[mapvalues.ServiceTypeList] {
	return pointerValueCodec(mapvalues.UnmarshalBERServiceTypeList, mapvalues.MarshalBERServiceTypeList, mapvalues.MarshalDERServiceTypeList)
}

// ServiceTypeCodec binds MAP-MS-DataTypes.ServiceType.
func ServiceTypeCodec() mapvalues.ValueCodec[mapvalues.ServiceType] {
	return compositeValueCodec[mapvalues.ServiceType, *mapvalues.ServiceType]()
}

// MOLRListCodec binds MAP-MS-DataTypes.MOLR-List.
func MOLRListCodec() mapvalues.ValueCodec[mapvalues.MOLRList] {
	return pointerValueCodec(mapvalues.UnmarshalBERMOLRList, mapvalues.MarshalBERMOLRList, mapvalues.MarshalDERMOLRList)
}

// MOLRClassCodec binds MAP-MS-DataTypes.MOLR-Class.
func MOLRClassCodec() mapvalues.ValueCodec[mapvalues.MOLRClass] {
	return compositeValueCodec[mapvalues.MOLRClass, *mapvalues.MOLRClass]()
}

// ZoneCodeListCodec binds MAP-MS-DataTypes.ZoneCodeList.
func ZoneCodeListCodec() mapvalues.ValueCodec[mapvalues.ZoneCodeList] {
	return pointerValueCodec(mapvalues.UnmarshalBERZoneCodeList, mapvalues.MarshalBERZoneCodeList, mapvalues.MarshalDERZoneCodeList)
}

// InsertSubscriberDataResCodec binds MAP-MS-DataTypes.InsertSubscriberDataRes.
func InsertSubscriberDataResCodec() mapvalues.ValueCodec[mapvalues.InsertSubscriberDataRes] {
	return compositeValueCodec[mapvalues.InsertSubscriberDataRes, *mapvalues.InsertSubscriberDataRes]()
}

// DeleteSubscriberDataArgCodec binds MAP-MS-DataTypes.DeleteSubscriberDataArg.
func DeleteSubscriberDataArgCodec() mapvalues.ValueCodec[mapvalues.DeleteSubscriberDataArg] {
	return compositeValueCodec[mapvalues.DeleteSubscriberDataArg, *mapvalues.DeleteSubscriberDataArg]()
}

// GPRSSubscriptionDataWithdrawCodec binds MAP-MS-DataTypes.GPRSSubscriptionDataWithdraw.
func GPRSSubscriptionDataWithdrawCodec() mapvalues.ValueCodec[mapvalues.GPRSSubscriptionDataWithdraw] {
	return compositeValueCodec[mapvalues.GPRSSubscriptionDataWithdraw, *mapvalues.GPRSSubscriptionDataWithdraw]()
}

// EPSSubscriptionDataWithdrawCodec binds MAP-MS-DataTypes.EPS-SubscriptionDataWithdraw.
func EPSSubscriptionDataWithdrawCodec() mapvalues.ValueCodec[mapvalues.EPSSubscriptionDataWithdraw] {
	return compositeValueCodec[mapvalues.EPSSubscriptionDataWithdraw, *mapvalues.EPSSubscriptionDataWithdraw]()
}

// ContextIdListCodec binds MAP-MS-DataTypes.ContextIdList.
func ContextIdListCodec() mapvalues.ValueCodec[mapvalues.ContextIdList] {
	return pointerValueCodec(mapvalues.UnmarshalBERContextIdList, mapvalues.MarshalBERContextIdList, mapvalues.MarshalDERContextIdList)
}

// LSAInformationWithdrawCodec binds MAP-MS-DataTypes.LSAInformationWithdraw.
func LSAInformationWithdrawCodec() mapvalues.ValueCodec[mapvalues.LSAInformationWithdraw] {
	return compositeValueCodec[mapvalues.LSAInformationWithdraw, *mapvalues.LSAInformationWithdraw]()
}

// LSAIdentityListCodec binds MAP-MS-DataTypes.LSAIdentityList.
func LSAIdentityListCodec() mapvalues.ValueCodec[mapvalues.LSAIdentityList] {
	return pointerValueCodec(mapvalues.UnmarshalBERLSAIdentityList, mapvalues.MarshalBERLSAIdentityList, mapvalues.MarshalDERLSAIdentityList)
}

// BasicServiceListCodec binds MAP-MS-DataTypes.BasicServiceList.
func BasicServiceListCodec() mapvalues.ValueCodec[mapvalues.BasicServiceList] {
	return pointerValueCodec(mapvalues.UnmarshalBERBasicServiceList, mapvalues.MarshalBERBasicServiceList, mapvalues.MarshalDERBasicServiceList)
}

// DeleteSubscriberDataResCodec binds MAP-MS-DataTypes.DeleteSubscriberDataRes.
func DeleteSubscriberDataResCodec() mapvalues.ValueCodec[mapvalues.DeleteSubscriberDataRes] {
	return compositeValueCodec[mapvalues.DeleteSubscriberDataRes, *mapvalues.DeleteSubscriberDataRes]()
}

// VlrCamelSubscriptionInfoCodec binds MAP-MS-DataTypes.VlrCamelSubscriptionInfo.
func VlrCamelSubscriptionInfoCodec() mapvalues.ValueCodec[mapvalues.VlrCamelSubscriptionInfo] {
	return compositeValueCodec[mapvalues.VlrCamelSubscriptionInfo, *mapvalues.VlrCamelSubscriptionInfo]()
}

// MTSmsCAMELTDPCriteriaListCodec binds MAP-MS-DataTypes.MT-smsCAMELTDP-CriteriaList.
func MTSmsCAMELTDPCriteriaListCodec() mapvalues.ValueCodec[mapvalues.MTSmsCAMELTDPCriteriaList] {
	return pointerValueCodec(mapvalues.UnmarshalBERMTSmsCAMELTDPCriteriaList, mapvalues.MarshalBERMTSmsCAMELTDPCriteriaList, mapvalues.MarshalDERMTSmsCAMELTDPCriteriaList)
}

// MTSmsCAMELTDPCriteriaCodec binds MAP-MS-DataTypes.MT-smsCAMELTDP-Criteria.
func MTSmsCAMELTDPCriteriaCodec() mapvalues.ValueCodec[mapvalues.MTSmsCAMELTDPCriteria] {
	return compositeValueCodec[mapvalues.MTSmsCAMELTDPCriteria, *mapvalues.MTSmsCAMELTDPCriteria]()
}

// TPDUTypeCriterionCodec binds MAP-MS-DataTypes.TPDU-TypeCriterion.
func TPDUTypeCriterionCodec() mapvalues.ValueCodec[mapvalues.TPDUTypeCriterion] {
	return pointerValueCodec(mapvalues.UnmarshalBERTPDUTypeCriterion, mapvalues.MarshalBERTPDUTypeCriterion, mapvalues.MarshalDERTPDUTypeCriterion)
}

// DCSICodec binds MAP-MS-DataTypes.D-CSI.
func DCSICodec() mapvalues.ValueCodec[mapvalues.DCSI] {
	return compositeValueCodec[mapvalues.DCSI, *mapvalues.DCSI]()
}

// DPAnalysedInfoCriteriaListCodec binds MAP-MS-DataTypes.DP-AnalysedInfoCriteriaList.
func DPAnalysedInfoCriteriaListCodec() mapvalues.ValueCodec[mapvalues.DPAnalysedInfoCriteriaList] {
	return pointerValueCodec(mapvalues.UnmarshalBERDPAnalysedInfoCriteriaList, mapvalues.MarshalBERDPAnalysedInfoCriteriaList, mapvalues.MarshalDERDPAnalysedInfoCriteriaList)
}

// DPAnalysedInfoCriteriumCodec binds MAP-MS-DataTypes.DP-AnalysedInfoCriterium.
func DPAnalysedInfoCriteriumCodec() mapvalues.ValueCodec[mapvalues.DPAnalysedInfoCriterium] {
	return compositeValueCodec[mapvalues.DPAnalysedInfoCriterium, *mapvalues.DPAnalysedInfoCriterium]()
}

// SSCSICodec binds MAP-MS-DataTypes.SS-CSI.
func SSCSICodec() mapvalues.ValueCodec[mapvalues.SSCSI] {
	return compositeValueCodec[mapvalues.SSCSI, *mapvalues.SSCSI]()
}

// SSCamelDataCodec binds MAP-MS-DataTypes.SS-CamelData.
func SSCamelDataCodec() mapvalues.ValueCodec[mapvalues.SSCamelData] {
	return compositeValueCodec[mapvalues.SSCamelData, *mapvalues.SSCamelData]()
}

// SSEventListCodec binds MAP-MS-DataTypes.SS-EventList.
func SSEventListCodec() mapvalues.ValueCodec[mapvalues.SSEventList] {
	return pointerValueCodec(mapvalues.UnmarshalBERSSEventList, mapvalues.MarshalBERSSEventList, mapvalues.MarshalDERSSEventList)
}

// OCSICodec binds MAP-MS-DataTypes.O-CSI.
func OCSICodec() mapvalues.ValueCodec[mapvalues.OCSI] {
	return compositeValueCodec[mapvalues.OCSI, *mapvalues.OCSI]()
}

// OBcsmCamelTDPDataListCodec binds MAP-MS-DataTypes.O-BcsmCamelTDPDataList.
func OBcsmCamelTDPDataListCodec() mapvalues.ValueCodec[mapvalues.OBcsmCamelTDPDataList] {
	return pointerValueCodec(mapvalues.UnmarshalBEROBcsmCamelTDPDataList, mapvalues.MarshalBEROBcsmCamelTDPDataList, mapvalues.MarshalDEROBcsmCamelTDPDataList)
}

// OBcsmCamelTDPDataCodec binds MAP-MS-DataTypes.O-BcsmCamelTDPData.
func OBcsmCamelTDPDataCodec() mapvalues.ValueCodec[mapvalues.OBcsmCamelTDPData] {
	return compositeValueCodec[mapvalues.OBcsmCamelTDPData, *mapvalues.OBcsmCamelTDPData]()
}

// OBcsmCamelTDPCriteriaListCodec binds MAP-MS-DataTypes.O-BcsmCamelTDPCriteriaList.
func OBcsmCamelTDPCriteriaListCodec() mapvalues.ValueCodec[mapvalues.OBcsmCamelTDPCriteriaList] {
	return pointerValueCodec(mapvalues.UnmarshalBEROBcsmCamelTDPCriteriaList, mapvalues.MarshalBEROBcsmCamelTDPCriteriaList, mapvalues.MarshalDEROBcsmCamelTDPCriteriaList)
}

// TBCSMCAMELTDPCriteriaListCodec binds MAP-MS-DataTypes.T-BCSM-CAMEL-TDP-CriteriaList.
func TBCSMCAMELTDPCriteriaListCodec() mapvalues.ValueCodec[mapvalues.TBCSMCAMELTDPCriteriaList] {
	return pointerValueCodec(mapvalues.UnmarshalBERTBCSMCAMELTDPCriteriaList, mapvalues.MarshalBERTBCSMCAMELTDPCriteriaList, mapvalues.MarshalDERTBCSMCAMELTDPCriteriaList)
}

// OBcsmCamelTDPCriteriaCodec binds MAP-MS-DataTypes.O-BcsmCamelTDP-Criteria.
func OBcsmCamelTDPCriteriaCodec() mapvalues.ValueCodec[mapvalues.OBcsmCamelTDPCriteria] {
	return compositeValueCodec[mapvalues.OBcsmCamelTDPCriteria, *mapvalues.OBcsmCamelTDPCriteria]()
}

// TBCSMCAMELTDPCriteriaCodec binds MAP-MS-DataTypes.T-BCSM-CAMEL-TDP-Criteria.
func TBCSMCAMELTDPCriteriaCodec() mapvalues.ValueCodec[mapvalues.TBCSMCAMELTDPCriteria] {
	return compositeValueCodec[mapvalues.TBCSMCAMELTDPCriteria, *mapvalues.TBCSMCAMELTDPCriteria]()
}

// DestinationNumberCriteriaCodec binds MAP-MS-DataTypes.DestinationNumberCriteria.
func DestinationNumberCriteriaCodec() mapvalues.ValueCodec[mapvalues.DestinationNumberCriteria] {
	return compositeValueCodec[mapvalues.DestinationNumberCriteria, *mapvalues.DestinationNumberCriteria]()
}

// DestinationNumberListCodec binds MAP-MS-DataTypes.DestinationNumberList.
func DestinationNumberListCodec() mapvalues.ValueCodec[mapvalues.DestinationNumberList] {
	return pointerValueCodec(mapvalues.UnmarshalBERDestinationNumberList, mapvalues.MarshalBERDestinationNumberList, mapvalues.MarshalDERDestinationNumberList)
}

// DestinationNumberLengthListCodec binds MAP-MS-DataTypes.DestinationNumberLengthList.
func DestinationNumberLengthListCodec() mapvalues.ValueCodec[mapvalues.DestinationNumberLengthList] {
	return pointerValueCodec(mapvalues.UnmarshalBERDestinationNumberLengthList, mapvalues.MarshalBERDestinationNumberLengthList, mapvalues.MarshalDERDestinationNumberLengthList)
}

// BasicServiceCriteriaCodec binds MAP-MS-DataTypes.BasicServiceCriteria.
func BasicServiceCriteriaCodec() mapvalues.ValueCodec[mapvalues.BasicServiceCriteria] {
	return pointerValueCodec(mapvalues.UnmarshalBERBasicServiceCriteria, mapvalues.MarshalBERBasicServiceCriteria, mapvalues.MarshalDERBasicServiceCriteria)
}

// OCauseValueCriteriaCodec binds MAP-MS-DataTypes.O-CauseValueCriteria.
func OCauseValueCriteriaCodec() mapvalues.ValueCodec[mapvalues.OCauseValueCriteria] {
	return pointerValueCodec(mapvalues.UnmarshalBEROCauseValueCriteria, mapvalues.MarshalBEROCauseValueCriteria, mapvalues.MarshalDEROCauseValueCriteria)
}

// TCauseValueCriteriaCodec binds MAP-MS-DataTypes.T-CauseValueCriteria.
func TCauseValueCriteriaCodec() mapvalues.ValueCodec[mapvalues.TCauseValueCriteria] {
	return pointerValueCodec(mapvalues.UnmarshalBERTCauseValueCriteria, mapvalues.MarshalBERTCauseValueCriteria, mapvalues.MarshalDERTCauseValueCriteria)
}

// SMSCSICodec binds MAP-MS-DataTypes.SMS-CSI.
func SMSCSICodec() mapvalues.ValueCodec[mapvalues.SMSCSI] {
	return compositeValueCodec[mapvalues.SMSCSI, *mapvalues.SMSCSI]()
}

// SMSCAMELTDPDataListCodec binds MAP-MS-DataTypes.SMS-CAMEL-TDP-DataList.
func SMSCAMELTDPDataListCodec() mapvalues.ValueCodec[mapvalues.SMSCAMELTDPDataList] {
	return pointerValueCodec(mapvalues.UnmarshalBERSMSCAMELTDPDataList, mapvalues.MarshalBERSMSCAMELTDPDataList, mapvalues.MarshalDERSMSCAMELTDPDataList)
}

// SMSCAMELTDPDataCodec binds MAP-MS-DataTypes.SMS-CAMEL-TDP-Data.
func SMSCAMELTDPDataCodec() mapvalues.ValueCodec[mapvalues.SMSCAMELTDPData] {
	return compositeValueCodec[mapvalues.SMSCAMELTDPData, *mapvalues.SMSCAMELTDPData]()
}

// MCSICodec binds MAP-MS-DataTypes.M-CSI.
func MCSICodec() mapvalues.ValueCodec[mapvalues.MCSI] {
	return compositeValueCodec[mapvalues.MCSI, *mapvalues.MCSI]()
}

// MGCSICodec binds MAP-MS-DataTypes.MG-CSI.
func MGCSICodec() mapvalues.ValueCodec[mapvalues.MGCSI] {
	return compositeValueCodec[mapvalues.MGCSI, *mapvalues.MGCSI]()
}

// MobilityTriggersCodec binds MAP-MS-DataTypes.MobilityTriggers.
func MobilityTriggersCodec() mapvalues.ValueCodec[mapvalues.MobilityTriggers] {
	return pointerValueCodec(mapvalues.UnmarshalBERMobilityTriggers, mapvalues.MarshalBERMobilityTriggers, mapvalues.MarshalDERMobilityTriggers)
}

// TCSICodec binds MAP-MS-DataTypes.T-CSI.
func TCSICodec() mapvalues.ValueCodec[mapvalues.TCSI] {
	return compositeValueCodec[mapvalues.TCSI, *mapvalues.TCSI]()
}

// TBcsmCamelTDPDataListCodec binds MAP-MS-DataTypes.T-BcsmCamelTDPDataList.
func TBcsmCamelTDPDataListCodec() mapvalues.ValueCodec[mapvalues.TBcsmCamelTDPDataList] {
	return pointerValueCodec(mapvalues.UnmarshalBERTBcsmCamelTDPDataList, mapvalues.MarshalBERTBcsmCamelTDPDataList, mapvalues.MarshalDERTBcsmCamelTDPDataList)
}

// TBcsmCamelTDPDataCodec binds MAP-MS-DataTypes.T-BcsmCamelTDPData.
func TBcsmCamelTDPDataCodec() mapvalues.ValueCodec[mapvalues.TBcsmCamelTDPData] {
	return compositeValueCodec[mapvalues.TBcsmCamelTDPData, *mapvalues.TBcsmCamelTDPData]()
}

// SendRoutingInfoForGprsArgCodec binds MAP-MS-DataTypes.SendRoutingInfoForGprsArg.
func SendRoutingInfoForGprsArgCodec() mapvalues.ValueCodec[mapvalues.SendRoutingInfoForGprsArg] {
	return compositeValueCodec[mapvalues.SendRoutingInfoForGprsArg, *mapvalues.SendRoutingInfoForGprsArg]()
}

// SendRoutingInfoForGprsResCodec binds MAP-MS-DataTypes.SendRoutingInfoForGprsRes.
func SendRoutingInfoForGprsResCodec() mapvalues.ValueCodec[mapvalues.SendRoutingInfoForGprsRes] {
	return compositeValueCodec[mapvalues.SendRoutingInfoForGprsRes, *mapvalues.SendRoutingInfoForGprsRes]()
}

// FailureReportArgCodec binds MAP-MS-DataTypes.FailureReportArg.
func FailureReportArgCodec() mapvalues.ValueCodec[mapvalues.FailureReportArg] {
	return compositeValueCodec[mapvalues.FailureReportArg, *mapvalues.FailureReportArg]()
}

// FailureReportResCodec binds MAP-MS-DataTypes.FailureReportRes.
func FailureReportResCodec() mapvalues.ValueCodec[mapvalues.FailureReportRes] {
	return compositeValueCodec[mapvalues.FailureReportRes, *mapvalues.FailureReportRes]()
}

// NoteMsPresentForGprsArgCodec binds MAP-MS-DataTypes.NoteMsPresentForGprsArg.
func NoteMsPresentForGprsArgCodec() mapvalues.ValueCodec[mapvalues.NoteMsPresentForGprsArg] {
	return compositeValueCodec[mapvalues.NoteMsPresentForGprsArg, *mapvalues.NoteMsPresentForGprsArg]()
}

// NoteMsPresentForGprsResCodec binds MAP-MS-DataTypes.NoteMsPresentForGprsRes.
func NoteMsPresentForGprsResCodec() mapvalues.ValueCodec[mapvalues.NoteMsPresentForGprsRes] {
	return compositeValueCodec[mapvalues.NoteMsPresentForGprsRes, *mapvalues.NoteMsPresentForGprsRes]()
}

// ResetArgCodec binds MAP-MS-DataTypes.ResetArg.
func ResetArgCodec() mapvalues.ValueCodec[mapvalues.ResetArg] {
	return compositeValueCodec[mapvalues.ResetArg, *mapvalues.ResetArg]()
}

// SendingNodeNumberCodec binds MAP-MS-DataTypes.SendingNode-Number.
func SendingNodeNumberCodec() mapvalues.ValueCodec[mapvalues.SendingNodeNumber] {
	return compositeValueCodec[mapvalues.SendingNodeNumber, *mapvalues.SendingNodeNumber]()
}

// RestoreDataArgCodec binds MAP-MS-DataTypes.RestoreDataArg.
func RestoreDataArgCodec() mapvalues.ValueCodec[mapvalues.RestoreDataArg] {
	return compositeValueCodec[mapvalues.RestoreDataArg, *mapvalues.RestoreDataArg]()
}

// RestoreDataResCodec binds MAP-MS-DataTypes.RestoreDataRes.
func RestoreDataResCodec() mapvalues.ValueCodec[mapvalues.RestoreDataRes] {
	return compositeValueCodec[mapvalues.RestoreDataRes, *mapvalues.RestoreDataRes]()
}

// VBSDataListCodec binds MAP-MS-DataTypes.VBSDataList.
func VBSDataListCodec() mapvalues.ValueCodec[mapvalues.VBSDataList] {
	return pointerValueCodec(mapvalues.UnmarshalBERVBSDataList, mapvalues.MarshalBERVBSDataList, mapvalues.MarshalDERVBSDataList)
}

// VGCSDataListCodec binds MAP-MS-DataTypes.VGCSDataList.
func VGCSDataListCodec() mapvalues.ValueCodec[mapvalues.VGCSDataList] {
	return pointerValueCodec(mapvalues.UnmarshalBERVGCSDataList, mapvalues.MarshalBERVGCSDataList, mapvalues.MarshalDERVGCSDataList)
}

// VoiceGroupCallDataCodec binds MAP-MS-DataTypes.VoiceGroupCallData.
func VoiceGroupCallDataCodec() mapvalues.ValueCodec[mapvalues.VoiceGroupCallData] {
	return compositeValueCodec[mapvalues.VoiceGroupCallData, *mapvalues.VoiceGroupCallData]()
}

// VoiceBroadcastDataCodec binds MAP-MS-DataTypes.VoiceBroadcastData.
func VoiceBroadcastDataCodec() mapvalues.ValueCodec[mapvalues.VoiceBroadcastData] {
	return compositeValueCodec[mapvalues.VoiceBroadcastData, *mapvalues.VoiceBroadcastData]()
}

// GroupIdCodec binds MAP-MS-DataTypes.GroupId.
func GroupIdCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.GroupId]] {
	return pointerValueCodec(mapvalues.UnmarshalBERGroupId, mapvalues.MarshalBERGroupId, mapvalues.MarshalDERGroupId)
}

// LongGroupIdCodec binds MAP-MS-DataTypes.Long-GroupId.
func LongGroupIdCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.LongGroupId]] {
	return pointerValueCodec(mapvalues.UnmarshalBERLongGroupId, mapvalues.MarshalBERLongGroupId, mapvalues.MarshalDERLongGroupId)
}

// ProvideSubscriberInfoArgCodec binds MAP-MS-DataTypes.ProvideSubscriberInfoArg.
func ProvideSubscriberInfoArgCodec() mapvalues.ValueCodec[mapvalues.ProvideSubscriberInfoArg] {
	return compositeValueCodec[mapvalues.ProvideSubscriberInfoArg, *mapvalues.ProvideSubscriberInfoArg]()
}

// ProvideSubscriberInfoResCodec binds MAP-MS-DataTypes.ProvideSubscriberInfoRes.
func ProvideSubscriberInfoResCodec() mapvalues.ValueCodec[mapvalues.ProvideSubscriberInfoRes] {
	return compositeValueCodec[mapvalues.ProvideSubscriberInfoRes, *mapvalues.ProvideSubscriberInfoRes]()
}

// SubscriberInfoCodec binds MAP-MS-DataTypes.SubscriberInfo.
func SubscriberInfoCodec() mapvalues.ValueCodec[mapvalues.SubscriberInfo] {
	return compositeValueCodec[mapvalues.SubscriberInfo, *mapvalues.SubscriberInfo]()
}

// MNPInfoResCodec binds MAP-MS-DataTypes.MNPInfoRes.
func MNPInfoResCodec() mapvalues.ValueCodec[mapvalues.MNPInfoRes] {
	return compositeValueCodec[mapvalues.MNPInfoRes, *mapvalues.MNPInfoRes]()
}

// RouteingNumberCodec binds MAP-MS-DataTypes.RouteingNumber.
func RouteingNumberCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.RouteingNumber]] {
	return pointerValueCodec(mapvalues.UnmarshalBERRouteingNumber, mapvalues.MarshalBERRouteingNumber, mapvalues.MarshalDERRouteingNumber)
}

// GPRSMSClassCodec binds MAP-MS-DataTypes.GPRSMSClass.
func GPRSMSClassCodec() mapvalues.ValueCodec[mapvalues.GPRSMSClass] {
	return compositeValueCodec[mapvalues.GPRSMSClass, *mapvalues.GPRSMSClass]()
}

// RequestedInfoCodec binds MAP-MS-DataTypes.RequestedInfo.
func RequestedInfoCodec() mapvalues.ValueCodec[mapvalues.RequestedInfo] {
	return compositeValueCodec[mapvalues.RequestedInfo, *mapvalues.RequestedInfo]()
}

// LocationInformationCodec binds MAP-MS-DataTypes.LocationInformation.
func LocationInformationCodec() mapvalues.ValueCodec[mapvalues.LocationInformation] {
	return compositeValueCodec[mapvalues.LocationInformation, *mapvalues.LocationInformation]()
}

// LocationInformationEPSCodec binds MAP-MS-DataTypes.LocationInformationEPS.
func LocationInformationEPSCodec() mapvalues.ValueCodec[mapvalues.LocationInformationEPS] {
	return compositeValueCodec[mapvalues.LocationInformationEPS, *mapvalues.LocationInformationEPS]()
}

// LocationInformationGPRSCodec binds MAP-MS-DataTypes.LocationInformationGPRS.
func LocationInformationGPRSCodec() mapvalues.ValueCodec[mapvalues.LocationInformationGPRS] {
	return compositeValueCodec[mapvalues.LocationInformationGPRS, *mapvalues.LocationInformationGPRS]()
}

// LocationInformation5GSCodec binds MAP-MS-DataTypes.LocationInformation5GS.
func LocationInformation5GSCodec() mapvalues.ValueCodec[mapvalues.LocationInformation5GS] {
	return compositeValueCodec[mapvalues.LocationInformation5GS, *mapvalues.LocationInformation5GS]()
}

// UserCSGInformationCodec binds MAP-MS-DataTypes.UserCSGInformation.
func UserCSGInformationCodec() mapvalues.ValueCodec[mapvalues.UserCSGInformation] {
	return compositeValueCodec[mapvalues.UserCSGInformation, *mapvalues.UserCSGInformation]()
}

// SubscriberStateCodec binds MAP-MS-DataTypes.SubscriberState.
func SubscriberStateCodec() mapvalues.ValueCodec[mapvalues.SubscriberState] {
	return compositeValueCodec[mapvalues.SubscriberState, *mapvalues.SubscriberState]()
}

// PSSubscriberStateCodec binds MAP-MS-DataTypes.PS-SubscriberState.
func PSSubscriberStateCodec() mapvalues.ValueCodec[mapvalues.PSSubscriberState] {
	return compositeValueCodec[mapvalues.PSSubscriberState, *mapvalues.PSSubscriberState]()
}

// PDPContextInfoListCodec binds MAP-MS-DataTypes.PDP-ContextInfoList.
func PDPContextInfoListCodec() mapvalues.ValueCodec[mapvalues.PDPContextInfoList] {
	return pointerValueCodec(mapvalues.UnmarshalBERPDPContextInfoList, mapvalues.MarshalBERPDPContextInfoList, mapvalues.MarshalDERPDPContextInfoList)
}

// PDPContextInfoCodec binds MAP-MS-DataTypes.PDP-ContextInfo.
func PDPContextInfoCodec() mapvalues.ValueCodec[mapvalues.PDPContextInfo] {
	return compositeValueCodec[mapvalues.PDPContextInfo, *mapvalues.PDPContextInfo]()
}

// AnyTimeInterrogationArgCodec binds MAP-MS-DataTypes.AnyTimeInterrogationArg.
func AnyTimeInterrogationArgCodec() mapvalues.ValueCodec[mapvalues.AnyTimeInterrogationArg] {
	return compositeValueCodec[mapvalues.AnyTimeInterrogationArg, *mapvalues.AnyTimeInterrogationArg]()
}

// AnyTimeInterrogationResCodec binds MAP-MS-DataTypes.AnyTimeInterrogationRes.
func AnyTimeInterrogationResCodec() mapvalues.ValueCodec[mapvalues.AnyTimeInterrogationRes] {
	return compositeValueCodec[mapvalues.AnyTimeInterrogationRes, *mapvalues.AnyTimeInterrogationRes]()
}

// AnyTimeSubscriptionInterrogationArgCodec binds MAP-MS-DataTypes.AnyTimeSubscriptionInterrogationArg.
func AnyTimeSubscriptionInterrogationArgCodec() mapvalues.ValueCodec[mapvalues.AnyTimeSubscriptionInterrogationArg] {
	return compositeValueCodec[mapvalues.AnyTimeSubscriptionInterrogationArg, *mapvalues.AnyTimeSubscriptionInterrogationArg]()
}

// AnyTimeSubscriptionInterrogationResCodec binds MAP-MS-DataTypes.AnyTimeSubscriptionInterrogationRes.
func AnyTimeSubscriptionInterrogationResCodec() mapvalues.ValueCodec[mapvalues.AnyTimeSubscriptionInterrogationRes] {
	return compositeValueCodec[mapvalues.AnyTimeSubscriptionInterrogationRes, *mapvalues.AnyTimeSubscriptionInterrogationRes]()
}

// CallWaitingDataCodec binds MAP-MS-DataTypes.CallWaitingData.
func CallWaitingDataCodec() mapvalues.ValueCodec[mapvalues.CallWaitingData] {
	return compositeValueCodec[mapvalues.CallWaitingData, *mapvalues.CallWaitingData]()
}

// ExtCwFeatureListCodec binds MAP-MS-DataTypes.Ext-CwFeatureList.
func ExtCwFeatureListCodec() mapvalues.ValueCodec[mapvalues.ExtCwFeatureList] {
	return pointerValueCodec(mapvalues.UnmarshalBERExtCwFeatureList, mapvalues.MarshalBERExtCwFeatureList, mapvalues.MarshalDERExtCwFeatureList)
}

// ExtCwFeatureCodec binds MAP-MS-DataTypes.Ext-CwFeature.
func ExtCwFeatureCodec() mapvalues.ValueCodec[mapvalues.ExtCwFeature] {
	return compositeValueCodec[mapvalues.ExtCwFeature, *mapvalues.ExtCwFeature]()
}

// ClipDataCodec binds MAP-MS-DataTypes.ClipData.
func ClipDataCodec() mapvalues.ValueCodec[mapvalues.ClipData] {
	return compositeValueCodec[mapvalues.ClipData, *mapvalues.ClipData]()
}

// ClirDataCodec binds MAP-MS-DataTypes.ClirData.
func ClirDataCodec() mapvalues.ValueCodec[mapvalues.ClirData] {
	return compositeValueCodec[mapvalues.ClirData, *mapvalues.ClirData]()
}

// CallHoldDataCodec binds MAP-MS-DataTypes.CallHoldData.
func CallHoldDataCodec() mapvalues.ValueCodec[mapvalues.CallHoldData] {
	return compositeValueCodec[mapvalues.CallHoldData, *mapvalues.CallHoldData]()
}

// EctDataCodec binds MAP-MS-DataTypes.EctData.
func EctDataCodec() mapvalues.ValueCodec[mapvalues.EctData] {
	return compositeValueCodec[mapvalues.EctData, *mapvalues.EctData]()
}

// RequestedSubscriptionInfoCodec binds MAP-MS-DataTypes.RequestedSubscriptionInfo.
func RequestedSubscriptionInfoCodec() mapvalues.ValueCodec[mapvalues.RequestedSubscriptionInfo] {
	return compositeValueCodec[mapvalues.RequestedSubscriptionInfo, *mapvalues.RequestedSubscriptionInfo]()
}

// MSISDNBSListCodec binds MAP-MS-DataTypes.MSISDN-BS-List.
func MSISDNBSListCodec() mapvalues.ValueCodec[mapvalues.MSISDNBSList] {
	return pointerValueCodec(mapvalues.UnmarshalBERMSISDNBSList, mapvalues.MarshalBERMSISDNBSList, mapvalues.MarshalDERMSISDNBSList)
}

// MSISDNBSCodec binds MAP-MS-DataTypes.MSISDN-BS.
func MSISDNBSCodec() mapvalues.ValueCodec[mapvalues.MSISDNBS] {
	return compositeValueCodec[mapvalues.MSISDNBS, *mapvalues.MSISDNBS]()
}

// CallForwardingDataCodec binds MAP-MS-DataTypes.CallForwardingData.
func CallForwardingDataCodec() mapvalues.ValueCodec[mapvalues.CallForwardingData] {
	return compositeValueCodec[mapvalues.CallForwardingData, *mapvalues.CallForwardingData]()
}

// CallBarringDataCodec binds MAP-MS-DataTypes.CallBarringData.
func CallBarringDataCodec() mapvalues.ValueCodec[mapvalues.CallBarringData] {
	return compositeValueCodec[mapvalues.CallBarringData, *mapvalues.CallBarringData]()
}

// ODBInfoCodec binds MAP-MS-DataTypes.ODB-Info.
func ODBInfoCodec() mapvalues.ValueCodec[mapvalues.ODBInfo] {
	return compositeValueCodec[mapvalues.ODBInfo, *mapvalues.ODBInfo]()
}

// CAMELSubscriptionInfoCodec binds MAP-MS-DataTypes.CAMEL-SubscriptionInfo.
func CAMELSubscriptionInfoCodec() mapvalues.ValueCodec[mapvalues.CAMELSubscriptionInfo] {
	return compositeValueCodec[mapvalues.CAMELSubscriptionInfo, *mapvalues.CAMELSubscriptionInfo]()
}

// AnyTimeModificationArgCodec binds MAP-MS-DataTypes.AnyTimeModificationArg.
func AnyTimeModificationArgCodec() mapvalues.ValueCodec[mapvalues.AnyTimeModificationArg] {
	return compositeValueCodec[mapvalues.AnyTimeModificationArg, *mapvalues.AnyTimeModificationArg]()
}

// ModificationRequestForCWInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CW-Info.
func ModificationRequestForCWInfoCodec() mapvalues.ValueCodec[mapvalues.ModificationRequestForCWInfo] {
	return compositeValueCodec[mapvalues.ModificationRequestForCWInfo, *mapvalues.ModificationRequestForCWInfo]()
}

// ModificationRequestForCHInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CH-Info.
func ModificationRequestForCHInfoCodec() mapvalues.ValueCodec[mapvalues.ModificationRequestForCHInfo] {
	return compositeValueCodec[mapvalues.ModificationRequestForCHInfo, *mapvalues.ModificationRequestForCHInfo]()
}

// ModificationRequestForECTInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-ECT-Info.
func ModificationRequestForECTInfoCodec() mapvalues.ValueCodec[mapvalues.ModificationRequestForECTInfo] {
	return compositeValueCodec[mapvalues.ModificationRequestForECTInfo, *mapvalues.ModificationRequestForECTInfo]()
}

// ModificationRequestForCLIRInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CLIR-Info.
func ModificationRequestForCLIRInfoCodec() mapvalues.ValueCodec[mapvalues.ModificationRequestForCLIRInfo] {
	return compositeValueCodec[mapvalues.ModificationRequestForCLIRInfo, *mapvalues.ModificationRequestForCLIRInfo]()
}

// ModificationRequestForCLIPInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CLIP-Info.
func ModificationRequestForCLIPInfoCodec() mapvalues.ValueCodec[mapvalues.ModificationRequestForCLIPInfo] {
	return compositeValueCodec[mapvalues.ModificationRequestForCLIPInfo, *mapvalues.ModificationRequestForCLIPInfo]()
}

// ModificationRequestForCSGCodec binds MAP-MS-DataTypes.ModificationRequestFor-CSG.
func ModificationRequestForCSGCodec() mapvalues.ValueCodec[mapvalues.ModificationRequestForCSG] {
	return compositeValueCodec[mapvalues.ModificationRequestForCSG, *mapvalues.ModificationRequestForCSG]()
}

// AnyTimeModificationResCodec binds MAP-MS-DataTypes.AnyTimeModificationRes.
func AnyTimeModificationResCodec() mapvalues.ValueCodec[mapvalues.AnyTimeModificationRes] {
	return compositeValueCodec[mapvalues.AnyTimeModificationRes, *mapvalues.AnyTimeModificationRes]()
}

// ModificationRequestForCFInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CF-Info.
func ModificationRequestForCFInfoCodec() mapvalues.ValueCodec[mapvalues.ModificationRequestForCFInfo] {
	return compositeValueCodec[mapvalues.ModificationRequestForCFInfo, *mapvalues.ModificationRequestForCFInfo]()
}

// ModificationRequestForCBInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CB-Info.
func ModificationRequestForCBInfoCodec() mapvalues.ValueCodec[mapvalues.ModificationRequestForCBInfo] {
	return compositeValueCodec[mapvalues.ModificationRequestForCBInfo, *mapvalues.ModificationRequestForCBInfo]()
}

// ModificationRequestForODBDataCodec binds MAP-MS-DataTypes.ModificationRequestFor-ODB-data.
func ModificationRequestForODBDataCodec() mapvalues.ValueCodec[mapvalues.ModificationRequestForODBData] {
	return compositeValueCodec[mapvalues.ModificationRequestForODBData, *mapvalues.ModificationRequestForODBData]()
}

// ModificationRequestForCSICodec binds MAP-MS-DataTypes.ModificationRequestFor-CSI.
func ModificationRequestForCSICodec() mapvalues.ValueCodec[mapvalues.ModificationRequestForCSI] {
	return compositeValueCodec[mapvalues.ModificationRequestForCSI, *mapvalues.ModificationRequestForCSI]()
}

// ModificationRequestForIPSMGWDataCodec binds MAP-MS-DataTypes.ModificationRequestFor-IP-SM-GW-Data.
func ModificationRequestForIPSMGWDataCodec() mapvalues.ValueCodec[mapvalues.ModificationRequestForIPSMGWData] {
	return compositeValueCodec[mapvalues.ModificationRequestForIPSMGWData, *mapvalues.ModificationRequestForIPSMGWData]()
}

// NoteSubscriberDataModifiedArgCodec binds MAP-MS-DataTypes.NoteSubscriberDataModifiedArg.
func NoteSubscriberDataModifiedArgCodec() mapvalues.ValueCodec[mapvalues.NoteSubscriberDataModifiedArg] {
	return compositeValueCodec[mapvalues.NoteSubscriberDataModifiedArg, *mapvalues.NoteSubscriberDataModifiedArg]()
}

// NoteSubscriberDataModifiedResCodec binds MAP-MS-DataTypes.NoteSubscriberDataModifiedRes.
func NoteSubscriberDataModifiedResCodec() mapvalues.ValueCodec[mapvalues.NoteSubscriberDataModifiedRes] {
	return compositeValueCodec[mapvalues.NoteSubscriberDataModifiedRes, *mapvalues.NoteSubscriberDataModifiedRes]()
}

// NoteMMEventArgCodec binds MAP-MS-DataTypes.NoteMM-EventArg.
func NoteMMEventArgCodec() mapvalues.ValueCodec[mapvalues.NoteMMEventArg] {
	return compositeValueCodec[mapvalues.NoteMMEventArg, *mapvalues.NoteMMEventArg]()
}

// NoteMMEventResCodec binds MAP-MS-DataTypes.NoteMM-EventRes.
func NoteMMEventResCodec() mapvalues.ValueCodec[mapvalues.NoteMMEventRes] {
	return compositeValueCodec[mapvalues.NoteMMEventRes, *mapvalues.NoteMMEventRes]()
}

// ExtSSInfoForCSECodec binds MAP-MS-DataTypes.Ext-SS-InfoFor-CSE.
func ExtSSInfoForCSECodec() mapvalues.ValueCodec[mapvalues.ExtSSInfoForCSE] {
	return compositeValueCodec[mapvalues.ExtSSInfoForCSE, *mapvalues.ExtSSInfoForCSE]()
}

// ExtForwardingInfoForCSECodec binds MAP-MS-DataTypes.Ext-ForwardingInfoFor-CSE.
func ExtForwardingInfoForCSECodec() mapvalues.ValueCodec[mapvalues.ExtForwardingInfoForCSE] {
	return compositeValueCodec[mapvalues.ExtForwardingInfoForCSE, *mapvalues.ExtForwardingInfoForCSE]()
}

// ExtCallBarringInfoForCSECodec binds MAP-MS-DataTypes.Ext-CallBarringInfoFor-CSE.
func ExtCallBarringInfoForCSECodec() mapvalues.ValueCodec[mapvalues.ExtCallBarringInfoForCSE] {
	return compositeValueCodec[mapvalues.ExtCallBarringInfoForCSE, *mapvalues.ExtCallBarringInfoForCSE]()
}

// UpdateVcsgLocationArgCodec binds MAP-MS-DataTypes.UpdateVcsgLocationArg.
func UpdateVcsgLocationArgCodec() mapvalues.ValueCodec[mapvalues.UpdateVcsgLocationArg] {
	return compositeValueCodec[mapvalues.UpdateVcsgLocationArg, *mapvalues.UpdateVcsgLocationArg]()
}

// UpdateVcsgLocationResCodec binds MAP-MS-DataTypes.UpdateVcsgLocationRes.
func UpdateVcsgLocationResCodec() mapvalues.ValueCodec[mapvalues.UpdateVcsgLocationRes] {
	return compositeValueCodec[mapvalues.UpdateVcsgLocationRes, *mapvalues.UpdateVcsgLocationRes]()
}

// CancelVcsgLocationArgCodec binds MAP-MS-DataTypes.CancelVcsgLocationArg.
func CancelVcsgLocationArgCodec() mapvalues.ValueCodec[mapvalues.CancelVcsgLocationArg] {
	return compositeValueCodec[mapvalues.CancelVcsgLocationArg, *mapvalues.CancelVcsgLocationArg]()
}

// CancelVcsgLocationResCodec binds MAP-MS-DataTypes.CancelVcsgLocationRes.
func CancelVcsgLocationResCodec() mapvalues.ValueCodec[mapvalues.CancelVcsgLocationRes] {
	return compositeValueCodec[mapvalues.CancelVcsgLocationRes, *mapvalues.CancelVcsgLocationRes]()
}

// CUGCheckInfoCodec binds MAP-CH-DataTypes.CUG-CheckInfo.
func CUGCheckInfoCodec() mapvalues.ValueCodec[mapvalues.CUGCheckInfo] {
	return compositeValueCodec[mapvalues.CUGCheckInfo, *mapvalues.CUGCheckInfo]()
}

// SendRoutingInfoArgCodec binds MAP-CH-DataTypes.SendRoutingInfoArg.
func SendRoutingInfoArgCodec() mapvalues.ValueCodec[mapvalues.SendRoutingInfoArg] {
	return compositeValueCodec[mapvalues.SendRoutingInfoArg, *mapvalues.SendRoutingInfoArg]()
}

// SuppressionOfAnnouncementCodec binds MAP-CH-DataTypes.SuppressionOfAnnouncement.
func SuppressionOfAnnouncementCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.SuppressionOfAnnouncement]] {
	return pointerValueCodec(mapvalues.UnmarshalBERSuppressionOfAnnouncement, mapvalues.MarshalBERSuppressionOfAnnouncement, mapvalues.MarshalDERSuppressionOfAnnouncement)
}

// SendRoutingInfoResCodec binds MAP-CH-DataTypes.SendRoutingInfoRes.
func SendRoutingInfoResCodec() mapvalues.ValueCodec[mapvalues.SendRoutingInfoRes] {
	return compositeValueCodec[mapvalues.SendRoutingInfoRes, *mapvalues.SendRoutingInfoRes]()
}

// CCBSIndicatorsCodec binds MAP-CH-DataTypes.CCBS-Indicators.
func CCBSIndicatorsCodec() mapvalues.ValueCodec[mapvalues.CCBSIndicators] {
	return compositeValueCodec[mapvalues.CCBSIndicators, *mapvalues.CCBSIndicators]()
}

// RoutingInfoCodec binds MAP-CH-DataTypes.RoutingInfo.
func RoutingInfoCodec() mapvalues.ValueCodec[mapvalues.RoutingInfo] {
	return compositeValueCodec[mapvalues.RoutingInfo, *mapvalues.RoutingInfo]()
}

// ForwardingDataCodec binds MAP-CH-DataTypes.ForwardingData.
func ForwardingDataCodec() mapvalues.ValueCodec[mapvalues.ForwardingData] {
	return compositeValueCodec[mapvalues.ForwardingData, *mapvalues.ForwardingData]()
}

// ProvideRoamingNumberArgCodec binds MAP-CH-DataTypes.ProvideRoamingNumberArg.
func ProvideRoamingNumberArgCodec() mapvalues.ValueCodec[mapvalues.ProvideRoamingNumberArg] {
	return compositeValueCodec[mapvalues.ProvideRoamingNumberArg, *mapvalues.ProvideRoamingNumberArg]()
}

// ProvideRoamingNumberResCodec binds MAP-CH-DataTypes.ProvideRoamingNumberRes.
func ProvideRoamingNumberResCodec() mapvalues.ValueCodec[mapvalues.ProvideRoamingNumberRes] {
	return compositeValueCodec[mapvalues.ProvideRoamingNumberRes, *mapvalues.ProvideRoamingNumberRes]()
}

// ResumeCallHandlingArgCodec binds MAP-CH-DataTypes.ResumeCallHandlingArg.
func ResumeCallHandlingArgCodec() mapvalues.ValueCodec[mapvalues.ResumeCallHandlingArg] {
	return compositeValueCodec[mapvalues.ResumeCallHandlingArg, *mapvalues.ResumeCallHandlingArg]()
}

// UUDataCodec binds MAP-CH-DataTypes.UU-Data.
func UUDataCodec() mapvalues.ValueCodec[mapvalues.UUData] {
	return compositeValueCodec[mapvalues.UUData, *mapvalues.UUData]()
}

// ResumeCallHandlingResCodec binds MAP-CH-DataTypes.ResumeCallHandlingRes.
func ResumeCallHandlingResCodec() mapvalues.ValueCodec[mapvalues.ResumeCallHandlingRes] {
	return compositeValueCodec[mapvalues.ResumeCallHandlingRes, *mapvalues.ResumeCallHandlingRes]()
}

// CamelInfoCodec binds MAP-CH-DataTypes.CamelInfo.
func CamelInfoCodec() mapvalues.ValueCodec[mapvalues.CamelInfo] {
	return compositeValueCodec[mapvalues.CamelInfo, *mapvalues.CamelInfo]()
}

// ExtendedRoutingInfoCodec binds MAP-CH-DataTypes.ExtendedRoutingInfo.
func ExtendedRoutingInfoCodec() mapvalues.ValueCodec[mapvalues.ExtendedRoutingInfo] {
	return compositeValueCodec[mapvalues.ExtendedRoutingInfo, *mapvalues.ExtendedRoutingInfo]()
}

// CamelRoutingInfoCodec binds MAP-CH-DataTypes.CamelRoutingInfo.
func CamelRoutingInfoCodec() mapvalues.ValueCodec[mapvalues.CamelRoutingInfo] {
	return compositeValueCodec[mapvalues.CamelRoutingInfo, *mapvalues.CamelRoutingInfo]()
}

// GmscCamelSubscriptionInfoCodec binds MAP-CH-DataTypes.GmscCamelSubscriptionInfo.
func GmscCamelSubscriptionInfoCodec() mapvalues.ValueCodec[mapvalues.GmscCamelSubscriptionInfo] {
	return compositeValueCodec[mapvalues.GmscCamelSubscriptionInfo, *mapvalues.GmscCamelSubscriptionInfo]()
}

// SetReportingStateArgCodec binds MAP-CH-DataTypes.SetReportingStateArg.
func SetReportingStateArgCodec() mapvalues.ValueCodec[mapvalues.SetReportingStateArg] {
	return compositeValueCodec[mapvalues.SetReportingStateArg, *mapvalues.SetReportingStateArg]()
}

// SetReportingStateResCodec binds MAP-CH-DataTypes.SetReportingStateRes.
func SetReportingStateResCodec() mapvalues.ValueCodec[mapvalues.SetReportingStateRes] {
	return compositeValueCodec[mapvalues.SetReportingStateRes, *mapvalues.SetReportingStateRes]()
}

// StatusReportArgCodec binds MAP-CH-DataTypes.StatusReportArg.
func StatusReportArgCodec() mapvalues.ValueCodec[mapvalues.StatusReportArg] {
	return compositeValueCodec[mapvalues.StatusReportArg, *mapvalues.StatusReportArg]()
}

// EventReportDataCodec binds MAP-CH-DataTypes.EventReportData.
func EventReportDataCodec() mapvalues.ValueCodec[mapvalues.EventReportData] {
	return compositeValueCodec[mapvalues.EventReportData, *mapvalues.EventReportData]()
}

// CallReportDataCodec binds MAP-CH-DataTypes.CallReportData.
func CallReportDataCodec() mapvalues.ValueCodec[mapvalues.CallReportData] {
	return compositeValueCodec[mapvalues.CallReportData, *mapvalues.CallReportData]()
}

// StatusReportResCodec binds MAP-CH-DataTypes.StatusReportRes.
func StatusReportResCodec() mapvalues.ValueCodec[mapvalues.StatusReportRes] {
	return compositeValueCodec[mapvalues.StatusReportRes, *mapvalues.StatusReportRes]()
}

// RemoteUserFreeArgCodec binds MAP-CH-DataTypes.RemoteUserFreeArg.
func RemoteUserFreeArgCodec() mapvalues.ValueCodec[mapvalues.RemoteUserFreeArg] {
	return compositeValueCodec[mapvalues.RemoteUserFreeArg, *mapvalues.RemoteUserFreeArg]()
}

// RemoteUserFreeResCodec binds MAP-CH-DataTypes.RemoteUserFreeRes.
func RemoteUserFreeResCodec() mapvalues.ValueCodec[mapvalues.RemoteUserFreeRes] {
	return compositeValueCodec[mapvalues.RemoteUserFreeRes, *mapvalues.RemoteUserFreeRes]()
}

// ISTAlertArgCodec binds MAP-CH-DataTypes.IST-AlertArg.
func ISTAlertArgCodec() mapvalues.ValueCodec[mapvalues.ISTAlertArg] {
	return compositeValueCodec[mapvalues.ISTAlertArg, *mapvalues.ISTAlertArg]()
}

// ISTAlertResCodec binds MAP-CH-DataTypes.IST-AlertRes.
func ISTAlertResCodec() mapvalues.ValueCodec[mapvalues.ISTAlertRes] {
	return compositeValueCodec[mapvalues.ISTAlertRes, *mapvalues.ISTAlertRes]()
}

// ISTCommandArgCodec binds MAP-CH-DataTypes.IST-CommandArg.
func ISTCommandArgCodec() mapvalues.ValueCodec[mapvalues.ISTCommandArg] {
	return compositeValueCodec[mapvalues.ISTCommandArg, *mapvalues.ISTCommandArg]()
}

// ISTCommandResCodec binds MAP-CH-DataTypes.IST-CommandRes.
func ISTCommandResCodec() mapvalues.ValueCodec[mapvalues.ISTCommandRes] {
	return compositeValueCodec[mapvalues.ISTCommandRes, *mapvalues.ISTCommandRes]()
}

// ReleaseResourcesArgCodec binds MAP-CH-DataTypes.ReleaseResourcesArg.
func ReleaseResourcesArgCodec() mapvalues.ValueCodec[mapvalues.ReleaseResourcesArg] {
	return compositeValueCodec[mapvalues.ReleaseResourcesArg, *mapvalues.ReleaseResourcesArg]()
}

// ReleaseResourcesResCodec binds MAP-CH-DataTypes.ReleaseResourcesRes.
func ReleaseResourcesResCodec() mapvalues.ValueCodec[mapvalues.ReleaseResourcesRes] {
	return compositeValueCodec[mapvalues.ReleaseResourcesRes, *mapvalues.ReleaseResourcesRes]()
}

// MAPDialoguePDUCodec binds MAP-DialogueInformation.MAP-DialoguePDU.
func MAPDialoguePDUCodec() mapvalues.ValueCodec[mapvalues.MAPDialoguePDU] {
	return compositeValueCodec[mapvalues.MAPDialoguePDU, *mapvalues.MAPDialoguePDU]()
}

// MAPOpenInfoCodec binds MAP-DialogueInformation.MAP-OpenInfo.
func MAPOpenInfoCodec() mapvalues.ValueCodec[mapvalues.MAPOpenInfo] {
	return compositeValueCodec[mapvalues.MAPOpenInfo, *mapvalues.MAPOpenInfo]()
}

// MAPAcceptInfoCodec binds MAP-DialogueInformation.MAP-AcceptInfo.
func MAPAcceptInfoCodec() mapvalues.ValueCodec[mapvalues.MAPAcceptInfo] {
	return compositeValueCodec[mapvalues.MAPAcceptInfo, *mapvalues.MAPAcceptInfo]()
}

// MAPCloseInfoCodec binds MAP-DialogueInformation.MAP-CloseInfo.
func MAPCloseInfoCodec() mapvalues.ValueCodec[mapvalues.MAPCloseInfo] {
	return compositeValueCodec[mapvalues.MAPCloseInfo, *mapvalues.MAPCloseInfo]()
}

// MAPRefuseInfoCodec binds MAP-DialogueInformation.MAP-RefuseInfo.
func MAPRefuseInfoCodec() mapvalues.ValueCodec[mapvalues.MAPRefuseInfo] {
	return compositeValueCodec[mapvalues.MAPRefuseInfo, *mapvalues.MAPRefuseInfo]()
}

// MAPUserAbortInfoCodec binds MAP-DialogueInformation.MAP-UserAbortInfo.
func MAPUserAbortInfoCodec() mapvalues.ValueCodec[mapvalues.MAPUserAbortInfo] {
	return compositeValueCodec[mapvalues.MAPUserAbortInfo, *mapvalues.MAPUserAbortInfo]()
}

// MAPUserAbortChoiceCodec binds MAP-DialogueInformation.MAP-UserAbortChoice.
func MAPUserAbortChoiceCodec() mapvalues.ValueCodec[mapvalues.MAPUserAbortChoice] {
	return compositeValueCodec[mapvalues.MAPUserAbortChoice, *mapvalues.MAPUserAbortChoice]()
}

// MAPProviderAbortInfoCodec binds MAP-DialogueInformation.MAP-ProviderAbortInfo.
func MAPProviderAbortInfoCodec() mapvalues.ValueCodec[mapvalues.MAPProviderAbortInfo] {
	return compositeValueCodec[mapvalues.MAPProviderAbortInfo, *mapvalues.MAPProviderAbortInfo]()
}

// PrepareGroupCallArgCodec binds MAP-GR-DataTypes.PrepareGroupCallArg.
func PrepareGroupCallArgCodec() mapvalues.ValueCodec[mapvalues.PrepareGroupCallArg] {
	return compositeValueCodec[mapvalues.PrepareGroupCallArg, *mapvalues.PrepareGroupCallArg]()
}

// PrepareGroupCallResCodec binds MAP-GR-DataTypes.PrepareGroupCallRes.
func PrepareGroupCallResCodec() mapvalues.ValueCodec[mapvalues.PrepareGroupCallRes] {
	return compositeValueCodec[mapvalues.PrepareGroupCallRes, *mapvalues.PrepareGroupCallRes]()
}

// SendGroupCallEndSignalArgCodec binds MAP-GR-DataTypes.SendGroupCallEndSignalArg.
func SendGroupCallEndSignalArgCodec() mapvalues.ValueCodec[mapvalues.SendGroupCallEndSignalArg] {
	return compositeValueCodec[mapvalues.SendGroupCallEndSignalArg, *mapvalues.SendGroupCallEndSignalArg]()
}

// SendGroupCallEndSignalResCodec binds MAP-GR-DataTypes.SendGroupCallEndSignalRes.
func SendGroupCallEndSignalResCodec() mapvalues.ValueCodec[mapvalues.SendGroupCallEndSignalRes] {
	return compositeValueCodec[mapvalues.SendGroupCallEndSignalRes, *mapvalues.SendGroupCallEndSignalRes]()
}

// ForwardGroupCallSignallingArgCodec binds MAP-GR-DataTypes.ForwardGroupCallSignallingArg.
func ForwardGroupCallSignallingArgCodec() mapvalues.ValueCodec[mapvalues.ForwardGroupCallSignallingArg] {
	return compositeValueCodec[mapvalues.ForwardGroupCallSignallingArg, *mapvalues.ForwardGroupCallSignallingArg]()
}

// ProcessGroupCallSignallingArgCodec binds MAP-GR-DataTypes.ProcessGroupCallSignallingArg.
func ProcessGroupCallSignallingArgCodec() mapvalues.ValueCodec[mapvalues.ProcessGroupCallSignallingArg] {
	return compositeValueCodec[mapvalues.ProcessGroupCallSignallingArg, *mapvalues.ProcessGroupCallSignallingArg]()
}

// StateAttributesCodec binds MAP-GR-DataTypes.StateAttributes.
func StateAttributesCodec() mapvalues.ValueCodec[mapvalues.StateAttributes] {
	return compositeValueCodec[mapvalues.StateAttributes, *mapvalues.StateAttributes]()
}

// SendGroupCallInfoArgCodec binds MAP-GR-DataTypes.SendGroupCallInfoArg.
func SendGroupCallInfoArgCodec() mapvalues.ValueCodec[mapvalues.SendGroupCallInfoArg] {
	return compositeValueCodec[mapvalues.SendGroupCallInfoArg, *mapvalues.SendGroupCallInfoArg]()
}

// SendGroupCallInfoResCodec binds MAP-GR-DataTypes.SendGroupCallInfoRes.
func SendGroupCallInfoResCodec() mapvalues.ValueCodec[mapvalues.SendGroupCallInfoRes] {
	return compositeValueCodec[mapvalues.SendGroupCallInfoRes, *mapvalues.SendGroupCallInfoRes]()
}

// RoutingInfoForSMArgCodec binds MAP-SM-DataTypes.RoutingInfoForSM-Arg.
func RoutingInfoForSMArgCodec() mapvalues.ValueCodec[mapvalues.RoutingInfoForSMArg] {
	return compositeValueCodec[mapvalues.RoutingInfoForSMArg, *mapvalues.RoutingInfoForSMArg]()
}

// RoutingInfoForSMResCodec binds MAP-SM-DataTypes.RoutingInfoForSM-Res.
func RoutingInfoForSMResCodec() mapvalues.ValueCodec[mapvalues.RoutingInfoForSMRes] {
	return compositeValueCodec[mapvalues.RoutingInfoForSMRes, *mapvalues.RoutingInfoForSMRes]()
}

// IPSMGWGuidanceCodec binds MAP-SM-DataTypes.IP-SM-GW-Guidance.
func IPSMGWGuidanceCodec() mapvalues.ValueCodec[mapvalues.IPSMGWGuidance] {
	return compositeValueCodec[mapvalues.IPSMGWGuidance, *mapvalues.IPSMGWGuidance]()
}

// LocationInfoWithLMSICodec binds MAP-SM-DataTypes.LocationInfoWithLMSI.
func LocationInfoWithLMSICodec() mapvalues.ValueCodec[mapvalues.LocationInfoWithLMSI] {
	return compositeValueCodec[mapvalues.LocationInfoWithLMSI, *mapvalues.LocationInfoWithLMSI]()
}

// AdditionalNumberCodec binds MAP-SM-DataTypes.Additional-Number.
func AdditionalNumberCodec() mapvalues.ValueCodec[mapvalues.AdditionalNumber] {
	return compositeValueCodec[mapvalues.AdditionalNumber, *mapvalues.AdditionalNumber]()
}

// MOForwardSMArgCodec binds MAP-SM-DataTypes.MO-ForwardSM-Arg.
func MOForwardSMArgCodec() mapvalues.ValueCodec[mapvalues.MOForwardSMArg] {
	return compositeValueCodec[mapvalues.MOForwardSMArg, *mapvalues.MOForwardSMArg]()
}

// MOForwardSMResCodec binds MAP-SM-DataTypes.MO-ForwardSM-Res.
func MOForwardSMResCodec() mapvalues.ValueCodec[mapvalues.MOForwardSMRes] {
	return compositeValueCodec[mapvalues.MOForwardSMRes, *mapvalues.MOForwardSMRes]()
}

// MTForwardSMArgCodec binds MAP-SM-DataTypes.MT-ForwardSM-Arg.
func MTForwardSMArgCodec() mapvalues.ValueCodec[mapvalues.MTForwardSMArg] {
	return compositeValueCodec[mapvalues.MTForwardSMArg, *mapvalues.MTForwardSMArg]()
}

// CorrelationIDCodec binds MAP-SM-DataTypes.CorrelationID.
func CorrelationIDCodec() mapvalues.ValueCodec[mapvalues.CorrelationID] {
	return compositeValueCodec[mapvalues.CorrelationID, *mapvalues.CorrelationID]()
}

// MTForwardSMResCodec binds MAP-SM-DataTypes.MT-ForwardSM-Res.
func MTForwardSMResCodec() mapvalues.ValueCodec[mapvalues.MTForwardSMRes] {
	return compositeValueCodec[mapvalues.MTForwardSMRes, *mapvalues.MTForwardSMRes]()
}

// SMRPDACodec binds MAP-SM-DataTypes.SM-RP-DA.
func SMRPDACodec() mapvalues.ValueCodec[mapvalues.SMRPDA] {
	return compositeValueCodec[mapvalues.SMRPDA, *mapvalues.SMRPDA]()
}

// SMRPOACodec binds MAP-SM-DataTypes.SM-RP-OA.
func SMRPOACodec() mapvalues.ValueCodec[mapvalues.SMRPOA] {
	return compositeValueCodec[mapvalues.SMRPOA, *mapvalues.SMRPOA]()
}

// ReportSMDeliveryStatusArgCodec binds MAP-SM-DataTypes.ReportSM-DeliveryStatusArg.
func ReportSMDeliveryStatusArgCodec() mapvalues.ValueCodec[mapvalues.ReportSMDeliveryStatusArg] {
	return compositeValueCodec[mapvalues.ReportSMDeliveryStatusArg, *mapvalues.ReportSMDeliveryStatusArg]()
}

// ReportSMDeliveryStatusResCodec binds MAP-SM-DataTypes.ReportSM-DeliveryStatusRes.
func ReportSMDeliveryStatusResCodec() mapvalues.ValueCodec[mapvalues.ReportSMDeliveryStatusRes] {
	return compositeValueCodec[mapvalues.ReportSMDeliveryStatusRes, *mapvalues.ReportSMDeliveryStatusRes]()
}

// SMServingNodeAddressListCodec binds MAP-SM-DataTypes.SMServingNodeAddressList.
func SMServingNodeAddressListCodec() mapvalues.ValueCodec[mapvalues.SMServingNodeAddressList] {
	return pointerValueCodec(mapvalues.UnmarshalBERSMServingNodeAddressList, mapvalues.MarshalBERSMServingNodeAddressList, mapvalues.MarshalDERSMServingNodeAddressList)
}

// SMServingNodeAddressCodec binds MAP-SM-DataTypes.SMServingNodeAddress.
func SMServingNodeAddressCodec() mapvalues.ValueCodec[mapvalues.SMServingNodeAddress] {
	return compositeValueCodec[mapvalues.SMServingNodeAddress, *mapvalues.SMServingNodeAddress]()
}

// AlertServiceCentreArgCodec binds MAP-SM-DataTypes.AlertServiceCentreArg.
func AlertServiceCentreArgCodec() mapvalues.ValueCodec[mapvalues.AlertServiceCentreArg] {
	return compositeValueCodec[mapvalues.AlertServiceCentreArg, *mapvalues.AlertServiceCentreArg]()
}

// InformServiceCentreArgCodec binds MAP-SM-DataTypes.InformServiceCentreArg.
func InformServiceCentreArgCodec() mapvalues.ValueCodec[mapvalues.InformServiceCentreArg] {
	return compositeValueCodec[mapvalues.InformServiceCentreArg, *mapvalues.InformServiceCentreArg]()
}

// ReadyForSMArgCodec binds MAP-SM-DataTypes.ReadyForSM-Arg.
func ReadyForSMArgCodec() mapvalues.ValueCodec[mapvalues.ReadyForSMArg] {
	return compositeValueCodec[mapvalues.ReadyForSMArg, *mapvalues.ReadyForSMArg]()
}

// ReadyForSMResCodec binds MAP-SM-DataTypes.ReadyForSM-Res.
func ReadyForSMResCodec() mapvalues.ValueCodec[mapvalues.ReadyForSMRes] {
	return compositeValueCodec[mapvalues.ReadyForSMRes, *mapvalues.ReadyForSMRes]()
}

// MTForwardSMVGCSArgCodec binds MAP-SM-DataTypes.MT-ForwardSM-VGCS-Arg.
func MTForwardSMVGCSArgCodec() mapvalues.ValueCodec[mapvalues.MTForwardSMVGCSArg] {
	return compositeValueCodec[mapvalues.MTForwardSMVGCSArg, *mapvalues.MTForwardSMVGCSArg]()
}

// MTForwardSMVGCSResCodec binds MAP-SM-DataTypes.MT-ForwardSM-VGCS-Res.
func MTForwardSMVGCSResCodec() mapvalues.ValueCodec[mapvalues.MTForwardSMVGCSRes] {
	return compositeValueCodec[mapvalues.MTForwardSMVGCSRes, *mapvalues.MTForwardSMVGCSRes]()
}

// DispatcherListCodec binds MAP-SM-DataTypes.DispatcherList.
func DispatcherListCodec() mapvalues.ValueCodec[mapvalues.DispatcherList] {
	return pointerValueCodec(mapvalues.UnmarshalBERDispatcherList, mapvalues.MarshalBERDispatcherList, mapvalues.MarshalDERDispatcherList)
}

// AdditionalDispatcherListCodec binds MAP-SM-DataTypes.AdditionalDispatcherList.
func AdditionalDispatcherListCodec() mapvalues.ValueCodec[mapvalues.AdditionalDispatcherList] {
	return pointerValueCodec(mapvalues.UnmarshalBERAdditionalDispatcherList, mapvalues.MarshalBERAdditionalDispatcherList, mapvalues.MarshalDERAdditionalDispatcherList)
}

// RoutingInfoForLCSArgCodec binds MAP-LCS-DataTypes.RoutingInfoForLCS-Arg.
func RoutingInfoForLCSArgCodec() mapvalues.ValueCodec[mapvalues.RoutingInfoForLCSArg] {
	return compositeValueCodec[mapvalues.RoutingInfoForLCSArg, *mapvalues.RoutingInfoForLCSArg]()
}

// RoutingInfoForLCSResCodec binds MAP-LCS-DataTypes.RoutingInfoForLCS-Res.
func RoutingInfoForLCSResCodec() mapvalues.ValueCodec[mapvalues.RoutingInfoForLCSRes] {
	return compositeValueCodec[mapvalues.RoutingInfoForLCSRes, *mapvalues.RoutingInfoForLCSRes]()
}

// LCSLocationInfoCodec binds MAP-LCS-DataTypes.LCSLocationInfo.
func LCSLocationInfoCodec() mapvalues.ValueCodec[mapvalues.LCSLocationInfo] {
	return compositeValueCodec[mapvalues.LCSLocationInfo, *mapvalues.LCSLocationInfo]()
}

// ProvideSubscriberLocationArgCodec binds MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg.
func ProvideSubscriberLocationArgCodec() mapvalues.ValueCodec[mapvalues.ProvideSubscriberLocationArg] {
	return compositeValueCodec[mapvalues.ProvideSubscriberLocationArg, *mapvalues.ProvideSubscriberLocationArg]()
}

// LocationTypeCodec binds MAP-LCS-DataTypes.LocationType.
func LocationTypeCodec() mapvalues.ValueCodec[mapvalues.LocationType] {
	return compositeValueCodec[mapvalues.LocationType, *mapvalues.LocationType]()
}

// LCSClientIDCodec binds MAP-LCS-DataTypes.LCS-ClientID.
func LCSClientIDCodec() mapvalues.ValueCodec[mapvalues.LCSClientID] {
	return compositeValueCodec[mapvalues.LCSClientID, *mapvalues.LCSClientID]()
}

// LCSClientNameCodec binds MAP-LCS-DataTypes.LCSClientName.
func LCSClientNameCodec() mapvalues.ValueCodec[mapvalues.LCSClientName] {
	return compositeValueCodec[mapvalues.LCSClientName, *mapvalues.LCSClientName]()
}

// NameStringCodec binds MAP-LCS-DataTypes.NameString.
func NameStringCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.NameString]] {
	return pointerValueCodec(mapvalues.UnmarshalBERNameString, mapvalues.MarshalBERNameString, mapvalues.MarshalDERNameString)
}

// LCSRequestorIDCodec binds MAP-LCS-DataTypes.LCSRequestorID.
func LCSRequestorIDCodec() mapvalues.ValueCodec[mapvalues.LCSRequestorID] {
	return compositeValueCodec[mapvalues.LCSRequestorID, *mapvalues.LCSRequestorID]()
}

// RequestorIDStringCodec binds MAP-LCS-DataTypes.RequestorIDString.
func RequestorIDStringCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.RequestorIDString]] {
	return pointerValueCodec(mapvalues.UnmarshalBERRequestorIDString, mapvalues.MarshalBERRequestorIDString, mapvalues.MarshalDERRequestorIDString)
}

// LCSQoSCodec binds MAP-LCS-DataTypes.LCS-QoS.
func LCSQoSCodec() mapvalues.ValueCodec[mapvalues.LCSQoS] {
	return compositeValueCodec[mapvalues.LCSQoS, *mapvalues.LCSQoS]()
}

// ResponseTimeCodec binds MAP-LCS-DataTypes.ResponseTime.
func ResponseTimeCodec() mapvalues.ValueCodec[mapvalues.ResponseTime] {
	return compositeValueCodec[mapvalues.ResponseTime, *mapvalues.ResponseTime]()
}

// LCSCodewordCodec binds MAP-LCS-DataTypes.LCSCodeword.
func LCSCodewordCodec() mapvalues.ValueCodec[mapvalues.LCSCodeword] {
	return compositeValueCodec[mapvalues.LCSCodeword, *mapvalues.LCSCodeword]()
}

// LCSCodewordStringCodec binds MAP-LCS-DataTypes.LCSCodewordString.
func LCSCodewordStringCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.LCSCodewordString]] {
	return pointerValueCodec(mapvalues.UnmarshalBERLCSCodewordString, mapvalues.MarshalBERLCSCodewordString, mapvalues.MarshalDERLCSCodewordString)
}

// LCSPrivacyCheckCodec binds MAP-LCS-DataTypes.LCS-PrivacyCheck.
func LCSPrivacyCheckCodec() mapvalues.ValueCodec[mapvalues.LCSPrivacyCheck] {
	return compositeValueCodec[mapvalues.LCSPrivacyCheck, *mapvalues.LCSPrivacyCheck]()
}

// AreaEventInfoCodec binds MAP-LCS-DataTypes.AreaEventInfo.
func AreaEventInfoCodec() mapvalues.ValueCodec[mapvalues.AreaEventInfo] {
	return compositeValueCodec[mapvalues.AreaEventInfo, *mapvalues.AreaEventInfo]()
}

// AreaDefinitionCodec binds MAP-LCS-DataTypes.AreaDefinition.
func AreaDefinitionCodec() mapvalues.ValueCodec[mapvalues.AreaDefinition] {
	return compositeValueCodec[mapvalues.AreaDefinition, *mapvalues.AreaDefinition]()
}

// AreaListCodec binds MAP-LCS-DataTypes.AreaList.
func AreaListCodec() mapvalues.ValueCodec[mapvalues.AreaList] {
	return pointerValueCodec(mapvalues.UnmarshalBERAreaList, mapvalues.MarshalBERAreaList, mapvalues.MarshalDERAreaList)
}

// AreaCodec binds MAP-LCS-DataTypes.Area.
func AreaCodec() mapvalues.ValueCodec[mapvalues.Area] {
	return compositeValueCodec[mapvalues.Area, *mapvalues.Area]()
}

// PeriodicLDRInfoCodec binds MAP-LCS-DataTypes.PeriodicLDRInfo.
func PeriodicLDRInfoCodec() mapvalues.ValueCodec[mapvalues.PeriodicLDRInfo] {
	return compositeValueCodec[mapvalues.PeriodicLDRInfo, *mapvalues.PeriodicLDRInfo]()
}

// ReportingOptionMillisecondsCodec binds MAP-LCS-DataTypes.ReportingOptionMilliseconds.
func ReportingOptionMillisecondsCodec() mapvalues.ValueCodec[mapvalues.ReportingOptionMilliseconds] {
	return compositeValueCodec[mapvalues.ReportingOptionMilliseconds, *mapvalues.ReportingOptionMilliseconds]()
}

// ReportingPLMNListCodec binds MAP-LCS-DataTypes.ReportingPLMNList.
func ReportingPLMNListCodec() mapvalues.ValueCodec[mapvalues.ReportingPLMNList] {
	return compositeValueCodec[mapvalues.ReportingPLMNList, *mapvalues.ReportingPLMNList]()
}

// PLMNListCodec binds MAP-LCS-DataTypes.PLMNList.
func PLMNListCodec() mapvalues.ValueCodec[mapvalues.PLMNList] {
	return pointerValueCodec(mapvalues.UnmarshalBERPLMNList, mapvalues.MarshalBERPLMNList, mapvalues.MarshalDERPLMNList)
}

// ReportingPLMNCodec binds MAP-LCS-DataTypes.ReportingPLMN.
func ReportingPLMNCodec() mapvalues.ValueCodec[mapvalues.ReportingPLMN] {
	return compositeValueCodec[mapvalues.ReportingPLMN, *mapvalues.ReportingPLMN]()
}

// ProvideSubscriberLocationResCodec binds MAP-LCS-DataTypes.ProvideSubscriberLocation-Res.
func ProvideSubscriberLocationResCodec() mapvalues.ValueCodec[mapvalues.ProvideSubscriberLocationRes] {
	return compositeValueCodec[mapvalues.ProvideSubscriberLocationRes, *mapvalues.ProvideSubscriberLocationRes]()
}

// SubscriberLocationReportArgCodec binds MAP-LCS-DataTypes.SubscriberLocationReport-Arg.
func SubscriberLocationReportArgCodec() mapvalues.ValueCodec[mapvalues.SubscriberLocationReportArg] {
	return compositeValueCodec[mapvalues.SubscriberLocationReportArg, *mapvalues.SubscriberLocationReportArg]()
}

// DeferredmtLrDataCodec binds MAP-LCS-DataTypes.Deferredmt-lrData.
func DeferredmtLrDataCodec() mapvalues.ValueCodec[mapvalues.DeferredmtLrData] {
	return compositeValueCodec[mapvalues.DeferredmtLrData, *mapvalues.DeferredmtLrData]()
}

// ServingNodeAddressCodec binds MAP-LCS-DataTypes.ServingNodeAddress.
func ServingNodeAddressCodec() mapvalues.ValueCodec[mapvalues.ServingNodeAddress] {
	return compositeValueCodec[mapvalues.ServingNodeAddress, *mapvalues.ServingNodeAddress]()
}

// SubscriberLocationReportResCodec binds MAP-LCS-DataTypes.SubscriberLocationReport-Res.
func SubscriberLocationReportResCodec() mapvalues.ValueCodec[mapvalues.SubscriberLocationReportRes] {
	return compositeValueCodec[mapvalues.SubscriberLocationReportRes, *mapvalues.SubscriberLocationReportRes]()
}

// SSUserDataCodec binds SS-DataTypes.SS-UserData.
func SSUserDataCodec() mapvalues.ValueCodec[mapvalues.BERValue[mapvalues.SSUserData]] {
	return pointerValueCodec(mapvalues.UnmarshalBERSSUserData, mapvalues.MarshalBERSSUserData, mapvalues.MarshalDERSSUserData)
}

// NotifySSArgCodec binds SS-DataTypes.NotifySS-Arg.
func NotifySSArgCodec() mapvalues.ValueCodec[mapvalues.NotifySSArg] {
	return compositeValueCodec[mapvalues.NotifySSArg, *mapvalues.NotifySSArg]()
}

// ForwardChargeAdviceArgCodec binds SS-DataTypes.ForwardChargeAdviceArg.
func ForwardChargeAdviceArgCodec() mapvalues.ValueCodec[mapvalues.ForwardChargeAdviceArg] {
	return compositeValueCodec[mapvalues.ForwardChargeAdviceArg, *mapvalues.ForwardChargeAdviceArg]()
}

// ChargingInformationCodec binds SS-DataTypes.ChargingInformation.
func ChargingInformationCodec() mapvalues.ValueCodec[mapvalues.ChargingInformation] {
	return compositeValueCodec[mapvalues.ChargingInformation, *mapvalues.ChargingInformation]()
}

// ForwardCUGInfoArgCodec binds SS-DataTypes.ForwardCUG-InfoArg.
func ForwardCUGInfoArgCodec() mapvalues.ValueCodec[mapvalues.ForwardCUGInfoArg] {
	return compositeValueCodec[mapvalues.ForwardCUGInfoArg, *mapvalues.ForwardCUGInfoArg]()
}

// ECTIndicatorCodec binds SS-DataTypes.ECT-Indicator.
func ECTIndicatorCodec() mapvalues.ValueCodec[mapvalues.ECTIndicator] {
	return compositeValueCodec[mapvalues.ECTIndicator, *mapvalues.ECTIndicator]()
}

// NameIndicatorCodec binds SS-DataTypes.NameIndicator.
func NameIndicatorCodec() mapvalues.ValueCodec[mapvalues.NameIndicator] {
	return compositeValueCodec[mapvalues.NameIndicator, *mapvalues.NameIndicator]()
}

// NameCodec binds SS-DataTypes.Name.
func NameCodec() mapvalues.ValueCodec[mapvalues.Name] {
	return compositeValueCodec[mapvalues.Name, *mapvalues.Name]()
}

// NameSetCodec binds SS-DataTypes.NameSet.
func NameSetCodec() mapvalues.ValueCodec[mapvalues.NameSet] {
	return compositeValueCodec[mapvalues.NameSet, *mapvalues.NameSet]()
}

// RDNCodec binds SS-DataTypes.RDN.
func RDNCodec() mapvalues.ValueCodec[mapvalues.RDN] {
	return compositeValueCodec[mapvalues.RDN, *mapvalues.RDN]()
}

// RemotePartyNumberCodec binds SS-DataTypes.RemotePartyNumber.
func RemotePartyNumberCodec() mapvalues.ValueCodec[mapvalues.RemotePartyNumber] {
	return compositeValueCodec[mapvalues.RemotePartyNumber, *mapvalues.RemotePartyNumber]()
}

// AccessRegisterCCEntryArgCodec binds SS-DataTypes.AccessRegisterCCEntryArg.
func AccessRegisterCCEntryArgCodec() mapvalues.ValueCodec[mapvalues.AccessRegisterCCEntryArg] {
	return compositeValueCodec[mapvalues.AccessRegisterCCEntryArg, *mapvalues.AccessRegisterCCEntryArg]()
}

// CallDeflectionArgCodec binds SS-DataTypes.CallDeflectionArg.
func CallDeflectionArgCodec() mapvalues.ValueCodec[mapvalues.CallDeflectionArg] {
	return compositeValueCodec[mapvalues.CallDeflectionArg, *mapvalues.CallDeflectionArg]()
}

// UserUserServiceArgCodec binds SS-DataTypes.UserUserServiceArg.
func UserUserServiceArgCodec() mapvalues.ValueCodec[mapvalues.UserUserServiceArg] {
	return compositeValueCodec[mapvalues.UserUserServiceArg, *mapvalues.UserUserServiceArg]()
}

// LocationNotificationArgCodec binds SS-DataTypes.LocationNotificationArg.
func LocationNotificationArgCodec() mapvalues.ValueCodec[mapvalues.LocationNotificationArg] {
	return compositeValueCodec[mapvalues.LocationNotificationArg, *mapvalues.LocationNotificationArg]()
}

// LocationNotificationResCodec binds SS-DataTypes.LocationNotificationRes.
func LocationNotificationResCodec() mapvalues.ValueCodec[mapvalues.LocationNotificationRes] {
	return compositeValueCodec[mapvalues.LocationNotificationRes, *mapvalues.LocationNotificationRes]()
}

// LCSMOLRArgCodec binds SS-DataTypes.LCS-MOLRArg.
func LCSMOLRArgCodec() mapvalues.ValueCodec[mapvalues.LCSMOLRArg] {
	return compositeValueCodec[mapvalues.LCSMOLRArg, *mapvalues.LCSMOLRArg]()
}

// MultiplePositioningProtocolPDUsCodec binds SS-DataTypes.MultiplePositioningProtocolPDUs.
func MultiplePositioningProtocolPDUsCodec() mapvalues.ValueCodec[mapvalues.MultiplePositioningProtocolPDUs] {
	return pointerValueCodec(mapvalues.UnmarshalBERMultiplePositioningProtocolPDUs, mapvalues.MarshalBERMultiplePositioningProtocolPDUs, mapvalues.MarshalDERMultiplePositioningProtocolPDUs)
}

// LCSMOLRResCodec binds SS-DataTypes.LCS-MOLRRes.
func LCSMOLRResCodec() mapvalues.ValueCodec[mapvalues.LCSMOLRRes] {
	return compositeValueCodec[mapvalues.LCSMOLRRes, *mapvalues.LCSMOLRRes]()
}

// LCSAreaEventRequestArgCodec binds SS-DataTypes.LCS-AreaEventRequestArg.
func LCSAreaEventRequestArgCodec() mapvalues.ValueCodec[mapvalues.LCSAreaEventRequestArg] {
	return compositeValueCodec[mapvalues.LCSAreaEventRequestArg, *mapvalues.LCSAreaEventRequestArg]()
}

// LCSSLMOLRArgCodec binds SS-DataTypes.LCS-SLMOLRArg.
func LCSSLMOLRArgCodec() mapvalues.ValueCodec[mapvalues.LCSSLMOLRArg] {
	return compositeValueCodec[mapvalues.LCSSLMOLRArg, *mapvalues.LCSSLMOLRArg]()
}

// PreferredRangingResultCodec binds SS-DataTypes.PreferredRangingResult.
func PreferredRangingResultCodec() mapvalues.ValueCodec[mapvalues.PreferredRangingResult] {
	return compositeValueCodec[mapvalues.PreferredRangingResult, *mapvalues.PreferredRangingResult]()
}

// RelatedUEInfoCodec binds SS-DataTypes.RelatedUEInfo.
func RelatedUEInfoCodec() mapvalues.ValueCodec[mapvalues.RelatedUEInfo] {
	return pointerValueCodec(mapvalues.UnmarshalBERRelatedUEInfo, mapvalues.MarshalBERRelatedUEInfo, mapvalues.MarshalDERRelatedUEInfo)
}

// RangingUEInfoCodec binds SS-DataTypes.RangingUEInfo.
func RangingUEInfoCodec() mapvalues.ValueCodec[mapvalues.RangingUEInfo] {
	return compositeValueCodec[mapvalues.RangingUEInfo, *mapvalues.RangingUEInfo]()
}

// LCSSLMOLRResCodec binds SS-DataTypes.LCS-SLMOLRRes.
func LCSSLMOLRResCodec() mapvalues.ValueCodec[mapvalues.LCSSLMOLRRes] {
	return compositeValueCodec[mapvalues.LCSSLMOLRRes, *mapvalues.LCSSLMOLRRes]()
}

// RelativeResultCodec binds SS-DataTypes.RelativeResult.
func RelativeResultCodec() mapvalues.ValueCodec[mapvalues.RelativeResult] {
	return pointerValueCodec(mapvalues.UnmarshalBERRelativeResult, mapvalues.MarshalBERRelativeResult, mapvalues.MarshalDERRelativeResult)
}

// SingleRelativeResultCodec binds SS-DataTypes.SingleRelativeResult.
func SingleRelativeResultCodec() mapvalues.ValueCodec[mapvalues.SingleRelativeResult] {
	return compositeValueCodec[mapvalues.SingleRelativeResult, *mapvalues.SingleRelativeResult]()
}

// RelativeLocationCoordinatesCodec binds SS-DataTypes.RelativeLocationCoordinates.
func RelativeLocationCoordinatesCodec() mapvalues.ValueCodec[mapvalues.RelativeLocationCoordinates] {
	return compositeValueCodec[mapvalues.RelativeLocationCoordinates, *mapvalues.RelativeLocationCoordinates]()
}

// Relative2DLocationWithUncertaintyEllipseCodec binds SS-DataTypes.Relative2D-LocationWithUncertaintyEllipse.
func Relative2DLocationWithUncertaintyEllipseCodec() mapvalues.ValueCodec[mapvalues.Relative2DLocationWithUncertaintyEllipse] {
	return compositeValueCodec[mapvalues.Relative2DLocationWithUncertaintyEllipse, *mapvalues.Relative2DLocationWithUncertaintyEllipse]()
}

// Relative3DLocationWithUncertaintyEllipsoidCodec binds SS-DataTypes.Relative3D-LocationWithUncertaintyEllipsoid.
func Relative3DLocationWithUncertaintyEllipsoidCodec() mapvalues.ValueCodec[mapvalues.Relative3DLocationWithUncertaintyEllipsoid] {
	return compositeValueCodec[mapvalues.Relative3DLocationWithUncertaintyEllipsoid, *mapvalues.Relative3DLocationWithUncertaintyEllipsoid]()
}

// RangeDirectionCodec binds SS-DataTypes.RangeDirection.
func RangeDirectionCodec() mapvalues.ValueCodec[mapvalues.RangeDirection] {
	return compositeValueCodec[mapvalues.RangeDirection, *mapvalues.RangeDirection]()
}

// RangeCodec binds SS-DataTypes.Range.
func RangeCodec() mapvalues.ValueCodec[mapvalues.Range] {
	return compositeValueCodec[mapvalues.Range, *mapvalues.Range]()
}

// AzimuthCodec binds SS-DataTypes.Azimuth.
func AzimuthCodec() mapvalues.ValueCodec[mapvalues.Azimuth] {
	return compositeValueCodec[mapvalues.Azimuth, *mapvalues.Azimuth]()
}

// ElevationCodec binds SS-DataTypes.Elevation.
func ElevationCodec() mapvalues.ValueCodec[mapvalues.Elevation] {
	return compositeValueCodec[mapvalues.Elevation, *mapvalues.Elevation]()
}

// RelVelocityEstimateCodec binds SS-DataTypes.RelVelocityEstimate.
func RelVelocityEstimateCodec() mapvalues.ValueCodec[mapvalues.RelVelocityEstimate] {
	return compositeValueCodec[mapvalues.RelVelocityEstimate, *mapvalues.RelVelocityEstimate]()
}

// LCSAreaEventReportArgCodec binds SS-DataTypes.LCS-AreaEventReportArg.
func LCSAreaEventReportArgCodec() mapvalues.ValueCodec[mapvalues.LCSAreaEventReportArg] {
	return compositeValueCodec[mapvalues.LCSAreaEventReportArg, *mapvalues.LCSAreaEventReportArg]()
}

// LCSAreaEventCancellationArgCodec binds SS-DataTypes.LCS-AreaEventCancellationArg.
func LCSAreaEventCancellationArgCodec() mapvalues.ValueCodec[mapvalues.LCSAreaEventCancellationArg] {
	return compositeValueCodec[mapvalues.LCSAreaEventCancellationArg, *mapvalues.LCSAreaEventCancellationArg]()
}

// LCSPeriodicLocationRequestArgCodec binds SS-DataTypes.LCS-PeriodicLocationRequestArg.
func LCSPeriodicLocationRequestArgCodec() mapvalues.ValueCodec[mapvalues.LCSPeriodicLocationRequestArg] {
	return compositeValueCodec[mapvalues.LCSPeriodicLocationRequestArg, *mapvalues.LCSPeriodicLocationRequestArg]()
}

// LCSPeriodicLocationRequestResCodec binds SS-DataTypes.LCS-PeriodicLocationRequestRes.
func LCSPeriodicLocationRequestResCodec() mapvalues.ValueCodec[mapvalues.LCSPeriodicLocationRequestRes] {
	return compositeValueCodec[mapvalues.LCSPeriodicLocationRequestRes, *mapvalues.LCSPeriodicLocationRequestRes]()
}

// LCSLocationUpdateArgCodec binds SS-DataTypes.LCS-LocationUpdateArg.
func LCSLocationUpdateArgCodec() mapvalues.ValueCodec[mapvalues.LCSLocationUpdateArg] {
	return compositeValueCodec[mapvalues.LCSLocationUpdateArg, *mapvalues.LCSLocationUpdateArg]()
}

// LCSLocationUpdateResCodec binds SS-DataTypes.LCS-LocationUpdateRes.
func LCSLocationUpdateResCodec() mapvalues.ValueCodec[mapvalues.LCSLocationUpdateRes] {
	return compositeValueCodec[mapvalues.LCSLocationUpdateRes, *mapvalues.LCSLocationUpdateRes]()
}

// LCSPeriodicLocationCancellationArgCodec binds SS-DataTypes.LCS-PeriodicLocationCancellationArg.
func LCSPeriodicLocationCancellationArgCodec() mapvalues.ValueCodec[mapvalues.LCSPeriodicLocationCancellationArg] {
	return compositeValueCodec[mapvalues.LCSPeriodicLocationCancellationArg, *mapvalues.LCSPeriodicLocationCancellationArg]()
}

// LCSPeriodicTriggeredInvokeArgCodec binds SS-DataTypes.LCS-PeriodicTriggeredInvokeArg.
func LCSPeriodicTriggeredInvokeArgCodec() mapvalues.ValueCodec[mapvalues.LCSPeriodicTriggeredInvokeArg] {
	return compositeValueCodec[mapvalues.LCSPeriodicTriggeredInvokeArg, *mapvalues.LCSPeriodicTriggeredInvokeArg]()
}

// PeriodicLocationCodec binds SS-DataTypes.PeriodicLocation.
func PeriodicLocationCodec() mapvalues.ValueCodec[mapvalues.PeriodicLocation] {
	return compositeValueCodec[mapvalues.PeriodicLocation, *mapvalues.PeriodicLocation]()
}

// AreaEventReportingCodec binds SS-DataTypes.AreaEventReporting.
func AreaEventReportingCodec() mapvalues.ValueCodec[mapvalues.AreaEventReporting] {
	return compositeValueCodec[mapvalues.AreaEventReporting, *mapvalues.AreaEventReporting]()
}

// DataTypesAreaListCodec binds SS-DataTypes.AreaList.
func DataTypesAreaListCodec() mapvalues.ValueCodec[mapvalues.DataTypesAreaList] {
	return pointerValueCodec(mapvalues.UnmarshalBERDataTypesAreaList, mapvalues.MarshalBERDataTypesAreaList, mapvalues.MarshalDERDataTypesAreaList)
}

// DataTypesAreaCodec binds SS-DataTypes.Area.
func DataTypesAreaCodec() mapvalues.ValueCodec[mapvalues.DataTypesArea] {
	return compositeValueCodec[mapvalues.DataTypesArea, *mapvalues.DataTypesArea]()
}

// MotionEventReportingCodec binds SS-DataTypes.MotionEventReporting.
func MotionEventReportingCodec() mapvalues.ValueCodec[mapvalues.MotionEventReporting] {
	return compositeValueCodec[mapvalues.MotionEventReporting, *mapvalues.MotionEventReporting]()
}

// LCSPeriodicTriggeredInvokeResCodec binds SS-DataTypes.LCS-PeriodicTriggeredInvokeRes.
func LCSPeriodicTriggeredInvokeResCodec() mapvalues.ValueCodec[mapvalues.LCSPeriodicTriggeredInvokeRes] {
	return compositeValueCodec[mapvalues.LCSPeriodicTriggeredInvokeRes, *mapvalues.LCSPeriodicTriggeredInvokeRes]()
}

// LCSEventReportArgCodec binds SS-DataTypes.LCS-EventReportArg.
func LCSEventReportArgCodec() mapvalues.ValueCodec[mapvalues.LCSEventReportArg] {
	return compositeValueCodec[mapvalues.LCSEventReportArg, *mapvalues.LCSEventReportArg]()
}

// ControlPlaneCIoT5GSOptimisationCodec binds SS-DataTypes.ControlPlane-CIoT-5GS-Optimisation.
func ControlPlaneCIoT5GSOptimisationCodec() mapvalues.ValueCodec[mapvalues.ControlPlaneCIoT5GSOptimisation] {
	return compositeValueCodec[mapvalues.ControlPlaneCIoT5GSOptimisation, *mapvalues.ControlPlaneCIoT5GSOptimisation]()
}

// LCSUserPlaneReportAFAddrCodec binds SS-DataTypes.LCS-UserPlaneReportAFAddr.
func LCSUserPlaneReportAFAddrCodec() mapvalues.ValueCodec[mapvalues.LCSUserPlaneReportAFAddr] {
	return compositeValueCodec[mapvalues.LCSUserPlaneReportAFAddr, *mapvalues.LCSUserPlaneReportAFAddr]()
}

// Ipv4AddrsCodec binds SS-DataTypes.Ipv4Addrs.
func Ipv4AddrsCodec() mapvalues.ValueCodec[mapvalues.Ipv4Addrs] {
	return pointerValueCodec(mapvalues.UnmarshalBERIpv4Addrs, mapvalues.MarshalBERIpv4Addrs, mapvalues.MarshalDERIpv4Addrs)
}

// Ipv6AddrsCodec binds SS-DataTypes.Ipv6Addrs.
func Ipv6AddrsCodec() mapvalues.ValueCodec[mapvalues.Ipv6Addrs] {
	return pointerValueCodec(mapvalues.UnmarshalBERIpv6Addrs, mapvalues.MarshalBERIpv6Addrs, mapvalues.MarshalDERIpv6Addrs)
}

// LCSCumulativeReportCriteriaCodec binds SS-DataTypes.LCS-CumulativeReportCriteria.
func LCSCumulativeReportCriteriaCodec() mapvalues.ValueCodec[mapvalues.LCSCumulativeReportCriteria] {
	return compositeValueCodec[mapvalues.LCSCumulativeReportCriteria, *mapvalues.LCSCumulativeReportCriteria]()
}

// LCSEventReportResCodec binds SS-DataTypes.LCS-EventReportRes.
func LCSEventReportResCodec() mapvalues.ValueCodec[mapvalues.LCSEventReportRes] {
	return compositeValueCodec[mapvalues.LCSEventReportRes, *mapvalues.LCSEventReportRes]()
}

// LCSCancelDeferredLocationArgCodec binds SS-DataTypes.LCS-CancelDeferredLocationArg.
func LCSCancelDeferredLocationArgCodec() mapvalues.ValueCodec[mapvalues.LCSCancelDeferredLocationArg] {
	return compositeValueCodec[mapvalues.LCSCancelDeferredLocationArg, *mapvalues.LCSCancelDeferredLocationArg]()
}

// LCSLocationPrivacySettingArgCodec binds SS-DataTypes.LCS-LocationPrivacySettingArg.
func LCSLocationPrivacySettingArgCodec() mapvalues.ValueCodec[mapvalues.LCSLocationPrivacySettingArg] {
	return compositeValueCodec[mapvalues.LCSLocationPrivacySettingArg, *mapvalues.LCSLocationPrivacySettingArg]()
}

// LCSValidTimePeriodCodec binds SS-DataTypes.LCS-ValidTimePeriod.
func LCSValidTimePeriodCodec() mapvalues.ValueCodec[mapvalues.LCSValidTimePeriod] {
	return compositeValueCodec[mapvalues.LCSValidTimePeriod, *mapvalues.LCSValidTimePeriod]()
}

// LCSPruAssociationArgCodec binds SS-DataTypes.LCS-PruAssociationArg.
func LCSPruAssociationArgCodec() mapvalues.ValueCodec[mapvalues.LCSPruAssociationArg] {
	return compositeValueCodec[mapvalues.LCSPruAssociationArg, *mapvalues.LCSPruAssociationArg]()
}

// LCSPruAssociationResCodec binds SS-DataTypes.LCS-PruAssociationRes.
func LCSPruAssociationResCodec() mapvalues.ValueCodec[mapvalues.LCSPruAssociationRes] {
	return compositeValueCodec[mapvalues.LCSPruAssociationRes, *mapvalues.LCSPruAssociationRes]()
}

// LCSPruDisassociationArgCodec binds SS-DataTypes.LCS-PruDisassociationArg.
func LCSPruDisassociationArgCodec() mapvalues.ValueCodec[mapvalues.LCSPruDisassociationArg] {
	return compositeValueCodec[mapvalues.LCSPruDisassociationArg, *mapvalues.LCSPruDisassociationArg]()
}

// LCSSLMTLRArgCodec binds SS-DataTypes.LCS-SLMTLRArg.
func LCSSLMTLRArgCodec() mapvalues.ValueCodec[mapvalues.LCSSLMTLRArg] {
	return compositeValueCodec[mapvalues.LCSSLMTLRArg, *mapvalues.LCSSLMTLRArg]()
}

// LCSSLMTLRResCodec binds SS-DataTypes.LCS-SLMTLRRes.
func LCSSLMTLRResCodec() mapvalues.ValueCodec[mapvalues.LCSSLMTLRRes] {
	return compositeValueCodec[mapvalues.LCSSLMTLRRes, *mapvalues.LCSSLMTLRRes]()
}

// RangingSLPPListCodec binds SS-DataTypes.RangingSLPPList.
func RangingSLPPListCodec() mapvalues.ValueCodec[mapvalues.RangingSLPPList] {
	return pointerValueCodec(mapvalues.UnmarshalBERRangingSLPPList, mapvalues.MarshalBERRangingSLPPList, mapvalues.MarshalDERRangingSLPPList)
}

// RangingSLPPInfoCodec binds SS-DataTypes.RangingSLPPInfo.
func RangingSLPPInfoCodec() mapvalues.ValueCodec[mapvalues.RangingSLPPInfo] {
	return compositeValueCodec[mapvalues.RangingSLPPInfo, *mapvalues.RangingSLPPInfo]()
}

// LCSDLRSPPTransportArgCodec binds SS-DataTypes.LCS-DLRSPPTransportArg.
func LCSDLRSPPTransportArgCodec() mapvalues.ValueCodec[mapvalues.LCSDLRSPPTransportArg] {
	return compositeValueCodec[mapvalues.LCSDLRSPPTransportArg, *mapvalues.LCSDLRSPPTransportArg]()
}

// LCSDLRSPPTransportResCodec binds SS-DataTypes.LCS-DLRSPPTransportRes.
func LCSDLRSPPTransportResCodec() mapvalues.ValueCodec[mapvalues.LCSDLRSPPTransportRes] {
	return compositeValueCodec[mapvalues.LCSDLRSPPTransportRes, *mapvalues.LCSDLRSPPTransportRes]()
}

// LCSULRSPPTransportArgCodec binds SS-DataTypes.LCS-ULRSPPTransportArg.
func LCSULRSPPTransportArgCodec() mapvalues.ValueCodec[mapvalues.LCSULRSPPTransportArg] {
	return compositeValueCodec[mapvalues.LCSULRSPPTransportArg, *mapvalues.LCSULRSPPTransportArg]()
}

// LCSULRSPPTransportResCodec binds SS-DataTypes.LCS-ULRSPPTransportRes.
func LCSULRSPPTransportResCodec() mapvalues.ValueCodec[mapvalues.LCSULRSPPTransportRes] {
	return compositeValueCodec[mapvalues.LCSULRSPPTransportRes, *mapvalues.LCSULRSPPTransportRes]()
}

// PruAssociationRejParamCodec binds SS-Errors.PruAssociationRejParam.
func PruAssociationRejParamCodec() mapvalues.ValueCodec[mapvalues.PruAssociationRejParam] {
	return compositeValueCodec[mapvalues.PruAssociationRejParam, *mapvalues.PruAssociationRejParam]()
}
