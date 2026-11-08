// Code generated from ASN.1 module "MAP-MS-DataTypes". DO NOT EDIT.

package gsm0902_v4_19_1

import (
	"fmt"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

const (

	// MaxNumOfSentParameter is the integer constant for maxNumOfSentParameter.
	MaxNumOfSentParameter int64 = 6

	// MaxNumOfZoneCodes is the integer constant for maxNumOfZoneCodes.
	MaxNumOfZoneCodes int64 = 10
)

// UpdateLocationArg represents the ASN.1 type UpdateLocationArg (SEQUENCE).
type UpdateLocationArg struct {
	Imsi         IMSI              `asn1:""`
	LocationInfo LocationInfo      `asn1:""`
	VlrNumber    ISDNAddressString `asn1:""`
	Lmsi         *LMSI             `asn1:"tag:10,context,implicit,optional" json:"Lmsi,omitempty"`
	ExtCount_    int64             `asn1:"-" json:"-"`
	ExtPresent_  []bool            `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// UpdateLocationRes choice constants.
const (
	UpdateLocationResChoiceHlrNumber                   = 1
	UpdateLocationResChoiceExtensibleUpdateLocationRes = 2
)

// UpdateLocationRes represents the ASN.1 CHOICE type UpdateLocationRes.
type UpdateLocationRes struct {
	Choice                      int
	berReplayNode_              *ber.ReplayNode              `json:"-"`
	HlrNumber                   *ISDNAddressString           `json:"HlrNumber,omitempty"`
	ExtensibleUpdateLocationRes *ExtensibleUpdateLocationRes `json:"ExtensibleUpdateLocationRes,omitempty"`
}

// NewUpdateLocationResHlrNumber creates a UpdateLocationRes with the hlr-Number alternative.
func NewUpdateLocationResHlrNumber(v ISDNAddressString) UpdateLocationRes {
	return UpdateLocationRes{
		Choice:    UpdateLocationResChoiceHlrNumber,
		HlrNumber: &v,
	}
}

// NewUpdateLocationResExtensibleUpdateLocationRes creates a UpdateLocationRes with the extensibleUpdateLocationRes alternative.
func NewUpdateLocationResExtensibleUpdateLocationRes(v ExtensibleUpdateLocationRes) UpdateLocationRes {
	return UpdateLocationRes{
		Choice:                      UpdateLocationResChoiceExtensibleUpdateLocationRes,
		ExtensibleUpdateLocationRes: &v,
	}
}

// ExtensibleUpdateLocationRes represents the ASN.1 type ExtensibleUpdateLocationRes (SEQUENCE).
type ExtensibleUpdateLocationRes struct {
	HlrNumber   ISDNAddressString `asn1:""`
	ExtCount_   int64             `asn1:"-" json:"-"`
	ExtPresent_ []bool            `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CancelLocationArg choice constants.
const (
	CancelLocationArgChoiceImsi         = 1
	CancelLocationArgChoiceImsiWithLMSI = 2
)

// CancelLocationArg represents the ASN.1 CHOICE type CancelLocationArg.
type CancelLocationArg struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Imsi           *IMSI           `json:"Imsi,omitempty"`
	ImsiWithLMSI   *IMSIWithLMSI   `json:"ImsiWithLMSI,omitempty"`
}

// NewCancelLocationArgImsi creates a CancelLocationArg with the imsi alternative.
func NewCancelLocationArgImsi(v IMSI) CancelLocationArg {
	return CancelLocationArg{
		Choice: CancelLocationArgChoiceImsi,
		Imsi:   &v,
	}
}

// NewCancelLocationArgImsiWithLMSI creates a CancelLocationArg with the imsi-WithLMSI alternative.
func NewCancelLocationArgImsiWithLMSI(v IMSIWithLMSI) CancelLocationArg {
	return CancelLocationArg{
		Choice:       CancelLocationArgChoiceImsiWithLMSI,
		ImsiWithLMSI: &v,
	}
}

// PurgeMSArg represents the ASN.1 type PurgeMS-Arg (SEQUENCE).
type PurgeMSArg struct {
	Imsi        IMSI              `asn1:""`
	VlrNumber   ISDNAddressString `asn1:""`
	ExtCount_   int64             `asn1:"-" json:"-"`
	ExtPresent_ []bool            `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// IMSIWithLMSI represents the ASN.1 type IMSI-WithLMSI (SEQUENCE).
type IMSIWithLMSI struct {
	Imsi        IMSI   `asn1:""`
	Lmsi        LMSI   `asn1:""`
	ExtCount_   int64  `asn1:"-" json:"-"`
	ExtPresent_ []bool `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SendIdentificationRes represents the ASN.1 type SendIdentificationRes (SEQUENCE).
type SendIdentificationRes struct {
	Imsi                           IMSI                   `asn1:""`
	AuthenticationSetList          *AuthenticationSetList `asn1:",optional" json:"AuthenticationSetList,omitempty"`
	berAuthenticationSetListIndef_ bool                   `asn1:"-" json:"-"`
	ExtCount_                      int64                  `asn1:"-" json:"-"`
	ExtPresent_                    []bool                 `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// AuthenticationSetList represents the ASN.1 type AuthenticationSetList (SEQUENCE_OF).
type AuthenticationSetList struct {
	Values         []AuthenticationSet `json:"Values"`
	berReplayNode_ *ber.ReplayNode     `json:"-"`
}

// AuthenticationSet represents the ASN.1 type AuthenticationSet (SEQUENCE).
type AuthenticationSet struct {
	Rand        RAND   `asn1:""`
	Sres        SRES   `asn1:""`
	Kc          Kc     `asn1:""`
	ExtCount_   int64  `asn1:"-" json:"-"`
	ExtPresent_ []bool `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// RAND represents the ASN.1 type RAND (OCTET_STRING).
type RAND = []byte

// SRES represents the ASN.1 type SRES (OCTET_STRING).
type SRES = []byte

// Kc represents the ASN.1 type Kc (OCTET_STRING).
type Kc = []byte

// PrepareHOArg represents the ASN.1 type PrepareHO-Arg (SEQUENCE).
type PrepareHOArg struct {
	TargetCellId        *GlobalCellId       `asn1:",optional" json:"TargetCellId,omitempty"`
	HoNumberNotRequired *struct{}           `asn1:",optional" json:"HoNumberNotRequired,omitempty"`
	BssAPDU             *ExternalSignalInfo `asn1:",optional" json:"BssAPDU,omitempty"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// PerformHOArg represents the ASN.1 type PerformHO-Arg (SEQUENCE).
type PerformHOArg struct {
	TargetCellId     GlobalCellId      `asn1:""`
	ServingCellId    GlobalCellId      `asn1:""`
	ChannelType      ChannelType       `asn1:""`
	ClassmarkInfo    ClassmarkInfo     `asn1:""`
	HandoverPriority *HandoverPriority `asn1:"tag:11,context,implicit,optional" json:"HandoverPriority,omitempty"`
	Kc               *Kc               `asn1:"tag:12,context,implicit,optional" json:"Kc,omitempty"`
	berReplayNode_   *ber.ReplayNode   `asn1:"-" json:"-"`
}

// ChannelType represents the ASN.1 type ChannelType (OCTET_STRING).
type ChannelType = []byte

// ClassmarkInfo represents the ASN.1 type ClassmarkInfo (OCTET_STRING).
type ClassmarkInfo = []byte

// HandoverPriority represents the ASN.1 type HandoverPriority (OCTET_STRING).
type HandoverPriority = []byte

// PrepareHORes represents the ASN.1 type PrepareHO-Res (SEQUENCE).
type PrepareHORes struct {
	HandoverNumber *ISDNAddressString  `asn1:",optional" json:"HandoverNumber,omitempty"`
	BssAPDU        *ExternalSignalInfo `asn1:",optional" json:"BssAPDU,omitempty"`
	ExtCount_      int64               `asn1:"-" json:"-"`
	ExtPresent_    []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// PerformHORes represents the ASN.1 type PerformHO-Res (SEQUENCE).
type PerformHORes struct {
	HandoverNumber   ISDNAddressString  `asn1:""`
	AccessSignalInfo ExternalSignalInfo `asn1:""`
	berReplayNode_   *ber.ReplayNode    `asn1:"-" json:"-"`
}

// PrepareSubsequentHOArg represents the ASN.1 type PrepareSubsequentHO-Arg (SEQUENCE).
type PrepareSubsequentHOArg struct {
	TargetCellId    GlobalCellId       `asn1:""`
	TargetMSCNumber ISDNAddressString  `asn1:""`
	BssAPDU         ExternalSignalInfo `asn1:""`
	ExtCount_       int64              `asn1:"-" json:"-"`
	ExtPresent_     []bool             `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// PerformSubsequentHOArg represents the ASN.1 type PerformSubsequentHO-Arg (SEQUENCE).
type PerformSubsequentHOArg struct {
	TargetCellId    GlobalCellId      `asn1:""`
	ServingCellId   GlobalCellId      `asn1:""`
	TargetMSCNumber ISDNAddressString `asn1:""`
	ClassmarkInfo   *ClassmarkInfo    `asn1:"tag:10,context,implicit,optional" json:"ClassmarkInfo,omitempty"`
	berReplayNode_  *ber.ReplayNode   `asn1:"-" json:"-"`
}

// SendAuthenticationInfoArg represents the ASN.1 type SendAuthenticationInfoArg (OCTET_STRING).
type SendAuthenticationInfoArg = IMSI

// SendAuthenticationInfoRes represents the ASN.1 type SendAuthenticationInfoRes (SEQUENCE_OF).
type SendAuthenticationInfoRes = AuthenticationSetList

// Ki represents the ASN.1 type Ki (OCTET_STRING).
type Ki = []byte

// EquipmentStatus represents the ASN.1 ENUMERATED type EquipmentStatus.
type EquipmentStatus int64

const (
	EquipmentStatusWhiteListed EquipmentStatus = 0
	EquipmentStatusBlackListed EquipmentStatus = 1
	EquipmentStatusGreyListed  EquipmentStatus = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v EquipmentStatus) String() string {
	switch v {
	case EquipmentStatusWhiteListed:
		return "whiteListed"
	case EquipmentStatusBlackListed:
		return "blackListed"
	case EquipmentStatusGreyListed:
		return "greyListed"
	default:
		return "unknown"
	}
}

// SendParametersArg represents the ASN.1 type SendParametersArg (SEQUENCE).
type SendParametersArg struct {
	SubscriberId                  SubscriberId          `asn1:""`
	RequestParameterList          *RequestParameterList `asn1:""`
	berRequestParameterListIndef_ bool                  `asn1:"-" json:"-"`
	berReplayNode_                *ber.ReplayNode       `asn1:"-" json:"-"`
}

// RequestParameterList represents the ASN.1 type RequestParameterList (SEQUENCE_OF).
type RequestParameterList struct {
	Values         []RequestParameter `json:"Values"`
	berReplayNode_ *ber.ReplayNode    `json:"-"`
}

// RequestParameter represents the ASN.1 ENUMERATED type RequestParameter.
type RequestParameter int64

const (
	RequestParameterRequestIMSI              RequestParameter = 0
	RequestParameterRequestAuthenticationSet RequestParameter = 1
	RequestParameterRequestSubscriberData    RequestParameter = 2
	RequestParameterRequestKi                RequestParameter = 4
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v RequestParameter) String() string {
	switch v {
	case RequestParameterRequestIMSI:
		return "requestIMSI"
	case RequestParameterRequestAuthenticationSet:
		return "requestAuthenticationSet"
	case RequestParameterRequestSubscriberData:
		return "requestSubscriberData"
	case RequestParameterRequestKi:
		return "requestKi"
	default:
		return "unknown"
	}
}

// SentParameterList represents the ASN.1 type SentParameterList (SEQUENCE_OF).
type SentParameterList struct {
	Values         []SentParameter `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// SentParameter choice constants.
const (
	SentParameterChoiceImsi              = 1
	SentParameterChoiceAuthenticationSet = 2
	SentParameterChoiceSubscriberData    = 3
	SentParameterChoiceKi                = 4
)

// SentParameter represents the ASN.1 CHOICE type SentParameter.
type SentParameter struct {
	Choice            int
	berReplayNode_    *ber.ReplayNode    `json:"-"`
	Imsi              *IMSI              `json:"Imsi,omitempty"`
	AuthenticationSet *AuthenticationSet `json:"AuthenticationSet,omitempty"`
	SubscriberData    *SubscriberData    `json:"SubscriberData,omitempty"`
	Ki                *Ki                `json:"Ki,omitempty"`
}

// NewSentParameterImsi creates a SentParameter with the imsi alternative.
func NewSentParameterImsi(v IMSI) SentParameter {
	return SentParameter{
		Choice: SentParameterChoiceImsi,
		Imsi:   &v,
	}
}

// NewSentParameterAuthenticationSet creates a SentParameter with the authenticationSet alternative.
func NewSentParameterAuthenticationSet(v AuthenticationSet) SentParameter {
	return SentParameter{
		Choice:            SentParameterChoiceAuthenticationSet,
		AuthenticationSet: &v,
	}
}

// NewSentParameterSubscriberData creates a SentParameter with the subscriberData alternative.
func NewSentParameterSubscriberData(v SubscriberData) SentParameter {
	return SentParameter{
		Choice:         SentParameterChoiceSubscriberData,
		SubscriberData: &v,
	}
}

// NewSentParameterKi creates a SentParameter with the ki alternative.
func NewSentParameterKi(v Ki) SentParameter {
	return SentParameter{
		Choice: SentParameterChoiceKi,
		Ki:     &v,
	}
}

// InsertSubscriberDataArg represents the ASN.1 type InsertSubscriberDataArg (SEQUENCE).
type InsertSubscriberDataArg struct {
	Imsi                                      *IMSI              `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	Msisdn                                    *ISDNAddressString `asn1:"tag:1,context,implicit,optional" json:"Msisdn,omitempty"`
	Category                                  *Category          `asn1:"tag:2,context,implicit,optional" json:"Category,omitempty"`
	SubscriberStatus                          *SubscriberStatus  `asn1:"tag:3,context,implicit,optional" json:"SubscriberStatus,omitempty"`
	BearerServiceList                         *BearerServiceList `asn1:"tag:4,context,implicit,optional" json:"BearerServiceList,omitempty"`
	berBearerServiceListIndef_                bool               `asn1:"-" json:"-"`
	TeleserviceList                           *TeleserviceList   `asn1:"tag:6,context,implicit,optional" json:"TeleserviceList,omitempty"`
	berTeleserviceListIndef_                  bool               `asn1:"-" json:"-"`
	ProvisionedSS                             *SSInfoList        `asn1:"tag:7,context,implicit,optional" json:"ProvisionedSS,omitempty"`
	berProvisionedSSIndef_                    bool               `asn1:"-" json:"-"`
	OdbData                                   *ODBData           `asn1:"tag:8,context,implicit,optional" json:"OdbData,omitempty"`
	RoamingRestrictionDueToUnsupportedFeature *struct{}          `asn1:"tag:9,context,implicit,optional" json:"RoamingRestrictionDueToUnsupportedFeature,omitempty"`
	RegionalSubscriptionData                  *ZoneCodeList      `asn1:"tag:10,context,implicit,optional" json:"RegionalSubscriptionData,omitempty"`
	berRegionalSubscriptionDataIndef_         bool               `asn1:"-" json:"-"`
	ExtCount_                                 int64              `asn1:"-" json:"-"`
	ExtPresent_                               []bool             `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SubscriberData represents the ASN.1 type SubscriberData (SEQUENCE).
type SubscriberData struct {
	Msisdn                                    *ISDNAddressString `asn1:"tag:1,context,implicit,optional" json:"Msisdn,omitempty"`
	Category                                  *Category          `asn1:"tag:2,context,implicit,optional" json:"Category,omitempty"`
	SubscriberStatus                          *SubscriberStatus  `asn1:"tag:3,context,implicit,optional" json:"SubscriberStatus,omitempty"`
	BearerServiceList                         *BearerServiceList `asn1:"tag:4,context,implicit,optional" json:"BearerServiceList,omitempty"`
	berBearerServiceListIndef_                bool               `asn1:"-" json:"-"`
	TeleserviceList                           *TeleserviceList   `asn1:"tag:6,context,implicit,optional" json:"TeleserviceList,omitempty"`
	berTeleserviceListIndef_                  bool               `asn1:"-" json:"-"`
	ProvisionedSS                             *SSInfoList        `asn1:"tag:7,context,implicit,optional" json:"ProvisionedSS,omitempty"`
	berProvisionedSSIndef_                    bool               `asn1:"-" json:"-"`
	OdbData                                   *ODBData           `asn1:"tag:8,context,implicit,optional" json:"OdbData,omitempty"`
	RoamingRestrictionDueToUnsupportedFeature *struct{}          `asn1:"tag:9,context,implicit,optional" json:"RoamingRestrictionDueToUnsupportedFeature,omitempty"`
	RegionalSubscriptionData                  *ZoneCodeList      `asn1:"tag:10,context,implicit,optional" json:"RegionalSubscriptionData,omitempty"`
	berRegionalSubscriptionDataIndef_         bool               `asn1:"-" json:"-"`
	berReplayNode_                            *ber.ReplayNode    `asn1:"-" json:"-"`
}

// SubscriberStatus represents the ASN.1 ENUMERATED type SubscriberStatus.
type SubscriberStatus int64

const (
	SubscriberStatusServiceGranted            SubscriberStatus = 0
	SubscriberStatusOperatorDeterminedBarring SubscriberStatus = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v SubscriberStatus) String() string {
	switch v {
	case SubscriberStatusServiceGranted:
		return "serviceGranted"
	case SubscriberStatusOperatorDeterminedBarring:
		return "operatorDeterminedBarring"
	default:
		return "unknown"
	}
}

// ODBData represents the ASN.1 type ODB-Data (SEQUENCE).
type ODBData struct {
	OdbGeneralData ODBGeneralData `asn1:""`
	OdbHPLMNData   *ODBHPLMNData  `asn1:",optional" json:"OdbHPLMNData,omitempty"`
	ExtCount_      int64          `asn1:"-" json:"-"`
	ExtPresent_    []bool         `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ODBGeneralData represents the ASN.1 type ODB-GeneralData (BIT_STRING).
type ODBGeneralData = runtime.BitString

const (
	// ODBGeneralDataAllOGCallsBarred is position 0 of ASN.1 named bit allOG-CallsBarred of ODB-GeneralData (CCITT X.208 (11/1988) §17).
	ODBGeneralDataAllOGCallsBarred = 0
	// ODBGeneralDataInternationalOGCallsBarred is position 1 of ASN.1 named bit internationalOGCallsBarred of ODB-GeneralData (CCITT X.208 (11/1988) §17).
	ODBGeneralDataInternationalOGCallsBarred = 1
	// ODBGeneralDataInternationalOGCallsNotToHPLMNCountryBarred is position 2 of ASN.1 named bit internationalOGCallsNotToHPLMN-CountryBarred of ODB-GeneralData (CCITT X.208 (11/1988) §17).
	ODBGeneralDataInternationalOGCallsNotToHPLMNCountryBarred = 2
	// ODBGeneralDataPremiumRateInformationOGCallsBarred is position 3 of ASN.1 named bit premiumRateInformationOGCallsBarred of ODB-GeneralData (CCITT X.208 (11/1988) §17).
	ODBGeneralDataPremiumRateInformationOGCallsBarred = 3
	// ODBGeneralDataPremiumRateEntertainementOGCallsBarred is position 4 of ASN.1 named bit premiumRateEntertainementOGCallsBarred of ODB-GeneralData (CCITT X.208 (11/1988) §17).
	ODBGeneralDataPremiumRateEntertainementOGCallsBarred = 4
	// ODBGeneralDataSsAccessBarred is position 5 of ASN.1 named bit ss-AccessBarred of ODB-GeneralData (CCITT X.208 (11/1988) §17).
	ODBGeneralDataSsAccessBarred = 5
)

// ODBHPLMNData represents the ASN.1 type ODB-HPLMN-Data (BIT_STRING).
type ODBHPLMNData = runtime.BitString

const (
	// ODBHPLMNDataPlmnSpecificBarringType1 is position 0 of ASN.1 named bit plmn-SpecificBarringType1 of ODB-HPLMN-Data (CCITT X.208 (11/1988) §17).
	ODBHPLMNDataPlmnSpecificBarringType1 = 0
	// ODBHPLMNDataPlmnSpecificBarringType2 is position 1 of ASN.1 named bit plmn-SpecificBarringType2 of ODB-HPLMN-Data (CCITT X.208 (11/1988) §17).
	ODBHPLMNDataPlmnSpecificBarringType2 = 1
	// ODBHPLMNDataPlmnSpecificBarringType3 is position 2 of ASN.1 named bit plmn-SpecificBarringType3 of ODB-HPLMN-Data (CCITT X.208 (11/1988) §17).
	ODBHPLMNDataPlmnSpecificBarringType3 = 2
	// ODBHPLMNDataPlmnSpecificBarringType4 is position 3 of ASN.1 named bit plmn-SpecificBarringType4 of ODB-HPLMN-Data (CCITT X.208 (11/1988) §17).
	ODBHPLMNDataPlmnSpecificBarringType4 = 3
)

// ZoneCodeList represents the ASN.1 type ZoneCodeList (SEQUENCE_OF).
type ZoneCodeList struct {
	Values         []ZoneCode      `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// ZoneCode represents the ASN.1 type ZoneCode (OCTET_STRING).
type ZoneCode = []byte

// InsertSubscriberDataRes represents the ASN.1 type InsertSubscriberDataRes (SEQUENCE).
type InsertSubscriberDataRes struct {
	TeleserviceList              *TeleserviceList              `asn1:"tag:1,context,implicit,optional" json:"TeleserviceList,omitempty"`
	berTeleserviceListIndef_     bool                          `asn1:"-" json:"-"`
	BearerServiceList            *BearerServiceList            `asn1:"tag:2,context,implicit,optional" json:"BearerServiceList,omitempty"`
	berBearerServiceListIndef_   bool                          `asn1:"-" json:"-"`
	SsList                       *SSList                       `asn1:"tag:3,context,implicit,optional" json:"SsList,omitempty"`
	berSsListIndef_              bool                          `asn1:"-" json:"-"`
	OdbGeneralData               *ODBGeneralData               `asn1:"tag:4,context,implicit,optional" json:"OdbGeneralData,omitempty"`
	RegionalSubscriptionResponse *RegionalSubscriptionResponse `asn1:"tag:5,context,implicit,optional" json:"RegionalSubscriptionResponse,omitempty"`
	ExtCount_                    int64                         `asn1:"-" json:"-"`
	ExtPresent_                  []bool                        `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// RegionalSubscriptionResponse represents the ASN.1 ENUMERATED type RegionalSubscriptionResponse.
type RegionalSubscriptionResponse int64

const (
	RegionalSubscriptionResponseMscAreaRestricted         RegionalSubscriptionResponse = 0
	RegionalSubscriptionResponseTooManyZoneCodes          RegionalSubscriptionResponse = 1
	RegionalSubscriptionResponseZoneCodesConflict         RegionalSubscriptionResponse = 2
	RegionalSubscriptionResponseRegionalSubscNotSupported RegionalSubscriptionResponse = 3
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v RegionalSubscriptionResponse) String() string {
	switch v {
	case RegionalSubscriptionResponseMscAreaRestricted:
		return "msc-AreaRestricted"
	case RegionalSubscriptionResponseTooManyZoneCodes:
		return "tooManyZoneCodes"
	case RegionalSubscriptionResponseZoneCodesConflict:
		return "zoneCodesConflict"
	case RegionalSubscriptionResponseRegionalSubscNotSupported:
		return "regionalSubscNotSupported"
	default:
		return "unknown"
	}
}

// DeleteSubscriberDataArg represents the ASN.1 type DeleteSubscriberDataArg (SEQUENCE).
type DeleteSubscriberDataArg struct {
	Imsi                                      IMSI              `asn1:"tag:0,context,implicit"`
	BasicServiceList                          *BasicServiceList `asn1:"tag:1,context,implicit,optional" json:"BasicServiceList,omitempty"`
	berBasicServiceListIndef_                 bool              `asn1:"-" json:"-"`
	SsList                                    *SSList           `asn1:"tag:2,context,implicit,optional" json:"SsList,omitempty"`
	berSsListIndef_                           bool              `asn1:"-" json:"-"`
	RoamingRestrictionDueToUnsupportedFeature *struct{}         `asn1:"tag:4,context,implicit,optional" json:"RoamingRestrictionDueToUnsupportedFeature,omitempty"`
	RegionalSubscriptionIdentifier            *ZoneCode         `asn1:"tag:5,context,implicit,optional" json:"RegionalSubscriptionIdentifier,omitempty"`
	ExtCount_                                 int64             `asn1:"-" json:"-"`
	ExtPresent_                               []bool            `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// DeleteSubscriberDataRes represents the ASN.1 type DeleteSubscriberDataRes (SEQUENCE).
type DeleteSubscriberDataRes struct {
	RegionalSubscriptionResponse *RegionalSubscriptionResponse `asn1:"tag:0,context,implicit,optional" json:"RegionalSubscriptionResponse,omitempty"`
	ExtCount_                    int64                         `asn1:"-" json:"-"`
	ExtPresent_                  []bool                        `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ResetArg represents the ASN.1 type ResetArg (SEQUENCE).
type ResetArg struct {
	NetworkResource  *NetworkResource  `asn1:",optional" json:"NetworkResource,omitempty"`
	HlrNumber        ISDNAddressString `asn1:""`
	HlrList          *HLRList          `asn1:",optional" json:"HlrList,omitempty"`
	berHlrListIndef_ bool              `asn1:"-" json:"-"`
	ExtCount_        int64             `asn1:"-" json:"-"`
	ExtPresent_      []bool            `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// RestoreDataArg represents the ASN.1 type RestoreDataArg (SEQUENCE).
type RestoreDataArg struct {
	Imsi        IMSI   `asn1:""`
	Lmsi        *LMSI  `asn1:",optional" json:"Lmsi,omitempty"`
	ExtCount_   int64  `asn1:"-" json:"-"`
	ExtPresent_ []bool `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// RestoreDataRes represents the ASN.1 type RestoreDataRes (SEQUENCE).
type RestoreDataRes struct {
	HlrNumber      ISDNAddressString `asn1:""`
	MsNotReachable *struct{}         `asn1:",optional" json:"MsNotReachable,omitempty"`
	ExtCount_      int64             `asn1:"-" json:"-"`
	ExtPresent_    []bool            `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes UpdateLocationArg to BER format.
func (v *UpdateLocationArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: UpdateLocationArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*UpdateLocationArg).MarshalBER, (*UpdateLocationArg).marshalBER, 3)

}
func (v *UpdateLocationArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	enc_locationinfo, err := v.LocationInfo.MarshalBER(ber.ChildEncodeOptions(opts, "locationInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "locationInfo", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_locationinfo)
	children = append(children, enc_locationinfo...)
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..9)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..20)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_vlrnumber, encodeErr_enc_vlrnumber := ber.EncodeOctetString([]byte(v.VlrNumber))
	if encodeErr_enc_vlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_vlrnumber, "vlr-Number", "encoding", false)
	}
	children = append(children, enc_vlrnumber...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", false)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, qualifyBERError(tagErr_enc_lmsi, "lmsi", "encoding", false)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_0, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *UpdateLocationArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes UpdateLocationArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *UpdateLocationArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UpdateLocationArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	enc_locationinfo, err := v.LocationInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "locationInfo", "encoding", true)
	}
	children = append(children, enc_locationinfo...)
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..9)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..20)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_vlrnumber, encodeErr_enc_vlrnumber := ber.EncodeOctetString([]byte(v.VlrNumber))
	if encodeErr_enc_vlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_vlrnumber, "vlr-Number", "encoding", true)
	}
	children = append(children, enc_vlrnumber...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", true)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, qualifyBERError(tagErr_enc_lmsi, "lmsi", "encoding", true)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding UpdateLocationArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *UpdateLocationArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes UpdateLocationArg from BER/DER format.
func (destination *UpdateLocationArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: UpdateLocationArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(UpdateLocationArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe UpdateLocationArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_0, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = UpdateLocationArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*UpdateLocationArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding UpdateLocationArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UpdateLocationArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field imsi", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "imsi", content[offset:])
		val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "imsi", "decoding", false)
		}
		v.Imsi = IMSI(val_imsi)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode locationInfo
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field locationInfo", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "locationInfo", content[offset:])
		// Decode nested CHOICE (LocationInfo)
		_, n_locationinfo, _, tlvErr_locationinfo := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_locationinfo != nil {
			return qualifyBERError(tlvErr_locationinfo, "locationInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_locationinfo < 0 || n_locationinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.LocationInfo.UnmarshalBER(content[offset:offset+n_locationinfo], ber.ChildDecodeOptions(opts, "locationInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "locationInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_locationinfo < 0 || n_locationinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_locationinfo
	}
	// Decode vlr-Number
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field vlr-Number", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "vlr-Number", content[offset:])
		val_vlrnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "vlr-Number", "decoding", false)
		}
		v.VlrNumber = ISDNAddressString(val_vlrnumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..9)", len(v.VlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..20)", len(v.VlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "lmsi", content[offset:])
				decodedTag_lmsi, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lmsi", "decoding", false)
				}
				if decodedTag_lmsi.Class != tag.ClassContextSpecific || decodedTag_lmsi.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_lmsi), "lmsi", "decoding", false)
				}
				decVal_lmsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lmsi.Constructed, rawVal_lmsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lmsi", "decoding", false)
				}
				tmp_lmsi := LMSI(decVal_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n_lmsi < 0 || n_lmsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lmsi
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UpdateLocationArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "UpdateLocationArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UpdateLocationRes to BER format.
func (v *UpdateLocationRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: UpdateLocationRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*UpdateLocationRes).MarshalBER, (*UpdateLocationRes).marshalBER, 3)

}
func (v *UpdateLocationRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *UpdateLocationRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case UpdateLocationResChoiceHlrNumber:
		if v.HlrNumber == nil {
			return nil, fmt.Errorf("%w: choice UpdateLocationRes: hlr-Number is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.HlrNumber))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "hlr-Number", "encoding", false)
		}
		if len(*v.HlrNumber) < 1 || len(*v.HlrNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..9)", len(*v.HlrNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.HlrNumber) < 1 || len(*v.HlrNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..20)", len(*v.HlrNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case UpdateLocationResChoiceExtensibleUpdateLocationRes:
		if v.ExtensibleUpdateLocationRes == nil {
			return nil, fmt.Errorf("%w: choice UpdateLocationRes: extensibleUpdateLocationRes is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ExtensibleUpdateLocationRes.MarshalBER(ber.ChildEncodeOptions(opts, "extensibleUpdateLocationRes")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensibleUpdateLocationRes", "encoding", false)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for UpdateLocationRes", v.Choice)
	}
}

// MarshalDER encodes UpdateLocationRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *UpdateLocationRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UpdateLocationRes receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case UpdateLocationResChoiceExtensibleUpdateLocationRes:
		if v.ExtensibleUpdateLocationRes == nil {
			return nil, fmt.Errorf("%w: choice UpdateLocationRes: extensibleUpdateLocationRes is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ExtensibleUpdateLocationRes.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensibleUpdateLocationRes", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "extensibleUpdateLocationRes", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case UpdateLocationResChoiceHlrNumber:
			return nil, qualifyBERError(err, "hlr-Number", "encoding", true)
		case UpdateLocationResChoiceExtensibleUpdateLocationRes:
			return nil, qualifyBERError(err, "extensibleUpdateLocationRes", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding UpdateLocationRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *UpdateLocationRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes UpdateLocationRes from BER/DER format.
func (destination *UpdateLocationRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: UpdateLocationRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(UpdateLocationRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*UpdateLocationRes).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe UpdateLocationRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_1, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = UpdateLocationRes{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for UpdateLocationRes CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for UpdateLocationRes: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding UpdateLocationRes CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "UpdateLocationRes", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "UpdateLocationRes.extensibleUpdateLocationRes", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = UpdateLocationResChoiceHlrNumber
		ber.MarkPreflightTarget(opts, "hlr-Number", choiceData)
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return qualifyBERError(osErr, "hlr-Number", "decoding", false)
		}
		tmp := ISDNAddressString(decVal)
		v.HlrNumber = &tmp
		if len(*v.HlrNumber) < 1 || len(*v.HlrNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..9)", len(*v.HlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.HlrNumber) < 1 || len(*v.HlrNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..20)", len(*v.HlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = UpdateLocationResChoiceExtensibleUpdateLocationRes
		ber.MarkPreflightTarget(opts, "extensibleUpdateLocationRes", choiceData)
		var dec ExtensibleUpdateLocationRes
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "extensibleUpdateLocationRes")...); unmErr != nil {
			return qualifyBERError(unmErr, "extensibleUpdateLocationRes", "decoding", false)
		}
		v.ExtensibleUpdateLocationRes = &dec
	} else {
		return fmt.Errorf("%w: unknown tag %s for UpdateLocationRes CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ExtensibleUpdateLocationRes to BER format.
func (v *ExtensibleUpdateLocationRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExtensibleUpdateLocationRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExtensibleUpdateLocationRes).MarshalBER, (*ExtensibleUpdateLocationRes).marshalBER, 3)

}
func (v *ExtensibleUpdateLocationRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_hlrnumber, encodeErr_enc_hlrnumber := ber.EncodeOctetString([]byte(v.HlrNumber))
	if encodeErr_enc_hlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_hlrnumber, "hlr-Number", "encoding", false)
	}
	children = append(children, enc_hlrnumber...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_2, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ExtensibleUpdateLocationRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ExtensibleUpdateLocationRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExtensibleUpdateLocationRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensibleUpdateLocationRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_hlrnumber, encodeErr_enc_hlrnumber := ber.EncodeOctetString([]byte(v.HlrNumber))
	if encodeErr_enc_hlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_hlrnumber, "hlr-Number", "encoding", true)
	}
	children = append(children, enc_hlrnumber...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_2, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ExtensibleUpdateLocationRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ExtensibleUpdateLocationRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExtensibleUpdateLocationRes from BER/DER format.
func (destination *ExtensibleUpdateLocationRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExtensibleUpdateLocationRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExtensibleUpdateLocationRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ExtensibleUpdateLocationRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_2, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExtensibleUpdateLocationRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExtensibleUpdateLocationRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ExtensibleUpdateLocationRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensibleUpdateLocationRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode hlr-Number
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field hlr-Number", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "hlr-Number", content[offset:])
		val_hlrnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "hlr-Number", "decoding", false)
		}
		v.HlrNumber = ISDNAddressString(val_hlrnumber)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensibleUpdateLocationRes", Cause: extErr_}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CancelLocationArg to BER format.
func (v *CancelLocationArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CancelLocationArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CancelLocationArg).MarshalBER, (*CancelLocationArg).marshalBER, 3)

}
func (v *CancelLocationArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *CancelLocationArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CancelLocationArgChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice CancelLocationArg: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-MS-DataTypes.CancelLocationArg", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case CancelLocationArgChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice CancelLocationArg: imsi-WithLMSI is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ImsiWithLMSI.MarshalBER(ber.ChildEncodeOptions(opts, "imsi-WithLMSI")...)
		if err != nil {
			return nil, qualifyBERError(err, "imsi-WithLMSI", "encoding", false)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CancelLocationArg", v.Choice)
	}
}

// MarshalDER encodes CancelLocationArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CancelLocationArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CancelLocationArg receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case CancelLocationArgChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice CancelLocationArg: imsi-WithLMSI is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ImsiWithLMSI.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "imsi-WithLMSI", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "imsi-WithLMSI", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case CancelLocationArgChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case CancelLocationArgChoiceImsiWithLMSI:
			return nil, qualifyBERError(err, "imsi-WithLMSI", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding CancelLocationArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *CancelLocationArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CancelLocationArg from BER/DER format.
func (destination *CancelLocationArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CancelLocationArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(CancelLocationArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CancelLocationArg).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CancelLocationArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-MS-DataTypes.CancelLocationArg", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CancelLocationArg{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CancelLocationArg CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CancelLocationArg: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding CancelLocationArg CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelLocationArg", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "CancelLocationArg.imsi-WithLMSI", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = CancelLocationArgChoiceImsi
		ber.MarkPreflightTarget(opts, "imsi", choiceData)
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return qualifyBERError(osErr, "imsi", "decoding", false)
		}
		tmp := IMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-MS-DataTypes.CancelLocationArg", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = CancelLocationArgChoiceImsiWithLMSI
		ber.MarkPreflightTarget(opts, "imsi-WithLMSI", choiceData)
		var dec IMSIWithLMSI
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "imsi-WithLMSI")...); unmErr != nil {
			return qualifyBERError(unmErr, "imsi-WithLMSI", "decoding", false)
		}
		v.ImsiWithLMSI = &dec
	} else {
		return fmt.Errorf("%w: unknown tag %s for CancelLocationArg CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes PurgeMSArg to BER format.
func (v *PurgeMSArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PurgeMSArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PurgeMSArg).MarshalBER, (*PurgeMSArg).marshalBER, 3)

}
func (v *PurgeMSArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..9)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..20)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_vlrnumber, encodeErr_enc_vlrnumber := ber.EncodeOctetString([]byte(v.VlrNumber))
	if encodeErr_enc_vlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_vlrnumber, "vlr-Number", "encoding", false)
	}
	children = append(children, enc_vlrnumber...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_3, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PurgeMSArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PurgeMSArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PurgeMSArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PurgeMSArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..9)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..20)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_vlrnumber, encodeErr_enc_vlrnumber := ber.EncodeOctetString([]byte(v.VlrNumber))
	if encodeErr_enc_vlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_vlrnumber, "vlr-Number", "encoding", true)
	}
	children = append(children, enc_vlrnumber...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_3, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PurgeMSArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PurgeMSArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PurgeMSArg from BER/DER format.
func (destination *PurgeMSArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PurgeMSArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(PurgeMSArg)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PurgeMSArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_3, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PurgeMSArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PurgeMSArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PurgeMSArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PurgeMSArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field imsi", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "imsi", content[offset:])
		val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "imsi", "decoding", false)
		}
		v.Imsi = IMSI(val_imsi)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode vlr-Number
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field vlr-Number", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "vlr-Number", content[offset:])
		val_vlrnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "vlr-Number", "decoding", false)
		}
		v.VlrNumber = ISDNAddressString(val_vlrnumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..9)", len(v.VlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "vlr-Number", "SIZE (1..20)", len(v.VlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PurgeMSArg", Cause: extErr_}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes IMSIWithLMSI to BER format.
func (v *IMSIWithLMSI) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: IMSIWithLMSI receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*IMSIWithLMSI).MarshalBER, (*IMSIWithLMSI).marshalBER, 3)

}
func (v *IMSIWithLMSI) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(v.Lmsi))
	if encodeErr_enc_lmsi != nil {
		return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", false)
	}
	children = append(children, enc_lmsi...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_4, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *IMSIWithLMSI) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes IMSIWithLMSI to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *IMSIWithLMSI) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IMSIWithLMSI receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(v.Lmsi))
	if encodeErr_enc_lmsi != nil {
		return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", true)
	}
	children = append(children, enc_lmsi...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_4, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IMSIWithLMSI as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *IMSIWithLMSI) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes IMSIWithLMSI from BER/DER format.
func (destination *IMSIWithLMSI) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: IMSIWithLMSI destination is nil", ber.ErrInvalidValue)
	}
	v := new(IMSIWithLMSI)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe IMSIWithLMSI
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_4, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = IMSIWithLMSI{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*IMSIWithLMSI).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding IMSIWithLMSI SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IMSIWithLMSI", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field imsi", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "imsi", content[offset:])
		val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "imsi", "decoding", false)
		}
		v.Imsi = IMSI(val_imsi)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode lmsi
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field lmsi", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "lmsi", content[offset:])
		val_lmsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "lmsi", "decoding", false)
		}
		v.Lmsi = LMSI(val_lmsi)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IMSIWithLMSI", Cause: extErr_}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SendIdentificationRes to BER format.
func (v *SendIdentificationRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendIdentificationRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendIdentificationRes).MarshalBER, (*SendIdentificationRes).marshalBER, 3)

}
func (v *SendIdentificationRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	if v.AuthenticationSetList != nil {
		if len((v.AuthenticationSetList).Values) < 1 || len((v.AuthenticationSetList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "authenticationSetList", "SIZE (1..5)", len((v.AuthenticationSetList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_authenticationsetlist, err := MarshalBERAuthenticationSetList(v.AuthenticationSetList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "authenticationSetList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "authenticationSetList", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_authenticationsetlist)
		children = append(children, enc_authenticationsetlist...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_5, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendIdentificationRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendIdentificationRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendIdentificationRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendIdentificationRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	if v.AuthenticationSetList != nil {
		if len((v.AuthenticationSetList).Values) < 1 || len((v.AuthenticationSetList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "authenticationSetList", "SIZE (1..5)", len((v.AuthenticationSetList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_authenticationsetlist, err := MarshalDERAuthenticationSetList(v.AuthenticationSetList)
		if err != nil {
			return nil, qualifyBERError(err, "authenticationSetList", "encoding", true)
		}
		children = append(children, enc_authenticationsetlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_5, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendIdentificationRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendIdentificationRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendIdentificationRes from BER/DER format.
func (destination *SendIdentificationRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendIdentificationRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendIdentificationRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SendIdentificationRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_5, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendIdentificationRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendIdentificationRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendIdentificationRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendIdentificationRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field imsi", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "imsi", content[offset:])
		val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "imsi", "decoding", false)
		}
		v.Imsi = IMSI(val_imsi)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode authenticationSetList
	v.berAuthenticationSetListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "authenticationSetList", content[offset:])
				// Decode nested SEQUENCE_OF (AuthenticationSetList)
				_, n_authenticationsetlist, _, tlvErr_authenticationsetlist := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_authenticationsetlist != nil {
					return qualifyBERError(tlvErr_authenticationsetlist, "authenticationSetList", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_authenticationsetlist < 0 || n_authenticationsetlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_authenticationsetlist := content[offset : offset+n_authenticationsetlist]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_authenticationsetlist)
					if tagSz_ < len(tlv_authenticationsetlist) && tlv_authenticationsetlist[tagSz_] == 0x80 {
						v.berAuthenticationSetListIndef_ = true
					}
				}
				dec_authenticationsetlist, unmErr := UnmarshalBERAuthenticationSetList(tlv_authenticationsetlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "authenticationSetList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "authenticationSetList", "decoding", false)
				}
				v.AuthenticationSetList = dec_authenticationsetlist
				if offset < 0 || offset >
					len(content) || n_authenticationsetlist < 0 || n_authenticationsetlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_authenticationsetlist
				if len((v.AuthenticationSetList).Values) < 1 || len((v.AuthenticationSetList).Values) > 5 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "authenticationSetList", "SIZE (1..5)", len((v.AuthenticationSetList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendIdentificationRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SendIdentificationRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERAuthenticationSetList encodes a AuthenticationSetList list to BER.
func MarshalBERAuthenticationSetList(collection *AuthenticationSetList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERAuthenticationSetList, marshalBERAuthenticationSetList, 3, UnmarshalBERAuthenticationSetList)

}
func marshalBERAuthenticationSetList(collection *AuthenticationSetList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-MS-DataTypes.marshalBERAuthenticationSetList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "AuthenticationSetList", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
		ber.RecordGeneratedBERChildPlacement(opts, len(children)-len(enc), enc)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearAuthenticationSetList(encoder *ber.LinearEncoder, collection *AuthenticationSetList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERAuthenticationSetList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERAuthenticationSetList encodes a AuthenticationSetList list to DER.
func MarshalDERAuthenticationSetList(collection *AuthenticationSetList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, "MAP-MS-DataTypes.AuthenticationSetList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "AuthenticationSetList", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AuthenticationSetList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearAuthenticationSetList(encoder *ber.LinearEncoder, collection *AuthenticationSetList) ([]byte, error) {
	encoded, err := MarshalDERAuthenticationSetList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERAuthenticationSetList decodes a AuthenticationSetList list from BER.
func UnmarshalBERAuthenticationSetList(data []byte, opts ...ber.DecodeOption) (returnValue *AuthenticationSetList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERAuthenticationSetList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-MS-DataTypes.AuthenticationSetList", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding AuthenticationSetList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AuthenticationSetList", Cause: ber.ErrExtraData}
	}
	var result []AuthenticationSet
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem AuthenticationSet
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeIndexOptions(opts, len(result))...); unmErr != nil {
			return nil, qualifyBERError(unmErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 5 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, "MAP-MS-DataTypes.AuthenticationSetList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "AuthenticationSetList", "SIZE (1..5)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &AuthenticationSetList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERAuthenticationSetList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes AuthenticationSet to BER format.
func (v *AuthenticationSet) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: AuthenticationSet receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*AuthenticationSet).MarshalBER, (*AuthenticationSet).marshalBER, 3)

}
func (v *AuthenticationSet) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_rand, encodeErr_enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	if encodeErr_enc_rand != nil {
		return nil, qualifyBERError(encodeErr_enc_rand, "rand", "encoding", false)
	}
	children = append(children, enc_rand...)
	if len(v.Sres) < 4 || len(v.Sres) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sres, encodeErr_enc_sres := ber.EncodeOctetString([]byte(v.Sres))
	if encodeErr_enc_sres != nil {
		return nil, qualifyBERError(encodeErr_enc_sres, "sres", "encoding", false)
	}
	children = append(children, enc_sres...)
	if len(v.Kc) < 8 || len(v.Kc) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(v.Kc))
	if encodeErr_enc_kc != nil {
		return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", false)
	}
	children = append(children, enc_kc...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_6, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *AuthenticationSet) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes AuthenticationSet to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *AuthenticationSet) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AuthenticationSet receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_rand, encodeErr_enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	if encodeErr_enc_rand != nil {
		return nil, qualifyBERError(encodeErr_enc_rand, "rand", "encoding", true)
	}
	children = append(children, enc_rand...)
	if len(v.Sres) < 4 || len(v.Sres) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sres, encodeErr_enc_sres := ber.EncodeOctetString([]byte(v.Sres))
	if encodeErr_enc_sres != nil {
		return nil, qualifyBERError(encodeErr_enc_sres, "sres", "encoding", true)
	}
	children = append(children, enc_sres...)
	if len(v.Kc) < 8 || len(v.Kc) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(v.Kc))
	if encodeErr_enc_kc != nil {
		return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", true)
	}
	children = append(children, enc_kc...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_6, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AuthenticationSet as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *AuthenticationSet) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes AuthenticationSet from BER/DER format.
func (destination *AuthenticationSet) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: AuthenticationSet destination is nil", ber.ErrInvalidValue)
	}
	v := new(AuthenticationSet)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AuthenticationSet
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_6, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = AuthenticationSet{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*AuthenticationSet).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding AuthenticationSet SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticationSet", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode rand
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field rand", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "rand", content[offset:])
		val_rand, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "rand", "decoding", false)
		}
		v.Rand = RAND(val_rand)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Rand) < 16 || len(v.Rand) > 16 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode sres
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field sres", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "sres", content[offset:])
		val_sres, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "sres", "decoding", false)
		}
		v.Sres = SRES(val_sres)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Sres) < 4 || len(v.Sres) > 4 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode kc
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field kc", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "kc", content[offset:])
		val_kc, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "kc", "decoding", false)
		}
		v.Kc = Kc(val_kc)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Kc) < 8 || len(v.Kc) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AuthenticationSet", Cause: extErr_}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PrepareHOArg to BER format.
func (v *PrepareHOArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PrepareHOArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PrepareHOArg).MarshalBER, (*PrepareHOArg).marshalBER, 3)

}
func (v *PrepareHOArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.TargetCellId != nil {
		if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(*v.TargetCellId))
		if encodeErr_enc_targetcellid != nil {
			return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", false)
		}
		children = append(children, enc_targetcellid...)
	}
	if v.HoNumberNotRequired != nil {
		enc_honumbernotrequired := ber.EncodeNull()
		children = append(children, enc_honumbernotrequired...)
	}
	if v.BssAPDU != nil {
		enc_bssapdu, err := v.BssAPDU.MarshalBER(ber.ChildEncodeOptions(opts, "bss-APDU")...)
		if err != nil {
			return nil, qualifyBERError(err, "bss-APDU", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_bssapdu)
		children = append(children, enc_bssapdu...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_7, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PrepareHOArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PrepareHOArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PrepareHOArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareHOArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.TargetCellId != nil {
		if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(*v.TargetCellId))
		if encodeErr_enc_targetcellid != nil {
			return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", true)
		}
		children = append(children, enc_targetcellid...)
	}
	if v.HoNumberNotRequired != nil {
		enc_honumbernotrequired := ber.EncodeNull()
		children = append(children, enc_honumbernotrequired...)
	}
	if v.BssAPDU != nil {
		enc_bssapdu, err := v.BssAPDU.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "bss-APDU", "encoding", true)
		}
		children = append(children, enc_bssapdu...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_7, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PrepareHOArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PrepareHOArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PrepareHOArg from BER/DER format.
func (destination *PrepareHOArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PrepareHOArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(PrepareHOArg)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PrepareHOArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_7, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PrepareHOArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PrepareHOArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PrepareHOArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareHOArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode targetCellId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "targetCellId", content[offset:])
				val_targetcellid, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "targetCellId", "decoding", false)
				}
				tmp_targetcellid := GlobalCellId(val_targetcellid)
				v.TargetCellId = &tmp_targetcellid
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ho-NumberNotRequired
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "ho-NumberNotRequired", content[offset:])
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ho-NumberNotRequired", "decoding", false)
				}
				v.HoNumberNotRequired = &struct{}{}
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	// Decode bss-APDU
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "bss-APDU", content[offset:])
				// Decode nested SEQUENCE (ExternalSignalInfo)
				_, n_bssapdu, _, tlvErr_bssapdu := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_bssapdu != nil {
					return qualifyBERError(tlvErr_bssapdu, "bss-APDU", "decoding", false)
				}
				var dec_bssapdu ExternalSignalInfo
				if offset < 0 || offset >
					len(content) || n_bssapdu < 0 || n_bssapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_bssapdu.UnmarshalBER(content[offset:offset+n_bssapdu], ber.ChildDecodeOptions(opts, "bss-APDU")...); unmErr != nil {
					return qualifyBERError(unmErr, "bss-APDU", "decoding", false)
				}
				v.BssAPDU = &dec_bssapdu
				if offset < 0 || offset >
					len(content) || n_bssapdu < 0 || n_bssapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bssapdu
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareHOArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "PrepareHOArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PerformHOArg to BER format.
func (v *PerformHOArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PerformHOArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PerformHOArg).MarshalBER, (*PerformHOArg).marshalBER, 3)

}
func (v *PerformHOArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(v.TargetCellId))
	if encodeErr_enc_targetcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", false)
	}
	children = append(children, enc_targetcellid...)
	if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servingcellid, encodeErr_enc_servingcellid := ber.EncodeOctetString([]byte(v.ServingCellId))
	if encodeErr_enc_servingcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_servingcellid, "servingCellId", "encoding", false)
	}
	children = append(children, enc_servingcellid...)
	if len(v.ChannelType) < 1 || len(v.ChannelType) > 10 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "channelType", "SIZE (1..10)", len(v.ChannelType)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_channeltype, encodeErr_enc_channeltype := ber.EncodeOctetString([]byte(v.ChannelType))
	if encodeErr_enc_channeltype != nil {
		return nil, qualifyBERError(encodeErr_enc_channeltype, "channelType", "encoding", false)
	}
	children = append(children, enc_channeltype...)
	if len(v.ClassmarkInfo) < 1 || len(v.ClassmarkInfo) > 2 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "classmarkInfo", "SIZE (1..2)", len(v.ClassmarkInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_classmarkinfo, encodeErr_enc_classmarkinfo := ber.EncodeOctetString([]byte(v.ClassmarkInfo))
	if encodeErr_enc_classmarkinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_classmarkinfo, "classmarkInfo", "encoding", false)
	}
	children = append(children, enc_classmarkinfo...)
	if v.HandoverPriority != nil {
		if len(*v.HandoverPriority) < 1 || len(*v.HandoverPriority) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverPriority", "SIZE (1)", len(*v.HandoverPriority)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_handoverpriority, encodeErr_enc_handoverpriority := ber.EncodeOctetString([]byte(*v.HandoverPriority))
		if encodeErr_enc_handoverpriority != nil {
			return nil, qualifyBERError(encodeErr_enc_handoverpriority, "handoverPriority", "encoding", false)
		}
		retagged_enc_handoverpriority, tagErr_enc_handoverpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_handoverpriority)
		if tagErr_enc_handoverpriority != nil {
			return nil, qualifyBERError(tagErr_enc_handoverpriority, "handoverPriority", "encoding", false)
		}
		enc_handoverpriority = retagged_enc_handoverpriority
		children = append(children, enc_handoverpriority...)
	}
	if v.Kc != nil {
		if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(*v.Kc))
		if encodeErr_enc_kc != nil {
			return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", false)
		}
		retagged_enc_kc, tagErr_enc_kc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_kc)
		if tagErr_enc_kc != nil {
			return nil, qualifyBERError(tagErr_enc_kc, "kc", "encoding", false)
		}
		enc_kc = retagged_enc_kc
		children = append(children, enc_kc...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PerformHOArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PerformHOArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PerformHOArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PerformHOArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(v.TargetCellId))
	if encodeErr_enc_targetcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", true)
	}
	children = append(children, enc_targetcellid...)
	if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servingcellid, encodeErr_enc_servingcellid := ber.EncodeOctetString([]byte(v.ServingCellId))
	if encodeErr_enc_servingcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_servingcellid, "servingCellId", "encoding", true)
	}
	children = append(children, enc_servingcellid...)
	if len(v.ChannelType) < 1 || len(v.ChannelType) > 10 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "channelType", "SIZE (1..10)", len(v.ChannelType)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_channeltype, encodeErr_enc_channeltype := ber.EncodeOctetString([]byte(v.ChannelType))
	if encodeErr_enc_channeltype != nil {
		return nil, qualifyBERError(encodeErr_enc_channeltype, "channelType", "encoding", true)
	}
	children = append(children, enc_channeltype...)
	if len(v.ClassmarkInfo) < 1 || len(v.ClassmarkInfo) > 2 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "classmarkInfo", "SIZE (1..2)", len(v.ClassmarkInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_classmarkinfo, encodeErr_enc_classmarkinfo := ber.EncodeOctetString([]byte(v.ClassmarkInfo))
	if encodeErr_enc_classmarkinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_classmarkinfo, "classmarkInfo", "encoding", true)
	}
	children = append(children, enc_classmarkinfo...)
	if v.HandoverPriority != nil {
		if len(*v.HandoverPriority) < 1 || len(*v.HandoverPriority) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverPriority", "SIZE (1)", len(*v.HandoverPriority)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_handoverpriority, encodeErr_enc_handoverpriority := ber.EncodeOctetString([]byte(*v.HandoverPriority))
		if encodeErr_enc_handoverpriority != nil {
			return nil, qualifyBERError(encodeErr_enc_handoverpriority, "handoverPriority", "encoding", true)
		}
		retagged_enc_handoverpriority, tagErr_enc_handoverpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_handoverpriority)
		if tagErr_enc_handoverpriority != nil {
			return nil, qualifyBERError(tagErr_enc_handoverpriority, "handoverPriority", "encoding", true)
		}
		enc_handoverpriority = retagged_enc_handoverpriority
		children = append(children, enc_handoverpriority...)
	}
	if v.Kc != nil {
		if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(*v.Kc))
		if encodeErr_enc_kc != nil {
			return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", true)
		}
		retagged_enc_kc, tagErr_enc_kc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_kc)
		if tagErr_enc_kc != nil {
			return nil, qualifyBERError(tagErr_enc_kc, "kc", "encoding", true)
		}
		enc_kc = retagged_enc_kc
		children = append(children, enc_kc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PerformHOArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PerformHOArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PerformHOArg from BER/DER format.
func (destination *PerformHOArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PerformHOArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(PerformHOArg)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PerformHOArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_8, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PerformHOArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PerformHOArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PerformHOArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PerformHOArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode targetCellId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field targetCellId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "targetCellId", content[offset:])
		val_targetcellid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "targetCellId", "decoding", false)
		}
		v.TargetCellId = GlobalCellId(val_targetcellid)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode servingCellId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field servingCellId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "servingCellId", content[offset:])
		val_servingcellid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "servingCellId", "decoding", false)
		}
		v.ServingCellId = GlobalCellId(val_servingcellid)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode channelType
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field channelType", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "channelType", content[offset:])
		val_channeltype, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "channelType", "decoding", false)
		}
		v.ChannelType = ChannelType(val_channeltype)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ChannelType) < 1 || len(v.ChannelType) > 10 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "channelType", "SIZE (1..10)", len(v.ChannelType)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode classmarkInfo
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field classmarkInfo", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "classmarkInfo", content[offset:])
		val_classmarkinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "classmarkInfo", "decoding", false)
		}
		v.ClassmarkInfo = ClassmarkInfo(val_classmarkinfo)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ClassmarkInfo) < 1 || len(v.ClassmarkInfo) > 2 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "classmarkInfo", "SIZE (1..2)", len(v.ClassmarkInfo)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode handoverPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "handoverPriority", content[offset:])
				decodedTag_handoverpriority, n_handoverpriority, rawVal_handoverpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "handoverPriority", "decoding", false)
				}
				if decodedTag_handoverpriority.Class != tag.ClassContextSpecific || decodedTag_handoverpriority.Number != 11 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_handoverpriority), "handoverPriority", "decoding", false)
				}
				decVal_handoverpriority, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_handoverpriority.Constructed, rawVal_handoverpriority, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "handoverPriority", "decoding", false)
				}
				tmp_handoverpriority := HandoverPriority(decVal_handoverpriority)
				v.HandoverPriority = &tmp_handoverpriority
				if offset < 0 || offset >
					len(content) || n_handoverpriority < 0 || n_handoverpriority >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_handoverpriority
				if len(*v.HandoverPriority) < 1 || len(*v.HandoverPriority) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverPriority", "SIZE (1)", len(*v.HandoverPriority)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode kc
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "kc", content[offset:])
				decodedTag_kc, n_kc, rawVal_kc, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "kc", "decoding", false)
				}
				if decodedTag_kc.Class != tag.ClassContextSpecific || decodedTag_kc.Number != 12 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_kc), "kc", "decoding", false)
				}
				decVal_kc, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_kc.Constructed, rawVal_kc, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "kc", "decoding", false)
				}
				tmp_kc := Kc(decVal_kc)
				v.Kc = &tmp_kc
				if offset < 0 || offset >
					len(content) || n_kc < 0 || n_kc > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_kc
				if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PerformHOArg", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes PrepareHORes to BER format.
func (v *PrepareHORes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PrepareHORes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PrepareHORes).MarshalBER, (*PrepareHORes).marshalBER, 3)

}
func (v *PrepareHORes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.HandoverNumber != nil {
		if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_9, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..9)", len(*v.HandoverNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_9, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..20)", len(*v.HandoverNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_handovernumber, encodeErr_enc_handovernumber := ber.EncodeOctetString([]byte(*v.HandoverNumber))
		if encodeErr_enc_handovernumber != nil {
			return nil, qualifyBERError(encodeErr_enc_handovernumber, "handoverNumber", "encoding", false)
		}
		children = append(children, enc_handovernumber...)
	}
	if v.BssAPDU != nil {
		enc_bssapdu, err := v.BssAPDU.MarshalBER(ber.ChildEncodeOptions(opts, "bss-APDU")...)
		if err != nil {
			return nil, qualifyBERError(err, "bss-APDU", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_bssapdu)
		children = append(children, enc_bssapdu...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_9, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PrepareHORes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PrepareHORes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PrepareHORes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareHORes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.HandoverNumber != nil {
		if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_9, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..9)", len(*v.HandoverNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_9, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..20)", len(*v.HandoverNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_handovernumber, encodeErr_enc_handovernumber := ber.EncodeOctetString([]byte(*v.HandoverNumber))
		if encodeErr_enc_handovernumber != nil {
			return nil, qualifyBERError(encodeErr_enc_handovernumber, "handoverNumber", "encoding", true)
		}
		children = append(children, enc_handovernumber...)
	}
	if v.BssAPDU != nil {
		enc_bssapdu, err := v.BssAPDU.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "bss-APDU", "encoding", true)
		}
		children = append(children, enc_bssapdu...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_9, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PrepareHORes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PrepareHORes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PrepareHORes from BER/DER format.
func (destination *PrepareHORes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PrepareHORes destination is nil", ber.ErrInvalidValue)
	}
	v := new(PrepareHORes)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PrepareHORes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_9, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PrepareHORes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PrepareHORes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PrepareHORes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareHORes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode handoverNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "handoverNumber", content[offset:])
				val_handovernumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "handoverNumber", "decoding", false)
				}
				tmp_handovernumber := ISDNAddressString(val_handovernumber)
				v.HandoverNumber = &tmp_handovernumber
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_9, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..9)", len(*v.HandoverNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_9, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..20)", len(*v.HandoverNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode bss-APDU
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "bss-APDU", content[offset:])
				// Decode nested SEQUENCE (ExternalSignalInfo)
				_, n_bssapdu, _, tlvErr_bssapdu := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_bssapdu != nil {
					return qualifyBERError(tlvErr_bssapdu, "bss-APDU", "decoding", false)
				}
				var dec_bssapdu ExternalSignalInfo
				if offset < 0 || offset >
					len(content) || n_bssapdu < 0 || n_bssapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_bssapdu.UnmarshalBER(content[offset:offset+n_bssapdu], ber.ChildDecodeOptions(opts, "bss-APDU")...); unmErr != nil {
					return qualifyBERError(unmErr, "bss-APDU", "decoding", false)
				}
				v.BssAPDU = &dec_bssapdu
				if offset < 0 || offset >
					len(content) || n_bssapdu < 0 || n_bssapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bssapdu
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareHORes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "PrepareHORes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PerformHORes to BER format.
func (v *PerformHORes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PerformHORes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PerformHORes).MarshalBER, (*PerformHORes).marshalBER, 3)

}
func (v *PerformHORes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_10, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..9)", len(v.HandoverNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_10, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..20)", len(v.HandoverNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_handovernumber, encodeErr_enc_handovernumber := ber.EncodeOctetString([]byte(v.HandoverNumber))
	if encodeErr_enc_handovernumber != nil {
		return nil, qualifyBERError(encodeErr_enc_handovernumber, "handoverNumber", "encoding", false)
	}
	children = append(children, enc_handovernumber...)
	enc_accesssignalinfo, err := v.AccessSignalInfo.MarshalBER(ber.ChildEncodeOptions(opts, "accessSignalInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "accessSignalInfo", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_accesssignalinfo)
	children = append(children, enc_accesssignalinfo...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PerformHORes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PerformHORes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PerformHORes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PerformHORes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_10, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..9)", len(v.HandoverNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_10, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..20)", len(v.HandoverNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_handovernumber, encodeErr_enc_handovernumber := ber.EncodeOctetString([]byte(v.HandoverNumber))
	if encodeErr_enc_handovernumber != nil {
		return nil, qualifyBERError(encodeErr_enc_handovernumber, "handoverNumber", "encoding", true)
	}
	children = append(children, enc_handovernumber...)
	enc_accesssignalinfo, err := v.AccessSignalInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "accessSignalInfo", "encoding", true)
	}
	children = append(children, enc_accesssignalinfo...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PerformHORes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PerformHORes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PerformHORes from BER/DER format.
func (destination *PerformHORes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PerformHORes destination is nil", ber.ErrInvalidValue)
	}
	v := new(PerformHORes)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PerformHORes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_10, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PerformHORes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PerformHORes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PerformHORes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PerformHORes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode handoverNumber
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field handoverNumber", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "handoverNumber", content[offset:])
		val_handovernumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "handoverNumber", "decoding", false)
		}
		v.HandoverNumber = ISDNAddressString(val_handovernumber)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_10, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..9)", len(v.HandoverNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_10, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "handoverNumber", "SIZE (1..20)", len(v.HandoverNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode accessSignalInfo
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field accessSignalInfo", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "accessSignalInfo", content[offset:])
		// Decode nested SEQUENCE (ExternalSignalInfo)
		_, n_accesssignalinfo, _, tlvErr_accesssignalinfo := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_accesssignalinfo != nil {
			return qualifyBERError(tlvErr_accesssignalinfo, "accessSignalInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_accesssignalinfo < 0 || n_accesssignalinfo >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.AccessSignalInfo.UnmarshalBER(content[offset:offset+n_accesssignalinfo], ber.ChildDecodeOptions(opts, "accessSignalInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "accessSignalInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_accesssignalinfo < 0 || n_accesssignalinfo >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_accesssignalinfo
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PerformHORes", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes PrepareSubsequentHOArg to BER format.
func (v *PrepareSubsequentHOArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PrepareSubsequentHOArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PrepareSubsequentHOArg).MarshalBER, (*PrepareSubsequentHOArg).marshalBER, 3)

}
func (v *PrepareSubsequentHOArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(v.TargetCellId))
	if encodeErr_enc_targetcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", false)
	}
	children = append(children, enc_targetcellid...)
	if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..9)", len(v.TargetMSCNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..20)", len(v.TargetMSCNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetmscnumber, encodeErr_enc_targetmscnumber := ber.EncodeOctetString([]byte(v.TargetMSCNumber))
	if encodeErr_enc_targetmscnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_targetmscnumber, "targetMSC-Number", "encoding", false)
	}
	children = append(children, enc_targetmscnumber...)
	enc_bssapdu, err := v.BssAPDU.MarshalBER(ber.ChildEncodeOptions(opts, "bss-APDU")...)
	if err != nil {
		return nil, qualifyBERError(err, "bss-APDU", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_bssapdu)
	children = append(children, enc_bssapdu...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_11, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PrepareSubsequentHOArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PrepareSubsequentHOArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PrepareSubsequentHOArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareSubsequentHOArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(v.TargetCellId))
	if encodeErr_enc_targetcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", true)
	}
	children = append(children, enc_targetcellid...)
	if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..9)", len(v.TargetMSCNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..20)", len(v.TargetMSCNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetmscnumber, encodeErr_enc_targetmscnumber := ber.EncodeOctetString([]byte(v.TargetMSCNumber))
	if encodeErr_enc_targetmscnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_targetmscnumber, "targetMSC-Number", "encoding", true)
	}
	children = append(children, enc_targetmscnumber...)
	enc_bssapdu, err := v.BssAPDU.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "bss-APDU", "encoding", true)
	}
	children = append(children, enc_bssapdu...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_11, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PrepareSubsequentHOArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PrepareSubsequentHOArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PrepareSubsequentHOArg from BER/DER format.
func (destination *PrepareSubsequentHOArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PrepareSubsequentHOArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(PrepareSubsequentHOArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PrepareSubsequentHOArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_11, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PrepareSubsequentHOArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PrepareSubsequentHOArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PrepareSubsequentHOArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareSubsequentHOArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode targetCellId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field targetCellId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "targetCellId", content[offset:])
		val_targetcellid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "targetCellId", "decoding", false)
		}
		v.TargetCellId = GlobalCellId(val_targetcellid)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode targetMSC-Number
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field targetMSC-Number", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "targetMSC-Number", content[offset:])
		val_targetmscnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "targetMSC-Number", "decoding", false)
		}
		v.TargetMSCNumber = ISDNAddressString(val_targetmscnumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..9)", len(v.TargetMSCNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..20)", len(v.TargetMSCNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode bss-APDU
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field bss-APDU", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "bss-APDU", content[offset:])
		// Decode nested SEQUENCE (ExternalSignalInfo)
		_, n_bssapdu, _, tlvErr_bssapdu := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_bssapdu != nil {
			return qualifyBERError(tlvErr_bssapdu, "bss-APDU", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_bssapdu < 0 || n_bssapdu > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.BssAPDU.UnmarshalBER(content[offset:offset+n_bssapdu], ber.ChildDecodeOptions(opts, "bss-APDU")...); unmErr != nil {
			return qualifyBERError(unmErr, "bss-APDU", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_bssapdu < 0 || n_bssapdu > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_bssapdu
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareSubsequentHOArg", Cause: extErr_}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PerformSubsequentHOArg to BER format.
func (v *PerformSubsequentHOArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PerformSubsequentHOArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PerformSubsequentHOArg).MarshalBER, (*PerformSubsequentHOArg).marshalBER, 3)

}
func (v *PerformSubsequentHOArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(v.TargetCellId))
	if encodeErr_enc_targetcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", false)
	}
	children = append(children, enc_targetcellid...)
	if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servingcellid, encodeErr_enc_servingcellid := ber.EncodeOctetString([]byte(v.ServingCellId))
	if encodeErr_enc_servingcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_servingcellid, "servingCellId", "encoding", false)
	}
	children = append(children, enc_servingcellid...)
	if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..9)", len(v.TargetMSCNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..20)", len(v.TargetMSCNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetmscnumber, encodeErr_enc_targetmscnumber := ber.EncodeOctetString([]byte(v.TargetMSCNumber))
	if encodeErr_enc_targetmscnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_targetmscnumber, "targetMSC-Number", "encoding", false)
	}
	children = append(children, enc_targetmscnumber...)
	if v.ClassmarkInfo != nil {
		if len(*v.ClassmarkInfo) < 1 || len(*v.ClassmarkInfo) > 2 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "classmarkInfo", "SIZE (1..2)", len(*v.ClassmarkInfo)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_classmarkinfo, encodeErr_enc_classmarkinfo := ber.EncodeOctetString([]byte(*v.ClassmarkInfo))
		if encodeErr_enc_classmarkinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_classmarkinfo, "classmarkInfo", "encoding", false)
		}
		retagged_enc_classmarkinfo, tagErr_enc_classmarkinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_classmarkinfo)
		if tagErr_enc_classmarkinfo != nil {
			return nil, qualifyBERError(tagErr_enc_classmarkinfo, "classmarkInfo", "encoding", false)
		}
		enc_classmarkinfo = retagged_enc_classmarkinfo
		children = append(children, enc_classmarkinfo...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PerformSubsequentHOArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PerformSubsequentHOArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PerformSubsequentHOArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PerformSubsequentHOArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(v.TargetCellId))
	if encodeErr_enc_targetcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", true)
	}
	children = append(children, enc_targetcellid...)
	if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servingcellid, encodeErr_enc_servingcellid := ber.EncodeOctetString([]byte(v.ServingCellId))
	if encodeErr_enc_servingcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_servingcellid, "servingCellId", "encoding", true)
	}
	children = append(children, enc_servingcellid...)
	if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..9)", len(v.TargetMSCNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..20)", len(v.TargetMSCNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetmscnumber, encodeErr_enc_targetmscnumber := ber.EncodeOctetString([]byte(v.TargetMSCNumber))
	if encodeErr_enc_targetmscnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_targetmscnumber, "targetMSC-Number", "encoding", true)
	}
	children = append(children, enc_targetmscnumber...)
	if v.ClassmarkInfo != nil {
		if len(*v.ClassmarkInfo) < 1 || len(*v.ClassmarkInfo) > 2 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "classmarkInfo", "SIZE (1..2)", len(*v.ClassmarkInfo)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_classmarkinfo, encodeErr_enc_classmarkinfo := ber.EncodeOctetString([]byte(*v.ClassmarkInfo))
		if encodeErr_enc_classmarkinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_classmarkinfo, "classmarkInfo", "encoding", true)
		}
		retagged_enc_classmarkinfo, tagErr_enc_classmarkinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_classmarkinfo)
		if tagErr_enc_classmarkinfo != nil {
			return nil, qualifyBERError(tagErr_enc_classmarkinfo, "classmarkInfo", "encoding", true)
		}
		enc_classmarkinfo = retagged_enc_classmarkinfo
		children = append(children, enc_classmarkinfo...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PerformSubsequentHOArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PerformSubsequentHOArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PerformSubsequentHOArg from BER/DER format.
func (destination *PerformSubsequentHOArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PerformSubsequentHOArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(PerformSubsequentHOArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PerformSubsequentHOArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_12, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PerformSubsequentHOArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PerformSubsequentHOArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PerformSubsequentHOArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PerformSubsequentHOArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode targetCellId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field targetCellId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "targetCellId", content[offset:])
		val_targetcellid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "targetCellId", "decoding", false)
		}
		v.TargetCellId = GlobalCellId(val_targetcellid)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode servingCellId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field servingCellId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "servingCellId", content[offset:])
		val_servingcellid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "servingCellId", "decoding", false)
		}
		v.ServingCellId = GlobalCellId(val_servingcellid)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode targetMSC-Number
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field targetMSC-Number", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "targetMSC-Number", content[offset:])
		val_targetmscnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "targetMSC-Number", "decoding", false)
		}
		v.TargetMSCNumber = ISDNAddressString(val_targetmscnumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..9)", len(v.TargetMSCNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.TargetMSCNumber) < 1 || len(v.TargetMSCNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetMSC-Number", "SIZE (1..20)", len(v.TargetMSCNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode classmarkInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "classmarkInfo", content[offset:])
				decodedTag_classmarkinfo, n_classmarkinfo, rawVal_classmarkinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "classmarkInfo", "decoding", false)
				}
				if decodedTag_classmarkinfo.Class != tag.ClassContextSpecific || decodedTag_classmarkinfo.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_classmarkinfo), "classmarkInfo", "decoding", false)
				}
				decVal_classmarkinfo, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_classmarkinfo.Constructed, rawVal_classmarkinfo, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "classmarkInfo", "decoding", false)
				}
				tmp_classmarkinfo := ClassmarkInfo(decVal_classmarkinfo)
				v.ClassmarkInfo = &tmp_classmarkinfo
				if offset < 0 || offset >
					len(content) || n_classmarkinfo < 0 || n_classmarkinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_classmarkinfo
				if len(*v.ClassmarkInfo) < 1 || len(*v.ClassmarkInfo) > 2 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "classmarkInfo", "SIZE (1..2)", len(*v.ClassmarkInfo)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PerformSubsequentHOArg", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBERSendAuthenticationInfoArg encodes a typed standalone SendAuthenticationInfoArg, preserving unchanged received BER.
func MarshalBERSendAuthenticationInfoArg(value *BERValue[SendAuthenticationInfoArg], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required SendAuthenticationInfoArg is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERSendAuthenticationInfoArg, marshalBERSendAuthenticationInfoArg, 2, UnmarshalBERSendAuthenticationInfoArg)

}
func marshalBERSendAuthenticationInfoArg(value *BERValue[SendAuthenticationInfoArg], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value SendAuthenticationInfoArg }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 3 || len(v.Value) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-MS-DataTypes.marshalBERSendAuthenticationInfoArg", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SendAuthenticationInfoArg", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendAuthenticationInfoArg", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERSendAuthenticationInfoArg encodes a typed standalone SendAuthenticationInfoArg using DER.
func MarshalDERSendAuthenticationInfoArg(value *BERValue[SendAuthenticationInfoArg]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required SendAuthenticationInfoArg is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value SendAuthenticationInfoArg }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 3 || len(v.Value) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-MS-DataTypes.SendAuthenticationInfoArg", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SendAuthenticationInfoArg", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendAuthenticationInfoArg", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERSendAuthenticationInfoArg decodes one complete typed standalone SendAuthenticationInfoArg from BER/DER.
func UnmarshalBERSendAuthenticationInfoArg(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[SendAuthenticationInfoArg], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERSendAuthenticationInfoArg(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-MS-DataTypes.SendAuthenticationInfoArg", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value SendAuthenticationInfoArg }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "SendAuthenticationInfoArg", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding SendAuthenticationInfoArg", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = SendAuthenticationInfoArg(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 3 || len(v.Value) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-MS-DataTypes.SendAuthenticationInfoArg", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SendAuthenticationInfoArg", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
				return constraintErr
			}
		}
		if offset != len(content) {
			return ber.ErrExtraData
		}
		return nil
	}
	if err := decode(); err != nil {
		return nil, err
	}
	decoded := &BERValue[SendAuthenticationInfoArg]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSendAuthenticationInfoArg); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERSendAuthenticationInfoRes encodes the standalone collection alias SendAuthenticationInfoRes.
func MarshalBERSendAuthenticationInfoRes(value *SendAuthenticationInfoRes, opts ...ber.EncodeOption) ([]byte, error) {
	return MarshalBERAuthenticationSetList(value, opts...)
}

// MarshalDERSendAuthenticationInfoRes encodes the standalone collection alias SendAuthenticationInfoRes using DER.
func MarshalDERSendAuthenticationInfoRes(value *SendAuthenticationInfoRes) ([]byte, error) {
	return MarshalDERAuthenticationSetList(value)
}

// UnmarshalBERSendAuthenticationInfoRes decodes the standalone collection alias SendAuthenticationInfoRes.
func UnmarshalBERSendAuthenticationInfoRes(data []byte, opts ...ber.DecodeOption) (*SendAuthenticationInfoRes, error) {
	return UnmarshalBERAuthenticationSetList(data, opts...)
}

// MarshalBER encodes SendParametersArg to BER format.
func (v *SendParametersArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendParametersArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendParametersArg).MarshalBER, (*SendParametersArg).marshalBER, 3)

}
func (v *SendParametersArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_subscriberid, err := v.SubscriberId.MarshalBER(ber.ChildEncodeOptions(opts, "subscriberId")...)
	if err != nil {
		return nil, qualifyBERError(err, "subscriberId", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_subscriberid)
	children = append(children, enc_subscriberid...)
	if v.RequestParameterList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "requestParameterList", "encoding", false)
	}
	if len((v.RequestParameterList).Values) < 1 || len((v.RequestParameterList).Values) > 2 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_13, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "requestParameterList", "SIZE (1..2)", len((v.RequestParameterList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_requestparameterlist, err := MarshalBERRequestParameterList(v.RequestParameterList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "requestParameterList"))...)
	if err != nil {
		return nil, qualifyBERError(err, "requestParameterList", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_requestparameterlist)
	children = append(children, enc_requestparameterlist...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendParametersArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendParametersArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendParametersArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendParametersArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_subscriberid, err := v.SubscriberId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "subscriberId", "encoding", true)
	}
	children = append(children, enc_subscriberid...)
	if v.RequestParameterList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "requestParameterList", "encoding", true)
	}
	if len((v.RequestParameterList).Values) < 1 || len((v.RequestParameterList).Values) > 2 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_13, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "requestParameterList", "SIZE (1..2)", len((v.RequestParameterList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_requestparameterlist, err := MarshalDERRequestParameterList(v.RequestParameterList)
	if err != nil {
		return nil, qualifyBERError(err, "requestParameterList", "encoding", true)
	}
	children = append(children, enc_requestparameterlist...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendParametersArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendParametersArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendParametersArg from BER/DER format.
func (destination *SendParametersArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendParametersArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendParametersArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SendParametersArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_13, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendParametersArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendParametersArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendParametersArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendParametersArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode subscriberId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field subscriberId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "subscriberId", content[offset:])
		// Decode nested CHOICE (SubscriberId)
		_, n_subscriberid, _, tlvErr_subscriberid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_subscriberid != nil {
			return qualifyBERError(tlvErr_subscriberid, "subscriberId", "decoding", false)
		}
		if offset > len(content) || n_subscriberid < 0 || n_subscriberid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.SubscriberId.UnmarshalBER(content[offset:offset+n_subscriberid], ber.ChildDecodeOptions(opts, "subscriberId")...); unmErr != nil {
			return qualifyBERError(unmErr, "subscriberId", "decoding", false)
		}
		if offset > len(content) || n_subscriberid < 0 || n_subscriberid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_subscriberid
	}
	// Decode requestParameterList
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field requestParameterList", ber.ErrUnexpectedElement)
	}
	{
		v.berRequestParameterListIndef_ = false
		ber.MarkPreflightTarget(opts, "requestParameterList", content[offset:])
		// Decode nested SEQUENCE_OF (RequestParameterList)
		_, n_requestparameterlist, _, tlvErr_requestparameterlist := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_requestparameterlist != nil {
			return qualifyBERError(tlvErr_requestparameterlist, "requestParameterList", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_requestparameterlist < 0 || n_requestparameterlist >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tlv_requestparameterlist := content[offset : offset+n_requestparameterlist]
		{
			_, tagSz_, _ := ber.DecodeTag(tlv_requestparameterlist)
			if tagSz_ < len(tlv_requestparameterlist) && tlv_requestparameterlist[tagSz_] == 0x80 {
				v.berRequestParameterListIndef_ = true
			}
		}
		dec_requestparameterlist, unmErr := UnmarshalBERRequestParameterList(tlv_requestparameterlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "requestParameterList"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "requestParameterList", "decoding", false)
		}
		v.RequestParameterList = dec_requestparameterlist
		if offset < 0 || offset >
			len(content) || n_requestparameterlist < 0 || n_requestparameterlist >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_requestparameterlist
		if len((v.RequestParameterList).Values) < 1 || len((v.RequestParameterList).Values) > 2 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_13, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "requestParameterList", "SIZE (1..2)", len((v.RequestParameterList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SendParametersArg", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBERRequestParameterList encodes a RequestParameterList list to BER.
func MarshalBERRequestParameterList(collection *RequestParameterList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERRequestParameterList, marshalBERRequestParameterList, 3, UnmarshalBERRequestParameterList)

}
func marshalBERRequestParameterList(collection *RequestParameterList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 2 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-MS-DataTypes.marshalBERRequestParameterList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "RequestParameterList", "SIZE (1..2)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if int64(elem) != 0 && int64(elem) != 1 && int64(elem) != 2 && int64(elem) != 4 {
			if constraintErr := checkEncodedValue(opts, "MAP-MS-DataTypes.marshalBERRequestParameterList", "20", fmt.Sprintf("element[%d]", elemIndex), "ENUMERATED {0, 1, 2, 4}", fmt.Sprint(int64(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ber.EncodeEnumerated(int64(elem))...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearRequestParameterList(encoder *ber.LinearEncoder, collection *RequestParameterList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERRequestParameterList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERRequestParameterList encodes a RequestParameterList list to DER.
func MarshalDERRequestParameterList(collection *RequestParameterList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 2 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, s990e88_14, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "RequestParameterList", "SIZE (1..2)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if int64(elem) != 0 && int64(elem) != 1 && int64(elem) != 2 && int64(elem) != 4 {
			if constraintErr := checkEncodedValue(nil, s990e88_14, "20", fmt.Sprintf("element[%d]", elemIndex), "ENUMERATED {0, 1, 2, 4}", fmt.Sprint(int64(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ber.EncodeEnumerated(int64(elem))...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RequestParameterList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearRequestParameterList(encoder *ber.LinearEncoder, collection *RequestParameterList) ([]byte, error) {
	encoded, err := MarshalDERRequestParameterList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERRequestParameterList decodes a RequestParameterList list from BER.
func UnmarshalBERRequestParameterList(data []byte, opts ...ber.DecodeOption) (returnValue *RequestParameterList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERRequestParameterList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_14, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding RequestParameterList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RequestParameterList", Cause: ber.ErrExtraData}
	}
	var result []RequestParameter
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, intErr := ber.DecodeEnumerated(elementData, opts...)
		if intErr != nil {
			return nil, qualifyBERError(intErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if val != 0 && val != 1 && val != 2 && val != 4 {
			if constraintErr := checkDecodedValue(opts, s990e88_14, "20", fmt.Sprintf("element[%d]", len(result)), "ENUMERATED {0, 1, 2, 4}", fmt.Sprint(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, RequestParameter(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 2 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, s990e88_14, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "RequestParameterList", "SIZE (1..2)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &RequestParameterList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERRequestParameterList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERSentParameterList encodes a SentParameterList list to BER.
func MarshalBERSentParameterList(collection *SentParameterList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSentParameterList, marshalBERSentParameterList, 3, UnmarshalBERSentParameterList)

}
func marshalBERSentParameterList(collection *SentParameterList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 6 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-MS-DataTypes.marshalBERSentParameterList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SentParameterList", "SIZE (1..6)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
		ber.RecordGeneratedBERChildPlacement(opts, len(children)-len(enc), enc)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearSentParameterList(encoder *ber.LinearEncoder, collection *SentParameterList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSentParameterList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSentParameterList encodes a SentParameterList list to DER.
func MarshalDERSentParameterList(collection *SentParameterList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 6 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, "MAP-MS-DataTypes.SentParameterList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SentParameterList", "SIZE (1..6)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SentParameterList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSentParameterList(encoder *ber.LinearEncoder, collection *SentParameterList) ([]byte, error) {
	encoded, err := MarshalDERSentParameterList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSentParameterList decodes a SentParameterList list from BER.
func UnmarshalBERSentParameterList(data []byte, opts ...ber.DecodeOption) (returnValue *SentParameterList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERSentParameterList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-MS-DataTypes.SentParameterList", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SentParameterList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SentParameterList", Cause: ber.ErrExtraData}
	}
	var result []SentParameter
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem SentParameter
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeIndexOptions(opts, len(result))...); unmErr != nil {
			return nil, qualifyBERError(unmErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 6 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, "MAP-MS-DataTypes.SentParameterList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SentParameterList", "SIZE (1..6)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SentParameterList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSentParameterList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SentParameter to BER format.
func (v *SentParameter) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SentParameter receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SentParameter).MarshalBER, (*SentParameter).marshalBER, 3)

}
func (v *SentParameter) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SentParameter) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SentParameterChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_15, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "imsi", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SentParameterChoiceAuthenticationSet:
		if v.AuthenticationSet == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: authenticationSet is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.AuthenticationSet.MarshalBER(ber.ChildEncodeOptions(opts, "authenticationSet")...)
		if err != nil {
			return nil, qualifyBERError(err, "authenticationSet", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "authenticationSet", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SentParameterChoiceSubscriberData:
		if v.SubscriberData == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: subscriberData is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.SubscriberData.MarshalBER(ber.ChildEncodeOptions(opts, "subscriberData")...)
		if err != nil {
			return nil, qualifyBERError(err, "subscriberData", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "subscriberData", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SentParameterChoiceKi:
		if v.Ki == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: ki is nil", ber.ErrInvalidValue)
		}
		enc_3, encodeErr_enc_3 := ber.EncodeOctetString([]byte(*v.Ki))
		if encodeErr_enc_3 != nil {
			return nil, qualifyBERError(encodeErr_enc_3, "ki", "encoding", false)
		}
		if len(*v.Ki) < 16 || len(*v.Ki) > 16 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_15, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ki", "SIZE (16)", len(*v.Ki)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "ki", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SentParameter", v.Choice)
	}
}

// MarshalDER encodes SentParameter to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SentParameter) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SentParameter receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SentParameterChoiceAuthenticationSet:
		if v.AuthenticationSet == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: authenticationSet is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.AuthenticationSet.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "authenticationSet", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "authenticationSet", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "authenticationSet", "encoding", true)
		}
		return enc_der_1, nil
	case SentParameterChoiceSubscriberData:
		if v.SubscriberData == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: subscriberData is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.SubscriberData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "subscriberData", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "subscriberData", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "subscriberData", "encoding", true)
		}
		return enc_der_2, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SentParameterChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case SentParameterChoiceAuthenticationSet:
			return nil, qualifyBERError(err, "authenticationSet", "encoding", true)
		case SentParameterChoiceSubscriberData:
			return nil, qualifyBERError(err, "subscriberData", "encoding", true)
		case SentParameterChoiceKi:
			return nil, qualifyBERError(err, "ki", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SentParameter as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SentParameter) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SentParameter from BER/DER format.
func (destination *SentParameter) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SentParameter destination is nil", ber.ErrInvalidValue)
	}
	v := new(SentParameter)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SentParameter).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SentParameter
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_15, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SentParameter{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SentParameter CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SentParameter: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SentParameter CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SentParameter", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SentParameter.authenticationSet", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SentParameter.subscriberData", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SentParameterChoiceImsi
		ber.MarkPreflightTarget(opts, "imsi", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "imsi", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "imsi", "decoding", false)
		}
		tmp := IMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_15, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = SentParameterChoiceAuthenticationSet
		ber.MarkPreflightTarget(opts, "authenticationSet", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "authenticationSet", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec AuthenticationSet
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "authenticationSet")...); unmErr != nil {
			return qualifyBERError(unmErr, "authenticationSet", "decoding", false)
		}
		v.AuthenticationSet = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = SentParameterChoiceSubscriberData
		ber.MarkPreflightTarget(opts, "subscriberData", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "subscriberData", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec SubscriberData
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "subscriberData")...); unmErr != nil {
			return qualifyBERError(unmErr, "subscriberData", "decoding", false)
		}
		v.SubscriberData = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SentParameterChoiceKi
		ber.MarkPreflightTarget(opts, "ki", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "ki", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ki", "decoding", false)
		}
		tmp := Ki(decVal)
		v.Ki = &tmp
		if len(*v.Ki) < 16 || len(*v.Ki) > 16 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_15, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ki", "SIZE (16)", len(*v.Ki)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for SentParameter CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes InsertSubscriberDataArg to BER format.
func (v *InsertSubscriberDataArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: InsertSubscriberDataArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*InsertSubscriberDataArg).MarshalBER, (*InsertSubscriberDataArg).marshalBER, 3)

}
func (v *InsertSubscriberDataArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, qualifyBERError(encodeErr_enc_category, "category", "encoding", false)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_category)
		if tagErr_enc_category != nil {
			return nil, qualifyBERError(tagErr_enc_category, "category", "encoding", false)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.SubscriberStatus != nil {
		if int64(*v.SubscriberStatus) != 0 && int64(*v.SubscriberStatus) != 1 {
			if constraintErr := checkEncodedValue(opts, s990e88_16, "20", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_subscriberstatus := ber.EncodeEnumerated(int64(*v.SubscriberStatus))
		retagged_enc_subscriberstatus, tagErr_enc_subscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_subscriberstatus)
		if tagErr_enc_subscriberstatus != nil {
			return nil, qualifyBERError(tagErr_enc_subscriberstatus, "subscriberStatus", "encoding", false)
		}
		enc_subscriberstatus = retagged_enc_subscriberstatus
		children = append(children, enc_subscriberstatus...)
	}
	if v.BearerServiceList != nil {
		if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservicelist, err := MarshalBERBearerServiceList(v.BearerServiceList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "bearerServiceList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "bearerServiceList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berBearerServiceListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_bearerservicelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_bearerservicelist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "bearerServiceList", "encoding", false)
				}
			}
		} else {
			retagged_enc_bearerservicelist, tagErr_enc_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_bearerservicelist)
			if tagErr_enc_bearerservicelist != nil {
				return nil, qualifyBERError(tagErr_enc_bearerservicelist, "bearerServiceList", "encoding", false)
			}
			enc_bearerservicelist = retagged_enc_bearerservicelist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_bearerservicelist)
		children = append(children, enc_bearerservicelist...)
	}
	if v.TeleserviceList != nil {
		if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicelist, err := MarshalBERTeleserviceList(v.TeleserviceList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "teleserviceList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "teleserviceList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berTeleserviceListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_teleservicelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_teleservicelist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 6}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "teleserviceList", "encoding", false)
				}
			}
		} else {
			retagged_enc_teleservicelist, tagErr_enc_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_teleservicelist)
			if tagErr_enc_teleservicelist != nil {
				return nil, qualifyBERError(tagErr_enc_teleservicelist, "teleserviceList", "encoding", false)
			}
			enc_teleservicelist = retagged_enc_teleservicelist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_teleservicelist)
		children = append(children, enc_teleservicelist...)
	}
	if v.ProvisionedSS != nil {
		if len((v.ProvisionedSS).Values) < 1 || len((v.ProvisionedSS).Values) > 30 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "provisionedSS", "SIZE (1..30)", len((v.ProvisionedSS).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_provisionedss, err := MarshalBERSSInfoList(v.ProvisionedSS, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "provisionedSS"))...)
		if err != nil {
			return nil, qualifyBERError(err, "provisionedSS", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berProvisionedSSIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_provisionedss)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_provisionedss, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 7}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "provisionedSS", "encoding", false)
				}
			}
		} else {
			retagged_enc_provisionedss, tagErr_enc_provisionedss := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_provisionedss)
			if tagErr_enc_provisionedss != nil {
				return nil, qualifyBERError(tagErr_enc_provisionedss, "provisionedSS", "encoding", false)
			}
			enc_provisionedss = retagged_enc_provisionedss
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_provisionedss)
		children = append(children, enc_provisionedss...)
	}
	if v.OdbData != nil {
		enc_odbdata, err := v.OdbData.MarshalBER(ber.ChildEncodeOptions(opts, "odb-Data")...)
		if err != nil {
			return nil, qualifyBERError(err, "odb-Data", "encoding", false)
		}
		retagged_enc_odbdata, tagErr_enc_odbdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_odbdata)
		if tagErr_enc_odbdata != nil {
			return nil, qualifyBERError(tagErr_enc_odbdata, "odb-Data", "encoding", false)
		}
		enc_odbdata = retagged_enc_odbdata
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_odbdata)
		children = append(children, enc_odbdata...)
	}
	if v.RoamingRestrictionDueToUnsupportedFeature != nil {
		enc_roamingrestrictionduetounsupportedfeature := ber.EncodeNull()
		retagged_enc_roamingrestrictionduetounsupportedfeature, tagErr_enc_roamingrestrictionduetounsupportedfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_roamingrestrictionduetounsupportedfeature)
		if tagErr_enc_roamingrestrictionduetounsupportedfeature != nil {
			return nil, qualifyBERError(tagErr_enc_roamingrestrictionduetounsupportedfeature, "roamingRestrictionDueToUnsupportedFeature", "encoding", false)
		}
		enc_roamingrestrictionduetounsupportedfeature = retagged_enc_roamingrestrictionduetounsupportedfeature
		children = append(children, enc_roamingrestrictionduetounsupportedfeature...)
	}
	if v.RegionalSubscriptionData != nil {
		if len((v.RegionalSubscriptionData).Values) < 1 || len((v.RegionalSubscriptionData).Values) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "regionalSubscriptionData", "SIZE (1..10)", len((v.RegionalSubscriptionData).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_regionalsubscriptiondata, err := MarshalBERZoneCodeList(v.RegionalSubscriptionData, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "regionalSubscriptionData"))...)
		if err != nil {
			return nil, qualifyBERError(err, "regionalSubscriptionData", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berRegionalSubscriptionDataIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_regionalsubscriptiondata)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_regionalsubscriptiondata, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 10}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "regionalSubscriptionData", "encoding", false)
				}
			}
		} else {
			retagged_enc_regionalsubscriptiondata, tagErr_enc_regionalsubscriptiondata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_regionalsubscriptiondata)
			if tagErr_enc_regionalsubscriptiondata != nil {
				return nil, qualifyBERError(tagErr_enc_regionalsubscriptiondata, "regionalSubscriptionData", "encoding", false)
			}
			enc_regionalsubscriptiondata = retagged_enc_regionalsubscriptiondata
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_regionalsubscriptiondata)
		children = append(children, enc_regionalsubscriptiondata...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_16, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *InsertSubscriberDataArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes InsertSubscriberDataArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *InsertSubscriberDataArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InsertSubscriberDataArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, qualifyBERError(encodeErr_enc_category, "category", "encoding", true)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_category)
		if tagErr_enc_category != nil {
			return nil, qualifyBERError(tagErr_enc_category, "category", "encoding", true)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.SubscriberStatus != nil {
		if int64(*v.SubscriberStatus) != 0 && int64(*v.SubscriberStatus) != 1 {
			if constraintErr := checkEncodedValue(nil, s990e88_16, "20", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_subscriberstatus := ber.EncodeEnumerated(int64(*v.SubscriberStatus))
		retagged_enc_subscriberstatus, tagErr_enc_subscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_subscriberstatus)
		if tagErr_enc_subscriberstatus != nil {
			return nil, qualifyBERError(tagErr_enc_subscriberstatus, "subscriberStatus", "encoding", true)
		}
		enc_subscriberstatus = retagged_enc_subscriberstatus
		children = append(children, enc_subscriberstatus...)
	}
	if v.BearerServiceList != nil {
		if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservicelist, err := MarshalDERBearerServiceList(v.BearerServiceList)
		if err != nil {
			return nil, qualifyBERError(err, "bearerServiceList", "encoding", true)
		}
		retagged_enc_bearerservicelist, tagErr_enc_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_bearerservicelist)
		if tagErr_enc_bearerservicelist != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservicelist, "bearerServiceList", "encoding", true)
		}
		enc_bearerservicelist = retagged_enc_bearerservicelist
		children = append(children, enc_bearerservicelist...)
	}
	if v.TeleserviceList != nil {
		if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicelist, err := MarshalDERTeleserviceList(v.TeleserviceList)
		if err != nil {
			return nil, qualifyBERError(err, "teleserviceList", "encoding", true)
		}
		retagged_enc_teleservicelist, tagErr_enc_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_teleservicelist)
		if tagErr_enc_teleservicelist != nil {
			return nil, qualifyBERError(tagErr_enc_teleservicelist, "teleserviceList", "encoding", true)
		}
		enc_teleservicelist = retagged_enc_teleservicelist
		children = append(children, enc_teleservicelist...)
	}
	if v.ProvisionedSS != nil {
		if len((v.ProvisionedSS).Values) < 1 || len((v.ProvisionedSS).Values) > 30 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "provisionedSS", "SIZE (1..30)", len((v.ProvisionedSS).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_provisionedss, err := MarshalDERSSInfoList(v.ProvisionedSS)
		if err != nil {
			return nil, qualifyBERError(err, "provisionedSS", "encoding", true)
		}
		retagged_enc_provisionedss, tagErr_enc_provisionedss := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_provisionedss)
		if tagErr_enc_provisionedss != nil {
			return nil, qualifyBERError(tagErr_enc_provisionedss, "provisionedSS", "encoding", true)
		}
		enc_provisionedss = retagged_enc_provisionedss
		children = append(children, enc_provisionedss...)
	}
	if v.OdbData != nil {
		enc_odbdata, err := v.OdbData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "odb-Data", "encoding", true)
		}
		retagged_enc_odbdata, tagErr_enc_odbdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_odbdata)
		if tagErr_enc_odbdata != nil {
			return nil, qualifyBERError(tagErr_enc_odbdata, "odb-Data", "encoding", true)
		}
		enc_odbdata = retagged_enc_odbdata
		children = append(children, enc_odbdata...)
	}
	if v.RoamingRestrictionDueToUnsupportedFeature != nil {
		enc_roamingrestrictionduetounsupportedfeature := ber.EncodeNull()
		retagged_enc_roamingrestrictionduetounsupportedfeature, tagErr_enc_roamingrestrictionduetounsupportedfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_roamingrestrictionduetounsupportedfeature)
		if tagErr_enc_roamingrestrictionduetounsupportedfeature != nil {
			return nil, qualifyBERError(tagErr_enc_roamingrestrictionduetounsupportedfeature, "roamingRestrictionDueToUnsupportedFeature", "encoding", true)
		}
		enc_roamingrestrictionduetounsupportedfeature = retagged_enc_roamingrestrictionduetounsupportedfeature
		children = append(children, enc_roamingrestrictionduetounsupportedfeature...)
	}
	if v.RegionalSubscriptionData != nil {
		if len((v.RegionalSubscriptionData).Values) < 1 || len((v.RegionalSubscriptionData).Values) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "regionalSubscriptionData", "SIZE (1..10)", len((v.RegionalSubscriptionData).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_regionalsubscriptiondata, err := MarshalDERZoneCodeList(v.RegionalSubscriptionData)
		if err != nil {
			return nil, qualifyBERError(err, "regionalSubscriptionData", "encoding", true)
		}
		retagged_enc_regionalsubscriptiondata, tagErr_enc_regionalsubscriptiondata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_regionalsubscriptiondata)
		if tagErr_enc_regionalsubscriptiondata != nil {
			return nil, qualifyBERError(tagErr_enc_regionalsubscriptiondata, "regionalSubscriptionData", "encoding", true)
		}
		enc_regionalsubscriptiondata = retagged_enc_regionalsubscriptiondata
		children = append(children, enc_regionalsubscriptiondata...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_16, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding InsertSubscriberDataArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *InsertSubscriberDataArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes InsertSubscriberDataArg from BER/DER format.
func (destination *InsertSubscriberDataArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: InsertSubscriberDataArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(InsertSubscriberDataArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe InsertSubscriberDataArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_16, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = InsertSubscriberDataArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*InsertSubscriberDataArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding InsertSubscriberDataArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InsertSubscriberDataArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msisdn", "decoding", false)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_msisdn), "msisdn", "decoding", false)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msisdn", "decoding", false)
				}
				tmp_msisdn := ISDNAddressString(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode category
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "category", content[offset:])
				decodedTag_category, n_category, rawVal_category, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "category", "decoding", false)
				}
				if decodedTag_category.Class != tag.ClassContextSpecific || decodedTag_category.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_category), "category", "decoding", false)
				}
				decVal_category, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_category.Constructed, rawVal_category, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "category", "decoding", false)
				}
				tmp_category := Category(decVal_category)
				v.Category = &tmp_category
				if offset < 0 || offset >
					len(content) || n_category < 0 || n_category > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_category
				if len(*v.Category) < 1 || len(*v.Category) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode subscriberStatus
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "subscriberStatus", content[offset:])
				decodedTag_subscriberstatus, n_subscriberstatus, rawVal_subscriberstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "subscriberStatus", "decoding", false)
				}
				if decodedTag_subscriberstatus.Class != tag.ClassContextSpecific || decodedTag_subscriberstatus.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_subscriberstatus), "subscriberStatus", "decoding", false)
				}
				if decodedTag_subscriberstatus.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_subscriberstatus), "subscriberStatus", "decoding", false)
				}
				decVal_subscriberstatus, intErr := ber.DecodeEnumeratedValue(rawVal_subscriberstatus)
				if intErr != nil {
					return qualifyBERError(intErr, "subscriberStatus", "decoding", false)
				}
				tmp_subscriberstatus := SubscriberStatus(decVal_subscriberstatus)
				v.SubscriberStatus = &tmp_subscriberstatus
				if offset < 0 || offset >
					len(content) || n_subscriberstatus < 0 || n_subscriberstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_subscriberstatus
				if int64(*v.SubscriberStatus) != 0 && int64(*v.SubscriberStatus) != 1 {
					if constraintErr := checkDecodedValue(opts, s990e88_16, "20", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode bearerServiceList
	v.berBearerServiceListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "bearerServiceList", content[offset:])
				decodedTag_bearerservicelist, n_bearerservicelist, rawVal_bearerservicelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bearerServiceList", "decoding", false)
				}
				if decodedTag_bearerservicelist.Class != tag.ClassContextSpecific || decodedTag_bearerservicelist.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_bearerservicelist), "bearerServiceList", "decoding", false)
				}
				if decodedTag_bearerservicelist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_bearerservicelist), "bearerServiceList", "decoding", false)
				}
				_ = rawVal_bearerservicelist
				if offset < 0 || offset >
					len(content) || n_bearerservicelist < 0 || n_bearerservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_bearerservicelist, reconstructionErr_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_bearerservicelist])
				if reconstructionErr_bearerservicelist != nil {
					return qualifyBERError(reconstructionErr_bearerservicelist, "bearerServiceList", "decoding", false)
				}
				dec_bearerservicelist, unmErr := UnmarshalBERBearerServiceList(reconstructed_bearerservicelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "bearerServiceList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "bearerServiceList", "decoding", false)
				}
				v.BearerServiceList = dec_bearerservicelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berBearerServiceListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_bearerservicelist < 0 || n_bearerservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bearerservicelist
				if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode teleserviceList
	v.berTeleserviceListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "teleserviceList", content[offset:])
				decodedTag_teleservicelist, n_teleservicelist, rawVal_teleservicelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "teleserviceList", "decoding", false)
				}
				if decodedTag_teleservicelist.Class != tag.ClassContextSpecific || decodedTag_teleservicelist.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_teleservicelist), "teleserviceList", "decoding", false)
				}
				if decodedTag_teleservicelist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_teleservicelist), "teleserviceList", "decoding", false)
				}
				_ = rawVal_teleservicelist
				if offset < 0 || offset >
					len(content) || n_teleservicelist < 0 || n_teleservicelist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_teleservicelist, reconstructionErr_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_teleservicelist])
				if reconstructionErr_teleservicelist != nil {
					return qualifyBERError(reconstructionErr_teleservicelist, "teleserviceList", "decoding", false)
				}
				dec_teleservicelist, unmErr := UnmarshalBERTeleserviceList(reconstructed_teleservicelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "teleserviceList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "teleserviceList", "decoding", false)
				}
				v.TeleserviceList = dec_teleservicelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berTeleserviceListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_teleservicelist < 0 || n_teleservicelist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_teleservicelist
				if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode provisionedSS
	v.berProvisionedSSIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "provisionedSS", content[offset:])
				decodedTag_provisionedss, n_provisionedss, rawVal_provisionedss, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "provisionedSS", "decoding", false)
				}
				if decodedTag_provisionedss.Class != tag.ClassContextSpecific || decodedTag_provisionedss.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_provisionedss), "provisionedSS", "decoding", false)
				}
				if decodedTag_provisionedss.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_provisionedss), "provisionedSS", "decoding", false)
				}
				_ = rawVal_provisionedss
				if offset < 0 || offset >
					len(content) || n_provisionedss < 0 || n_provisionedss > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_provisionedss, reconstructionErr_provisionedss := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_provisionedss])
				if reconstructionErr_provisionedss != nil {
					return qualifyBERError(reconstructionErr_provisionedss, "provisionedSS", "decoding", false)
				}
				dec_provisionedss, unmErr := UnmarshalBERSSInfoList(reconstructed_provisionedss, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "provisionedSS"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "provisionedSS", "decoding", false)
				}
				v.ProvisionedSS = dec_provisionedss
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berProvisionedSSIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_provisionedss < 0 || n_provisionedss > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_provisionedss
				if len((v.ProvisionedSS).Values) < 1 || len((v.ProvisionedSS).Values) > 30 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "provisionedSS", "SIZE (1..30)", len((v.ProvisionedSS).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode odb-Data
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "odb-Data", content[offset:])
				decodedTag_odbdata, n_odbdata, rawVal_odbdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "odb-Data", "decoding", false)
				}
				if decodedTag_odbdata.Class != tag.ClassContextSpecific || decodedTag_odbdata.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_odbdata), "odb-Data", "decoding", false)
				}
				if decodedTag_odbdata.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_odbdata), "odb-Data", "decoding", false)
				}
				_ = rawVal_odbdata
				if offset < 0 || offset >
					len(content) || n_odbdata < 0 || n_odbdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_odbdata, reconstructionErr_odbdata := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_odbdata])
				if reconstructionErr_odbdata != nil {
					return qualifyBERError(reconstructionErr_odbdata, "odb-Data", "decoding", false)
				}
				var dec_odbdata ODBData
				if unmErr := dec_odbdata.UnmarshalBER(reconstructed_odbdata, ber.ChildDecodeOptions(opts, "odb-Data")...); unmErr != nil {
					return qualifyBERError(unmErr, "odb-Data", "decoding", false)
				}
				v.OdbData = &dec_odbdata
				if offset < 0 || offset >
					len(content) || n_odbdata < 0 || n_odbdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_odbdata
			}
		}
	}
	// Decode roamingRestrictionDueToUnsupportedFeature
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				ber.MarkPreflightTarget(opts, "roamingRestrictionDueToUnsupportedFeature", content[offset:])
				decodedTag_roamingrestrictionduetounsupportedfeature, n_roamingrestrictionduetounsupportedfeature, rawVal_roamingrestrictionduetounsupportedfeature, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				if decodedTag_roamingrestrictionduetounsupportedfeature.Class != tag.ClassContextSpecific || decodedTag_roamingrestrictionduetounsupportedfeature.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_roamingrestrictionduetounsupportedfeature), "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				if decodedTag_roamingrestrictionduetounsupportedfeature.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_roamingrestrictionduetounsupportedfeature), "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				if len(rawVal_roamingrestrictionduetounsupportedfeature) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_roamingrestrictionduetounsupportedfeature)), "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				v.RoamingRestrictionDueToUnsupportedFeature = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_roamingrestrictionduetounsupportedfeature < 0 ||
					n_roamingrestrictionduetounsupportedfeature > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_roamingrestrictionduetounsupportedfeature
			}
		}
	}
	// Decode regionalSubscriptionData
	v.berRegionalSubscriptionDataIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "regionalSubscriptionData", content[offset:])
				decodedTag_regionalsubscriptiondata, n_regionalsubscriptiondata, rawVal_regionalsubscriptiondata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "regionalSubscriptionData", "decoding", false)
				}
				if decodedTag_regionalsubscriptiondata.Class != tag.ClassContextSpecific || decodedTag_regionalsubscriptiondata.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_regionalsubscriptiondata), "regionalSubscriptionData", "decoding", false)
				}
				if decodedTag_regionalsubscriptiondata.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_regionalsubscriptiondata), "regionalSubscriptionData", "decoding", false)
				}
				_ = rawVal_regionalsubscriptiondata
				if offset < 0 || offset >
					len(content) || n_regionalsubscriptiondata < 0 || n_regionalsubscriptiondata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_regionalsubscriptiondata, reconstructionErr_regionalsubscriptiondata := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_regionalsubscriptiondata])
				if reconstructionErr_regionalsubscriptiondata != nil {
					return qualifyBERError(reconstructionErr_regionalsubscriptiondata, "regionalSubscriptionData", "decoding", false)
				}
				dec_regionalsubscriptiondata, unmErr := UnmarshalBERZoneCodeList(reconstructed_regionalsubscriptiondata, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "regionalSubscriptionData"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "regionalSubscriptionData", "decoding", false)
				}
				v.RegionalSubscriptionData = dec_regionalsubscriptiondata
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berRegionalSubscriptionDataIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_regionalsubscriptiondata < 0 || n_regionalsubscriptiondata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_regionalsubscriptiondata
				if len((v.RegionalSubscriptionData).Values) < 1 || len((v.RegionalSubscriptionData).Values) > 10 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "regionalSubscriptionData", "SIZE (1..10)", len((v.RegionalSubscriptionData).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "InsertSubscriberDataArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "InsertSubscriberDataArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubscriberData to BER format.
func (v *SubscriberData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SubscriberData).MarshalBER, (*SubscriberData).marshalBER, 3)

}
func (v *SubscriberData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, qualifyBERError(encodeErr_enc_category, "category", "encoding", false)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_category)
		if tagErr_enc_category != nil {
			return nil, qualifyBERError(tagErr_enc_category, "category", "encoding", false)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.SubscriberStatus != nil {
		if int64(*v.SubscriberStatus) != 0 && int64(*v.SubscriberStatus) != 1 {
			if constraintErr := checkEncodedValue(opts, s990e88_17, "20", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_subscriberstatus := ber.EncodeEnumerated(int64(*v.SubscriberStatus))
		retagged_enc_subscriberstatus, tagErr_enc_subscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_subscriberstatus)
		if tagErr_enc_subscriberstatus != nil {
			return nil, qualifyBERError(tagErr_enc_subscriberstatus, "subscriberStatus", "encoding", false)
		}
		enc_subscriberstatus = retagged_enc_subscriberstatus
		children = append(children, enc_subscriberstatus...)
	}
	if v.BearerServiceList != nil {
		if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservicelist, err := MarshalBERBearerServiceList(v.BearerServiceList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "bearerServiceList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "bearerServiceList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berBearerServiceListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_bearerservicelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_bearerservicelist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "bearerServiceList", "encoding", false)
				}
			}
		} else {
			retagged_enc_bearerservicelist, tagErr_enc_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_bearerservicelist)
			if tagErr_enc_bearerservicelist != nil {
				return nil, qualifyBERError(tagErr_enc_bearerservicelist, "bearerServiceList", "encoding", false)
			}
			enc_bearerservicelist = retagged_enc_bearerservicelist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_bearerservicelist)
		children = append(children, enc_bearerservicelist...)
	}
	if v.TeleserviceList != nil {
		if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicelist, err := MarshalBERTeleserviceList(v.TeleserviceList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "teleserviceList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "teleserviceList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berTeleserviceListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_teleservicelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_teleservicelist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 6}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "teleserviceList", "encoding", false)
				}
			}
		} else {
			retagged_enc_teleservicelist, tagErr_enc_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_teleservicelist)
			if tagErr_enc_teleservicelist != nil {
				return nil, qualifyBERError(tagErr_enc_teleservicelist, "teleserviceList", "encoding", false)
			}
			enc_teleservicelist = retagged_enc_teleservicelist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_teleservicelist)
		children = append(children, enc_teleservicelist...)
	}
	if v.ProvisionedSS != nil {
		if len((v.ProvisionedSS).Values) < 1 || len((v.ProvisionedSS).Values) > 30 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "provisionedSS", "SIZE (1..30)", len((v.ProvisionedSS).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_provisionedss, err := MarshalBERSSInfoList(v.ProvisionedSS, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "provisionedSS"))...)
		if err != nil {
			return nil, qualifyBERError(err, "provisionedSS", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berProvisionedSSIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_provisionedss)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_provisionedss, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 7}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "provisionedSS", "encoding", false)
				}
			}
		} else {
			retagged_enc_provisionedss, tagErr_enc_provisionedss := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_provisionedss)
			if tagErr_enc_provisionedss != nil {
				return nil, qualifyBERError(tagErr_enc_provisionedss, "provisionedSS", "encoding", false)
			}
			enc_provisionedss = retagged_enc_provisionedss
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_provisionedss)
		children = append(children, enc_provisionedss...)
	}
	if v.OdbData != nil {
		enc_odbdata, err := v.OdbData.MarshalBER(ber.ChildEncodeOptions(opts, "odb-Data")...)
		if err != nil {
			return nil, qualifyBERError(err, "odb-Data", "encoding", false)
		}
		retagged_enc_odbdata, tagErr_enc_odbdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_odbdata)
		if tagErr_enc_odbdata != nil {
			return nil, qualifyBERError(tagErr_enc_odbdata, "odb-Data", "encoding", false)
		}
		enc_odbdata = retagged_enc_odbdata
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_odbdata)
		children = append(children, enc_odbdata...)
	}
	if v.RoamingRestrictionDueToUnsupportedFeature != nil {
		enc_roamingrestrictionduetounsupportedfeature := ber.EncodeNull()
		retagged_enc_roamingrestrictionduetounsupportedfeature, tagErr_enc_roamingrestrictionduetounsupportedfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_roamingrestrictionduetounsupportedfeature)
		if tagErr_enc_roamingrestrictionduetounsupportedfeature != nil {
			return nil, qualifyBERError(tagErr_enc_roamingrestrictionduetounsupportedfeature, "roamingRestrictionDueToUnsupportedFeature", "encoding", false)
		}
		enc_roamingrestrictionduetounsupportedfeature = retagged_enc_roamingrestrictionduetounsupportedfeature
		children = append(children, enc_roamingrestrictionduetounsupportedfeature...)
	}
	if v.RegionalSubscriptionData != nil {
		if len((v.RegionalSubscriptionData).Values) < 1 || len((v.RegionalSubscriptionData).Values) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "regionalSubscriptionData", "SIZE (1..10)", len((v.RegionalSubscriptionData).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_regionalsubscriptiondata, err := MarshalBERZoneCodeList(v.RegionalSubscriptionData, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "regionalSubscriptionData"))...)
		if err != nil {
			return nil, qualifyBERError(err, "regionalSubscriptionData", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berRegionalSubscriptionDataIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_regionalsubscriptiondata)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_regionalsubscriptiondata, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 10}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "regionalSubscriptionData", "encoding", false)
				}
			}
		} else {
			retagged_enc_regionalsubscriptiondata, tagErr_enc_regionalsubscriptiondata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_regionalsubscriptiondata)
			if tagErr_enc_regionalsubscriptiondata != nil {
				return nil, qualifyBERError(tagErr_enc_regionalsubscriptiondata, "regionalSubscriptionData", "encoding", false)
			}
			enc_regionalsubscriptiondata = retagged_enc_regionalsubscriptiondata
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_regionalsubscriptiondata)
		children = append(children, enc_regionalsubscriptiondata...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SubscriberData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SubscriberData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SubscriberData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, qualifyBERError(encodeErr_enc_category, "category", "encoding", true)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_category)
		if tagErr_enc_category != nil {
			return nil, qualifyBERError(tagErr_enc_category, "category", "encoding", true)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.SubscriberStatus != nil {
		if int64(*v.SubscriberStatus) != 0 && int64(*v.SubscriberStatus) != 1 {
			if constraintErr := checkEncodedValue(nil, s990e88_17, "20", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_subscriberstatus := ber.EncodeEnumerated(int64(*v.SubscriberStatus))
		retagged_enc_subscriberstatus, tagErr_enc_subscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_subscriberstatus)
		if tagErr_enc_subscriberstatus != nil {
			return nil, qualifyBERError(tagErr_enc_subscriberstatus, "subscriberStatus", "encoding", true)
		}
		enc_subscriberstatus = retagged_enc_subscriberstatus
		children = append(children, enc_subscriberstatus...)
	}
	if v.BearerServiceList != nil {
		if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservicelist, err := MarshalDERBearerServiceList(v.BearerServiceList)
		if err != nil {
			return nil, qualifyBERError(err, "bearerServiceList", "encoding", true)
		}
		retagged_enc_bearerservicelist, tagErr_enc_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_bearerservicelist)
		if tagErr_enc_bearerservicelist != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservicelist, "bearerServiceList", "encoding", true)
		}
		enc_bearerservicelist = retagged_enc_bearerservicelist
		children = append(children, enc_bearerservicelist...)
	}
	if v.TeleserviceList != nil {
		if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicelist, err := MarshalDERTeleserviceList(v.TeleserviceList)
		if err != nil {
			return nil, qualifyBERError(err, "teleserviceList", "encoding", true)
		}
		retagged_enc_teleservicelist, tagErr_enc_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_teleservicelist)
		if tagErr_enc_teleservicelist != nil {
			return nil, qualifyBERError(tagErr_enc_teleservicelist, "teleserviceList", "encoding", true)
		}
		enc_teleservicelist = retagged_enc_teleservicelist
		children = append(children, enc_teleservicelist...)
	}
	if v.ProvisionedSS != nil {
		if len((v.ProvisionedSS).Values) < 1 || len((v.ProvisionedSS).Values) > 30 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "provisionedSS", "SIZE (1..30)", len((v.ProvisionedSS).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_provisionedss, err := MarshalDERSSInfoList(v.ProvisionedSS)
		if err != nil {
			return nil, qualifyBERError(err, "provisionedSS", "encoding", true)
		}
		retagged_enc_provisionedss, tagErr_enc_provisionedss := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_provisionedss)
		if tagErr_enc_provisionedss != nil {
			return nil, qualifyBERError(tagErr_enc_provisionedss, "provisionedSS", "encoding", true)
		}
		enc_provisionedss = retagged_enc_provisionedss
		children = append(children, enc_provisionedss...)
	}
	if v.OdbData != nil {
		enc_odbdata, err := v.OdbData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "odb-Data", "encoding", true)
		}
		retagged_enc_odbdata, tagErr_enc_odbdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_odbdata)
		if tagErr_enc_odbdata != nil {
			return nil, qualifyBERError(tagErr_enc_odbdata, "odb-Data", "encoding", true)
		}
		enc_odbdata = retagged_enc_odbdata
		children = append(children, enc_odbdata...)
	}
	if v.RoamingRestrictionDueToUnsupportedFeature != nil {
		enc_roamingrestrictionduetounsupportedfeature := ber.EncodeNull()
		retagged_enc_roamingrestrictionduetounsupportedfeature, tagErr_enc_roamingrestrictionduetounsupportedfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_roamingrestrictionduetounsupportedfeature)
		if tagErr_enc_roamingrestrictionduetounsupportedfeature != nil {
			return nil, qualifyBERError(tagErr_enc_roamingrestrictionduetounsupportedfeature, "roamingRestrictionDueToUnsupportedFeature", "encoding", true)
		}
		enc_roamingrestrictionduetounsupportedfeature = retagged_enc_roamingrestrictionduetounsupportedfeature
		children = append(children, enc_roamingrestrictionduetounsupportedfeature...)
	}
	if v.RegionalSubscriptionData != nil {
		if len((v.RegionalSubscriptionData).Values) < 1 || len((v.RegionalSubscriptionData).Values) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "regionalSubscriptionData", "SIZE (1..10)", len((v.RegionalSubscriptionData).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_regionalsubscriptiondata, err := MarshalDERZoneCodeList(v.RegionalSubscriptionData)
		if err != nil {
			return nil, qualifyBERError(err, "regionalSubscriptionData", "encoding", true)
		}
		retagged_enc_regionalsubscriptiondata, tagErr_enc_regionalsubscriptiondata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_regionalsubscriptiondata)
		if tagErr_enc_regionalsubscriptiondata != nil {
			return nil, qualifyBERError(tagErr_enc_regionalsubscriptiondata, "regionalSubscriptionData", "encoding", true)
		}
		enc_regionalsubscriptiondata = retagged_enc_regionalsubscriptiondata
		children = append(children, enc_regionalsubscriptiondata...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SubscriberData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SubscriberData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SubscriberData from BER/DER format.
func (destination *SubscriberData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SubscriberData destination is nil", ber.ErrInvalidValue)
	}
	v := new(SubscriberData)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SubscriberData
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_17, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SubscriberData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SubscriberData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SubscriberData SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msisdn", "decoding", false)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_msisdn), "msisdn", "decoding", false)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msisdn", "decoding", false)
				}
				tmp_msisdn := ISDNAddressString(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset > len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode category
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "category", content[offset:])
				decodedTag_category, n_category, rawVal_category, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "category", "decoding", false)
				}
				if decodedTag_category.Class != tag.ClassContextSpecific || decodedTag_category.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_category), "category", "decoding", false)
				}
				decVal_category, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_category.Constructed, rawVal_category, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "category", "decoding", false)
				}
				tmp_category := Category(decVal_category)
				v.Category = &tmp_category
				if offset < 0 || offset >
					len(content) || n_category < 0 || n_category > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_category
				if len(*v.Category) < 1 || len(*v.Category) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode subscriberStatus
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "subscriberStatus", content[offset:])
				decodedTag_subscriberstatus, n_subscriberstatus, rawVal_subscriberstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "subscriberStatus", "decoding", false)
				}
				if decodedTag_subscriberstatus.Class != tag.ClassContextSpecific || decodedTag_subscriberstatus.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_subscriberstatus), "subscriberStatus", "decoding", false)
				}
				if decodedTag_subscriberstatus.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_subscriberstatus), "subscriberStatus", "decoding", false)
				}
				decVal_subscriberstatus, intErr := ber.DecodeEnumeratedValue(rawVal_subscriberstatus)
				if intErr != nil {
					return qualifyBERError(intErr, "subscriberStatus", "decoding", false)
				}
				tmp_subscriberstatus := SubscriberStatus(decVal_subscriberstatus)
				v.SubscriberStatus = &tmp_subscriberstatus
				if offset < 0 || offset >
					len(content) || n_subscriberstatus < 0 || n_subscriberstatus >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_subscriberstatus
				if int64(*v.SubscriberStatus) != 0 && int64(*v.SubscriberStatus) != 1 {
					if constraintErr := checkDecodedValue(opts, s990e88_17, "20", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode bearerServiceList
	v.berBearerServiceListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "bearerServiceList", content[offset:])
				decodedTag_bearerservicelist, n_bearerservicelist, rawVal_bearerservicelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bearerServiceList", "decoding", false)
				}
				if decodedTag_bearerservicelist.Class != tag.ClassContextSpecific || decodedTag_bearerservicelist.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_bearerservicelist), "bearerServiceList", "decoding", false)
				}
				if decodedTag_bearerservicelist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_bearerservicelist), "bearerServiceList", "decoding", false)
				}
				_ = rawVal_bearerservicelist
				if offset < 0 || offset >
					len(content) || n_bearerservicelist < 0 || n_bearerservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_bearerservicelist, reconstructionErr_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_bearerservicelist])
				if reconstructionErr_bearerservicelist != nil {
					return qualifyBERError(reconstructionErr_bearerservicelist, "bearerServiceList", "decoding", false)
				}
				dec_bearerservicelist, unmErr := UnmarshalBERBearerServiceList(reconstructed_bearerservicelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "bearerServiceList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "bearerServiceList", "decoding", false)
				}
				v.BearerServiceList = dec_bearerservicelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berBearerServiceListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_bearerservicelist < 0 || n_bearerservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bearerservicelist
				if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode teleserviceList
	v.berTeleserviceListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "teleserviceList", content[offset:])
				decodedTag_teleservicelist, n_teleservicelist, rawVal_teleservicelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "teleserviceList", "decoding", false)
				}
				if decodedTag_teleservicelist.Class != tag.ClassContextSpecific || decodedTag_teleservicelist.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_teleservicelist), "teleserviceList", "decoding", false)
				}
				if decodedTag_teleservicelist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_teleservicelist), "teleserviceList", "decoding", false)
				}
				_ = rawVal_teleservicelist
				if offset < 0 || offset >
					len(content) || n_teleservicelist < 0 || n_teleservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_teleservicelist, reconstructionErr_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_teleservicelist])
				if reconstructionErr_teleservicelist != nil {
					return qualifyBERError(reconstructionErr_teleservicelist, "teleserviceList", "decoding", false)
				}
				dec_teleservicelist, unmErr := UnmarshalBERTeleserviceList(reconstructed_teleservicelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "teleserviceList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "teleserviceList", "decoding", false)
				}
				v.TeleserviceList = dec_teleservicelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berTeleserviceListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_teleservicelist < 0 || n_teleservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_teleservicelist
				if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode provisionedSS
	v.berProvisionedSSIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "provisionedSS", content[offset:])
				decodedTag_provisionedss, n_provisionedss, rawVal_provisionedss, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "provisionedSS", "decoding", false)
				}
				if decodedTag_provisionedss.Class != tag.ClassContextSpecific || decodedTag_provisionedss.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_provisionedss), "provisionedSS", "decoding", false)
				}
				if decodedTag_provisionedss.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_provisionedss), "provisionedSS", "decoding", false)
				}
				_ = rawVal_provisionedss
				if offset < 0 || offset >
					len(content) || n_provisionedss < 0 || n_provisionedss >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_provisionedss, reconstructionErr_provisionedss := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_provisionedss])
				if reconstructionErr_provisionedss != nil {
					return qualifyBERError(reconstructionErr_provisionedss, "provisionedSS", "decoding", false)
				}
				dec_provisionedss, unmErr := UnmarshalBERSSInfoList(reconstructed_provisionedss, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "provisionedSS"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "provisionedSS", "decoding", false)
				}
				v.ProvisionedSS = dec_provisionedss
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berProvisionedSSIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_provisionedss < 0 || n_provisionedss >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_provisionedss
				if len((v.ProvisionedSS).Values) < 1 || len((v.ProvisionedSS).Values) > 30 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "provisionedSS", "SIZE (1..30)", len((v.ProvisionedSS).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode odb-Data
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "odb-Data", content[offset:])
				decodedTag_odbdata, n_odbdata, rawVal_odbdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "odb-Data", "decoding", false)
				}
				if decodedTag_odbdata.Class != tag.ClassContextSpecific || decodedTag_odbdata.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_odbdata), "odb-Data", "decoding", false)
				}
				if decodedTag_odbdata.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_odbdata), "odb-Data", "decoding", false)
				}
				_ = rawVal_odbdata
				if offset < 0 || offset >
					len(content) || n_odbdata < 0 || n_odbdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_odbdata, reconstructionErr_odbdata := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_odbdata])
				if reconstructionErr_odbdata != nil {
					return qualifyBERError(reconstructionErr_odbdata, "odb-Data", "decoding", false)
				}
				var dec_odbdata ODBData
				if unmErr := dec_odbdata.UnmarshalBER(reconstructed_odbdata, ber.ChildDecodeOptions(opts, "odb-Data")...); unmErr != nil {
					return qualifyBERError(unmErr, "odb-Data", "decoding", false)
				}
				v.OdbData = &dec_odbdata
				if offset < 0 || offset >
					len(content) || n_odbdata < 0 || n_odbdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_odbdata
			}
		}
	}
	// Decode roamingRestrictionDueToUnsupportedFeature
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				ber.MarkPreflightTarget(opts, "roamingRestrictionDueToUnsupportedFeature", content[offset:])
				decodedTag_roamingrestrictionduetounsupportedfeature, n_roamingrestrictionduetounsupportedfeature, rawVal_roamingrestrictionduetounsupportedfeature, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				if decodedTag_roamingrestrictionduetounsupportedfeature.Class != tag.ClassContextSpecific || decodedTag_roamingrestrictionduetounsupportedfeature.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_roamingrestrictionduetounsupportedfeature), "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				if decodedTag_roamingrestrictionduetounsupportedfeature.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_roamingrestrictionduetounsupportedfeature), "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				if len(rawVal_roamingrestrictionduetounsupportedfeature) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_roamingrestrictionduetounsupportedfeature)), "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				v.RoamingRestrictionDueToUnsupportedFeature = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_roamingrestrictionduetounsupportedfeature <
					0 || n_roamingrestrictionduetounsupportedfeature > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_roamingrestrictionduetounsupportedfeature
			}
		}
	}
	// Decode regionalSubscriptionData
	v.berRegionalSubscriptionDataIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "regionalSubscriptionData", content[offset:])
				decodedTag_regionalsubscriptiondata, n_regionalsubscriptiondata, rawVal_regionalsubscriptiondata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "regionalSubscriptionData", "decoding", false)
				}
				if decodedTag_regionalsubscriptiondata.Class != tag.ClassContextSpecific || decodedTag_regionalsubscriptiondata.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_regionalsubscriptiondata), "regionalSubscriptionData", "decoding", false)
				}
				if decodedTag_regionalsubscriptiondata.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_regionalsubscriptiondata), "regionalSubscriptionData", "decoding", false)
				}
				_ = rawVal_regionalsubscriptiondata
				if offset < 0 || offset >
					len(content) || n_regionalsubscriptiondata < 0 || n_regionalsubscriptiondata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_regionalsubscriptiondata, reconstructionErr_regionalsubscriptiondata := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_regionalsubscriptiondata])
				if reconstructionErr_regionalsubscriptiondata != nil {
					return qualifyBERError(reconstructionErr_regionalsubscriptiondata, "regionalSubscriptionData", "decoding", false)
				}
				dec_regionalsubscriptiondata, unmErr := UnmarshalBERZoneCodeList(reconstructed_regionalsubscriptiondata, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "regionalSubscriptionData"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "regionalSubscriptionData", "decoding", false)
				}
				v.RegionalSubscriptionData = dec_regionalsubscriptiondata
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berRegionalSubscriptionDataIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_regionalsubscriptiondata < 0 || n_regionalsubscriptiondata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_regionalsubscriptiondata
				if len((v.RegionalSubscriptionData).Values) < 1 || len((v.RegionalSubscriptionData).Values) > 10 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "regionalSubscriptionData", "SIZE (1..10)", len((v.RegionalSubscriptionData).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SubscriberData", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ODBData to BER format.
func (v *ODBData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ODBData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ODBData).MarshalBER, (*ODBData).marshalBER, 3)

}
func (v *ODBData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	namedBits_OdbGeneralData, namedBitErr_ := normalizeNamedBits(v.OdbGeneralData, []ber.NamedBitSizeSet{{{Min: 6, Max: 6}}}, opts, "odb-GeneralData", s990e88_18)
	if namedBitErr_ != nil {
		return nil, namedBitErr_
	}
	if bitStringErr := ber.ValidateBitStringLength(namedBits_OdbGeneralData.Bytes, namedBits_OdbGeneralData.BitLength); bitStringErr != nil {
		return nil, qualifyBERError(bitStringErr, "odb-GeneralData", "encoding", false)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:757
	if namedBits_OdbGeneralData.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	if (namedBits_OdbGeneralData).BitLength < 6 || (namedBits_OdbGeneralData).BitLength > 6 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_18, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "odb-GeneralData", "SIZE (6)", namedBitObservedLength(namedBits_OdbGeneralData)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_odbgeneraldata, encodeErr_enc_odbgeneraldata := ber.EncodeBitString(namedBits_OdbGeneralData.Bytes, ber.UnusedBitCount(namedBits_OdbGeneralData.BitLength))
	if encodeErr_enc_odbgeneraldata != nil {
		return nil, qualifyBERError(encodeErr_enc_odbgeneraldata, "odb-GeneralData", "encoding", false)
	}
	children = append(children, enc_odbgeneraldata...)
	if v.OdbHPLMNData != nil {
		namedBits_OdbHPLMNData, namedBitErr_ := normalizeNamedBits(*v.OdbHPLMNData, []ber.NamedBitSizeSet{{{Min: 4, Max: 4}}}, opts, "odb-HPLMN-Data", s990e88_18)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_OdbHPLMNData.Bytes, namedBits_OdbHPLMNData.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "odb-HPLMN-Data", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:757
		if namedBits_OdbHPLMNData.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_OdbHPLMNData).BitLength < 4 || (namedBits_OdbHPLMNData).BitLength > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_18, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "odb-HPLMN-Data", "SIZE (4)", namedBitObservedLength(namedBits_OdbHPLMNData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_odbhplmndata, encodeErr_enc_odbhplmndata := ber.EncodeBitString(namedBits_OdbHPLMNData.Bytes, ber.UnusedBitCount(namedBits_OdbHPLMNData.BitLength))
		if encodeErr_enc_odbhplmndata != nil {
			return nil, qualifyBERError(encodeErr_enc_odbhplmndata, "odb-HPLMN-Data", "encoding", false)
		}
		children = append(children, enc_odbhplmndata...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_18, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ODBData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ODBData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ODBData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ODBData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	namedBits_OdbGeneralData, namedBitErr_ := normalizeNamedBits(v.OdbGeneralData, []ber.NamedBitSizeSet{{{Min: 6, Max: 6}}}, nil, "odb-GeneralData", s990e88_18)
	if namedBitErr_ != nil {
		return nil, namedBitErr_
	}
	if bitStringErr := ber.ValidateBitStringLength(namedBits_OdbGeneralData.Bytes, namedBits_OdbGeneralData.BitLength); bitStringErr != nil {
		return nil, qualifyBERError(bitStringErr, "odb-GeneralData", "encoding", true)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:757
	if namedBits_OdbGeneralData.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	if (namedBits_OdbGeneralData).BitLength < 6 || (namedBits_OdbGeneralData).BitLength > 6 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_18, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "odb-GeneralData", "SIZE (6)", namedBitObservedLength(namedBits_OdbGeneralData)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_odbgeneraldata, encodeErr_enc_odbgeneraldata := encodeEditionBitString(namedBits_OdbGeneralData.Bytes, namedBits_OdbGeneralData.BitLength)
	if encodeErr_enc_odbgeneraldata != nil {
		return nil, qualifyBERError(encodeErr_enc_odbgeneraldata, "odb-GeneralData", "encoding", true)
	}
	children = append(children, enc_odbgeneraldata...)
	if v.OdbHPLMNData != nil {
		namedBits_OdbHPLMNData, namedBitErr_ := normalizeNamedBits(*v.OdbHPLMNData, []ber.NamedBitSizeSet{{{Min: 4, Max: 4}}}, nil, "odb-HPLMN-Data", s990e88_18)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_OdbHPLMNData.Bytes, namedBits_OdbHPLMNData.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "odb-HPLMN-Data", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:757
		if namedBits_OdbHPLMNData.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_OdbHPLMNData).BitLength < 4 || (namedBits_OdbHPLMNData).BitLength > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_18, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "odb-HPLMN-Data", "SIZE (4)", namedBitObservedLength(namedBits_OdbHPLMNData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_odbhplmndata, encodeErr_enc_odbhplmndata := encodeEditionBitString(namedBits_OdbHPLMNData.Bytes, namedBits_OdbHPLMNData.BitLength)
		if encodeErr_enc_odbhplmndata != nil {
			return nil, qualifyBERError(encodeErr_enc_odbhplmndata, "odb-HPLMN-Data", "encoding", true)
		}
		children = append(children, enc_odbhplmndata...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_18, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ODBData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ODBData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ODBData from BER/DER format.
func (destination *ODBData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ODBData destination is nil", ber.ErrInvalidValue)
	}
	v := new(ODBData)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ODBData
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_18, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ODBData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ODBData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ODBData SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ODBData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode odb-GeneralData
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field odb-GeneralData", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "odb-GeneralData", content[offset:])
		bsBytes_odbgeneraldata, bsUnused_odbgeneraldata, n, err := ber.DecodeBitString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "odb-GeneralData", "decoding", false)
		}
		bsBitLength_odbgeneraldata, bsLenErr_odbgeneraldata := ber.BitStringBitLength(len(bsBytes_odbgeneraldata), bsUnused_odbgeneraldata)
		if bsLenErr_odbgeneraldata != nil {
			return qualifyBERError(bsLenErr_odbgeneraldata, "odb-GeneralData", "decoding", false)
		}
		v.OdbGeneralData = runtime.BitString{Bytes: bsBytes_odbgeneraldata, BitLength: bsBitLength_odbgeneraldata}
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		v.OdbGeneralData = keepEditionBitLength(v.OdbGeneralData, []ber.NamedBitSizeSet{{{Min: 6, Max: 6}}}, opts...)
		if (v.OdbGeneralData).BitLength < 6 || (v.OdbGeneralData).BitLength > 6 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_18, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "odb-GeneralData", "SIZE (6)", (v.OdbGeneralData).BitLength); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode odb-HPLMN-Data
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "odb-HPLMN-Data", content[offset:])
				bsBytes_odbhplmndata, bsUnused_odbhplmndata, n, err := ber.DecodeBitString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "odb-HPLMN-Data", "decoding", false)
				}
				bsBitLength_odbhplmndata, bsLenErr_odbhplmndata := ber.BitStringBitLength(len(bsBytes_odbhplmndata), bsUnused_odbhplmndata)
				if bsLenErr_odbhplmndata != nil {
					return qualifyBERError(bsLenErr_odbhplmndata, "odb-HPLMN-Data", "decoding", false)
				}
				tmp_odbhplmndata := runtime.BitString{Bytes: bsBytes_odbhplmndata, BitLength: bsBitLength_odbhplmndata}
				v.OdbHPLMNData = &tmp_odbhplmndata
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				*v.OdbHPLMNData = keepEditionBitLength(*v.OdbHPLMNData, []ber.NamedBitSizeSet{{{Min: 4, Max: 4}}}, opts...)
				if (*v.OdbHPLMNData).BitLength < 4 || (*v.OdbHPLMNData).BitLength > 4 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_18, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "odb-HPLMN-Data", "SIZE (4)", (*v.OdbHPLMNData).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ODBData", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ODBData", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERZoneCodeList encodes a ZoneCodeList list to BER.
func MarshalBERZoneCodeList(collection *ZoneCodeList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERZoneCodeList, marshalBERZoneCodeList, 3, UnmarshalBERZoneCodeList)

}
func marshalBERZoneCodeList(collection *ZoneCodeList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-MS-DataTypes.marshalBERZoneCodeList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ZoneCodeList", "SIZE (1..10)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 2 || len(elem) > 2 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-MS-DataTypes.marshalBERZoneCodeList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", elemIndex), "SIZE (2)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearZoneCodeList(encoder *ber.LinearEncoder, collection *ZoneCodeList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERZoneCodeList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERZoneCodeList encodes a ZoneCodeList list to DER.
func MarshalDERZoneCodeList(collection *ZoneCodeList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, s990e88_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ZoneCodeList", "SIZE (1..10)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 2 || len(elem) > 2 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", elemIndex), "SIZE (2)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ZoneCodeList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearZoneCodeList(encoder *ber.LinearEncoder, collection *ZoneCodeList) ([]byte, error) {
	encoded, err := MarshalDERZoneCodeList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERZoneCodeList decodes a ZoneCodeList list from BER.
func UnmarshalBERZoneCodeList(data []byte, opts ...ber.DecodeOption) (returnValue *ZoneCodeList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERZoneCodeList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_19, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding ZoneCodeList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ZoneCodeList", Cause: ber.ErrExtraData}
	}
	var result []ZoneCode
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 2 || len(val) > 2 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", len(result)), "SIZE (2)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, ZoneCode(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 10 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, s990e88_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ZoneCodeList", "SIZE (1..10)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &ZoneCodeList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERZoneCodeList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes InsertSubscriberDataRes to BER format.
func (v *InsertSubscriberDataRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: InsertSubscriberDataRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*InsertSubscriberDataRes).MarshalBER, (*InsertSubscriberDataRes).marshalBER, 3)

}
func (v *InsertSubscriberDataRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.TeleserviceList != nil {
		if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicelist, err := MarshalBERTeleserviceList(v.TeleserviceList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "teleserviceList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "teleserviceList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berTeleserviceListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_teleservicelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_teleservicelist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "teleserviceList", "encoding", false)
				}
			}
		} else {
			retagged_enc_teleservicelist, tagErr_enc_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_teleservicelist)
			if tagErr_enc_teleservicelist != nil {
				return nil, qualifyBERError(tagErr_enc_teleservicelist, "teleserviceList", "encoding", false)
			}
			enc_teleservicelist = retagged_enc_teleservicelist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_teleservicelist)
		children = append(children, enc_teleservicelist...)
	}
	if v.BearerServiceList != nil {
		if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservicelist, err := MarshalBERBearerServiceList(v.BearerServiceList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "bearerServiceList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "bearerServiceList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berBearerServiceListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_bearerservicelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_bearerservicelist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "bearerServiceList", "encoding", false)
				}
			}
		} else {
			retagged_enc_bearerservicelist, tagErr_enc_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_bearerservicelist)
			if tagErr_enc_bearerservicelist != nil {
				return nil, qualifyBERError(tagErr_enc_bearerservicelist, "bearerServiceList", "encoding", false)
			}
			enc_bearerservicelist = retagged_enc_bearerservicelist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_bearerservicelist)
		children = append(children, enc_bearerservicelist...)
	}
	if v.SsList != nil {
		if len((v.SsList).Values) < 1 || len((v.SsList).Values) > 30 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-List", "SIZE (1..30)", len((v.SsList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sslist, err := MarshalBERSSList(v.SsList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "ss-List"))...)
		if err != nil {
			return nil, qualifyBERError(err, "ss-List", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berSsListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_sslist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_sslist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "ss-List", "encoding", false)
				}
			}
		} else {
			retagged_enc_sslist, tagErr_enc_sslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_sslist)
			if tagErr_enc_sslist != nil {
				return nil, qualifyBERError(tagErr_enc_sslist, "ss-List", "encoding", false)
			}
			enc_sslist = retagged_enc_sslist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_sslist)
		children = append(children, enc_sslist...)
	}
	if v.OdbGeneralData != nil {
		namedBits_OdbGeneralData, namedBitErr_ := normalizeNamedBits(*v.OdbGeneralData, []ber.NamedBitSizeSet{{{Min: 6, Max: 6}}}, opts, "odb-GeneralData", s990e88_20)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_OdbGeneralData.Bytes, namedBits_OdbGeneralData.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "odb-GeneralData", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:757
		if namedBits_OdbGeneralData.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_OdbGeneralData).BitLength < 6 || (namedBits_OdbGeneralData).BitLength > 6 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "odb-GeneralData", "SIZE (6)", namedBitObservedLength(namedBits_OdbGeneralData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_odbgeneraldata, encodeErr_enc_odbgeneraldata := ber.EncodeBitString(namedBits_OdbGeneralData.Bytes, ber.UnusedBitCount(namedBits_OdbGeneralData.BitLength))
		if encodeErr_enc_odbgeneraldata != nil {
			return nil, qualifyBERError(encodeErr_enc_odbgeneraldata, "odb-GeneralData", "encoding", false)
		}
		retagged_enc_odbgeneraldata, tagErr_enc_odbgeneraldata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_odbgeneraldata)
		if tagErr_enc_odbgeneraldata != nil {
			return nil, qualifyBERError(tagErr_enc_odbgeneraldata, "odb-GeneralData", "encoding", false)
		}
		enc_odbgeneraldata = retagged_enc_odbgeneraldata
		children = append(children, enc_odbgeneraldata...)
	}
	if v.RegionalSubscriptionResponse != nil {
		if int64(*v.RegionalSubscriptionResponse) != 0 && int64(*v.RegionalSubscriptionResponse) != 1 && int64(*v.RegionalSubscriptionResponse) != 2 && int64(*v.RegionalSubscriptionResponse) != 3 {
			if constraintErr := checkEncodedValue(opts, s990e88_20, "20", "regionalSubscriptionResponse", "ENUMERATED {0, 1, 2, 3}", ber.ObserveInteger(int64(*v.RegionalSubscriptionResponse))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_regionalsubscriptionresponse := ber.EncodeEnumerated(int64(*v.RegionalSubscriptionResponse))
		retagged_enc_regionalsubscriptionresponse, tagErr_enc_regionalsubscriptionresponse := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_regionalsubscriptionresponse)
		if tagErr_enc_regionalsubscriptionresponse != nil {
			return nil, qualifyBERError(tagErr_enc_regionalsubscriptionresponse, "regionalSubscriptionResponse", "encoding", false)
		}
		enc_regionalsubscriptionresponse = retagged_enc_regionalsubscriptionresponse
		children = append(children, enc_regionalsubscriptionresponse...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_20, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *InsertSubscriberDataRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes InsertSubscriberDataRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *InsertSubscriberDataRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InsertSubscriberDataRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.TeleserviceList != nil {
		if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicelist, err := MarshalDERTeleserviceList(v.TeleserviceList)
		if err != nil {
			return nil, qualifyBERError(err, "teleserviceList", "encoding", true)
		}
		retagged_enc_teleservicelist, tagErr_enc_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_teleservicelist)
		if tagErr_enc_teleservicelist != nil {
			return nil, qualifyBERError(tagErr_enc_teleservicelist, "teleserviceList", "encoding", true)
		}
		enc_teleservicelist = retagged_enc_teleservicelist
		children = append(children, enc_teleservicelist...)
	}
	if v.BearerServiceList != nil {
		if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservicelist, err := MarshalDERBearerServiceList(v.BearerServiceList)
		if err != nil {
			return nil, qualifyBERError(err, "bearerServiceList", "encoding", true)
		}
		retagged_enc_bearerservicelist, tagErr_enc_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_bearerservicelist)
		if tagErr_enc_bearerservicelist != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservicelist, "bearerServiceList", "encoding", true)
		}
		enc_bearerservicelist = retagged_enc_bearerservicelist
		children = append(children, enc_bearerservicelist...)
	}
	if v.SsList != nil {
		if len((v.SsList).Values) < 1 || len((v.SsList).Values) > 30 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-List", "SIZE (1..30)", len((v.SsList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sslist, err := MarshalDERSSList(v.SsList)
		if err != nil {
			return nil, qualifyBERError(err, "ss-List", "encoding", true)
		}
		retagged_enc_sslist, tagErr_enc_sslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_sslist)
		if tagErr_enc_sslist != nil {
			return nil, qualifyBERError(tagErr_enc_sslist, "ss-List", "encoding", true)
		}
		enc_sslist = retagged_enc_sslist
		children = append(children, enc_sslist...)
	}
	if v.OdbGeneralData != nil {
		namedBits_OdbGeneralData, namedBitErr_ := normalizeNamedBits(*v.OdbGeneralData, []ber.NamedBitSizeSet{{{Min: 6, Max: 6}}}, nil, "odb-GeneralData", s990e88_20)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_OdbGeneralData.Bytes, namedBits_OdbGeneralData.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "odb-GeneralData", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:757
		if namedBits_OdbGeneralData.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_OdbGeneralData).BitLength < 6 || (namedBits_OdbGeneralData).BitLength > 6 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "odb-GeneralData", "SIZE (6)", namedBitObservedLength(namedBits_OdbGeneralData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_odbgeneraldata, encodeErr_enc_odbgeneraldata := encodeEditionBitString(namedBits_OdbGeneralData.Bytes, namedBits_OdbGeneralData.BitLength)
		if encodeErr_enc_odbgeneraldata != nil {
			return nil, qualifyBERError(encodeErr_enc_odbgeneraldata, "odb-GeneralData", "encoding", true)
		}
		retagged_enc_odbgeneraldata, tagErr_enc_odbgeneraldata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_odbgeneraldata)
		if tagErr_enc_odbgeneraldata != nil {
			return nil, qualifyBERError(tagErr_enc_odbgeneraldata, "odb-GeneralData", "encoding", true)
		}
		enc_odbgeneraldata = retagged_enc_odbgeneraldata
		children = append(children, enc_odbgeneraldata...)
	}
	if v.RegionalSubscriptionResponse != nil {
		if int64(*v.RegionalSubscriptionResponse) != 0 && int64(*v.RegionalSubscriptionResponse) != 1 && int64(*v.RegionalSubscriptionResponse) != 2 && int64(*v.RegionalSubscriptionResponse) != 3 {
			if constraintErr := checkEncodedValue(nil, s990e88_20, "20", "regionalSubscriptionResponse", "ENUMERATED {0, 1, 2, 3}", ber.ObserveInteger(int64(*v.RegionalSubscriptionResponse))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_regionalsubscriptionresponse := ber.EncodeEnumerated(int64(*v.RegionalSubscriptionResponse))
		retagged_enc_regionalsubscriptionresponse, tagErr_enc_regionalsubscriptionresponse := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_regionalsubscriptionresponse)
		if tagErr_enc_regionalsubscriptionresponse != nil {
			return nil, qualifyBERError(tagErr_enc_regionalsubscriptionresponse, "regionalSubscriptionResponse", "encoding", true)
		}
		enc_regionalsubscriptionresponse = retagged_enc_regionalsubscriptionresponse
		children = append(children, enc_regionalsubscriptionresponse...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_20, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding InsertSubscriberDataRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *InsertSubscriberDataRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes InsertSubscriberDataRes from BER/DER format.
func (destination *InsertSubscriberDataRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: InsertSubscriberDataRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(InsertSubscriberDataRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe InsertSubscriberDataRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_20, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = InsertSubscriberDataRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*InsertSubscriberDataRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding InsertSubscriberDataRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InsertSubscriberDataRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode teleserviceList
	v.berTeleserviceListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "teleserviceList", content[offset:])
				decodedTag_teleservicelist, n_teleservicelist, rawVal_teleservicelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "teleserviceList", "decoding", false)
				}
				if decodedTag_teleservicelist.Class != tag.ClassContextSpecific || decodedTag_teleservicelist.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_teleservicelist), "teleserviceList", "decoding", false)
				}
				if decodedTag_teleservicelist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_teleservicelist), "teleserviceList", "decoding", false)
				}
				_ = rawVal_teleservicelist
				if offset > len(content) || n_teleservicelist < 0 || n_teleservicelist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_teleservicelist, reconstructionErr_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_teleservicelist])
				if reconstructionErr_teleservicelist != nil {
					return qualifyBERError(reconstructionErr_teleservicelist, "teleserviceList", "decoding", false)
				}
				dec_teleservicelist, unmErr := UnmarshalBERTeleserviceList(reconstructed_teleservicelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "teleserviceList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "teleserviceList", "decoding", false)
				}
				v.TeleserviceList = dec_teleservicelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset > len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berTeleserviceListIndef_ = true
					}
				}
				if offset > len(content) || n_teleservicelist < 0 || n_teleservicelist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_teleservicelist
				if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode bearerServiceList
	v.berBearerServiceListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "bearerServiceList", content[offset:])
				decodedTag_bearerservicelist, n_bearerservicelist, rawVal_bearerservicelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bearerServiceList", "decoding", false)
				}
				if decodedTag_bearerservicelist.Class != tag.ClassContextSpecific || decodedTag_bearerservicelist.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_bearerservicelist), "bearerServiceList", "decoding", false)
				}
				if decodedTag_bearerservicelist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_bearerservicelist), "bearerServiceList", "decoding", false)
				}
				_ = rawVal_bearerservicelist
				if offset < 0 || offset >
					len(content) || n_bearerservicelist < 0 || n_bearerservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_bearerservicelist, reconstructionErr_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_bearerservicelist])
				if reconstructionErr_bearerservicelist != nil {
					return qualifyBERError(reconstructionErr_bearerservicelist, "bearerServiceList", "decoding", false)
				}
				dec_bearerservicelist, unmErr := UnmarshalBERBearerServiceList(reconstructed_bearerservicelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "bearerServiceList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "bearerServiceList", "decoding", false)
				}
				v.BearerServiceList = dec_bearerservicelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berBearerServiceListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_bearerservicelist < 0 || n_bearerservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bearerservicelist
				if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ss-List
	v.berSsListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "ss-List", content[offset:])
				decodedTag_sslist, n_sslist, rawVal_sslist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-List", "decoding", false)
				}
				if decodedTag_sslist.Class != tag.ClassContextSpecific || decodedTag_sslist.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_sslist), "ss-List", "decoding", false)
				}
				if decodedTag_sslist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_sslist), "ss-List", "decoding", false)
				}
				_ = rawVal_sslist
				if offset < 0 || offset >
					len(content) || n_sslist < 0 || n_sslist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_sslist, reconstructionErr_sslist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_sslist])
				if reconstructionErr_sslist != nil {
					return qualifyBERError(reconstructionErr_sslist, "ss-List", "decoding", false)
				}
				dec_sslist, unmErr := UnmarshalBERSSList(reconstructed_sslist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "ss-List"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "ss-List", "decoding", false)
				}
				v.SsList = dec_sslist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berSsListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_sslist < 0 || n_sslist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sslist
				if len((v.SsList).Values) < 1 || len((v.SsList).Values) > 30 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-List", "SIZE (1..30)", len((v.SsList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode odb-GeneralData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "odb-GeneralData", content[offset:])
				decodedTag_odbgeneraldata, n_odbgeneraldata, rawVal_odbgeneraldata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "odb-GeneralData", "decoding", false)
				}
				if decodedTag_odbgeneraldata.Class != tag.ClassContextSpecific || decodedTag_odbgeneraldata.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_odbgeneraldata), "odb-GeneralData", "decoding", false)
				}
				bsBytes_odbgeneraldata, bsUnused_odbgeneraldata, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_odbgeneraldata.Constructed, rawVal_odbgeneraldata, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "odb-GeneralData", "decoding", false)
				}
				bsBitLength_odbgeneraldata, bsLenErr_odbgeneraldata := ber.BitStringBitLength(len(bsBytes_odbgeneraldata), bsUnused_odbgeneraldata)
				if bsLenErr_odbgeneraldata != nil {
					return qualifyBERError(bsLenErr_odbgeneraldata, "odb-GeneralData", "decoding", false)
				}
				tmp_odbgeneraldata := runtime.BitString{Bytes: bsBytes_odbgeneraldata, BitLength: bsBitLength_odbgeneraldata}
				v.OdbGeneralData = &tmp_odbgeneraldata
				if offset < 0 || offset >
					len(content) || n_odbgeneraldata < 0 || n_odbgeneraldata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_odbgeneraldata
				*v.OdbGeneralData = keepEditionBitLength(*v.OdbGeneralData, []ber.NamedBitSizeSet{{{Min: 6, Max: 6}}}, opts...)
				if (*v.OdbGeneralData).BitLength < 6 || (*v.OdbGeneralData).BitLength > 6 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_20, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "odb-GeneralData", "SIZE (6)", (*v.OdbGeneralData).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode regionalSubscriptionResponse
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "regionalSubscriptionResponse", content[offset:])
				decodedTag_regionalsubscriptionresponse, n_regionalsubscriptionresponse, rawVal_regionalsubscriptionresponse, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "regionalSubscriptionResponse", "decoding", false)
				}
				if decodedTag_regionalsubscriptionresponse.Class != tag.ClassContextSpecific || decodedTag_regionalsubscriptionresponse.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_regionalsubscriptionresponse), "regionalSubscriptionResponse", "decoding", false)
				}
				if decodedTag_regionalsubscriptionresponse.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_regionalsubscriptionresponse), "regionalSubscriptionResponse", "decoding", false)
				}
				decVal_regionalsubscriptionresponse, intErr := ber.DecodeEnumeratedValue(rawVal_regionalsubscriptionresponse)
				if intErr != nil {
					return qualifyBERError(intErr, "regionalSubscriptionResponse", "decoding", false)
				}
				tmp_regionalsubscriptionresponse := RegionalSubscriptionResponse(decVal_regionalsubscriptionresponse)
				v.RegionalSubscriptionResponse = &tmp_regionalsubscriptionresponse
				if offset < 0 || offset >
					len(content) || n_regionalsubscriptionresponse < 0 || n_regionalsubscriptionresponse >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_regionalsubscriptionresponse
				if int64(*v.RegionalSubscriptionResponse) != 0 && int64(*v.RegionalSubscriptionResponse) != 1 && int64(*v.RegionalSubscriptionResponse) != 2 && int64(*v.RegionalSubscriptionResponse) != 3 {
					if constraintErr := checkDecodedValue(opts, s990e88_20, "20", "regionalSubscriptionResponse", "ENUMERATED {0, 1, 2, 3}", ber.ObserveInteger(int64(*v.RegionalSubscriptionResponse))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "InsertSubscriberDataRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "InsertSubscriberDataRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeleteSubscriberDataArg to BER format.
func (v *DeleteSubscriberDataArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: DeleteSubscriberDataArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*DeleteSubscriberDataArg).MarshalBER, (*DeleteSubscriberDataArg).marshalBER, 3)

}
func (v *DeleteSubscriberDataArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if v.BasicServiceList != nil {
		if len((v.BasicServiceList).Values) < 1 || len((v.BasicServiceList).Values) > 70 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceList", "SIZE (1..70)", len((v.BasicServiceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservicelist, err := MarshalBERBasicServiceList(v.BasicServiceList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "basicServiceList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berBasicServiceListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_basicservicelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_basicservicelist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "basicServiceList", "encoding", false)
				}
			}
		} else {
			retagged_enc_basicservicelist, tagErr_enc_basicservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_basicservicelist)
			if tagErr_enc_basicservicelist != nil {
				return nil, qualifyBERError(tagErr_enc_basicservicelist, "basicServiceList", "encoding", false)
			}
			enc_basicservicelist = retagged_enc_basicservicelist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservicelist)
		children = append(children, enc_basicservicelist...)
	}
	if v.SsList != nil {
		if len((v.SsList).Values) < 1 || len((v.SsList).Values) > 30 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-List", "SIZE (1..30)", len((v.SsList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sslist, err := MarshalBERSSList(v.SsList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "ss-List"))...)
		if err != nil {
			return nil, qualifyBERError(err, "ss-List", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berSsListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_sslist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_sslist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "ss-List", "encoding", false)
				}
			}
		} else {
			retagged_enc_sslist, tagErr_enc_sslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sslist)
			if tagErr_enc_sslist != nil {
				return nil, qualifyBERError(tagErr_enc_sslist, "ss-List", "encoding", false)
			}
			enc_sslist = retagged_enc_sslist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_sslist)
		children = append(children, enc_sslist...)
	}
	if v.RoamingRestrictionDueToUnsupportedFeature != nil {
		enc_roamingrestrictionduetounsupportedfeature := ber.EncodeNull()
		retagged_enc_roamingrestrictionduetounsupportedfeature, tagErr_enc_roamingrestrictionduetounsupportedfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_roamingrestrictionduetounsupportedfeature)
		if tagErr_enc_roamingrestrictionduetounsupportedfeature != nil {
			return nil, qualifyBERError(tagErr_enc_roamingrestrictionduetounsupportedfeature, "roamingRestrictionDueToUnsupportedFeature", "encoding", false)
		}
		enc_roamingrestrictionduetounsupportedfeature = retagged_enc_roamingrestrictionduetounsupportedfeature
		children = append(children, enc_roamingrestrictionduetounsupportedfeature...)
	}
	if v.RegionalSubscriptionIdentifier != nil {
		if len(*v.RegionalSubscriptionIdentifier) < 2 || len(*v.RegionalSubscriptionIdentifier) > 2 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "regionalSubscriptionIdentifier", "SIZE (2)", len(*v.RegionalSubscriptionIdentifier)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_regionalsubscriptionidentifier, encodeErr_enc_regionalsubscriptionidentifier := ber.EncodeOctetString([]byte(*v.RegionalSubscriptionIdentifier))
		if encodeErr_enc_regionalsubscriptionidentifier != nil {
			return nil, qualifyBERError(encodeErr_enc_regionalsubscriptionidentifier, "regionalSubscriptionIdentifier", "encoding", false)
		}
		retagged_enc_regionalsubscriptionidentifier, tagErr_enc_regionalsubscriptionidentifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_regionalsubscriptionidentifier)
		if tagErr_enc_regionalsubscriptionidentifier != nil {
			return nil, qualifyBERError(tagErr_enc_regionalsubscriptionidentifier, "regionalSubscriptionIdentifier", "encoding", false)
		}
		enc_regionalsubscriptionidentifier = retagged_enc_regionalsubscriptionidentifier
		children = append(children, enc_regionalsubscriptionidentifier...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_21, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_21, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *DeleteSubscriberDataArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes DeleteSubscriberDataArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *DeleteSubscriberDataArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DeleteSubscriberDataArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if v.BasicServiceList != nil {
		if len((v.BasicServiceList).Values) < 1 || len((v.BasicServiceList).Values) > 70 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceList", "SIZE (1..70)", len((v.BasicServiceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservicelist, err := MarshalDERBasicServiceList(v.BasicServiceList)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceList", "encoding", true)
		}
		retagged_enc_basicservicelist, tagErr_enc_basicservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_basicservicelist)
		if tagErr_enc_basicservicelist != nil {
			return nil, qualifyBERError(tagErr_enc_basicservicelist, "basicServiceList", "encoding", true)
		}
		enc_basicservicelist = retagged_enc_basicservicelist
		children = append(children, enc_basicservicelist...)
	}
	if v.SsList != nil {
		if len((v.SsList).Values) < 1 || len((v.SsList).Values) > 30 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-List", "SIZE (1..30)", len((v.SsList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sslist, err := MarshalDERSSList(v.SsList)
		if err != nil {
			return nil, qualifyBERError(err, "ss-List", "encoding", true)
		}
		retagged_enc_sslist, tagErr_enc_sslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sslist)
		if tagErr_enc_sslist != nil {
			return nil, qualifyBERError(tagErr_enc_sslist, "ss-List", "encoding", true)
		}
		enc_sslist = retagged_enc_sslist
		children = append(children, enc_sslist...)
	}
	if v.RoamingRestrictionDueToUnsupportedFeature != nil {
		enc_roamingrestrictionduetounsupportedfeature := ber.EncodeNull()
		retagged_enc_roamingrestrictionduetounsupportedfeature, tagErr_enc_roamingrestrictionduetounsupportedfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_roamingrestrictionduetounsupportedfeature)
		if tagErr_enc_roamingrestrictionduetounsupportedfeature != nil {
			return nil, qualifyBERError(tagErr_enc_roamingrestrictionduetounsupportedfeature, "roamingRestrictionDueToUnsupportedFeature", "encoding", true)
		}
		enc_roamingrestrictionduetounsupportedfeature = retagged_enc_roamingrestrictionduetounsupportedfeature
		children = append(children, enc_roamingrestrictionduetounsupportedfeature...)
	}
	if v.RegionalSubscriptionIdentifier != nil {
		if len(*v.RegionalSubscriptionIdentifier) < 2 || len(*v.RegionalSubscriptionIdentifier) > 2 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "regionalSubscriptionIdentifier", "SIZE (2)", len(*v.RegionalSubscriptionIdentifier)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_regionalsubscriptionidentifier, encodeErr_enc_regionalsubscriptionidentifier := ber.EncodeOctetString([]byte(*v.RegionalSubscriptionIdentifier))
		if encodeErr_enc_regionalsubscriptionidentifier != nil {
			return nil, qualifyBERError(encodeErr_enc_regionalsubscriptionidentifier, "regionalSubscriptionIdentifier", "encoding", true)
		}
		retagged_enc_regionalsubscriptionidentifier, tagErr_enc_regionalsubscriptionidentifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_regionalsubscriptionidentifier)
		if tagErr_enc_regionalsubscriptionidentifier != nil {
			return nil, qualifyBERError(tagErr_enc_regionalsubscriptionidentifier, "regionalSubscriptionIdentifier", "encoding", true)
		}
		enc_regionalsubscriptionidentifier = retagged_enc_regionalsubscriptionidentifier
		children = append(children, enc_regionalsubscriptionidentifier...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_21, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_21, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding DeleteSubscriberDataArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *DeleteSubscriberDataArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes DeleteSubscriberDataArg from BER/DER format.
func (destination *DeleteSubscriberDataArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: DeleteSubscriberDataArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(DeleteSubscriberDataArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe DeleteSubscriberDataArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_21, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = DeleteSubscriberDataArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*DeleteSubscriberDataArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding DeleteSubscriberDataArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeleteSubscriberDataArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field imsi", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("%w: expected tag [%s %d] for imsi, got %s", ber.ErrUnexpectedElement, "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "imsi", content[offset:])
		decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "imsi", "decoding", false)
		}
		if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_imsi), "imsi", "decoding", false)
		}
		decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "imsi", "decoding", false)
		}
		v.Imsi = IMSI(decVal_imsi)
		if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_imsi
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode basicServiceList
	v.berBasicServiceListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "basicServiceList", content[offset:])
				decodedTag_basicservicelist, n_basicservicelist, rawVal_basicservicelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "basicServiceList", "decoding", false)
				}
				if decodedTag_basicservicelist.Class != tag.ClassContextSpecific || decodedTag_basicservicelist.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_basicservicelist), "basicServiceList", "decoding", false)
				}
				if decodedTag_basicservicelist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_basicservicelist), "basicServiceList", "decoding", false)
				}
				_ = rawVal_basicservicelist
				if offset < 0 || offset >
					len(content) || n_basicservicelist < 0 || n_basicservicelist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_basicservicelist, reconstructionErr_basicservicelist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_basicservicelist])
				if reconstructionErr_basicservicelist != nil {
					return qualifyBERError(reconstructionErr_basicservicelist, "basicServiceList", "decoding", false)
				}
				dec_basicservicelist, unmErr := UnmarshalBERBasicServiceList(reconstructed_basicservicelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "basicServiceList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "basicServiceList", "decoding", false)
				}
				v.BasicServiceList = dec_basicservicelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berBasicServiceListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_basicservicelist < 0 || n_basicservicelist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservicelist
				if len((v.BasicServiceList).Values) < 1 || len((v.BasicServiceList).Values) > 70 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceList", "SIZE (1..70)", len((v.BasicServiceList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ss-List
	v.berSsListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "ss-List", content[offset:])
				decodedTag_sslist, n_sslist, rawVal_sslist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-List", "decoding", false)
				}
				if decodedTag_sslist.Class != tag.ClassContextSpecific || decodedTag_sslist.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_sslist), "ss-List", "decoding", false)
				}
				if decodedTag_sslist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_sslist), "ss-List", "decoding", false)
				}
				_ = rawVal_sslist
				if offset < 0 || offset >
					len(content) || n_sslist < 0 || n_sslist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_sslist, reconstructionErr_sslist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_sslist])
				if reconstructionErr_sslist != nil {
					return qualifyBERError(reconstructionErr_sslist, "ss-List", "decoding", false)
				}
				dec_sslist, unmErr := UnmarshalBERSSList(reconstructed_sslist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "ss-List"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "ss-List", "decoding", false)
				}
				v.SsList = dec_sslist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berSsListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_sslist < 0 || n_sslist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sslist
				if len((v.SsList).Values) < 1 || len((v.SsList).Values) > 30 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-List", "SIZE (1..30)", len((v.SsList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode roamingRestrictionDueToUnsupportedFeature
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "roamingRestrictionDueToUnsupportedFeature", content[offset:])
				decodedTag_roamingrestrictionduetounsupportedfeature, n_roamingrestrictionduetounsupportedfeature, rawVal_roamingrestrictionduetounsupportedfeature, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				if decodedTag_roamingrestrictionduetounsupportedfeature.Class != tag.ClassContextSpecific || decodedTag_roamingrestrictionduetounsupportedfeature.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_roamingrestrictionduetounsupportedfeature), "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				if decodedTag_roamingrestrictionduetounsupportedfeature.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_roamingrestrictionduetounsupportedfeature), "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				if len(rawVal_roamingrestrictionduetounsupportedfeature) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_roamingrestrictionduetounsupportedfeature)), "roamingRestrictionDueToUnsupportedFeature", "decoding", false)
				}
				v.RoamingRestrictionDueToUnsupportedFeature = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_roamingrestrictionduetounsupportedfeature < 0 ||
					n_roamingrestrictionduetounsupportedfeature > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_roamingrestrictionduetounsupportedfeature
			}
		}
	}
	// Decode regionalSubscriptionIdentifier
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "regionalSubscriptionIdentifier", content[offset:])
				decodedTag_regionalsubscriptionidentifier, n_regionalsubscriptionidentifier, rawVal_regionalsubscriptionidentifier, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "regionalSubscriptionIdentifier", "decoding", false)
				}
				if decodedTag_regionalsubscriptionidentifier.Class != tag.ClassContextSpecific || decodedTag_regionalsubscriptionidentifier.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_regionalsubscriptionidentifier), "regionalSubscriptionIdentifier", "decoding", false)
				}
				decVal_regionalsubscriptionidentifier, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_regionalsubscriptionidentifier.Constructed, rawVal_regionalsubscriptionidentifier, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "regionalSubscriptionIdentifier", "decoding", false)
				}
				tmp_regionalsubscriptionidentifier := ZoneCode(decVal_regionalsubscriptionidentifier)
				v.RegionalSubscriptionIdentifier = &tmp_regionalsubscriptionidentifier
				if offset < 0 || offset >
					len(content) || n_regionalsubscriptionidentifier < 0 || n_regionalsubscriptionidentifier >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_regionalsubscriptionidentifier
				if len(*v.RegionalSubscriptionIdentifier) < 2 || len(*v.RegionalSubscriptionIdentifier) > 2 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_21, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "regionalSubscriptionIdentifier", "SIZE (2)", len(*v.RegionalSubscriptionIdentifier)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeleteSubscriberDataArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "DeleteSubscriberDataArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_21, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeleteSubscriberDataRes to BER format.
func (v *DeleteSubscriberDataRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: DeleteSubscriberDataRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*DeleteSubscriberDataRes).MarshalBER, (*DeleteSubscriberDataRes).marshalBER, 3)

}
func (v *DeleteSubscriberDataRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.RegionalSubscriptionResponse != nil {
		if int64(*v.RegionalSubscriptionResponse) != 0 && int64(*v.RegionalSubscriptionResponse) != 1 && int64(*v.RegionalSubscriptionResponse) != 2 && int64(*v.RegionalSubscriptionResponse) != 3 {
			if constraintErr := checkEncodedValue(opts, s990e88_22, "20", "regionalSubscriptionResponse", "ENUMERATED {0, 1, 2, 3}", ber.ObserveInteger(int64(*v.RegionalSubscriptionResponse))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_regionalsubscriptionresponse := ber.EncodeEnumerated(int64(*v.RegionalSubscriptionResponse))
		retagged_enc_regionalsubscriptionresponse, tagErr_enc_regionalsubscriptionresponse := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_regionalsubscriptionresponse)
		if tagErr_enc_regionalsubscriptionresponse != nil {
			return nil, qualifyBERError(tagErr_enc_regionalsubscriptionresponse, "regionalSubscriptionResponse", "encoding", false)
		}
		enc_regionalsubscriptionresponse = retagged_enc_regionalsubscriptionresponse
		children = append(children, enc_regionalsubscriptionresponse...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_22, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_22, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *DeleteSubscriberDataRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes DeleteSubscriberDataRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *DeleteSubscriberDataRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DeleteSubscriberDataRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.RegionalSubscriptionResponse != nil {
		if int64(*v.RegionalSubscriptionResponse) != 0 && int64(*v.RegionalSubscriptionResponse) != 1 && int64(*v.RegionalSubscriptionResponse) != 2 && int64(*v.RegionalSubscriptionResponse) != 3 {
			if constraintErr := checkEncodedValue(nil, s990e88_22, "20", "regionalSubscriptionResponse", "ENUMERATED {0, 1, 2, 3}", ber.ObserveInteger(int64(*v.RegionalSubscriptionResponse))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_regionalsubscriptionresponse := ber.EncodeEnumerated(int64(*v.RegionalSubscriptionResponse))
		retagged_enc_regionalsubscriptionresponse, tagErr_enc_regionalsubscriptionresponse := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_regionalsubscriptionresponse)
		if tagErr_enc_regionalsubscriptionresponse != nil {
			return nil, qualifyBERError(tagErr_enc_regionalsubscriptionresponse, "regionalSubscriptionResponse", "encoding", true)
		}
		enc_regionalsubscriptionresponse = retagged_enc_regionalsubscriptionresponse
		children = append(children, enc_regionalsubscriptionresponse...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_22, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_22, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding DeleteSubscriberDataRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *DeleteSubscriberDataRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes DeleteSubscriberDataRes from BER/DER format.
func (destination *DeleteSubscriberDataRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: DeleteSubscriberDataRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(DeleteSubscriberDataRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe DeleteSubscriberDataRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_22, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = DeleteSubscriberDataRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*DeleteSubscriberDataRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding DeleteSubscriberDataRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeleteSubscriberDataRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode regionalSubscriptionResponse
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "regionalSubscriptionResponse", content[offset:])
				decodedTag_regionalsubscriptionresponse, n_regionalsubscriptionresponse, rawVal_regionalsubscriptionresponse, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "regionalSubscriptionResponse", "decoding", false)
				}
				if decodedTag_regionalsubscriptionresponse.Class != tag.ClassContextSpecific || decodedTag_regionalsubscriptionresponse.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_regionalsubscriptionresponse), "regionalSubscriptionResponse", "decoding", false)
				}
				if decodedTag_regionalsubscriptionresponse.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_regionalsubscriptionresponse), "regionalSubscriptionResponse", "decoding", false)
				}
				decVal_regionalsubscriptionresponse, intErr := ber.DecodeEnumeratedValue(rawVal_regionalsubscriptionresponse)
				if intErr != nil {
					return qualifyBERError(intErr, "regionalSubscriptionResponse", "decoding", false)
				}
				tmp_regionalsubscriptionresponse := RegionalSubscriptionResponse(decVal_regionalsubscriptionresponse)
				v.RegionalSubscriptionResponse = &tmp_regionalsubscriptionresponse
				if offset > len(content) || n_regionalsubscriptionresponse < 0 || n_regionalsubscriptionresponse >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_regionalsubscriptionresponse
				if int64(*v.RegionalSubscriptionResponse) != 0 && int64(*v.RegionalSubscriptionResponse) != 1 && int64(*v.RegionalSubscriptionResponse) != 2 && int64(*v.RegionalSubscriptionResponse) != 3 {
					if constraintErr := checkDecodedValue(opts, s990e88_22, "20", "regionalSubscriptionResponse", "ENUMERATED {0, 1, 2, 3}", ber.ObserveInteger(int64(*v.RegionalSubscriptionResponse))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeleteSubscriberDataRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "DeleteSubscriberDataRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_22, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ResetArg to BER format.
func (v *ResetArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ResetArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ResetArg).MarshalBER, (*ResetArg).marshalBER, 3)

}
func (v *ResetArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.NetworkResource != nil {
		if int64(*v.NetworkResource) != 0 && int64(*v.NetworkResource) != 1 && int64(*v.NetworkResource) != 2 && int64(*v.NetworkResource) != 3 && int64(*v.NetworkResource) != 4 && int64(*v.NetworkResource) != 5 && int64(*v.NetworkResource) != 6 && int64(*v.NetworkResource) != 7 {
			if constraintErr := checkEncodedValue(opts, s990e88_23, "20", "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", ber.ObserveInteger(int64(*v.NetworkResource))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_networkresource := ber.EncodeEnumerated(int64(*v.NetworkResource))
		children = append(children, enc_networkresource...)
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_23, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_23, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_hlrnumber, encodeErr_enc_hlrnumber := ber.EncodeOctetString([]byte(v.HlrNumber))
	if encodeErr_enc_hlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_hlrnumber, "hlr-Number", "encoding", false)
	}
	children = append(children, enc_hlrnumber...)
	if v.HlrList != nil {
		if len((v.HlrList).Values) < 1 || len((v.HlrList).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_23, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-List", "SIZE (1..50)", len((v.HlrList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hlrlist, err := MarshalBERHLRList(v.HlrList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "hlr-List"))...)
		if err != nil {
			return nil, qualifyBERError(err, "hlr-List", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_hlrlist)
		children = append(children, enc_hlrlist...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_23, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_23, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ResetArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ResetArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ResetArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ResetArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.NetworkResource != nil {
		if int64(*v.NetworkResource) != 0 && int64(*v.NetworkResource) != 1 && int64(*v.NetworkResource) != 2 && int64(*v.NetworkResource) != 3 && int64(*v.NetworkResource) != 4 && int64(*v.NetworkResource) != 5 && int64(*v.NetworkResource) != 6 && int64(*v.NetworkResource) != 7 {
			if constraintErr := checkEncodedValue(nil, s990e88_23, "20", "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", ber.ObserveInteger(int64(*v.NetworkResource))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_networkresource := ber.EncodeEnumerated(int64(*v.NetworkResource))
		children = append(children, enc_networkresource...)
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_23, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_23, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_hlrnumber, encodeErr_enc_hlrnumber := ber.EncodeOctetString([]byte(v.HlrNumber))
	if encodeErr_enc_hlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_hlrnumber, "hlr-Number", "encoding", true)
	}
	children = append(children, enc_hlrnumber...)
	if v.HlrList != nil {
		if len((v.HlrList).Values) < 1 || len((v.HlrList).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_23, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-List", "SIZE (1..50)", len((v.HlrList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hlrlist, err := MarshalDERHLRList(v.HlrList)
		if err != nil {
			return nil, qualifyBERError(err, "hlr-List", "encoding", true)
		}
		children = append(children, enc_hlrlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_23, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_23, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ResetArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ResetArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ResetArg from BER/DER format.
func (destination *ResetArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ResetArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ResetArg)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ResetArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_23, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ResetArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ResetArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ResetArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ResetArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode networkResource
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "networkResource", content[offset:])
				val_networkresource, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "networkResource", "decoding", false)
				}
				tmp_networkresource := NetworkResource(val_networkresource)
				v.NetworkResource = &tmp_networkresource
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if int64(*v.NetworkResource) != 0 && int64(*v.NetworkResource) != 1 && int64(*v.NetworkResource) != 2 && int64(*v.NetworkResource) != 3 && int64(*v.NetworkResource) != 4 && int64(*v.NetworkResource) != 5 && int64(*v.NetworkResource) != 6 && int64(*v.NetworkResource) != 7 {
					if constraintErr := checkDecodedValue(opts, s990e88_23, "20", "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", ber.ObserveInteger(int64(*v.NetworkResource))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode hlr-Number
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field hlr-Number", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "hlr-Number", content[offset:])
		val_hlrnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "hlr-Number", "decoding", false)
		}
		v.HlrNumber = ISDNAddressString(val_hlrnumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_23, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_23, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode hlr-List
	v.berHlrListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "hlr-List", content[offset:])
				// Decode nested SEQUENCE_OF (HLRList)
				_, n_hlrlist, _, tlvErr_hlrlist := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_hlrlist != nil {
					return qualifyBERError(tlvErr_hlrlist, "hlr-List", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_hlrlist < 0 || n_hlrlist > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_hlrlist := content[offset : offset+n_hlrlist]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_hlrlist)
					if tagSz_ < len(tlv_hlrlist) && tlv_hlrlist[tagSz_] == 0x80 {
						v.berHlrListIndef_ = true
					}
				}
				dec_hlrlist, unmErr := UnmarshalBERHLRList(tlv_hlrlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "hlr-List"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "hlr-List", "decoding", false)
				}
				v.HlrList = dec_hlrlist
				if offset < 0 || offset >
					len(content) || n_hlrlist < 0 || n_hlrlist > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hlrlist
				if len((v.HlrList).Values) < 1 || len((v.HlrList).Values) > 50 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_23, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-List", "SIZE (1..50)", len((v.HlrList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ResetArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ResetArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_23, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RestoreDataArg to BER format.
func (v *RestoreDataArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RestoreDataArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RestoreDataArg).MarshalBER, (*RestoreDataArg).marshalBER, 3)

}
func (v *RestoreDataArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_24, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_24, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", false)
		}
		children = append(children, enc_lmsi...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_24, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_24, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *RestoreDataArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes RestoreDataArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RestoreDataArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RestoreDataArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_24, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_24, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", true)
		}
		children = append(children, enc_lmsi...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_24, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_24, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RestoreDataArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *RestoreDataArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RestoreDataArg from BER/DER format.
func (destination *RestoreDataArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RestoreDataArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(RestoreDataArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe RestoreDataArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_24, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RestoreDataArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RestoreDataArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding RestoreDataArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RestoreDataArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field imsi", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "imsi", content[offset:])
		val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "imsi", "decoding", false)
		}
		v.Imsi = IMSI(val_imsi)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_24, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "lmsi", content[offset:])
				val_lmsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lmsi", "decoding", false)
				}
				tmp_lmsi := LMSI(val_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_24, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RestoreDataArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "RestoreDataArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_24, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RestoreDataRes to BER format.
func (v *RestoreDataRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RestoreDataRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RestoreDataRes).MarshalBER, (*RestoreDataRes).marshalBER, 3)

}
func (v *RestoreDataRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_25, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s990e88_25, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_hlrnumber, encodeErr_enc_hlrnumber := ber.EncodeOctetString([]byte(v.HlrNumber))
	if encodeErr_enc_hlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_hlrnumber, "hlr-Number", "encoding", false)
	}
	children = append(children, enc_hlrnumber...)
	if v.MsNotReachable != nil {
		enc_msnotreachable := ber.EncodeNull()
		children = append(children, enc_msnotreachable...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s990e88_25, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s990e88_25, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *RestoreDataRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes RestoreDataRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RestoreDataRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RestoreDataRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_25, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s990e88_25, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_hlrnumber, encodeErr_enc_hlrnumber := ber.EncodeOctetString([]byte(v.HlrNumber))
	if encodeErr_enc_hlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_hlrnumber, "hlr-Number", "encoding", true)
	}
	children = append(children, enc_hlrnumber...)
	if v.MsNotReachable != nil {
		enc_msnotreachable := ber.EncodeNull()
		children = append(children, enc_msnotreachable...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s990e88_25, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s990e88_25, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RestoreDataRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *RestoreDataRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RestoreDataRes from BER/DER format.
func (destination *RestoreDataRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RestoreDataRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(RestoreDataRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe RestoreDataRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s990e88_25, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RestoreDataRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RestoreDataRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding RestoreDataRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RestoreDataRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode hlr-Number
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field hlr-Number", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "hlr-Number", content[offset:])
		val_hlrnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "hlr-Number", "decoding", false)
		}
		v.HlrNumber = ISDNAddressString(val_hlrnumber)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_25, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s990e88_25, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode msNotReachable
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "msNotReachable", content[offset:])
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msNotReachable", "decoding", false)
				}
				v.MsNotReachable = &struct{}{}
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RestoreDataRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "RestoreDataRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s990e88_25, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

const (
	s990e88_0  = "MAP-MS-DataTypes.UpdateLocationArg"
	s990e88_1  = "MAP-MS-DataTypes.UpdateLocationRes"
	s990e88_2  = "MAP-MS-DataTypes.ExtensibleUpdateLocationRes"
	s990e88_3  = "MAP-MS-DataTypes.PurgeMS-Arg"
	s990e88_4  = "MAP-MS-DataTypes.IMSI-WithLMSI"
	s990e88_5  = "MAP-MS-DataTypes.SendIdentificationRes"
	s990e88_6  = "MAP-MS-DataTypes.AuthenticationSet"
	s990e88_7  = "MAP-MS-DataTypes.PrepareHO-Arg"
	s990e88_8  = "MAP-MS-DataTypes.PerformHO-Arg"
	s990e88_9  = "MAP-MS-DataTypes.PrepareHO-Res"
	s990e88_10 = "MAP-MS-DataTypes.PerformHO-Res"
	s990e88_11 = "MAP-MS-DataTypes.PrepareSubsequentHO-Arg"
	s990e88_12 = "MAP-MS-DataTypes.PerformSubsequentHO-Arg"
	s990e88_13 = "MAP-MS-DataTypes.SendParametersArg"
	s990e88_14 = "MAP-MS-DataTypes.RequestParameterList"
	s990e88_15 = "MAP-MS-DataTypes.SentParameter"
	s990e88_16 = "MAP-MS-DataTypes.InsertSubscriberDataArg"
	s990e88_17 = "MAP-MS-DataTypes.SubscriberData"
	s990e88_18 = "MAP-MS-DataTypes.ODB-Data"
	s990e88_19 = "MAP-MS-DataTypes.ZoneCodeList"
	s990e88_20 = "MAP-MS-DataTypes.InsertSubscriberDataRes"
	s990e88_21 = "MAP-MS-DataTypes.DeleteSubscriberDataArg"
	s990e88_22 = "MAP-MS-DataTypes.DeleteSubscriberDataRes"
	s990e88_23 = "MAP-MS-DataTypes.ResetArg"
	s990e88_24 = "MAP-MS-DataTypes.RestoreDataArg"
	s990e88_25 = "MAP-MS-DataTypes.RestoreDataRes"
)
