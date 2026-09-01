// Code generated from ASN.1 module "MAP-CommonDataTypes". DO NOT EDIT.

package gsm_map

import (
	"fmt"

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

	// CommonDataTypesMaxAddressLength is the integer constant for CommonDataTypesMaxAddressLength.
	CommonDataTypesMaxAddressLength int64 = 20

	// CommonDataTypesMaxISDNAddressLength is the integer constant for CommonDataTypesMaxISDNAddressLength.
	CommonDataTypesMaxISDNAddressLength int64 = 9

	// CommonDataTypesMaxFTNAddressLength is the integer constant for CommonDataTypesMaxFTNAddressLength.
	CommonDataTypesMaxFTNAddressLength int64 = 15

	// CommonDataTypesMaxISDNSubaddressLength is the integer constant for CommonDataTypesMaxISDNSubaddressLength.
	CommonDataTypesMaxISDNSubaddressLength int64 = 21

	// CommonDataTypesMaxSignalInfoLength is the integer constant for CommonDataTypesMaxSignalInfoLength.
	CommonDataTypesMaxSignalInfoLength int64 = 200

	// CommonDataTypesMaxLongSignalInfoLength is the integer constant for CommonDataTypesMaxLongSignalInfoLength.
	CommonDataTypesMaxLongSignalInfoLength int64 = 2560

	// CommonDataTypesAlertingLevel0 is the octet string constant for CommonDataTypesAlertingLevel0.
	CommonDataTypesAlertingLevel0 = "\x00"

	// CommonDataTypesAlertingLevel1 is the octet string constant for CommonDataTypesAlertingLevel1.
	CommonDataTypesAlertingLevel1 = "\x01"

	// CommonDataTypesAlertingLevel2 is the octet string constant for CommonDataTypesAlertingLevel2.
	CommonDataTypesAlertingLevel2 = "\x02"

	// CommonDataTypesAlertingCategory1 is the octet string constant for CommonDataTypesAlertingCategory1.
	CommonDataTypesAlertingCategory1 = "\x04"

	// CommonDataTypesAlertingCategory2 is the octet string constant for CommonDataTypesAlertingCategory2.
	CommonDataTypesAlertingCategory2 = "\x05"

	// CommonDataTypesAlertingCategory3 is the octet string constant for CommonDataTypesAlertingCategory3.
	CommonDataTypesAlertingCategory3 = "\x06"

	// CommonDataTypesAlertingCategory4 is the octet string constant for CommonDataTypesAlertingCategory4.
	CommonDataTypesAlertingCategory4 = "\x07"

	// CommonDataTypesAlertingCategory5 is the octet string constant for CommonDataTypesAlertingCategory5.
	CommonDataTypesAlertingCategory5 = "\x08"

	// CommonDataTypesMaxNumOfHLRId is the integer constant for CommonDataTypesMaxNumOfHLRId.
	CommonDataTypesMaxNumOfHLRId int64 = 50

	// CommonDataTypesEmergencyServices is the integer constant for CommonDataTypesEmergencyServices.
	CommonDataTypesEmergencyServices int64 = 0

	// CommonDataTypesEmergencyAlertServices is the integer constant for CommonDataTypesEmergencyAlertServices.
	CommonDataTypesEmergencyAlertServices int64 = 1

	// CommonDataTypesPersonTracking is the integer constant for CommonDataTypesPersonTracking.
	CommonDataTypesPersonTracking int64 = 2

	// CommonDataTypesFleetManagement is the integer constant for CommonDataTypesFleetManagement.
	CommonDataTypesFleetManagement int64 = 3

	// CommonDataTypesAssetManagement is the integer constant for CommonDataTypesAssetManagement.
	CommonDataTypesAssetManagement int64 = 4

	// CommonDataTypesTrafficCongestionReporting is the integer constant for CommonDataTypesTrafficCongestionReporting.
	CommonDataTypesTrafficCongestionReporting int64 = 5

	// CommonDataTypesRoadsideAssistance is the integer constant for CommonDataTypesRoadsideAssistance.
	CommonDataTypesRoadsideAssistance int64 = 6

	// CommonDataTypesRoutingToNearestCommercialEnterprise is the integer constant for CommonDataTypesRoutingToNearestCommercialEnterprise.
	CommonDataTypesRoutingToNearestCommercialEnterprise int64 = 7

	// CommonDataTypesNavigation is the integer constant for CommonDataTypesNavigation.
	CommonDataTypesNavigation int64 = 8

	// CommonDataTypesCitySightseeing is the integer constant for CommonDataTypesCitySightseeing.
	CommonDataTypesCitySightseeing int64 = 9

	// CommonDataTypesLocalizedAdvertising is the integer constant for CommonDataTypesLocalizedAdvertising.
	CommonDataTypesLocalizedAdvertising int64 = 10

	// CommonDataTypesMobileYellowPages is the integer constant for CommonDataTypesMobileYellowPages.
	CommonDataTypesMobileYellowPages int64 = 11

	// CommonDataTypesTrafficAndPublicTransportationInfo is the integer constant for CommonDataTypesTrafficAndPublicTransportationInfo.
	CommonDataTypesTrafficAndPublicTransportationInfo int64 = 12

	// CommonDataTypesWeather is the integer constant for CommonDataTypesWeather.
	CommonDataTypesWeather int64 = 13

	// CommonDataTypesAssetAndServiceFinding is the integer constant for CommonDataTypesAssetAndServiceFinding.
	CommonDataTypesAssetAndServiceFinding int64 = 14

	// CommonDataTypesGaming is the integer constant for CommonDataTypesGaming.
	CommonDataTypesGaming int64 = 15

	// CommonDataTypesFindYourFriend is the integer constant for CommonDataTypesFindYourFriend.
	CommonDataTypesFindYourFriend int64 = 16

	// CommonDataTypesDating is the integer constant for CommonDataTypesDating.
	CommonDataTypesDating int64 = 17

	// CommonDataTypesChatting is the integer constant for CommonDataTypesChatting.
	CommonDataTypesChatting int64 = 18

	// CommonDataTypesRouteFinding is the integer constant for CommonDataTypesRouteFinding.
	CommonDataTypesRouteFinding int64 = 19

	// CommonDataTypesWhereAmI is the integer constant for CommonDataTypesWhereAmI.
	CommonDataTypesWhereAmI int64 = 20

	// CommonDataTypesServ64 is the integer constant for CommonDataTypesServ64.
	CommonDataTypesServ64 int64 = 64

	// CommonDataTypesServ65 is the integer constant for CommonDataTypesServ65.
	CommonDataTypesServ65 int64 = 65

	// CommonDataTypesServ66 is the integer constant for CommonDataTypesServ66.
	CommonDataTypesServ66 int64 = 66

	// CommonDataTypesServ67 is the integer constant for CommonDataTypesServ67.
	CommonDataTypesServ67 int64 = 67

	// CommonDataTypesServ68 is the integer constant for CommonDataTypesServ68.
	CommonDataTypesServ68 int64 = 68

	// CommonDataTypesServ69 is the integer constant for CommonDataTypesServ69.
	CommonDataTypesServ69 int64 = 69

	// CommonDataTypesServ70 is the integer constant for CommonDataTypesServ70.
	CommonDataTypesServ70 int64 = 70

	// CommonDataTypesServ71 is the integer constant for CommonDataTypesServ71.
	CommonDataTypesServ71 int64 = 71

	// CommonDataTypesServ72 is the integer constant for CommonDataTypesServ72.
	CommonDataTypesServ72 int64 = 72

	// CommonDataTypesServ73 is the integer constant for CommonDataTypesServ73.
	CommonDataTypesServ73 int64 = 73

	// CommonDataTypesServ74 is the integer constant for CommonDataTypesServ74.
	CommonDataTypesServ74 int64 = 74

	// CommonDataTypesServ75 is the integer constant for CommonDataTypesServ75.
	CommonDataTypesServ75 int64 = 75

	// CommonDataTypesServ76 is the integer constant for CommonDataTypesServ76.
	CommonDataTypesServ76 int64 = 76

	// CommonDataTypesServ77 is the integer constant for CommonDataTypesServ77.
	CommonDataTypesServ77 int64 = 77

	// CommonDataTypesServ78 is the integer constant for CommonDataTypesServ78.
	CommonDataTypesServ78 int64 = 78

	// CommonDataTypesServ79 is the integer constant for CommonDataTypesServ79.
	CommonDataTypesServ79 int64 = 79

	// CommonDataTypesServ80 is the integer constant for CommonDataTypesServ80.
	CommonDataTypesServ80 int64 = 80

	// CommonDataTypesServ81 is the integer constant for CommonDataTypesServ81.
	CommonDataTypesServ81 int64 = 81

	// CommonDataTypesServ82 is the integer constant for CommonDataTypesServ82.
	CommonDataTypesServ82 int64 = 82

	// CommonDataTypesServ83 is the integer constant for CommonDataTypesServ83.
	CommonDataTypesServ83 int64 = 83

	// CommonDataTypesServ84 is the integer constant for CommonDataTypesServ84.
	CommonDataTypesServ84 int64 = 84

	// CommonDataTypesServ85 is the integer constant for CommonDataTypesServ85.
	CommonDataTypesServ85 int64 = 85

	// CommonDataTypesServ86 is the integer constant for CommonDataTypesServ86.
	CommonDataTypesServ86 int64 = 86

	// CommonDataTypesServ87 is the integer constant for CommonDataTypesServ87.
	CommonDataTypesServ87 int64 = 87

	// CommonDataTypesServ88 is the integer constant for CommonDataTypesServ88.
	CommonDataTypesServ88 int64 = 88

	// CommonDataTypesServ89 is the integer constant for CommonDataTypesServ89.
	CommonDataTypesServ89 int64 = 89

	// CommonDataTypesServ90 is the integer constant for CommonDataTypesServ90.
	CommonDataTypesServ90 int64 = 90

	// CommonDataTypesServ91 is the integer constant for CommonDataTypesServ91.
	CommonDataTypesServ91 int64 = 91

	// CommonDataTypesServ92 is the integer constant for CommonDataTypesServ92.
	CommonDataTypesServ92 int64 = 92

	// CommonDataTypesServ93 is the integer constant for CommonDataTypesServ93.
	CommonDataTypesServ93 int64 = 93

	// CommonDataTypesServ94 is the integer constant for CommonDataTypesServ94.
	CommonDataTypesServ94 int64 = 94

	// CommonDataTypesServ95 is the integer constant for CommonDataTypesServ95.
	CommonDataTypesServ95 int64 = 95

	// CommonDataTypesServ96 is the integer constant for CommonDataTypesServ96.
	CommonDataTypesServ96 int64 = 96

	// CommonDataTypesServ97 is the integer constant for CommonDataTypesServ97.
	CommonDataTypesServ97 int64 = 97

	// CommonDataTypesServ98 is the integer constant for CommonDataTypesServ98.
	CommonDataTypesServ98 int64 = 98

	// CommonDataTypesServ99 is the integer constant for CommonDataTypesServ99.
	CommonDataTypesServ99 int64 = 99

	// CommonDataTypesServ100 is the integer constant for CommonDataTypesServ100.
	CommonDataTypesServ100 int64 = 100

	// CommonDataTypesServ101 is the integer constant for CommonDataTypesServ101.
	CommonDataTypesServ101 int64 = 101

	// CommonDataTypesServ102 is the integer constant for CommonDataTypesServ102.
	CommonDataTypesServ102 int64 = 102

	// CommonDataTypesServ103 is the integer constant for CommonDataTypesServ103.
	CommonDataTypesServ103 int64 = 103

	// CommonDataTypesServ104 is the integer constant for CommonDataTypesServ104.
	CommonDataTypesServ104 int64 = 104

	// CommonDataTypesServ105 is the integer constant for CommonDataTypesServ105.
	CommonDataTypesServ105 int64 = 105

	// CommonDataTypesServ106 is the integer constant for CommonDataTypesServ106.
	CommonDataTypesServ106 int64 = 106

	// CommonDataTypesServ107 is the integer constant for CommonDataTypesServ107.
	CommonDataTypesServ107 int64 = 107

	// CommonDataTypesServ108 is the integer constant for CommonDataTypesServ108.
	CommonDataTypesServ108 int64 = 108

	// CommonDataTypesServ109 is the integer constant for CommonDataTypesServ109.
	CommonDataTypesServ109 int64 = 109

	// CommonDataTypesServ110 is the integer constant for CommonDataTypesServ110.
	CommonDataTypesServ110 int64 = 110

	// CommonDataTypesServ111 is the integer constant for CommonDataTypesServ111.
	CommonDataTypesServ111 int64 = 111

	// CommonDataTypesServ112 is the integer constant for CommonDataTypesServ112.
	CommonDataTypesServ112 int64 = 112

	// CommonDataTypesServ113 is the integer constant for CommonDataTypesServ113.
	CommonDataTypesServ113 int64 = 113

	// CommonDataTypesServ114 is the integer constant for CommonDataTypesServ114.
	CommonDataTypesServ114 int64 = 114

	// CommonDataTypesServ115 is the integer constant for CommonDataTypesServ115.
	CommonDataTypesServ115 int64 = 115

	// CommonDataTypesServ116 is the integer constant for CommonDataTypesServ116.
	CommonDataTypesServ116 int64 = 116

	// CommonDataTypesServ117 is the integer constant for CommonDataTypesServ117.
	CommonDataTypesServ117 int64 = 117

	// CommonDataTypesServ118 is the integer constant for CommonDataTypesServ118.
	CommonDataTypesServ118 int64 = 118

	// CommonDataTypesServ119 is the integer constant for CommonDataTypesServ119.
	CommonDataTypesServ119 int64 = 119

	// CommonDataTypesServ120 is the integer constant for CommonDataTypesServ120.
	CommonDataTypesServ120 int64 = 120

	// CommonDataTypesServ121 is the integer constant for CommonDataTypesServ121.
	CommonDataTypesServ121 int64 = 121

	// CommonDataTypesServ122 is the integer constant for CommonDataTypesServ122.
	CommonDataTypesServ122 int64 = 122

	// CommonDataTypesServ123 is the integer constant for CommonDataTypesServ123.
	CommonDataTypesServ123 int64 = 123

	// CommonDataTypesServ124 is the integer constant for CommonDataTypesServ124.
	CommonDataTypesServ124 int64 = 124

	// CommonDataTypesServ125 is the integer constant for CommonDataTypesServ125.
	CommonDataTypesServ125 int64 = 125

	// CommonDataTypesServ126 is the integer constant for CommonDataTypesServ126.
	CommonDataTypesServ126 int64 = 126

	// CommonDataTypesServ127 is the integer constant for CommonDataTypesServ127.
	CommonDataTypesServ127 int64 = 127

	// CommonDataTypesPriorityLevelA is the integer constant for CommonDataTypesPriorityLevelA.
	CommonDataTypesPriorityLevelA int64 = 6

	// CommonDataTypesPriorityLevelB is the integer constant for CommonDataTypesPriorityLevelB.
	CommonDataTypesPriorityLevelB int64 = 5

	// CommonDataTypesPriorityLevel0 is the integer constant for CommonDataTypesPriorityLevel0.
	CommonDataTypesPriorityLevel0 int64 = 0

	// CommonDataTypesPriorityLevel1 is the integer constant for CommonDataTypesPriorityLevel1.
	CommonDataTypesPriorityLevel1 int64 = 1

	// CommonDataTypesPriorityLevel2 is the integer constant for CommonDataTypesPriorityLevel2.
	CommonDataTypesPriorityLevel2 int64 = 2

	// CommonDataTypesPriorityLevel3 is the integer constant for CommonDataTypesPriorityLevel3.
	CommonDataTypesPriorityLevel3 int64 = 3

	// CommonDataTypesPriorityLevel4 is the integer constant for CommonDataTypesPriorityLevel4.
	CommonDataTypesPriorityLevel4 int64 = 4

	// CommonDataTypesMaxNumOfMCBearers is the integer constant for CommonDataTypesMaxNumOfMCBearers.
	CommonDataTypesMaxNumOfMCBearers int64 = 7
)

// CommonDataTypesTBCDSTRING represents the ASN.1 type CommonDataTypesTBCDSTRING (OCTET_STRING).
type CommonDataTypesTBCDSTRING = []byte

// CommonDataTypesAddressString represents the ASN.1 type CommonDataTypesAddressString (OCTET_STRING).
type CommonDataTypesAddressString = []byte

// CommonDataTypesISDNAddressString represents the ASN.1 type CommonDataTypesISDNAddressString (OCTET_STRING).
type CommonDataTypesISDNAddressString = CommonDataTypesAddressString

// CommonDataTypesFTNAddressString represents the ASN.1 type CommonDataTypesFTNAddressString (OCTET_STRING).
type CommonDataTypesFTNAddressString = CommonDataTypesAddressString

// CommonDataTypesISDNSubaddressString represents the ASN.1 type CommonDataTypesISDNSubaddressString (OCTET_STRING).
type CommonDataTypesISDNSubaddressString = []byte

// CommonDataTypesExternalSignalInfo represents the ASN.1 type CommonDataTypesExternalSignalInfo (SEQUENCE).
type CommonDataTypesExternalSignalInfo struct {
	ProtocolId         CommonDataTypesProtocolId             `asn1:""`
	SignalInfo         CommonDataTypesSignalInfo             `asn1:""`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CommonDataTypesSignalInfo represents the ASN.1 type CommonDataTypesSignalInfo (OCTET_STRING).
type CommonDataTypesSignalInfo = []byte

// CommonDataTypesProtocolId represents the ASN.1 ENUMERATED type CommonDataTypesProtocolId.
type CommonDataTypesProtocolId int64

const (
	CommonDataTypesProtocolIdGsm0408    CommonDataTypesProtocolId = 1
	CommonDataTypesProtocolIdGsm0806    CommonDataTypesProtocolId = 2
	CommonDataTypesProtocolIdGsmBSSMAP  CommonDataTypesProtocolId = 3
	CommonDataTypesProtocolIdEts3001021 CommonDataTypesProtocolId = 4
)

func (v CommonDataTypesProtocolId) String() string {
	switch v {
	case CommonDataTypesProtocolIdGsm0408:
		return "gsm-0408"
	case CommonDataTypesProtocolIdGsm0806:
		return "gsm-0806"
	case CommonDataTypesProtocolIdGsmBSSMAP:
		return "gsm-BSSMAP"
	case CommonDataTypesProtocolIdEts3001021:
		return "ets-300102-1"
	default:
		return "unknown"
	}
}

// CommonDataTypesExtExternalSignalInfo represents the ASN.1 type CommonDataTypesExtExternalSignalInfo (SEQUENCE).
type CommonDataTypesExtExternalSignalInfo struct {
	ExtProtocolId      CommonDataTypesExtProtocolId          `asn1:""`
	SignalInfo         CommonDataTypesSignalInfo             `asn1:""`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CommonDataTypesExtProtocolId represents the ASN.1 ENUMERATED type CommonDataTypesExtProtocolId.
type CommonDataTypesExtProtocolId int64

const (
	CommonDataTypesExtProtocolIdEts300356 CommonDataTypesExtProtocolId = 1
)

func (v CommonDataTypesExtProtocolId) String() string {
	switch v {
	case CommonDataTypesExtProtocolIdEts300356:
		return "ets-300356"
	default:
		return "unknown"
	}
}

// CommonDataTypesAccessNetworkSignalInfo represents the ASN.1 type CommonDataTypesAccessNetworkSignalInfo (SEQUENCE).
type CommonDataTypesAccessNetworkSignalInfo struct {
	AccessNetworkProtocolId CommonDataTypesAccessNetworkProtocolId `asn1:""`
	SignalInfo              CommonDataTypesLongSignalInfo          `asn1:""`
	ExtensionContainer      *ExtensionDataTypesExtensionContainer  `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                                  `asn1:"-" json:"-"`
	ExtPresent_             []bool                                 `asn1:"-" json:"-"`
	ExtData_                [][]byte                               `asn1:"-" json:"-"`
}

// CommonDataTypesLongSignalInfo represents the ASN.1 type CommonDataTypesLongSignalInfo (OCTET_STRING).
type CommonDataTypesLongSignalInfo = []byte

// CommonDataTypesAccessNetworkProtocolId represents the ASN.1 ENUMERATED type CommonDataTypesAccessNetworkProtocolId.
type CommonDataTypesAccessNetworkProtocolId int64

const (
	CommonDataTypesAccessNetworkProtocolIdTs3G48006 CommonDataTypesAccessNetworkProtocolId = 1
	CommonDataTypesAccessNetworkProtocolIdTs3G25413 CommonDataTypesAccessNetworkProtocolId = 2
)

func (v CommonDataTypesAccessNetworkProtocolId) String() string {
	switch v {
	case CommonDataTypesAccessNetworkProtocolIdTs3G48006:
		return "ts3G-48006"
	case CommonDataTypesAccessNetworkProtocolIdTs3G25413:
		return "ts3G-25413"
	default:
		return "unknown"
	}
}

// CommonDataTypesAlertingPattern represents the ASN.1 type CommonDataTypesAlertingPattern (OCTET_STRING).
type CommonDataTypesAlertingPattern = []byte

// CommonDataTypesIMSI represents the ASN.1 type CommonDataTypesIMSI (OCTET_STRING).
type CommonDataTypesIMSI = CommonDataTypesTBCDSTRING

// CommonDataTypesIdentity choice constants.
const (
	CommonDataTypesIdentityChoiceImsi         = 1
	CommonDataTypesIdentityChoiceImsiWithLMSI = 2
)

// CommonDataTypesIdentity represents the ASN.1 CHOICE type CommonDataTypesIdentity.
type CommonDataTypesIdentity struct {
	Choice       int
	Imsi         *CommonDataTypesIMSI         `json:"Imsi,omitempty"`
	ImsiWithLMSI *CommonDataTypesIMSIWithLMSI `json:"ImsiWithLMSI,omitempty"`
}

// NewCommonDataTypesIdentityImsi creates a CommonDataTypesIdentity with the imsi alternative.
func NewCommonDataTypesIdentityImsi(v CommonDataTypesIMSI) CommonDataTypesIdentity {
	return CommonDataTypesIdentity{
		Choice: CommonDataTypesIdentityChoiceImsi,
		Imsi:   &v,
	}
}

// NewCommonDataTypesIdentityImsiWithLMSI creates a CommonDataTypesIdentity with the imsi-WithLMSI alternative.
func NewCommonDataTypesIdentityImsiWithLMSI(v CommonDataTypesIMSIWithLMSI) CommonDataTypesIdentity {
	return CommonDataTypesIdentity{
		Choice:       CommonDataTypesIdentityChoiceImsiWithLMSI,
		ImsiWithLMSI: &v,
	}
}

// CommonDataTypesIMSIWithLMSI represents the ASN.1 type CommonDataTypesIMSIWithLMSI (SEQUENCE).
type CommonDataTypesIMSIWithLMSI struct {
	Imsi        CommonDataTypesIMSI `asn1:""`
	Lmsi        CommonDataTypesLMSI `asn1:""`
	ExtCount_   int64               `asn1:"-" json:"-"`
	ExtPresent_ []bool              `asn1:"-" json:"-"`
	ExtData_    [][]byte            `asn1:"-" json:"-"`
}

// CommonDataTypesASCICallReference represents the ASN.1 type CommonDataTypesASCICallReference (OCTET_STRING).
type CommonDataTypesASCICallReference = CommonDataTypesTBCDSTRING

// CommonDataTypesTMSI represents the ASN.1 type CommonDataTypesTMSI (OCTET_STRING).
type CommonDataTypesTMSI = []byte

// CommonDataTypesSubscriberId choice constants.
const (
	CommonDataTypesSubscriberIdChoiceImsi = 1
	CommonDataTypesSubscriberIdChoiceTmsi = 2
)

// CommonDataTypesSubscriberId represents the ASN.1 CHOICE type CommonDataTypesSubscriberId.
type CommonDataTypesSubscriberId struct {
	Choice int
	Imsi   *CommonDataTypesIMSI `json:"Imsi,omitempty"`
	Tmsi   *CommonDataTypesTMSI `json:"Tmsi,omitempty"`
}

// NewCommonDataTypesSubscriberIdImsi creates a CommonDataTypesSubscriberId with the imsi alternative.
func NewCommonDataTypesSubscriberIdImsi(v CommonDataTypesIMSI) CommonDataTypesSubscriberId {
	return CommonDataTypesSubscriberId{
		Choice: CommonDataTypesSubscriberIdChoiceImsi,
		Imsi:   &v,
	}
}

// NewCommonDataTypesSubscriberIdTmsi creates a CommonDataTypesSubscriberId with the tmsi alternative.
func NewCommonDataTypesSubscriberIdTmsi(v CommonDataTypesTMSI) CommonDataTypesSubscriberId {
	return CommonDataTypesSubscriberId{
		Choice: CommonDataTypesSubscriberIdChoiceTmsi,
		Tmsi:   &v,
	}
}

// CommonDataTypesIMEI represents the ASN.1 type CommonDataTypesIMEI (OCTET_STRING).
type CommonDataTypesIMEI = CommonDataTypesTBCDSTRING

// CommonDataTypesHLRId represents the ASN.1 type CommonDataTypesHLRId (OCTET_STRING).
type CommonDataTypesHLRId = CommonDataTypesIMSI

// CommonDataTypesHLRList represents the ASN.1 type CommonDataTypesHLRList (SEQUENCE_OF).
type CommonDataTypesHLRList = []CommonDataTypesHLRId

// CommonDataTypesLMSI represents the ASN.1 type CommonDataTypesLMSI (OCTET_STRING).
type CommonDataTypesLMSI = []byte

// CommonDataTypesGlobalCellId represents the ASN.1 type CommonDataTypesGlobalCellId (OCTET_STRING).
type CommonDataTypesGlobalCellId = []byte

// CommonDataTypesNetworkResource represents the ASN.1 ENUMERATED type CommonDataTypesNetworkResource.
type CommonDataTypesNetworkResource int64

const (
	CommonDataTypesNetworkResourcePlmn           CommonDataTypesNetworkResource = 0
	CommonDataTypesNetworkResourceHlr            CommonDataTypesNetworkResource = 1
	CommonDataTypesNetworkResourceVlr            CommonDataTypesNetworkResource = 2
	CommonDataTypesNetworkResourcePvlr           CommonDataTypesNetworkResource = 3
	CommonDataTypesNetworkResourceControllingMSC CommonDataTypesNetworkResource = 4
	CommonDataTypesNetworkResourceVmsc           CommonDataTypesNetworkResource = 5
	CommonDataTypesNetworkResourceEir            CommonDataTypesNetworkResource = 6
	CommonDataTypesNetworkResourceRss            CommonDataTypesNetworkResource = 7
)

func (v CommonDataTypesNetworkResource) String() string {
	switch v {
	case CommonDataTypesNetworkResourcePlmn:
		return "plmn"
	case CommonDataTypesNetworkResourceHlr:
		return "hlr"
	case CommonDataTypesNetworkResourceVlr:
		return "vlr"
	case CommonDataTypesNetworkResourcePvlr:
		return "pvlr"
	case CommonDataTypesNetworkResourceControllingMSC:
		return "controllingMSC"
	case CommonDataTypesNetworkResourceVmsc:
		return "vmsc"
	case CommonDataTypesNetworkResourceEir:
		return "eir"
	case CommonDataTypesNetworkResourceRss:
		return "rss"
	default:
		return "unknown"
	}
}

// CommonDataTypesAdditionalNetworkResource represents the ASN.1 ENUMERATED type CommonDataTypesAdditionalNetworkResource.
type CommonDataTypesAdditionalNetworkResource int64

const (
	CommonDataTypesAdditionalNetworkResourceSgsn   CommonDataTypesAdditionalNetworkResource = 0
	CommonDataTypesAdditionalNetworkResourceGgsn   CommonDataTypesAdditionalNetworkResource = 1
	CommonDataTypesAdditionalNetworkResourceGmlc   CommonDataTypesAdditionalNetworkResource = 2
	CommonDataTypesAdditionalNetworkResourceGsmSCF CommonDataTypesAdditionalNetworkResource = 3
	CommonDataTypesAdditionalNetworkResourceNplr   CommonDataTypesAdditionalNetworkResource = 4
	CommonDataTypesAdditionalNetworkResourceAuc    CommonDataTypesAdditionalNetworkResource = 5
)

func (v CommonDataTypesAdditionalNetworkResource) String() string {
	switch v {
	case CommonDataTypesAdditionalNetworkResourceSgsn:
		return "sgsn"
	case CommonDataTypesAdditionalNetworkResourceGgsn:
		return "ggsn"
	case CommonDataTypesAdditionalNetworkResourceGmlc:
		return "gmlc"
	case CommonDataTypesAdditionalNetworkResourceGsmSCF:
		return "gsmSCF"
	case CommonDataTypesAdditionalNetworkResourceNplr:
		return "nplr"
	case CommonDataTypesAdditionalNetworkResourceAuc:
		return "auc"
	default:
		return "unknown"
	}
}

// CommonDataTypesNAEAPreferredCI represents the ASN.1 type CommonDataTypesNAEAPreferredCI (SEQUENCE).
type CommonDataTypesNAEAPreferredCI struct {
	NaeaPreferredCIC   CommonDataTypesNAEACIC                `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CommonDataTypesNAEACIC represents the ASN.1 type CommonDataTypesNAEACIC (OCTET_STRING).
type CommonDataTypesNAEACIC = []byte

// CommonDataTypesSubscriberIdentity choice constants.
const (
	CommonDataTypesSubscriberIdentityChoiceImsi   = 1
	CommonDataTypesSubscriberIdentityChoiceMsisdn = 2
)

// CommonDataTypesSubscriberIdentity represents the ASN.1 CHOICE type CommonDataTypesSubscriberIdentity.
type CommonDataTypesSubscriberIdentity struct {
	Choice int
	Imsi   *CommonDataTypesIMSI              `json:"Imsi,omitempty"`
	Msisdn *CommonDataTypesISDNAddressString `json:"Msisdn,omitempty"`
}

// NewCommonDataTypesSubscriberIdentityImsi creates a CommonDataTypesSubscriberIdentity with the imsi alternative.
func NewCommonDataTypesSubscriberIdentityImsi(v CommonDataTypesIMSI) CommonDataTypesSubscriberIdentity {
	return CommonDataTypesSubscriberIdentity{
		Choice: CommonDataTypesSubscriberIdentityChoiceImsi,
		Imsi:   &v,
	}
}

// NewCommonDataTypesSubscriberIdentityMsisdn creates a CommonDataTypesSubscriberIdentity with the msisdn alternative.
func NewCommonDataTypesSubscriberIdentityMsisdn(v CommonDataTypesISDNAddressString) CommonDataTypesSubscriberIdentity {
	return CommonDataTypesSubscriberIdentity{
		Choice: CommonDataTypesSubscriberIdentityChoiceMsisdn,
		Msisdn: &v,
	}
}

// CommonDataTypesLCSClientExternalID represents the ASN.1 type CommonDataTypesLCSClientExternalID (SEQUENCE).
type CommonDataTypesLCSClientExternalID struct {
	ExternalAddress    *CommonDataTypesISDNAddressString     `asn1:"tag:0,context,implicit,optional" json:"ExternalAddress,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CommonDataTypesLCSClientInternalID represents the ASN.1 ENUMERATED type CommonDataTypesLCSClientInternalID.
type CommonDataTypesLCSClientInternalID int64

const (
	CommonDataTypesLCSClientInternalIDBroadcastService          CommonDataTypesLCSClientInternalID = 0
	CommonDataTypesLCSClientInternalIDOAndMHPLMN                CommonDataTypesLCSClientInternalID = 1
	CommonDataTypesLCSClientInternalIDOAndMVPLMN                CommonDataTypesLCSClientInternalID = 2
	CommonDataTypesLCSClientInternalIDAnonymousLocation         CommonDataTypesLCSClientInternalID = 3
	CommonDataTypesLCSClientInternalIDTargetMSsubscribedService CommonDataTypesLCSClientInternalID = 4
)

func (v CommonDataTypesLCSClientInternalID) String() string {
	switch v {
	case CommonDataTypesLCSClientInternalIDBroadcastService:
		return "broadcastService"
	case CommonDataTypesLCSClientInternalIDOAndMHPLMN:
		return "o-andM-HPLMN"
	case CommonDataTypesLCSClientInternalIDOAndMVPLMN:
		return "o-andM-VPLMN"
	case CommonDataTypesLCSClientInternalIDAnonymousLocation:
		return "anonymousLocation"
	case CommonDataTypesLCSClientInternalIDTargetMSsubscribedService:
		return "targetMSsubscribedService"
	default:
		return "unknown"
	}
}

// CommonDataTypesLCSServiceTypeID represents the ASN.1 type CommonDataTypesLCSServiceTypeID (INTEGER).
type CommonDataTypesLCSServiceTypeID = int64

// CommonDataTypesPLMNId represents the ASN.1 type CommonDataTypesPLMNId (OCTET_STRING).
type CommonDataTypesPLMNId = []byte

// CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI choice constants.
const (
	CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength = 1
	CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength                         = 2
)

// CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI represents the ASN.1 CHOICE type CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI.
type CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI struct {
	Choice                                 int
	CellGlobalIdOrServiceAreaIdFixedLength *CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength `json:"CellGlobalIdOrServiceAreaIdFixedLength,omitempty"`
	LaiFixedLength                         *CommonDataTypesLAIFixedLength                         `json:"LaiFixedLength,omitempty"`
}

// NewCommonDataTypesCellGlobalIdOrServiceAreaIdOrLAICellGlobalIdOrServiceAreaIdFixedLength creates a CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI with the cellGlobalIdOrServiceAreaIdFixedLength alternative.
func NewCommonDataTypesCellGlobalIdOrServiceAreaIdOrLAICellGlobalIdOrServiceAreaIdFixedLength(v CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength) CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI {
	return CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI{
		Choice:                                 CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength,
		CellGlobalIdOrServiceAreaIdFixedLength: &v,
	}
}

// NewCommonDataTypesCellGlobalIdOrServiceAreaIdOrLAILaiFixedLength creates a CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI with the laiFixedLength alternative.
func NewCommonDataTypesCellGlobalIdOrServiceAreaIdOrLAILaiFixedLength(v CommonDataTypesLAIFixedLength) CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI {
	return CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI{
		Choice:         CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength,
		LaiFixedLength: &v,
	}
}

// CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength represents the ASN.1 type CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength (OCTET_STRING).
type CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength = []byte

// CommonDataTypesLAIFixedLength represents the ASN.1 type CommonDataTypesLAIFixedLength (OCTET_STRING).
type CommonDataTypesLAIFixedLength = []byte

// CommonDataTypesBasicServiceCode choice constants.
const (
	CommonDataTypesBasicServiceCodeChoiceBearerService = 1
	CommonDataTypesBasicServiceCodeChoiceTeleservice   = 2
)

// CommonDataTypesBasicServiceCode represents the ASN.1 CHOICE type CommonDataTypesBasicServiceCode.
type CommonDataTypesBasicServiceCode struct {
	Choice        int
	BearerService *BSBearerServiceCode `json:"BearerService,omitempty"`
	Teleservice   *TSTeleserviceCode   `json:"Teleservice,omitempty"`
}

// NewCommonDataTypesBasicServiceCodeBearerService creates a CommonDataTypesBasicServiceCode with the bearerService alternative.
func NewCommonDataTypesBasicServiceCodeBearerService(v BSBearerServiceCode) CommonDataTypesBasicServiceCode {
	return CommonDataTypesBasicServiceCode{
		Choice:        CommonDataTypesBasicServiceCodeChoiceBearerService,
		BearerService: &v,
	}
}

// NewCommonDataTypesBasicServiceCodeTeleservice creates a CommonDataTypesBasicServiceCode with the teleservice alternative.
func NewCommonDataTypesBasicServiceCodeTeleservice(v TSTeleserviceCode) CommonDataTypesBasicServiceCode {
	return CommonDataTypesBasicServiceCode{
		Choice:      CommonDataTypesBasicServiceCodeChoiceTeleservice,
		Teleservice: &v,
	}
}

// CommonDataTypesExtBasicServiceCode choice constants.
const (
	CommonDataTypesExtBasicServiceCodeChoiceExtBearerService = 1
	CommonDataTypesExtBasicServiceCodeChoiceExtTeleservice   = 2
)

// CommonDataTypesExtBasicServiceCode represents the ASN.1 CHOICE type CommonDataTypesExtBasicServiceCode.
type CommonDataTypesExtBasicServiceCode struct {
	Choice           int
	ExtBearerService *BSExtBearerServiceCode `json:"ExtBearerService,omitempty"`
	ExtTeleservice   *TSExtTeleserviceCode   `json:"ExtTeleservice,omitempty"`
}

// NewCommonDataTypesExtBasicServiceCodeExtBearerService creates a CommonDataTypesExtBasicServiceCode with the ext-BearerService alternative.
func NewCommonDataTypesExtBasicServiceCodeExtBearerService(v BSExtBearerServiceCode) CommonDataTypesExtBasicServiceCode {
	return CommonDataTypesExtBasicServiceCode{
		Choice:           CommonDataTypesExtBasicServiceCodeChoiceExtBearerService,
		ExtBearerService: &v,
	}
}

// NewCommonDataTypesExtBasicServiceCodeExtTeleservice creates a CommonDataTypesExtBasicServiceCode with the ext-Teleservice alternative.
func NewCommonDataTypesExtBasicServiceCodeExtTeleservice(v TSExtTeleserviceCode) CommonDataTypesExtBasicServiceCode {
	return CommonDataTypesExtBasicServiceCode{
		Choice:         CommonDataTypesExtBasicServiceCodeChoiceExtTeleservice,
		ExtTeleservice: &v,
	}
}

// CommonDataTypesEMLPPInfo represents the ASN.1 type CommonDataTypesEMLPPInfo (SEQUENCE).
type CommonDataTypesEMLPPInfo struct {
	MaximumentitledPriority CommonDataTypesEMLPPPriority          `asn1:""`
	DefaultPriority         CommonDataTypesEMLPPPriority          `asn1:""`
	ExtensionContainer      *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                                 `asn1:"-" json:"-"`
	ExtPresent_             []bool                                `asn1:"-" json:"-"`
	ExtData_                [][]byte                              `asn1:"-" json:"-"`
}

// CommonDataTypesEMLPPPriority represents the ASN.1 type CommonDataTypesEMLPPPriority (INTEGER).
type CommonDataTypesEMLPPPriority = int64

// CommonDataTypesMCSSInfo represents the ASN.1 type CommonDataTypesMCSSInfo (SEQUENCE).
type CommonDataTypesMCSSInfo struct {
	SsCode             SSSSCode                              `asn1:"tag:0,context,implicit"`
	SsStatus           CommonDataTypesExtSSStatus            `asn1:"tag:1,context,implicit"`
	NbrSB              CommonDataTypesMaxMCBearers           `asn1:"tag:2,context,implicit"`
	NbrUser            CommonDataTypesMCBearers              `asn1:"tag:3,context,implicit"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CommonDataTypesMaxMCBearers represents the ASN.1 type CommonDataTypesMaxMCBearers (INTEGER).
type CommonDataTypesMaxMCBearers = int64

// CommonDataTypesMCBearers represents the ASN.1 type CommonDataTypesMCBearers (INTEGER).
type CommonDataTypesMCBearers = int64

// CommonDataTypesExtSSStatus represents the ASN.1 type CommonDataTypesExtSSStatus (OCTET_STRING).
type CommonDataTypesExtSSStatus = []byte

// CommonDataTypesAgeOfLocationInformation represents the ASN.1 type CommonDataTypesAgeOfLocationInformation (INTEGER).
type CommonDataTypesAgeOfLocationInformation = int64

// MarshalBER encodes CommonDataTypesExternalSignalInfo to BER format.
func (v *CommonDataTypesExternalSignalInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CommonDataTypesExternalSignalInfo to DER format.
func (v *CommonDataTypesExternalSignalInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesExternalSignalInfo from BER/DER format.
func (v *CommonDataTypesExternalSignalInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CommonDataTypesExternalSignalInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesExternalSignalInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field protocolId")
	}
	val_protocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding protocolId: %w", err)
	}
	v.ProtocolId = CommonDataTypesProtocolId(val_protocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = CommonDataTypesSignalInfo(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesExternalSignalInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CommonDataTypesExtExternalSignalInfo to BER format.
func (v *CommonDataTypesExtExternalSignalInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_extprotocolid := ber.EncodeEnumerated(int64(v.ExtProtocolId))
	children = append(children, enc_extprotocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CommonDataTypesExtExternalSignalInfo to DER format.
func (v *CommonDataTypesExtExternalSignalInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesExtExternalSignalInfo from BER/DER format.
func (v *CommonDataTypesExtExternalSignalInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CommonDataTypesExtExternalSignalInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesExtExternalSignalInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ext-ProtocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field ext-ProtocolId")
	}
	val_extprotocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ext-ProtocolId: %w", err)
	}
	v.ExtProtocolId = CommonDataTypesExtProtocolId(val_extprotocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = CommonDataTypesSignalInfo(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesExtExternalSignalInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CommonDataTypesAccessNetworkSignalInfo to BER format.
func (v *CommonDataTypesAccessNetworkSignalInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_accessnetworkprotocolid := ber.EncodeEnumerated(int64(v.AccessNetworkProtocolId))
	children = append(children, enc_accessnetworkprotocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CommonDataTypesAccessNetworkSignalInfo to DER format.
func (v *CommonDataTypesAccessNetworkSignalInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesAccessNetworkSignalInfo from BER/DER format.
func (v *CommonDataTypesAccessNetworkSignalInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CommonDataTypesAccessNetworkSignalInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesAccessNetworkSignalInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode accessNetworkProtocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field accessNetworkProtocolId")
	}
	val_accessnetworkprotocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding accessNetworkProtocolId: %w", err)
	}
	v.AccessNetworkProtocolId = CommonDataTypesAccessNetworkProtocolId(val_accessnetworkprotocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = CommonDataTypesLongSignalInfo(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesAccessNetworkSignalInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CommonDataTypesIdentity to BER format.
func (v *CommonDataTypesIdentity) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CommonDataTypesIdentityChoiceImsi:
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		return enc_0, nil
	case CommonDataTypesIdentityChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("choice CommonDataTypesIdentity: imsi-WithLMSI is nil")
		}
		enc_1, err := v.ImsiWithLMSI.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesIdentity", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesIdentity to DER format.
func (v *CommonDataTypesIdentity) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CommonDataTypesIdentityChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("choice CommonDataTypesIdentity: imsi-WithLMSI is nil")
		}
		enc_der_1, err := v.ImsiWithLMSI.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI: %w", err)
		}
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesIdentity from BER/DER format.
func (v *CommonDataTypesIdentity) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesIdentity CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesIdentity: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CommonDataTypesIdentity CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesIdentity", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = CommonDataTypesIdentityChoiceImsi
		decVal, _, osErr := ber.DecodeOctetString(choiceData)
		if osErr != nil {
			return fmt.Errorf("decoding imsi: %w", osErr)
		}
		tmp := CommonDataTypesIMSI(decVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = CommonDataTypesIdentityChoiceImsiWithLMSI
		var dec CommonDataTypesIMSIWithLMSI
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding imsi-WithLMSI: %w", unmErr)
		}
		v.ImsiWithLMSI = &dec
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesIdentity CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CommonDataTypesIMSIWithLMSI to BER format.
func (v *CommonDataTypesIMSIWithLMSI) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	children = append(children, enc_imsi...)
	enc_lmsi := ber.EncodeOctetString([]byte(v.Lmsi))
	children = append(children, enc_lmsi...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CommonDataTypesIMSIWithLMSI to DER format.
func (v *CommonDataTypesIMSIWithLMSI) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesIMSIWithLMSI from BER/DER format.
func (v *CommonDataTypesIMSIWithLMSI) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CommonDataTypesIMSIWithLMSI SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesIMSIWithLMSI", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	val_imsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(val_imsi)
	offset += n
	// Decode lmsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field lmsi")
	}
	val_lmsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lmsi: %w", err)
	}
	v.Lmsi = CommonDataTypesLMSI(val_lmsi)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesIMSIWithLMSI", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CommonDataTypesSubscriberId to BER format.
func (v *CommonDataTypesSubscriberId) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CommonDataTypesSubscriberIdChoiceImsi:
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case CommonDataTypesSubscriberIdChoiceTmsi:
		enc_1 := ber.EncodeOctetString([]byte(*v.Tmsi))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesSubscriberId", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesSubscriberId to DER format.
func (v *CommonDataTypesSubscriberId) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesSubscriberId from BER/DER format.
func (v *CommonDataTypesSubscriberId) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesSubscriberId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesSubscriberId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CommonDataTypesSubscriberId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesSubscriberId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CommonDataTypesSubscriberIdChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := CommonDataTypesIMSI(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CommonDataTypesSubscriberIdChoiceTmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding tmsi: %w", tlvErr)
		}
		tmp := CommonDataTypesTMSI(rawVal)
		v.Tmsi = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesSubscriberId CHOICE", peekTag)
	}
	return nil
}

// MarshalBERCommonDataTypesHLRList encodes a CommonDataTypesHLRList list to BER.
func MarshalBERCommonDataTypesHLRList(list CommonDataTypesHLRList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERCommonDataTypesHLRList decodes a CommonDataTypesHLRList list from BER.
func UnmarshalBERCommonDataTypesHLRList(data []byte) (CommonDataTypesHLRList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding CommonDataTypesHLRList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesHLRList", Cause: ber.ErrExtraData}
	}
	var result CommonDataTypesHLRList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, CommonDataTypesHLRId(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes CommonDataTypesNAEAPreferredCI to BER format.
func (v *CommonDataTypesNAEAPreferredCI) MarshalBER() ([]byte, error) {
	var children []byte
	enc_naeapreferredcic := ber.EncodeOctetString([]byte(v.NaeaPreferredCIC))
	enc_naeapreferredcic = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_naeapreferredcic)
	children = append(children, enc_naeapreferredcic...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CommonDataTypesNAEAPreferredCI to DER format.
func (v *CommonDataTypesNAEAPreferredCI) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesNAEAPreferredCI from BER/DER format.
func (v *CommonDataTypesNAEAPreferredCI) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CommonDataTypesNAEAPreferredCI SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesNAEAPreferredCI", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode naea-PreferredCIC
	if offset >= len(content) {
		return fmt.Errorf("missing required field naea-PreferredCIC")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for naea-PreferredCIC, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_naeapreferredcic, rawVal_naeapreferredcic, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding naea-PreferredCIC: %w", err)
	}
	v.NaeaPreferredCIC = CommonDataTypesNAEACIC(rawVal_naeapreferredcic)
	offset += n_naeapreferredcic
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesNAEAPreferredCI", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CommonDataTypesSubscriberIdentity to BER format.
func (v *CommonDataTypesSubscriberIdentity) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CommonDataTypesSubscriberIdentityChoiceImsi:
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case CommonDataTypesSubscriberIdentityChoiceMsisdn:
		enc_1 := ber.EncodeOctetString([]byte(*v.Msisdn))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesSubscriberIdentity", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesSubscriberIdentity to DER format.
func (v *CommonDataTypesSubscriberIdentity) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesSubscriberIdentity from BER/DER format.
func (v *CommonDataTypesSubscriberIdentity) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesSubscriberIdentity CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesSubscriberIdentity: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CommonDataTypesSubscriberIdentity CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesSubscriberIdentity", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CommonDataTypesSubscriberIdentityChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := CommonDataTypesIMSI(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CommonDataTypesSubscriberIdentityChoiceMsisdn
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msisdn: %w", tlvErr)
		}
		tmp := CommonDataTypesISDNAddressString(rawVal)
		v.Msisdn = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesSubscriberIdentity CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CommonDataTypesLCSClientExternalID to BER format.
func (v *CommonDataTypesLCSClientExternalID) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExternalAddress != nil {
		enc_externaladdress := ber.EncodeOctetString([]byte(*v.ExternalAddress))
		enc_externaladdress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_externaladdress)
		children = append(children, enc_externaladdress...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CommonDataTypesLCSClientExternalID to DER format.
func (v *CommonDataTypesLCSClientExternalID) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesLCSClientExternalID from BER/DER format.
func (v *CommonDataTypesLCSClientExternalID) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CommonDataTypesLCSClientExternalID SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesLCSClientExternalID", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode externalAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_externaladdress, rawVal_externaladdress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding externalAddress: %w", err)
				}
				tmp_externaladdress := CommonDataTypesISDNAddressString(rawVal_externaladdress)
				v.ExternalAddress = &tmp_externaladdress
				offset += n_externaladdress
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesLCSClientExternalID", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI to BER format.
func (v *CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength:
		enc_0 := ber.EncodeOctetString([]byte(*v.CellGlobalIdOrServiceAreaIdFixedLength))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength:
		enc_1 := ber.EncodeOctetString([]byte(*v.LaiFixedLength))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI to DER format.
func (v *CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI from BER/DER format.
func (v *CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cellGlobalIdOrServiceAreaIdFixedLength: %w", tlvErr)
		}
		tmp := CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength(rawVal)
		v.CellGlobalIdOrServiceAreaIdFixedLength = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding laiFixedLength: %w", tlvErr)
		}
		tmp := CommonDataTypesLAIFixedLength(rawVal)
		v.LaiFixedLength = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CommonDataTypesBasicServiceCode to BER format.
func (v *CommonDataTypesBasicServiceCode) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CommonDataTypesBasicServiceCodeChoiceBearerService:
		enc_0 := ber.EncodeOctetString([]byte(*v.BearerService))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_0)
		return enc_0, nil
	case CommonDataTypesBasicServiceCodeChoiceTeleservice:
		enc_1 := ber.EncodeOctetString([]byte(*v.Teleservice))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesBasicServiceCode", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesBasicServiceCode to DER format.
func (v *CommonDataTypesBasicServiceCode) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesBasicServiceCode from BER/DER format.
func (v *CommonDataTypesBasicServiceCode) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesBasicServiceCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesBasicServiceCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CommonDataTypesBasicServiceCode CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesBasicServiceCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = CommonDataTypesBasicServiceCodeChoiceBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding bearerService: %w", tlvErr)
		}
		tmp := BSBearerServiceCode(rawVal)
		v.BearerService = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = CommonDataTypesBasicServiceCodeChoiceTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding teleservice: %w", tlvErr)
		}
		tmp := TSTeleserviceCode(rawVal)
		v.Teleservice = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesBasicServiceCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CommonDataTypesExtBasicServiceCode to BER format.
func (v *CommonDataTypesExtBasicServiceCode) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CommonDataTypesExtBasicServiceCodeChoiceExtBearerService:
		enc_0 := ber.EncodeOctetString([]byte(*v.ExtBearerService))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_0)
		return enc_0, nil
	case CommonDataTypesExtBasicServiceCodeChoiceExtTeleservice:
		enc_1 := ber.EncodeOctetString([]byte(*v.ExtTeleservice))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesExtBasicServiceCode", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesExtBasicServiceCode to DER format.
func (v *CommonDataTypesExtBasicServiceCode) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesExtBasicServiceCode from BER/DER format.
func (v *CommonDataTypesExtBasicServiceCode) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesExtBasicServiceCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesExtBasicServiceCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CommonDataTypesExtBasicServiceCode CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesExtBasicServiceCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = CommonDataTypesExtBasicServiceCodeChoiceExtBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-BearerService: %w", tlvErr)
		}
		tmp := BSExtBearerServiceCode(rawVal)
		v.ExtBearerService = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = CommonDataTypesExtBasicServiceCodeChoiceExtTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-Teleservice: %w", tlvErr)
		}
		tmp := TSExtTeleserviceCode(rawVal)
		v.ExtTeleservice = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesExtBasicServiceCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CommonDataTypesEMLPPInfo to BER format.
func (v *CommonDataTypesEMLPPInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_maximumentitledpriority := ber.EncodeInteger(int64(v.MaximumentitledPriority))
	children = append(children, enc_maximumentitledpriority...)
	enc_defaultpriority := ber.EncodeInteger(int64(v.DefaultPriority))
	children = append(children, enc_defaultpriority...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CommonDataTypesEMLPPInfo to DER format.
func (v *CommonDataTypesEMLPPInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesEMLPPInfo from BER/DER format.
func (v *CommonDataTypesEMLPPInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CommonDataTypesEMLPPInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesEMLPPInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode maximumentitledPriority
	if offset >= len(content) {
		return fmt.Errorf("missing required field maximumentitledPriority")
	}
	val_maximumentitledpriority, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding maximumentitledPriority: %w", err)
	}
	v.MaximumentitledPriority = CommonDataTypesEMLPPPriority(val_maximumentitledpriority)
	offset += n
	// Decode defaultPriority
	if offset >= len(content) {
		return fmt.Errorf("missing required field defaultPriority")
	}
	val_defaultpriority, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding defaultPriority: %w", err)
	}
	v.DefaultPriority = CommonDataTypesEMLPPPriority(val_defaultpriority)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesEMLPPInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CommonDataTypesMCSSInfo to BER format.
func (v *CommonDataTypesMCSSInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	enc_sscode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_sscode)
	children = append(children, enc_sscode...)
	enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	enc_ssstatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_ssstatus)
	children = append(children, enc_ssstatus...)
	enc_nbrsb := ber.EncodeInteger(int64(v.NbrSB))
	enc_nbrsb = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_nbrsb)
	children = append(children, enc_nbrsb...)
	enc_nbruser := ber.EncodeInteger(int64(v.NbrUser))
	enc_nbruser = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_nbruser)
	children = append(children, enc_nbruser...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CommonDataTypesMCSSInfo to DER format.
func (v *CommonDataTypesMCSSInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CommonDataTypesMCSSInfo from BER/DER format.
func (v *CommonDataTypesMCSSInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CommonDataTypesMCSSInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesMCSSInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ss-Code, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	v.SsCode = SSSSCode(rawVal_sscode)
	offset += n_sscode
	// Decode ss-Status
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Status")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for ss-Status, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Status: %w", err)
	}
	v.SsStatus = CommonDataTypesExtSSStatus(rawVal_ssstatus)
	offset += n_ssstatus
	// Decode nbrSB
	if offset >= len(content) {
		return fmt.Errorf("missing required field nbrSB")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for nbrSB, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_nbrsb, rawVal_nbrsb, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding nbrSB: %w", err)
	}
	decVal_nbrsb, intErr := ber.DecodeIntegerValue(rawVal_nbrsb)
	if intErr != nil {
		return fmt.Errorf("decoding nbrSB: %w", intErr)
	}
	v.NbrSB = CommonDataTypesMaxMCBearers(decVal_nbrsb)
	offset += n_nbrsb
	// Decode nbrUser
	if offset >= len(content) {
		return fmt.Errorf("missing required field nbrUser")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for nbrUser, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding nbrUser: %w", err)
	}
	decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
	if intErr != nil {
		return fmt.Errorf("decoding nbrUser: %w", intErr)
	}
	v.NbrUser = CommonDataTypesMCBearers(decVal_nbruser)
	offset += n_nbruser
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesMCSSInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
