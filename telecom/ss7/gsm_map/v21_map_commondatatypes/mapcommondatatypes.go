// Code generated from ASN.1 module "MAP-CommonDataTypes". DO NOT EDIT.

package v21_map_commondatatypes

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_bs_code"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_extensiondatatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_code"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ts_code"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

const (

	// CommonDataTypesMaxAddressLength is the integer constant for maxAddressLength.
	CommonDataTypesMaxAddressLength int64 = 20

	// CommonDataTypesMaxISDNAddressLength is the integer constant for maxISDN-AddressLength.
	CommonDataTypesMaxISDNAddressLength int64 = 9

	// CommonDataTypesMaxFTNAddressLength is the integer constant for maxFTN-AddressLength.
	CommonDataTypesMaxFTNAddressLength int64 = 15

	// CommonDataTypesMaxISDNSubaddressLength is the integer constant for maxISDN-SubaddressLength.
	CommonDataTypesMaxISDNSubaddressLength int64 = 21

	// CommonDataTypesMaxSignalInfoLength is the integer constant for maxSignalInfoLength.
	CommonDataTypesMaxSignalInfoLength int64 = 200

	// CommonDataTypesMaxLongSignalInfoLength is the integer constant for maxLongSignalInfoLength.
	CommonDataTypesMaxLongSignalInfoLength int64 = 2560

	// CommonDataTypesAlertingLevel0 is the octet string constant for alertingLevel-0.
	CommonDataTypesAlertingLevel0 = "\x00"

	// CommonDataTypesAlertingLevel1 is the octet string constant for alertingLevel-1.
	CommonDataTypesAlertingLevel1 = "\x01"

	// CommonDataTypesAlertingLevel2 is the octet string constant for alertingLevel-2.
	CommonDataTypesAlertingLevel2 = "\x02"

	// CommonDataTypesAlertingCategory1 is the octet string constant for alertingCategory-1.
	CommonDataTypesAlertingCategory1 = "\x04"

	// CommonDataTypesAlertingCategory2 is the octet string constant for alertingCategory-2.
	CommonDataTypesAlertingCategory2 = "\x05"

	// CommonDataTypesAlertingCategory3 is the octet string constant for alertingCategory-3.
	CommonDataTypesAlertingCategory3 = "\x06"

	// CommonDataTypesAlertingCategory4 is the octet string constant for alertingCategory-4.
	CommonDataTypesAlertingCategory4 = "\x07"

	// CommonDataTypesAlertingCategory5 is the octet string constant for alertingCategory-5.
	CommonDataTypesAlertingCategory5 = "\x08"

	// CommonDataTypesMaxNumOfHLRId is the integer constant for maxNumOfHLR-Id.
	CommonDataTypesMaxNumOfHLRId int64 = 50

	// CommonDataTypesEmergencyServices is the integer constant for emergencyServices.
	CommonDataTypesEmergencyServices int64 = 0

	// CommonDataTypesEmergencyAlertServices is the integer constant for emergencyAlertServices.
	CommonDataTypesEmergencyAlertServices int64 = 1

	// CommonDataTypesPersonTracking is the integer constant for personTracking.
	CommonDataTypesPersonTracking int64 = 2

	// CommonDataTypesFleetManagement is the integer constant for fleetManagement.
	CommonDataTypesFleetManagement int64 = 3

	// CommonDataTypesAssetManagement is the integer constant for assetManagement.
	CommonDataTypesAssetManagement int64 = 4

	// CommonDataTypesTrafficCongestionReporting is the integer constant for trafficCongestionReporting.
	CommonDataTypesTrafficCongestionReporting int64 = 5

	// CommonDataTypesRoadsideAssistance is the integer constant for roadsideAssistance.
	CommonDataTypesRoadsideAssistance int64 = 6

	// CommonDataTypesRoutingToNearestCommercialEnterprise is the integer constant for routingToNearestCommercialEnterprise.
	CommonDataTypesRoutingToNearestCommercialEnterprise int64 = 7

	// CommonDataTypesNavigation is the integer constant for navigation.
	CommonDataTypesNavigation int64 = 8

	// CommonDataTypesCitySightseeing is the integer constant for citySightseeing.
	CommonDataTypesCitySightseeing int64 = 9

	// CommonDataTypesLocalizedAdvertising is the integer constant for localizedAdvertising.
	CommonDataTypesLocalizedAdvertising int64 = 10

	// CommonDataTypesMobileYellowPages is the integer constant for mobileYellowPages.
	CommonDataTypesMobileYellowPages int64 = 11

	// CommonDataTypesTrafficAndPublicTransportationInfo is the integer constant for trafficAndPublicTransportationInfo.
	CommonDataTypesTrafficAndPublicTransportationInfo int64 = 12

	// CommonDataTypesWeather is the integer constant for weather.
	CommonDataTypesWeather int64 = 13

	// CommonDataTypesAssetAndServiceFinding is the integer constant for assetAndServiceFinding.
	CommonDataTypesAssetAndServiceFinding int64 = 14

	// CommonDataTypesGaming is the integer constant for gaming.
	CommonDataTypesGaming int64 = 15

	// CommonDataTypesFindYourFriend is the integer constant for findYourFriend.
	CommonDataTypesFindYourFriend int64 = 16

	// CommonDataTypesDating is the integer constant for dating.
	CommonDataTypesDating int64 = 17

	// CommonDataTypesChatting is the integer constant for chatting.
	CommonDataTypesChatting int64 = 18

	// CommonDataTypesRouteFinding is the integer constant for routeFinding.
	CommonDataTypesRouteFinding int64 = 19

	// CommonDataTypesWhereAmI is the integer constant for whereAmI.
	CommonDataTypesWhereAmI int64 = 20

	// CommonDataTypesServ64 is the integer constant for serv64.
	CommonDataTypesServ64 int64 = 64

	// CommonDataTypesServ65 is the integer constant for serv65.
	CommonDataTypesServ65 int64 = 65

	// CommonDataTypesServ66 is the integer constant for serv66.
	CommonDataTypesServ66 int64 = 66

	// CommonDataTypesServ67 is the integer constant for serv67.
	CommonDataTypesServ67 int64 = 67

	// CommonDataTypesServ68 is the integer constant for serv68.
	CommonDataTypesServ68 int64 = 68

	// CommonDataTypesServ69 is the integer constant for serv69.
	CommonDataTypesServ69 int64 = 69

	// CommonDataTypesServ70 is the integer constant for serv70.
	CommonDataTypesServ70 int64 = 70

	// CommonDataTypesServ71 is the integer constant for serv71.
	CommonDataTypesServ71 int64 = 71

	// CommonDataTypesServ72 is the integer constant for serv72.
	CommonDataTypesServ72 int64 = 72

	// CommonDataTypesServ73 is the integer constant for serv73.
	CommonDataTypesServ73 int64 = 73

	// CommonDataTypesServ74 is the integer constant for serv74.
	CommonDataTypesServ74 int64 = 74

	// CommonDataTypesServ75 is the integer constant for serv75.
	CommonDataTypesServ75 int64 = 75

	// CommonDataTypesServ76 is the integer constant for serv76.
	CommonDataTypesServ76 int64 = 76

	// CommonDataTypesServ77 is the integer constant for serv77.
	CommonDataTypesServ77 int64 = 77

	// CommonDataTypesServ78 is the integer constant for serv78.
	CommonDataTypesServ78 int64 = 78

	// CommonDataTypesServ79 is the integer constant for serv79.
	CommonDataTypesServ79 int64 = 79

	// CommonDataTypesServ80 is the integer constant for serv80.
	CommonDataTypesServ80 int64 = 80

	// CommonDataTypesServ81 is the integer constant for serv81.
	CommonDataTypesServ81 int64 = 81

	// CommonDataTypesServ82 is the integer constant for serv82.
	CommonDataTypesServ82 int64 = 82

	// CommonDataTypesServ83 is the integer constant for serv83.
	CommonDataTypesServ83 int64 = 83

	// CommonDataTypesServ84 is the integer constant for serv84.
	CommonDataTypesServ84 int64 = 84

	// CommonDataTypesServ85 is the integer constant for serv85.
	CommonDataTypesServ85 int64 = 85

	// CommonDataTypesServ86 is the integer constant for serv86.
	CommonDataTypesServ86 int64 = 86

	// CommonDataTypesServ87 is the integer constant for serv87.
	CommonDataTypesServ87 int64 = 87

	// CommonDataTypesServ88 is the integer constant for serv88.
	CommonDataTypesServ88 int64 = 88

	// CommonDataTypesServ89 is the integer constant for serv89.
	CommonDataTypesServ89 int64 = 89

	// CommonDataTypesServ90 is the integer constant for serv90.
	CommonDataTypesServ90 int64 = 90

	// CommonDataTypesServ91 is the integer constant for serv91.
	CommonDataTypesServ91 int64 = 91

	// CommonDataTypesServ92 is the integer constant for serv92.
	CommonDataTypesServ92 int64 = 92

	// CommonDataTypesServ93 is the integer constant for serv93.
	CommonDataTypesServ93 int64 = 93

	// CommonDataTypesServ94 is the integer constant for serv94.
	CommonDataTypesServ94 int64 = 94

	// CommonDataTypesServ95 is the integer constant for serv95.
	CommonDataTypesServ95 int64 = 95

	// CommonDataTypesServ96 is the integer constant for serv96.
	CommonDataTypesServ96 int64 = 96

	// CommonDataTypesServ97 is the integer constant for serv97.
	CommonDataTypesServ97 int64 = 97

	// CommonDataTypesServ98 is the integer constant for serv98.
	CommonDataTypesServ98 int64 = 98

	// CommonDataTypesServ99 is the integer constant for serv99.
	CommonDataTypesServ99 int64 = 99

	// CommonDataTypesServ100 is the integer constant for serv100.
	CommonDataTypesServ100 int64 = 100

	// CommonDataTypesServ101 is the integer constant for serv101.
	CommonDataTypesServ101 int64 = 101

	// CommonDataTypesServ102 is the integer constant for serv102.
	CommonDataTypesServ102 int64 = 102

	// CommonDataTypesServ103 is the integer constant for serv103.
	CommonDataTypesServ103 int64 = 103

	// CommonDataTypesServ104 is the integer constant for serv104.
	CommonDataTypesServ104 int64 = 104

	// CommonDataTypesServ105 is the integer constant for serv105.
	CommonDataTypesServ105 int64 = 105

	// CommonDataTypesServ106 is the integer constant for serv106.
	CommonDataTypesServ106 int64 = 106

	// CommonDataTypesServ107 is the integer constant for serv107.
	CommonDataTypesServ107 int64 = 107

	// CommonDataTypesServ108 is the integer constant for serv108.
	CommonDataTypesServ108 int64 = 108

	// CommonDataTypesServ109 is the integer constant for serv109.
	CommonDataTypesServ109 int64 = 109

	// CommonDataTypesServ110 is the integer constant for serv110.
	CommonDataTypesServ110 int64 = 110

	// CommonDataTypesServ111 is the integer constant for serv111.
	CommonDataTypesServ111 int64 = 111

	// CommonDataTypesServ112 is the integer constant for serv112.
	CommonDataTypesServ112 int64 = 112

	// CommonDataTypesServ113 is the integer constant for serv113.
	CommonDataTypesServ113 int64 = 113

	// CommonDataTypesServ114 is the integer constant for serv114.
	CommonDataTypesServ114 int64 = 114

	// CommonDataTypesServ115 is the integer constant for serv115.
	CommonDataTypesServ115 int64 = 115

	// CommonDataTypesServ116 is the integer constant for serv116.
	CommonDataTypesServ116 int64 = 116

	// CommonDataTypesServ117 is the integer constant for serv117.
	CommonDataTypesServ117 int64 = 117

	// CommonDataTypesServ118 is the integer constant for serv118.
	CommonDataTypesServ118 int64 = 118

	// CommonDataTypesServ119 is the integer constant for serv119.
	CommonDataTypesServ119 int64 = 119

	// CommonDataTypesServ120 is the integer constant for serv120.
	CommonDataTypesServ120 int64 = 120

	// CommonDataTypesServ121 is the integer constant for serv121.
	CommonDataTypesServ121 int64 = 121

	// CommonDataTypesServ122 is the integer constant for serv122.
	CommonDataTypesServ122 int64 = 122

	// CommonDataTypesServ123 is the integer constant for serv123.
	CommonDataTypesServ123 int64 = 123

	// CommonDataTypesServ124 is the integer constant for serv124.
	CommonDataTypesServ124 int64 = 124

	// CommonDataTypesServ125 is the integer constant for serv125.
	CommonDataTypesServ125 int64 = 125

	// CommonDataTypesServ126 is the integer constant for serv126.
	CommonDataTypesServ126 int64 = 126

	// CommonDataTypesServ127 is the integer constant for serv127.
	CommonDataTypesServ127 int64 = 127

	// CommonDataTypesPriorityLevelA is the integer constant for priorityLevelA.
	CommonDataTypesPriorityLevelA int64 = 6

	// CommonDataTypesPriorityLevelB is the integer constant for priorityLevelB.
	CommonDataTypesPriorityLevelB int64 = 5

	// CommonDataTypesPriorityLevel0 is the integer constant for priorityLevel0.
	CommonDataTypesPriorityLevel0 int64 = 0

	// CommonDataTypesPriorityLevel1 is the integer constant for priorityLevel1.
	CommonDataTypesPriorityLevel1 int64 = 1

	// CommonDataTypesPriorityLevel2 is the integer constant for priorityLevel2.
	CommonDataTypesPriorityLevel2 int64 = 2

	// CommonDataTypesPriorityLevel3 is the integer constant for priorityLevel3.
	CommonDataTypesPriorityLevel3 int64 = 3

	// CommonDataTypesPriorityLevel4 is the integer constant for priorityLevel4.
	CommonDataTypesPriorityLevel4 int64 = 4

	// CommonDataTypesMaxNumOfMCBearers is the integer constant for maxNumOfMC-Bearers.
	CommonDataTypesMaxNumOfMCBearers int64 = 7
)

// CommonDataTypesTBCDSTRING represents the ASN.1 type TBCD-STRING (OCTET_STRING).
type CommonDataTypesTBCDSTRING = []byte

// CommonDataTypesDiameterIdentity represents the ASN.1 type DiameterIdentity (OCTET_STRING).
type CommonDataTypesDiameterIdentity = []byte

// CommonDataTypesAddressString represents the ASN.1 type AddressString (OCTET_STRING).
type CommonDataTypesAddressString = []byte

// CommonDataTypesISDNAddressString represents the ASN.1 type ISDN-AddressString (OCTET_STRING).
type CommonDataTypesISDNAddressString = CommonDataTypesAddressString

// CommonDataTypesFTNAddressString represents the ASN.1 type FTN-AddressString (OCTET_STRING).
type CommonDataTypesFTNAddressString = CommonDataTypesAddressString

// CommonDataTypesISDNSubaddressString represents the ASN.1 type ISDN-SubaddressString (OCTET_STRING).
type CommonDataTypesISDNSubaddressString = []byte

// CommonDataTypesExternalSignalInfo represents the ASN.1 type ExternalSignalInfo (SEQUENCE).
type CommonDataTypesExternalSignalInfo struct {
	ProtocolId         CommonDataTypesProtocolId                                        `asn1:""`
	SignalInfo         CommonDataTypesSignalInfo                                        `asn1:""`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_     *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// CommonDataTypesSignalInfo represents the ASN.1 type SignalInfo (OCTET_STRING).
type CommonDataTypesSignalInfo = []byte

// CommonDataTypesProtocolId represents the ASN.1 ENUMERATED type ProtocolId.
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

// CommonDataTypesExtExternalSignalInfo represents the ASN.1 type Ext-ExternalSignalInfo (SEQUENCE).
type CommonDataTypesExtExternalSignalInfo struct {
	ExtProtocolId      CommonDataTypesExtProtocolId                                     `asn1:""`
	SignalInfo         CommonDataTypesSignalInfo                                        `asn1:""`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_     *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// CommonDataTypesExtProtocolId represents the ASN.1 ENUMERATED type Ext-ProtocolId.
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

// CommonDataTypesAccessNetworkSignalInfo represents the ASN.1 type AccessNetworkSignalInfo (SEQUENCE).
type CommonDataTypesAccessNetworkSignalInfo struct {
	AccessNetworkProtocolId CommonDataTypesAccessNetworkProtocolId                           `asn1:""`
	SignalInfo              CommonDataTypesLongSignalInfo                                    `asn1:""`
	ExtensionContainer      *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                                                            `asn1:"-" json:"-"`
	ExtPresent_             []bool                                                           `asn1:"-" json:"-"`
	ExtData_                [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_          *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// CommonDataTypesLongSignalInfo represents the ASN.1 type LongSignalInfo (OCTET_STRING).
type CommonDataTypesLongSignalInfo = []byte

// CommonDataTypesAccessNetworkProtocolId represents the ASN.1 ENUMERATED type AccessNetworkProtocolId.
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

// CommonDataTypesAlertingPattern represents the ASN.1 type AlertingPattern (OCTET_STRING).
type CommonDataTypesAlertingPattern = []byte

// CommonDataTypesGSNAddress represents the ASN.1 type GSN-Address (OCTET_STRING).
type CommonDataTypesGSNAddress = []byte

// CommonDataTypesTime represents the ASN.1 type Time (OCTET_STRING).
type CommonDataTypesTime = []byte

// CommonDataTypesIMSI represents the ASN.1 type IMSI (OCTET_STRING).
type CommonDataTypesIMSI = CommonDataTypesTBCDSTRING

// CommonDataTypesIdentity choice constants.
const (
	CommonDataTypesIdentityChoiceImsi         = 1
	CommonDataTypesIdentityChoiceImsiWithLMSI = 2
)

// CommonDataTypesIdentity represents the ASN.1 CHOICE type Identity.
type CommonDataTypesIdentity struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode              `json:"-"`
	Imsi           *CommonDataTypesIMSI         `json:"Imsi,omitempty"`
	ImsiWithLMSI   *CommonDataTypesIMSIWithLMSI `json:"ImsiWithLMSI,omitempty"`
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

// CommonDataTypesIMSIWithLMSI represents the ASN.1 type IMSI-WithLMSI (SEQUENCE).
type CommonDataTypesIMSIWithLMSI struct {
	Imsi           CommonDataTypesIMSI `asn1:""`
	Lmsi           CommonDataTypesLMSI `asn1:""`
	ExtCount_      int64               `asn1:"-" json:"-"`
	ExtPresent_    []bool              `asn1:"-" json:"-"`
	ExtData_       [][]byte            `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode     `asn1:"-" json:"-"`
}

// CommonDataTypesASCICallReference represents the ASN.1 type ASCI-CallReference (OCTET_STRING).
type CommonDataTypesASCICallReference = CommonDataTypesTBCDSTRING

// CommonDataTypesTMSI represents the ASN.1 type TMSI (OCTET_STRING).
type CommonDataTypesTMSI = []byte

// CommonDataTypesSubscriberId choice constants.
const (
	CommonDataTypesSubscriberIdChoiceImsi = 1
	CommonDataTypesSubscriberIdChoiceTmsi = 2
)

// CommonDataTypesSubscriberId represents the ASN.1 CHOICE type SubscriberId.
type CommonDataTypesSubscriberId struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode      `json:"-"`
	Imsi           *CommonDataTypesIMSI `json:"Imsi,omitempty"`
	Tmsi           *CommonDataTypesTMSI `json:"Tmsi,omitempty"`
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

// CommonDataTypesIMEI represents the ASN.1 type IMEI (OCTET_STRING).
type CommonDataTypesIMEI = CommonDataTypesTBCDSTRING

// CommonDataTypesHLRId represents the ASN.1 type HLR-Id (OCTET_STRING).
type CommonDataTypesHLRId = CommonDataTypesIMSI

// CommonDataTypesHLRList represents the ASN.1 type HLR-List (SEQUENCE_OF).
type CommonDataTypesHLRList struct {
	Values         []CommonDataTypesHLRId `json:"Values"`
	berReplayNode_ *ber.ReplayNode        `json:"-"`
}

// CommonDataTypesLMSI represents the ASN.1 type LMSI (OCTET_STRING).
type CommonDataTypesLMSI = []byte

// CommonDataTypesGlobalCellId represents the ASN.1 type GlobalCellId (OCTET_STRING).
type CommonDataTypesGlobalCellId = []byte

// CommonDataTypesNetworkResource represents the ASN.1 ENUMERATED type NetworkResource.
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

// CommonDataTypesAdditionalNetworkResource represents the ASN.1 ENUMERATED type AdditionalNetworkResource.
type CommonDataTypesAdditionalNetworkResource int64

const (
	CommonDataTypesAdditionalNetworkResourceSgsn   CommonDataTypesAdditionalNetworkResource = 0
	CommonDataTypesAdditionalNetworkResourceGgsn   CommonDataTypesAdditionalNetworkResource = 1
	CommonDataTypesAdditionalNetworkResourceGmlc   CommonDataTypesAdditionalNetworkResource = 2
	CommonDataTypesAdditionalNetworkResourceGsmSCF CommonDataTypesAdditionalNetworkResource = 3
	CommonDataTypesAdditionalNetworkResourceNplr   CommonDataTypesAdditionalNetworkResource = 4
	CommonDataTypesAdditionalNetworkResourceAuc    CommonDataTypesAdditionalNetworkResource = 5
	CommonDataTypesAdditionalNetworkResourceUe     CommonDataTypesAdditionalNetworkResource = 6
	CommonDataTypesAdditionalNetworkResourceMme    CommonDataTypesAdditionalNetworkResource = 7
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
	case CommonDataTypesAdditionalNetworkResourceUe:
		return "ue"
	case CommonDataTypesAdditionalNetworkResourceMme:
		return "mme"
	default:
		return "unknown"
	}
}

// CommonDataTypesNAEAPreferredCI represents the ASN.1 type NAEA-PreferredCI (SEQUENCE).
type CommonDataTypesNAEAPreferredCI struct {
	NaeaPreferredCIC   CommonDataTypesNAEACIC                                           `asn1:"tag:0,context,implicit"`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_     *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// CommonDataTypesNAEACIC represents the ASN.1 type NAEA-CIC (OCTET_STRING).
type CommonDataTypesNAEACIC = []byte

// CommonDataTypesSubscriberIdentity choice constants.
const (
	CommonDataTypesSubscriberIdentityChoiceImsi   = 1
	CommonDataTypesSubscriberIdentityChoiceMsisdn = 2
)

// CommonDataTypesSubscriberIdentity represents the ASN.1 CHOICE type SubscriberIdentity.
type CommonDataTypesSubscriberIdentity struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode                   `json:"-"`
	Imsi           *CommonDataTypesIMSI              `json:"Imsi,omitempty"`
	Msisdn         *CommonDataTypesISDNAddressString `json:"Msisdn,omitempty"`
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

// CommonDataTypesLCSClientExternalID represents the ASN.1 type LCSClientExternalID (SEQUENCE).
type CommonDataTypesLCSClientExternalID struct {
	ExternalAddress    *CommonDataTypesISDNAddressString                                `asn1:"tag:0,context,implicit,optional" json:"ExternalAddress,omitempty"`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_     *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// CommonDataTypesLCSClientInternalID represents the ASN.1 ENUMERATED type LCSClientInternalID.
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

// CommonDataTypesLCSServiceTypeID represents the ASN.1 type LCSServiceTypeID (INTEGER).
type CommonDataTypesLCSServiceTypeID = int64

// CommonDataTypesPLMNId represents the ASN.1 type PLMN-Id (OCTET_STRING).
type CommonDataTypesPLMNId = []byte

// CommonDataTypesEUTRANCGI represents the ASN.1 type E-UTRAN-CGI (OCTET_STRING).
type CommonDataTypesEUTRANCGI = []byte

// CommonDataTypesNRCGI represents the ASN.1 type NR-CGI (OCTET_STRING).
type CommonDataTypesNRCGI = []byte

// CommonDataTypesTAId represents the ASN.1 type TA-Id (OCTET_STRING).
type CommonDataTypesTAId = []byte

// CommonDataTypesNRTAId represents the ASN.1 type NR-TA-Id (OCTET_STRING).
type CommonDataTypesNRTAId = []byte

// CommonDataTypesRAIdentity represents the ASN.1 type RAIdentity (OCTET_STRING).
type CommonDataTypesRAIdentity = []byte

// CommonDataTypesNetworkNodeDiameterAddress represents the ASN.1 type NetworkNodeDiameterAddress (SEQUENCE).
type CommonDataTypesNetworkNodeDiameterAddress struct {
	DiameterName   CommonDataTypesDiameterIdentity `asn1:"tag:0,context,implicit"`
	DiameterRealm  CommonDataTypesDiameterIdentity `asn1:"tag:1,context,implicit"`
	berReplayNode_ *ber.ReplayNode                 `asn1:"-" json:"-"`
}

// CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI choice constants.
const (
	CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength = 1
	CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength                         = 2
)

// CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI represents the ASN.1 CHOICE type CellGlobalIdOrServiceAreaIdOrLAI.
type CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI struct {
	Choice                                 int
	berReplayNode_                         *ber.ReplayNode                                        `json:"-"`
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

// CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength represents the ASN.1 type CellGlobalIdOrServiceAreaIdFixedLength (OCTET_STRING).
type CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength = []byte

// CommonDataTypesLAIFixedLength represents the ASN.1 type LAIFixedLength (OCTET_STRING).
type CommonDataTypesLAIFixedLength = []byte

// CommonDataTypesBasicServiceCode choice constants.
const (
	CommonDataTypesBasicServiceCodeChoiceBearerService = 1
	CommonDataTypesBasicServiceCodeChoiceTeleservice   = 2
)

// CommonDataTypesBasicServiceCode represents the ASN.1 CHOICE type BasicServiceCode.
type CommonDataTypesBasicServiceCode struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode                      `json:"-"`
	BearerService  *v21_map_bs_code.BSBearerServiceCode `json:"BearerService,omitempty"`
	Teleservice    *v21_map_ts_code.TSTeleserviceCode   `json:"Teleservice,omitempty"`
}

// NewCommonDataTypesBasicServiceCodeBearerService creates a CommonDataTypesBasicServiceCode with the bearerService alternative.
func NewCommonDataTypesBasicServiceCodeBearerService(v v21_map_bs_code.BSBearerServiceCode) CommonDataTypesBasicServiceCode {
	return CommonDataTypesBasicServiceCode{
		Choice:        CommonDataTypesBasicServiceCodeChoiceBearerService,
		BearerService: &v,
	}
}

// NewCommonDataTypesBasicServiceCodeTeleservice creates a CommonDataTypesBasicServiceCode with the teleservice alternative.
func NewCommonDataTypesBasicServiceCodeTeleservice(v v21_map_ts_code.TSTeleserviceCode) CommonDataTypesBasicServiceCode {
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

// CommonDataTypesExtBasicServiceCode represents the ASN.1 CHOICE type Ext-BasicServiceCode.
type CommonDataTypesExtBasicServiceCode struct {
	Choice           int
	berReplayNode_   *ber.ReplayNode                         `json:"-"`
	ExtBearerService *v21_map_bs_code.BSExtBearerServiceCode `json:"ExtBearerService,omitempty"`
	ExtTeleservice   *v21_map_ts_code.TSExtTeleserviceCode   `json:"ExtTeleservice,omitempty"`
}

// NewCommonDataTypesExtBasicServiceCodeExtBearerService creates a CommonDataTypesExtBasicServiceCode with the ext-BearerService alternative.
func NewCommonDataTypesExtBasicServiceCodeExtBearerService(v v21_map_bs_code.BSExtBearerServiceCode) CommonDataTypesExtBasicServiceCode {
	return CommonDataTypesExtBasicServiceCode{
		Choice:           CommonDataTypesExtBasicServiceCodeChoiceExtBearerService,
		ExtBearerService: &v,
	}
}

// NewCommonDataTypesExtBasicServiceCodeExtTeleservice creates a CommonDataTypesExtBasicServiceCode with the ext-Teleservice alternative.
func NewCommonDataTypesExtBasicServiceCodeExtTeleservice(v v21_map_ts_code.TSExtTeleserviceCode) CommonDataTypesExtBasicServiceCode {
	return CommonDataTypesExtBasicServiceCode{
		Choice:         CommonDataTypesExtBasicServiceCodeChoiceExtTeleservice,
		ExtTeleservice: &v,
	}
}

// CommonDataTypesEMLPPInfo represents the ASN.1 type EMLPP-Info (SEQUENCE).
type CommonDataTypesEMLPPInfo struct {
	MaximumentitledPriority CommonDataTypesEMLPPPriority                                     `asn1:""`
	DefaultPriority         CommonDataTypesEMLPPPriority                                     `asn1:""`
	ExtensionContainer      *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                                                            `asn1:"-" json:"-"`
	ExtPresent_             []bool                                                           `asn1:"-" json:"-"`
	ExtData_                [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_          *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// CommonDataTypesEMLPPPriority represents the ASN.1 type EMLPP-Priority (INTEGER).
type CommonDataTypesEMLPPPriority = int64

// CommonDataTypesMCSSInfo represents the ASN.1 type MC-SS-Info (SEQUENCE).
type CommonDataTypesMCSSInfo struct {
	SsCode             v21_map_ss_code.SSSSCode                                         `asn1:"tag:0,context,implicit"`
	SsStatus           CommonDataTypesExtSSStatus                                       `asn1:"tag:1,context,implicit"`
	NbrSB              CommonDataTypesMaxMCBearers                                      `asn1:"tag:2,context,implicit"`
	NbrUser            CommonDataTypesMCBearers                                         `asn1:"tag:3,context,implicit"`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_     *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// CommonDataTypesMaxMCBearers represents the ASN.1 type MaxMC-Bearers (INTEGER).
type CommonDataTypesMaxMCBearers = int64

// CommonDataTypesMCBearers represents the ASN.1 type MC-Bearers (INTEGER).
type CommonDataTypesMCBearers = int64

// CommonDataTypesExtSSStatus represents the ASN.1 type Ext-SS-Status (OCTET_STRING).
type CommonDataTypesExtSSStatus = []byte

// CommonDataTypesAgeOfLocationInformation represents the ASN.1 type AgeOfLocationInformation (INTEGER).
type CommonDataTypesAgeOfLocationInformation = int64

// MarshalBER encodes CommonDataTypesExternalSignalInfo to BER format.
func (v *CommonDataTypesExternalSignalInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesExternalSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesExternalSignalInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := ber.CheckEncodedValue(opts, "protocolId", "ENUMERATED {1, 2, 3, 4}", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_signalinfo, "signalInfo", "encoding", false)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CommonDataTypesExternalSignalInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CommonDataTypesExternalSignalInfo to DER format.
func (v *CommonDataTypesExternalSignalInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesExternalSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := ber.CheckEncodedValue(nil, "protocolId", "ENUMERATED {1, 2, 3, 4}", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(nil, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_signalinfo, "signalInfo", "encoding", true)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesExternalSignalInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CommonDataTypesExternalSignalInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesExternalSignalInfo from BER/DER format.
func (v *CommonDataTypesExternalSignalInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesExternalSignalInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesExternalSignalInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesExternalSignalInfo{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesExternalSignalInfo, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesExternalSignalInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesExternalSignalInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field protocolId")
	}
	{
		ber.MarkPreflightTarget(opts, "protocolId", content[offset:])
		val_protocolid, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "protocolId", "decoding", false)
		}
		v.ProtocolId = CommonDataTypesProtocolId(val_protocolid)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
			if constraintErr := ber.CheckDecodedValue(opts, "protocolId", "ENUMERATED {1, 2, 3, 4}", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	{
		ber.MarkPreflightTarget(opts, "signalInfo", content[offset:])
		val_signalinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "signalInfo", "decoding", false)
		}
		v.SignalInfo = CommonDataTypesSignalInfo(val_signalinfo)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
			if constraintErr := ber.CheckDecodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesExternalSignalInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesExternalSignalInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
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

// MarshalBER encodes CommonDataTypesExtExternalSignalInfo to BER format.
func (v *CommonDataTypesExtExternalSignalInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesExtExternalSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesExtExternalSignalInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_extprotocolid := ber.EncodeEnumerated(int64(v.ExtProtocolId))
	children = append(children, enc_extprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_signalinfo, "signalInfo", "encoding", false)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CommonDataTypesExtExternalSignalInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CommonDataTypesExtExternalSignalInfo to DER format.
func (v *CommonDataTypesExtExternalSignalInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesExtExternalSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_extprotocolid := ber.EncodeEnumerated(int64(v.ExtProtocolId))
	children = append(children, enc_extprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(nil, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_signalinfo, "signalInfo", "encoding", true)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesExtExternalSignalInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CommonDataTypesExtExternalSignalInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesExtExternalSignalInfo from BER/DER format.
func (v *CommonDataTypesExtExternalSignalInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesExtExternalSignalInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesExtExternalSignalInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesExtExternalSignalInfo{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesExtExternalSignalInfo, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesExtExternalSignalInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesExtExternalSignalInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ext-ProtocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field ext-ProtocolId")
	}
	{
		ber.MarkPreflightTarget(opts, "ext-ProtocolId", content[offset:])
		val_extprotocolid, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ext-ProtocolId", "decoding", false)
		}
		v.ExtProtocolId = CommonDataTypesExtProtocolId(val_extprotocolid)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	{
		ber.MarkPreflightTarget(opts, "signalInfo", content[offset:])
		val_signalinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "signalInfo", "decoding", false)
		}
		v.SignalInfo = CommonDataTypesSignalInfo(val_signalinfo)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
			if constraintErr := ber.CheckDecodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesExtExternalSignalInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesExtExternalSignalInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
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

// MarshalBER encodes CommonDataTypesAccessNetworkSignalInfo to BER format.
func (v *CommonDataTypesAccessNetworkSignalInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesAccessNetworkSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesAccessNetworkSignalInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_accessnetworkprotocolid := ber.EncodeEnumerated(int64(v.AccessNetworkProtocolId))
	children = append(children, enc_accessnetworkprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 2560 {
		if constraintErr := ber.CheckEncodedLength(opts, "signalInfo", "SIZE (1..2560)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_signalinfo, "signalInfo", "encoding", false)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CommonDataTypesAccessNetworkSignalInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CommonDataTypesAccessNetworkSignalInfo to DER format.
func (v *CommonDataTypesAccessNetworkSignalInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesAccessNetworkSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_accessnetworkprotocolid := ber.EncodeEnumerated(int64(v.AccessNetworkProtocolId))
	children = append(children, enc_accessnetworkprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 2560 {
		if constraintErr := ber.CheckEncodedLength(nil, "signalInfo", "SIZE (1..2560)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_signalinfo, "signalInfo", "encoding", true)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesAccessNetworkSignalInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CommonDataTypesAccessNetworkSignalInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesAccessNetworkSignalInfo from BER/DER format.
func (v *CommonDataTypesAccessNetworkSignalInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesAccessNetworkSignalInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesAccessNetworkSignalInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesAccessNetworkSignalInfo{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesAccessNetworkSignalInfo, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesAccessNetworkSignalInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesAccessNetworkSignalInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode accessNetworkProtocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field accessNetworkProtocolId")
	}
	{
		ber.MarkPreflightTarget(opts, "accessNetworkProtocolId", content[offset:])
		val_accessnetworkprotocolid, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "accessNetworkProtocolId", "decoding", false)
		}
		v.AccessNetworkProtocolId = CommonDataTypesAccessNetworkProtocolId(val_accessnetworkprotocolid)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	{
		ber.MarkPreflightTarget(opts, "signalInfo", content[offset:])
		val_signalinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "signalInfo", "decoding", false)
		}
		v.SignalInfo = CommonDataTypesLongSignalInfo(val_signalinfo)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 2560 {
			if constraintErr := ber.CheckDecodedLength(opts, "signalInfo", "SIZE (1..2560)", len(v.SignalInfo)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesAccessNetworkSignalInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesAccessNetworkSignalInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
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

// MarshalBER encodes CommonDataTypesIdentity to BER format.
func (v *CommonDataTypesIdentity) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesIdentity receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesIdentity) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *CommonDataTypesIdentity) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CommonDataTypesIdentityChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesIdentity: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case CommonDataTypesIdentityChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesIdentity: imsi-WithLMSI is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ImsiWithLMSI.MarshalBER(ber.ChildEncodeOptions(opts, "imsi-WithLMSI")...)
		if err != nil {
			return nil, qualifyBERError(err, "imsi-WithLMSI", "encoding", false)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesIdentity", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesIdentity to DER format.
func (v *CommonDataTypesIdentity) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesIdentity receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case CommonDataTypesIdentityChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesIdentity: imsi-WithLMSI is nil", ber.ErrInvalidValue)
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
		case CommonDataTypesIdentityChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case CommonDataTypesIdentityChoiceImsiWithLMSI:
			return nil, qualifyBERError(err, "imsi-WithLMSI", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesIdentity as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *CommonDataTypesIdentity) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesIdentity from BER/DER format.
func (v *CommonDataTypesIdentity) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesIdentity destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesIdentity, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesIdentity
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesIdentity{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesIdentity CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesIdentity: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesIdentity CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesIdentity", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "CommonDataTypesIdentity.imsi-WithLMSI", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = CommonDataTypesIdentityChoiceImsi
		ber.MarkPreflightTarget(opts, "imsi", choiceData)
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return qualifyBERError(osErr, "imsi", "decoding", false)
		}
		tmp := CommonDataTypesIMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = CommonDataTypesIdentityChoiceImsiWithLMSI
		ber.MarkPreflightTarget(opts, "imsi-WithLMSI", choiceData)
		var dec CommonDataTypesIMSIWithLMSI
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "imsi-WithLMSI")...); unmErr != nil {
			return qualifyBERError(unmErr, "imsi-WithLMSI", "decoding", false)
		}
		v.ImsiWithLMSI = &dec
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesIdentity CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CommonDataTypesIMSIWithLMSI to BER format.
func (v *CommonDataTypesIMSIWithLMSI) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesIMSIWithLMSI receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesIMSIWithLMSI) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(v.Lmsi))
	if encodeErr_enc_lmsi != nil {
		return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", false)
	}
	children = append(children, enc_lmsi...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
func (v *CommonDataTypesIMSIWithLMSI) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CommonDataTypesIMSIWithLMSI to DER format.
func (v *CommonDataTypesIMSIWithLMSI) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesIMSIWithLMSI receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesIMSIWithLMSI as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CommonDataTypesIMSIWithLMSI) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesIMSIWithLMSI from BER/DER format.
func (v *CommonDataTypesIMSIWithLMSI) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesIMSIWithLMSI destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesIMSIWithLMSI
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesIMSIWithLMSI{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesIMSIWithLMSI, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesIMSIWithLMSI SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesIMSIWithLMSI", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	{
		ber.MarkPreflightTarget(opts, "imsi", content[offset:])
		val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "imsi", "decoding", false)
		}
		v.Imsi = CommonDataTypesIMSI(val_imsi)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode lmsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field lmsi")
	}
	{
		ber.MarkPreflightTarget(opts, "lmsi", content[offset:])
		val_lmsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "lmsi", "decoding", false)
		}
		v.Lmsi = CommonDataTypesLMSI(val_lmsi)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesIMSIWithLMSI", Cause: extErr_}
		}
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

// MarshalBER encodes CommonDataTypesSubscriberId to BER format.
func (v *CommonDataTypesSubscriberId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesSubscriberId receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesSubscriberId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *CommonDataTypesSubscriberId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CommonDataTypesSubscriberIdChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesSubscriberId: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "imsi", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case CommonDataTypesSubscriberIdChoiceTmsi:
		if v.Tmsi == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesSubscriberId: tmsi is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Tmsi))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "tmsi", "encoding", false)
		}
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "tmsi", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesSubscriberId", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesSubscriberId to DER format.
func (v *CommonDataTypesSubscriberId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesSubscriberId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case CommonDataTypesSubscriberIdChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case CommonDataTypesSubscriberIdChoiceTmsi:
			return nil, qualifyBERError(err, "tmsi", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesSubscriberId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *CommonDataTypesSubscriberId) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesSubscriberId from BER/DER format.
func (v *CommonDataTypesSubscriberId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesSubscriberId destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesSubscriberId, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesSubscriberId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesSubscriberId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesSubscriberId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesSubscriberId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesSubscriberId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesSubscriberId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CommonDataTypesSubscriberIdChoiceImsi
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
		tmp := CommonDataTypesIMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CommonDataTypesSubscriberIdChoiceTmsi
		ber.MarkPreflightTarget(opts, "tmsi", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "tmsi", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "tmsi", "decoding", false)
		}
		tmp := CommonDataTypesTMSI(decVal)
		v.Tmsi = &tmp
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesSubscriberId CHOICE", peekTag)
	}
	return nil
}

// MarshalBERCommonDataTypesHLRList encodes a CommonDataTypesHLRList list to BER.
func MarshalBERCommonDataTypesHLRList(collection *CommonDataTypesHLRList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	if collection.berReplayNode_ == nil {
		return marshalBERCommonDataTypesHLRList(collection, opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(collection.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) {
		return MarshalBERCommonDataTypesHLRList(collection, []ber.EncodeOption{mode}...)
	}, collection)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(collection.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := marshalBERCommonDataTypesHLRList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, collection.berReplayNode_, opts), nil
}
func marshalBERCommonDataTypesHLRList(collection *CommonDataTypesHLRList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "HLR-List", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 3 || len(elem) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (3..8)", len(elem)); constraintErr != nil {
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

func appendBERLinearCommonDataTypesHLRList(encoder *ber.LinearEncoder, collection *CommonDataTypesHLRList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERCommonDataTypesHLRList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERCommonDataTypesHLRList encodes a CommonDataTypesHLRList list to DER.
func MarshalDERCommonDataTypesHLRList(collection *CommonDataTypesHLRList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "HLR-List", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 3 || len(elem) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (3..8)", len(elem)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesHLRList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearCommonDataTypesHLRList(encoder *ber.LinearEncoder, collection *CommonDataTypesHLRList) ([]byte, error) {
	encoded, err := MarshalDERCommonDataTypesHLRList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERCommonDataTypesHLRList decodes a CommonDataTypesHLRList list from BER.
func UnmarshalBERCommonDataTypesHLRList(data []byte, opts ...ber.DecodeOption) (returnValue *CommonDataTypesHLRList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERCommonDataTypesHLRList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding CommonDataTypesHLRList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesHLRList", Cause: ber.ErrExtraData}
	}
	var result []CommonDataTypesHLRId
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
		if len(val) < 3 || len(val) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (3..8)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, CommonDataTypesHLRId(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "HLR-List", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &CommonDataTypesHLRList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		decoded.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		if replayErr := ber.CompleteGeneratedBERDecode(opts, decoded, func(base *CommonDataTypesHLRList, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return MarshalBERCommonDataTypesHLRList(base, replayOpts...)
		}); replayErr != nil {
			return nil, replayErr
		}
	}
	return decoded, nil
}

// MarshalBER encodes CommonDataTypesNAEAPreferredCI to BER format.
func (v *CommonDataTypesNAEAPreferredCI) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesNAEAPreferredCI receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesNAEAPreferredCI) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.NaeaPreferredCIC) < 3 || len(v.NaeaPreferredCIC) > 3 {
		if constraintErr := ber.CheckEncodedLength(opts, "naea-PreferredCIC", "SIZE (3)", len(v.NaeaPreferredCIC)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_naeapreferredcic, encodeErr_enc_naeapreferredcic := ber.EncodeOctetString([]byte(v.NaeaPreferredCIC))
	if encodeErr_enc_naeapreferredcic != nil {
		return nil, qualifyBERError(encodeErr_enc_naeapreferredcic, "naea-PreferredCIC", "encoding", false)
	}
	retagged_enc_naeapreferredcic, tagErr_enc_naeapreferredcic := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naeapreferredcic)
	if tagErr_enc_naeapreferredcic != nil {
		return nil, qualifyBERError(tagErr_enc_naeapreferredcic, "naea-PreferredCIC", "encoding", false)
	}
	enc_naeapreferredcic = retagged_enc_naeapreferredcic
	children = append(children, enc_naeapreferredcic...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CommonDataTypesNAEAPreferredCI) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CommonDataTypesNAEAPreferredCI to DER format.
func (v *CommonDataTypesNAEAPreferredCI) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesNAEAPreferredCI receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.NaeaPreferredCIC) < 3 || len(v.NaeaPreferredCIC) > 3 {
		if constraintErr := ber.CheckEncodedLength(nil, "naea-PreferredCIC", "SIZE (3)", len(v.NaeaPreferredCIC)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_naeapreferredcic, encodeErr_enc_naeapreferredcic := ber.EncodeOctetString([]byte(v.NaeaPreferredCIC))
	if encodeErr_enc_naeapreferredcic != nil {
		return nil, qualifyBERError(encodeErr_enc_naeapreferredcic, "naea-PreferredCIC", "encoding", true)
	}
	retagged_enc_naeapreferredcic, tagErr_enc_naeapreferredcic := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naeapreferredcic)
	if tagErr_enc_naeapreferredcic != nil {
		return nil, qualifyBERError(tagErr_enc_naeapreferredcic, "naea-PreferredCIC", "encoding", true)
	}
	enc_naeapreferredcic = retagged_enc_naeapreferredcic
	children = append(children, enc_naeapreferredcic...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesNAEAPreferredCI as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CommonDataTypesNAEAPreferredCI) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesNAEAPreferredCI from BER/DER format.
func (v *CommonDataTypesNAEAPreferredCI) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesNAEAPreferredCI destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesNAEAPreferredCI
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesNAEAPreferredCI{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesNAEAPreferredCI, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesNAEAPreferredCI SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "naea-PreferredCIC", content[offset:])
		decodedTag_naeapreferredcic, n_naeapreferredcic, rawVal_naeapreferredcic, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "naea-PreferredCIC", "decoding", false)
		}
		if decodedTag_naeapreferredcic.Class != tag.ClassContextSpecific || decodedTag_naeapreferredcic.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naeapreferredcic), "naea-PreferredCIC", "decoding", false)
		}
		decVal_naeapreferredcic, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_naeapreferredcic.Constructed, rawVal_naeapreferredcic, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "naea-PreferredCIC", "decoding", false)
		}
		v.NaeaPreferredCIC = CommonDataTypesNAEACIC(decVal_naeapreferredcic)
		if offset > len(content) || n_naeapreferredcic < 0 || n_naeapreferredcic > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_naeapreferredcic
		if len(v.NaeaPreferredCIC) < 3 || len(v.NaeaPreferredCIC) > 3 {
			if constraintErr := ber.CheckDecodedLength(opts, "naea-PreferredCIC", "SIZE (3)", len(v.NaeaPreferredCIC)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesNAEAPreferredCI", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesNAEAPreferredCI", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
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

// MarshalBER encodes CommonDataTypesSubscriberIdentity to BER format.
func (v *CommonDataTypesSubscriberIdentity) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesSubscriberIdentity receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesSubscriberIdentity) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *CommonDataTypesSubscriberIdentity) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CommonDataTypesSubscriberIdentityChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesSubscriberIdentity: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "imsi", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case CommonDataTypesSubscriberIdentityChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesSubscriberIdentity: msisdn is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "msisdn", "encoding", false)
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "msisdn", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesSubscriberIdentity", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesSubscriberIdentity to DER format.
func (v *CommonDataTypesSubscriberIdentity) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesSubscriberIdentity receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case CommonDataTypesSubscriberIdentityChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case CommonDataTypesSubscriberIdentityChoiceMsisdn:
			return nil, qualifyBERError(err, "msisdn", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesSubscriberIdentity as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *CommonDataTypesSubscriberIdentity) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesSubscriberIdentity from BER/DER format.
func (v *CommonDataTypesSubscriberIdentity) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesSubscriberIdentity destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesSubscriberIdentity, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesSubscriberIdentity
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesSubscriberIdentity{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesSubscriberIdentity CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesSubscriberIdentity: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesSubscriberIdentity CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesSubscriberIdentity", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CommonDataTypesSubscriberIdentityChoiceImsi
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
		tmp := CommonDataTypesIMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CommonDataTypesSubscriberIdentityChoiceMsisdn
		ber.MarkPreflightTarget(opts, "msisdn", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "msisdn", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msisdn", "decoding", false)
		}
		tmp := CommonDataTypesISDNAddressString(decVal)
		v.Msisdn = &tmp
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesSubscriberIdentity CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CommonDataTypesLCSClientExternalID to BER format.
func (v *CommonDataTypesLCSClientExternalID) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesLCSClientExternalID receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesLCSClientExternalID) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExternalAddress != nil {
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "externalAddress", "SIZE (1..9)", len(*v.ExternalAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "externalAddress", "SIZE (1..20)", len(*v.ExternalAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_externaladdress, encodeErr_enc_externaladdress := ber.EncodeOctetString([]byte(*v.ExternalAddress))
		if encodeErr_enc_externaladdress != nil {
			return nil, qualifyBERError(encodeErr_enc_externaladdress, "externalAddress", "encoding", false)
		}
		retagged_enc_externaladdress, tagErr_enc_externaladdress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_externaladdress)
		if tagErr_enc_externaladdress != nil {
			return nil, qualifyBERError(tagErr_enc_externaladdress, "externalAddress", "encoding", false)
		}
		enc_externaladdress = retagged_enc_externaladdress
		children = append(children, enc_externaladdress...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CommonDataTypesLCSClientExternalID) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CommonDataTypesLCSClientExternalID to DER format.
func (v *CommonDataTypesLCSClientExternalID) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesLCSClientExternalID receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExternalAddress != nil {
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "externalAddress", "SIZE (1..9)", len(*v.ExternalAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "externalAddress", "SIZE (1..20)", len(*v.ExternalAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_externaladdress, encodeErr_enc_externaladdress := ber.EncodeOctetString([]byte(*v.ExternalAddress))
		if encodeErr_enc_externaladdress != nil {
			return nil, qualifyBERError(encodeErr_enc_externaladdress, "externalAddress", "encoding", true)
		}
		retagged_enc_externaladdress, tagErr_enc_externaladdress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_externaladdress)
		if tagErr_enc_externaladdress != nil {
			return nil, qualifyBERError(tagErr_enc_externaladdress, "externalAddress", "encoding", true)
		}
		enc_externaladdress = retagged_enc_externaladdress
		children = append(children, enc_externaladdress...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesLCSClientExternalID as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CommonDataTypesLCSClientExternalID) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesLCSClientExternalID from BER/DER format.
func (v *CommonDataTypesLCSClientExternalID) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesLCSClientExternalID destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesLCSClientExternalID
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesLCSClientExternalID{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesLCSClientExternalID, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesLCSClientExternalID SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "externalAddress", content[offset:])
				decodedTag_externaladdress, n_externaladdress, rawVal_externaladdress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "externalAddress", "decoding", false)
				}
				if decodedTag_externaladdress.Class != tag.ClassContextSpecific || decodedTag_externaladdress.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_externaladdress), "externalAddress", "decoding", false)
				}
				decVal_externaladdress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_externaladdress.Constructed, rawVal_externaladdress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "externalAddress", "decoding", false)
				}
				tmp_externaladdress := CommonDataTypesISDNAddressString(decVal_externaladdress)
				v.ExternalAddress = &tmp_externaladdress
				if offset > len(content) || n_externaladdress < 0 || n_externaladdress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_externaladdress
				if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "externalAddress", "SIZE (1..9)", len(*v.ExternalAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "externalAddress", "SIZE (1..20)", len(*v.ExternalAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesLCSClientExternalID", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesLCSClientExternalID", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
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

// MarshalBER encodes CommonDataTypesNetworkNodeDiameterAddress to BER format.
func (v *CommonDataTypesNetworkNodeDiameterAddress) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesNetworkNodeDiameterAddress receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesNetworkNodeDiameterAddress) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.DiameterName) < 9 || len(v.DiameterName) > 255 {
		if constraintErr := ber.CheckEncodedLength(opts, "diameter-Name", "SIZE (9..255)", len(v.DiameterName)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_diametername, encodeErr_enc_diametername := ber.EncodeOctetString([]byte(v.DiameterName))
	if encodeErr_enc_diametername != nil {
		return nil, qualifyBERError(encodeErr_enc_diametername, "diameter-Name", "encoding", false)
	}
	retagged_enc_diametername, tagErr_enc_diametername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_diametername)
	if tagErr_enc_diametername != nil {
		return nil, qualifyBERError(tagErr_enc_diametername, "diameter-Name", "encoding", false)
	}
	enc_diametername = retagged_enc_diametername
	children = append(children, enc_diametername...)
	if len(v.DiameterRealm) < 9 || len(v.DiameterRealm) > 255 {
		if constraintErr := ber.CheckEncodedLength(opts, "diameter-Realm", "SIZE (9..255)", len(v.DiameterRealm)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_diameterrealm, encodeErr_enc_diameterrealm := ber.EncodeOctetString([]byte(v.DiameterRealm))
	if encodeErr_enc_diameterrealm != nil {
		return nil, qualifyBERError(encodeErr_enc_diameterrealm, "diameter-Realm", "encoding", false)
	}
	retagged_enc_diameterrealm, tagErr_enc_diameterrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_diameterrealm)
	if tagErr_enc_diameterrealm != nil {
		return nil, qualifyBERError(tagErr_enc_diameterrealm, "diameter-Realm", "encoding", false)
	}
	enc_diameterrealm = retagged_enc_diameterrealm
	children = append(children, enc_diameterrealm...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CommonDataTypesNetworkNodeDiameterAddress) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CommonDataTypesNetworkNodeDiameterAddress to DER format.
func (v *CommonDataTypesNetworkNodeDiameterAddress) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesNetworkNodeDiameterAddress receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.DiameterName) < 9 || len(v.DiameterName) > 255 {
		if constraintErr := ber.CheckEncodedLength(nil, "diameter-Name", "SIZE (9..255)", len(v.DiameterName)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_diametername, encodeErr_enc_diametername := ber.EncodeOctetString([]byte(v.DiameterName))
	if encodeErr_enc_diametername != nil {
		return nil, qualifyBERError(encodeErr_enc_diametername, "diameter-Name", "encoding", true)
	}
	retagged_enc_diametername, tagErr_enc_diametername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_diametername)
	if tagErr_enc_diametername != nil {
		return nil, qualifyBERError(tagErr_enc_diametername, "diameter-Name", "encoding", true)
	}
	enc_diametername = retagged_enc_diametername
	children = append(children, enc_diametername...)
	if len(v.DiameterRealm) < 9 || len(v.DiameterRealm) > 255 {
		if constraintErr := ber.CheckEncodedLength(nil, "diameter-Realm", "SIZE (9..255)", len(v.DiameterRealm)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_diameterrealm, encodeErr_enc_diameterrealm := ber.EncodeOctetString([]byte(v.DiameterRealm))
	if encodeErr_enc_diameterrealm != nil {
		return nil, qualifyBERError(encodeErr_enc_diameterrealm, "diameter-Realm", "encoding", true)
	}
	retagged_enc_diameterrealm, tagErr_enc_diameterrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_diameterrealm)
	if tagErr_enc_diameterrealm != nil {
		return nil, qualifyBERError(tagErr_enc_diameterrealm, "diameter-Realm", "encoding", true)
	}
	enc_diameterrealm = retagged_enc_diameterrealm
	children = append(children, enc_diameterrealm...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesNetworkNodeDiameterAddress as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CommonDataTypesNetworkNodeDiameterAddress) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesNetworkNodeDiameterAddress from BER/DER format.
func (v *CommonDataTypesNetworkNodeDiameterAddress) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesNetworkNodeDiameterAddress destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesNetworkNodeDiameterAddress
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesNetworkNodeDiameterAddress{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesNetworkNodeDiameterAddress, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesNetworkNodeDiameterAddress SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesNetworkNodeDiameterAddress", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode diameter-Name
	if offset >= len(content) {
		return fmt.Errorf("missing required field diameter-Name")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for diameter-Name, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "diameter-Name", content[offset:])
		decodedTag_diametername, n_diametername, rawVal_diametername, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "diameter-Name", "decoding", false)
		}
		if decodedTag_diametername.Class != tag.ClassContextSpecific || decodedTag_diametername.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_diametername), "diameter-Name", "decoding", false)
		}
		decVal_diametername, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_diametername.Constructed, rawVal_diametername, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "diameter-Name", "decoding", false)
		}
		v.DiameterName = CommonDataTypesDiameterIdentity(decVal_diametername)
		if offset > len(content) || n_diametername < 0 || n_diametername > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_diametername
		if len(v.DiameterName) < 9 || len(v.DiameterName) > 255 {
			if constraintErr := ber.CheckDecodedLength(opts, "diameter-Name", "SIZE (9..255)", len(v.DiameterName)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode diameter-Realm
	if offset >= len(content) {
		return fmt.Errorf("missing required field diameter-Realm")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for diameter-Realm, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "diameter-Realm", content[offset:])
		decodedTag_diameterrealm, n_diameterrealm, rawVal_diameterrealm, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "diameter-Realm", "decoding", false)
		}
		if decodedTag_diameterrealm.Class != tag.ClassContextSpecific || decodedTag_diameterrealm.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_diameterrealm), "diameter-Realm", "decoding", false)
		}
		decVal_diameterrealm, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_diameterrealm.Constructed, rawVal_diameterrealm, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "diameter-Realm", "decoding", false)
		}
		v.DiameterRealm = CommonDataTypesDiameterIdentity(decVal_diameterrealm)
		if offset < 0 || offset >
			len(content) || n_diameterrealm < 0 || n_diameterrealm > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_diameterrealm
		if len(v.DiameterRealm) < 9 || len(v.DiameterRealm) > 255 {
			if constraintErr := ber.CheckDecodedLength(opts, "diameter-Realm", "SIZE (9..255)", len(v.DiameterRealm)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesNetworkNodeDiameterAddress", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI to BER format.
func (v *CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength:
		if v.CellGlobalIdOrServiceAreaIdFixedLength == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI: cellGlobalIdOrServiceAreaIdFixedLength is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.CellGlobalIdOrServiceAreaIdFixedLength))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "cellGlobalIdOrServiceAreaIdFixedLength", "encoding", false)
		}
		if len(*v.CellGlobalIdOrServiceAreaIdFixedLength) < 7 || len(*v.CellGlobalIdOrServiceAreaIdFixedLength) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "cellGlobalIdOrServiceAreaIdFixedLength", "SIZE (7)", len(*v.CellGlobalIdOrServiceAreaIdFixedLength)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "cellGlobalIdOrServiceAreaIdFixedLength", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength:
		if v.LaiFixedLength == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI: laiFixedLength is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.LaiFixedLength))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "laiFixedLength", "encoding", false)
		}
		if len(*v.LaiFixedLength) < 5 || len(*v.LaiFixedLength) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "laiFixedLength", "SIZE (5)", len(*v.LaiFixedLength)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "laiFixedLength", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI to DER format.
func (v *CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength:
			return nil, qualifyBERError(err, "cellGlobalIdOrServiceAreaIdFixedLength", "encoding", true)
		case CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength:
			return nil, qualifyBERError(err, "laiFixedLength", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI from BER/DER format.
func (v *CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength
		ber.MarkPreflightTarget(opts, "cellGlobalIdOrServiceAreaIdFixedLength", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "cellGlobalIdOrServiceAreaIdFixedLength", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "cellGlobalIdOrServiceAreaIdFixedLength", "decoding", false)
		}
		tmp := CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength(decVal)
		v.CellGlobalIdOrServiceAreaIdFixedLength = &tmp
		if len(*v.CellGlobalIdOrServiceAreaIdFixedLength) < 7 || len(*v.CellGlobalIdOrServiceAreaIdFixedLength) > 7 {
			if constraintErr := ber.CheckDecodedLength(opts, "cellGlobalIdOrServiceAreaIdFixedLength", "SIZE (7)", len(*v.CellGlobalIdOrServiceAreaIdFixedLength)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength
		ber.MarkPreflightTarget(opts, "laiFixedLength", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "laiFixedLength", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "laiFixedLength", "decoding", false)
		}
		tmp := CommonDataTypesLAIFixedLength(decVal)
		v.LaiFixedLength = &tmp
		if len(*v.LaiFixedLength) < 5 || len(*v.LaiFixedLength) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "laiFixedLength", "SIZE (5)", len(*v.LaiFixedLength)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CommonDataTypesBasicServiceCode to BER format.
func (v *CommonDataTypesBasicServiceCode) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesBasicServiceCode receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesBasicServiceCode) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *CommonDataTypesBasicServiceCode) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CommonDataTypesBasicServiceCodeChoiceBearerService:
		if v.BearerService == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesBasicServiceCode: bearerService is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.BearerService))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "bearerService", "encoding", false)
		}
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "bearerService", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case CommonDataTypesBasicServiceCodeChoiceTeleservice:
		if v.Teleservice == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesBasicServiceCode: teleservice is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Teleservice))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "teleservice", "encoding", false)
		}
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "teleservice", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesBasicServiceCode", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesBasicServiceCode to DER format.
func (v *CommonDataTypesBasicServiceCode) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesBasicServiceCode receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case CommonDataTypesBasicServiceCodeChoiceBearerService:
			return nil, qualifyBERError(err, "bearerService", "encoding", true)
		case CommonDataTypesBasicServiceCodeChoiceTeleservice:
			return nil, qualifyBERError(err, "teleservice", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesBasicServiceCode as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *CommonDataTypesBasicServiceCode) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesBasicServiceCode from BER/DER format.
func (v *CommonDataTypesBasicServiceCode) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesBasicServiceCode destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesBasicServiceCode, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesBasicServiceCode
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesBasicServiceCode{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesBasicServiceCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesBasicServiceCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesBasicServiceCode CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesBasicServiceCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = CommonDataTypesBasicServiceCodeChoiceBearerService
		ber.MarkPreflightTarget(opts, "bearerService", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "bearerService", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "bearerService", "decoding", false)
		}
		tmp := v21_map_bs_code.BSBearerServiceCode(decVal)
		v.BearerService = &tmp
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = CommonDataTypesBasicServiceCodeChoiceTeleservice
		ber.MarkPreflightTarget(opts, "teleservice", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "teleservice", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "teleservice", "decoding", false)
		}
		tmp := v21_map_ts_code.TSTeleserviceCode(decVal)
		v.Teleservice = &tmp
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesBasicServiceCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CommonDataTypesExtBasicServiceCode to BER format.
func (v *CommonDataTypesExtBasicServiceCode) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesExtBasicServiceCode receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesExtBasicServiceCode) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *CommonDataTypesExtBasicServiceCode) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CommonDataTypesExtBasicServiceCodeChoiceExtBearerService:
		if v.ExtBearerService == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesExtBasicServiceCode: ext-BearerService is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.ExtBearerService))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "ext-BearerService", "encoding", false)
		}
		if len(*v.ExtBearerService) < 1 || len(*v.ExtBearerService) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "ext-BearerService", "SIZE (1..5)", len(*v.ExtBearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "ext-BearerService", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case CommonDataTypesExtBasicServiceCodeChoiceExtTeleservice:
		if v.ExtTeleservice == nil {
			return nil, fmt.Errorf("%w: choice CommonDataTypesExtBasicServiceCode: ext-Teleservice is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.ExtTeleservice))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "ext-Teleservice", "encoding", false)
		}
		if len(*v.ExtTeleservice) < 1 || len(*v.ExtTeleservice) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "ext-Teleservice", "SIZE (1..5)", len(*v.ExtTeleservice)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "ext-Teleservice", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CommonDataTypesExtBasicServiceCode", v.Choice)
	}
}

// MarshalDER encodes CommonDataTypesExtBasicServiceCode to DER format.
func (v *CommonDataTypesExtBasicServiceCode) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesExtBasicServiceCode receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case CommonDataTypesExtBasicServiceCodeChoiceExtBearerService:
			return nil, qualifyBERError(err, "ext-BearerService", "encoding", true)
		case CommonDataTypesExtBasicServiceCodeChoiceExtTeleservice:
			return nil, qualifyBERError(err, "ext-Teleservice", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesExtBasicServiceCode as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *CommonDataTypesExtBasicServiceCode) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesExtBasicServiceCode from BER/DER format.
func (v *CommonDataTypesExtBasicServiceCode) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesExtBasicServiceCode destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesExtBasicServiceCode, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesExtBasicServiceCode
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesExtBasicServiceCode{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CommonDataTypesExtBasicServiceCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CommonDataTypesExtBasicServiceCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesExtBasicServiceCode CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesExtBasicServiceCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = CommonDataTypesExtBasicServiceCodeChoiceExtBearerService
		ber.MarkPreflightTarget(opts, "ext-BearerService", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "ext-BearerService", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ext-BearerService", "decoding", false)
		}
		tmp := v21_map_bs_code.BSExtBearerServiceCode(decVal)
		v.ExtBearerService = &tmp
		if len(*v.ExtBearerService) < 1 || len(*v.ExtBearerService) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "ext-BearerService", "SIZE (1..5)", len(*v.ExtBearerService)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = CommonDataTypesExtBasicServiceCodeChoiceExtTeleservice
		ber.MarkPreflightTarget(opts, "ext-Teleservice", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "ext-Teleservice", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ext-Teleservice", "decoding", false)
		}
		tmp := v21_map_ts_code.TSExtTeleserviceCode(decVal)
		v.ExtTeleservice = &tmp
		if len(*v.ExtTeleservice) < 1 || len(*v.ExtTeleservice) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "ext-Teleservice", "SIZE (1..5)", len(*v.ExtTeleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for CommonDataTypesExtBasicServiceCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CommonDataTypesEMLPPInfo to BER format.
func (v *CommonDataTypesEMLPPInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesEMLPPInfo receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesEMLPPInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.MaximumentitledPriority) >= 0 && int64(v.MaximumentitledPriority) <= 15) {
		if constraintErr := ber.CheckEncodedValue(opts, "maximumentitledPriority", "(0..15)", fmt.Sprint(int64(v.MaximumentitledPriority))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_maximumentitledpriority := ber.EncodeInteger(int64(v.MaximumentitledPriority))
	children = append(children, enc_maximumentitledpriority...)
	if !(int64(v.DefaultPriority) >= 0 && int64(v.DefaultPriority) <= 15) {
		if constraintErr := ber.CheckEncodedValue(opts, "defaultPriority", "(0..15)", fmt.Sprint(int64(v.DefaultPriority))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_defaultpriority := ber.EncodeInteger(int64(v.DefaultPriority))
	children = append(children, enc_defaultpriority...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CommonDataTypesEMLPPInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CommonDataTypesEMLPPInfo to DER format.
func (v *CommonDataTypesEMLPPInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesEMLPPInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.MaximumentitledPriority) >= 0 && int64(v.MaximumentitledPriority) <= 15) {
		if constraintErr := ber.CheckEncodedValue(nil, "maximumentitledPriority", "(0..15)", fmt.Sprint(int64(v.MaximumentitledPriority))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_maximumentitledpriority := ber.EncodeInteger(int64(v.MaximumentitledPriority))
	children = append(children, enc_maximumentitledpriority...)
	if !(int64(v.DefaultPriority) >= 0 && int64(v.DefaultPriority) <= 15) {
		if constraintErr := ber.CheckEncodedValue(nil, "defaultPriority", "(0..15)", fmt.Sprint(int64(v.DefaultPriority))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_defaultpriority := ber.EncodeInteger(int64(v.DefaultPriority))
	children = append(children, enc_defaultpriority...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesEMLPPInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CommonDataTypesEMLPPInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesEMLPPInfo from BER/DER format.
func (v *CommonDataTypesEMLPPInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesEMLPPInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesEMLPPInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesEMLPPInfo{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesEMLPPInfo, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesEMLPPInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesEMLPPInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode maximumentitledPriority
	if offset >= len(content) {
		return fmt.Errorf("missing required field maximumentitledPriority")
	}
	{
		ber.MarkPreflightTarget(opts, "maximumentitledPriority", content[offset:])
		val_maximumentitledpriority, n, err := ber.DecodeInteger(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "maximumentitledPriority", "decoding", false)
		}
		v.MaximumentitledPriority = CommonDataTypesEMLPPPriority(val_maximumentitledpriority)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.MaximumentitledPriority) >= 0 && int64(v.MaximumentitledPriority) <= 15) {
			if constraintErr := ber.CheckDecodedValue(opts, "maximumentitledPriority", "(0..15)", fmt.Sprint(int64(v.MaximumentitledPriority))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode defaultPriority
	if offset >= len(content) {
		return fmt.Errorf("missing required field defaultPriority")
	}
	{
		ber.MarkPreflightTarget(opts, "defaultPriority", content[offset:])
		val_defaultpriority, n, err := ber.DecodeInteger(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "defaultPriority", "decoding", false)
		}
		v.DefaultPriority = CommonDataTypesEMLPPPriority(val_defaultpriority)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.DefaultPriority) >= 0 && int64(v.DefaultPriority) <= 15) {
			if constraintErr := ber.CheckDecodedValue(opts, "defaultPriority", "(0..15)", fmt.Sprint(int64(v.DefaultPriority))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesEMLPPInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesEMLPPInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
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

// MarshalBER encodes CommonDataTypesMCSSInfo to BER format.
func (v *CommonDataTypesMCSSInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesMCSSInfo receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *CommonDataTypesMCSSInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", false)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 5 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", false)
	}
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", false)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	if !(int64(v.NbrSB) >= 2 && int64(v.NbrSB) <= 7) {
		if constraintErr := ber.CheckEncodedValue(opts, "nbrSB", "(2..7)", fmt.Sprint(int64(v.NbrSB))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_nbrsb := ber.EncodeInteger(int64(v.NbrSB))
	retagged_enc_nbrsb, tagErr_enc_nbrsb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_nbrsb)
	if tagErr_enc_nbrsb != nil {
		return nil, qualifyBERError(tagErr_enc_nbrsb, "nbrSB", "encoding", false)
	}
	enc_nbrsb = retagged_enc_nbrsb
	children = append(children, enc_nbrsb...)
	if !(int64(v.NbrUser) >= 1 && int64(v.NbrUser) <= 7) {
		if constraintErr := ber.CheckEncodedValue(opts, "nbrUser", "(1..7)", fmt.Sprint(int64(v.NbrUser))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_nbruser := ber.EncodeInteger(int64(v.NbrUser))
	retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_nbruser)
	if tagErr_enc_nbruser != nil {
		return nil, qualifyBERError(tagErr_enc_nbruser, "nbrUser", "encoding", false)
	}
	enc_nbruser = retagged_enc_nbruser
	children = append(children, enc_nbruser...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CommonDataTypesMCSSInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CommonDataTypesMCSSInfo to DER format.
func (v *CommonDataTypesMCSSInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesMCSSInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", true)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 5 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", true)
	}
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", true)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	if !(int64(v.NbrSB) >= 2 && int64(v.NbrSB) <= 7) {
		if constraintErr := ber.CheckEncodedValue(nil, "nbrSB", "(2..7)", fmt.Sprint(int64(v.NbrSB))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_nbrsb := ber.EncodeInteger(int64(v.NbrSB))
	retagged_enc_nbrsb, tagErr_enc_nbrsb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_nbrsb)
	if tagErr_enc_nbrsb != nil {
		return nil, qualifyBERError(tagErr_enc_nbrsb, "nbrSB", "encoding", true)
	}
	enc_nbrsb = retagged_enc_nbrsb
	children = append(children, enc_nbrsb...)
	if !(int64(v.NbrUser) >= 1 && int64(v.NbrUser) <= 7) {
		if constraintErr := ber.CheckEncodedValue(nil, "nbrUser", "(1..7)", fmt.Sprint(int64(v.NbrUser))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_nbruser := ber.EncodeInteger(int64(v.NbrUser))
	retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_nbruser)
	if tagErr_enc_nbruser != nil {
		return nil, qualifyBERError(tagErr_enc_nbruser, "nbrUser", "encoding", true)
	}
	enc_nbruser = retagged_enc_nbruser
	children = append(children, enc_nbruser...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CommonDataTypesMCSSInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CommonDataTypesMCSSInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CommonDataTypesMCSSInfo from BER/DER format.
func (v *CommonDataTypesMCSSInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesMCSSInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CommonDataTypesMCSSInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = CommonDataTypesMCSSInfo{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *CommonDataTypesMCSSInfo, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CommonDataTypesMCSSInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
		decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Code", "decoding", false)
		}
		if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode), "ss-Code", "decoding", false)
		}
		decVal_sscode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sscode.Constructed, rawVal_sscode, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ss-Code", "decoding", false)
		}
		v.SsCode = v21_map_ss_code.SSSSCode(decVal_sscode)
		if offset > len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_sscode
		if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ss-Status
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Status")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for ss-Status, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "ss-Status", content[offset:])
		decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Status", "decoding", false)
		}
		if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus), "ss-Status", "decoding", false)
		}
		decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ss-Status", "decoding", false)
		}
		v.SsStatus = CommonDataTypesExtSSStatus(decVal_ssstatus)
		if offset < 0 || offset >
			len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_ssstatus
		if len(v.SsStatus) < 1 || len(v.SsStatus) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode nbrSB
	if offset >= len(content) {
		return fmt.Errorf("missing required field nbrSB")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for nbrSB, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "nbrSB", content[offset:])
		decodedTag_nbrsb, n_nbrsb, rawVal_nbrsb, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "nbrSB", "decoding", false)
		}
		if decodedTag_nbrsb.Class != tag.ClassContextSpecific || decodedTag_nbrsb.Number != 2 || decodedTag_nbrsb.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbrsb), "nbrSB", "decoding", false)
		}
		decVal_nbrsb, intErr := ber.DecodeIntegerValue(rawVal_nbrsb)
		if intErr != nil {
			return qualifyBERError(intErr, "nbrSB", "decoding", false)
		}
		v.NbrSB = CommonDataTypesMaxMCBearers(decVal_nbrsb)
		if offset < 0 || offset >
			len(content) || n_nbrsb < 0 || n_nbrsb > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_nbrsb
		if !(int64(v.NbrSB) >= 2 && int64(v.NbrSB) <= 7) {
			if constraintErr := ber.CheckDecodedValue(opts, "nbrSB", "(2..7)", fmt.Sprint(int64(v.NbrSB))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode nbrUser
	if offset >= len(content) {
		return fmt.Errorf("missing required field nbrUser")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for nbrUser, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "nbrUser", content[offset:])
		decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "nbrUser", "decoding", false)
		}
		if decodedTag_nbruser.Class != tag.ClassContextSpecific || decodedTag_nbruser.Number != 3 || decodedTag_nbruser.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbruser), "nbrUser", "decoding", false)
		}
		decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
		if intErr != nil {
			return qualifyBERError(intErr, "nbrUser", "decoding", false)
		}
		v.NbrUser = CommonDataTypesMCBearers(decVal_nbruser)
		if offset < 0 || offset >
			len(content) || n_nbruser < 0 || n_nbruser > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_nbruser
		if !(int64(v.NbrUser) >= 1 && int64(v.NbrUser) <= 7) {
			if constraintErr := ber.CheckDecodedValue(opts, "nbrUser", "(1..7)", fmt.Sprint(int64(v.NbrUser))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesMCSSInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesMCSSInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
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
