// Code generated from ASN.1 module "MAP-CommonDataTypes". DO NOT EDIT.

package gsm_map

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

	// MaxAddressLength is the integer constant for maxAddressLength.
	MaxAddressLength int64 = 20

	// MaxISDNAddressLength is the integer constant for maxISDN-AddressLength.
	MaxISDNAddressLength int64 = 9

	// MaxFTNAddressLength is the integer constant for maxFTN-AddressLength.
	MaxFTNAddressLength int64 = 15

	// MaxISDNSubaddressLength is the integer constant for maxISDN-SubaddressLength.
	MaxISDNSubaddressLength int64 = 21

	// MaxSignalInfoLength is the integer constant for maxSignalInfoLength.
	MaxSignalInfoLength int64 = 200

	// MaxLongSignalInfoLength is the integer constant for maxLongSignalInfoLength.
	MaxLongSignalInfoLength int64 = 2560

	// AlertingLevel0 is the octet string constant for alertingLevel-0.
	AlertingLevel0 = "\x00"

	// AlertingLevel1 is the octet string constant for alertingLevel-1.
	AlertingLevel1 = "\x01"

	// AlertingLevel2 is the octet string constant for alertingLevel-2.
	AlertingLevel2 = "\x02"

	// AlertingCategory1 is the octet string constant for alertingCategory-1.
	AlertingCategory1 = "\x04"

	// AlertingCategory2 is the octet string constant for alertingCategory-2.
	AlertingCategory2 = "\x05"

	// AlertingCategory3 is the octet string constant for alertingCategory-3.
	AlertingCategory3 = "\x06"

	// AlertingCategory4 is the octet string constant for alertingCategory-4.
	AlertingCategory4 = "\x07"

	// AlertingCategory5 is the octet string constant for alertingCategory-5.
	AlertingCategory5 = "\x08"

	// MaxNumOfHLRId is the integer constant for maxNumOfHLR-Id.
	MaxNumOfHLRId int64 = 50

	// EmergencyServices is the integer constant for emergencyServices.
	EmergencyServices int64 = 0

	// EmergencyAlertServices is the integer constant for emergencyAlertServices.
	EmergencyAlertServices int64 = 1

	// PersonTracking is the integer constant for personTracking.
	PersonTracking int64 = 2

	// FleetManagement is the integer constant for fleetManagement.
	FleetManagement int64 = 3

	// AssetManagement is the integer constant for assetManagement.
	AssetManagement int64 = 4

	// TrafficCongestionReporting is the integer constant for trafficCongestionReporting.
	TrafficCongestionReporting int64 = 5

	// RoadsideAssistance is the integer constant for roadsideAssistance.
	RoadsideAssistance int64 = 6

	// RoutingToNearestCommercialEnterprise is the integer constant for routingToNearestCommercialEnterprise.
	RoutingToNearestCommercialEnterprise int64 = 7

	// Navigation is the integer constant for navigation.
	Navigation int64 = 8

	// CitySightseeing is the integer constant for citySightseeing.
	CitySightseeing int64 = 9

	// LocalizedAdvertising is the integer constant for localizedAdvertising.
	LocalizedAdvertising int64 = 10

	// MobileYellowPages is the integer constant for mobileYellowPages.
	MobileYellowPages int64 = 11

	// TrafficAndPublicTransportationInfo is the integer constant for trafficAndPublicTransportationInfo.
	TrafficAndPublicTransportationInfo int64 = 12

	// Weather is the integer constant for weather.
	Weather int64 = 13

	// AssetAndServiceFinding is the integer constant for assetAndServiceFinding.
	AssetAndServiceFinding int64 = 14

	// Gaming is the integer constant for gaming.
	Gaming int64 = 15

	// FindYourFriend is the integer constant for findYourFriend.
	FindYourFriend int64 = 16

	// Dating is the integer constant for dating.
	Dating int64 = 17

	// Chatting is the integer constant for chatting.
	Chatting int64 = 18

	// RouteFinding is the integer constant for routeFinding.
	RouteFinding int64 = 19

	// WhereAmI is the integer constant for whereAmI.
	WhereAmI int64 = 20

	// Serv64 is the integer constant for serv64.
	Serv64 int64 = 64

	// Serv65 is the integer constant for serv65.
	Serv65 int64 = 65

	// Serv66 is the integer constant for serv66.
	Serv66 int64 = 66

	// Serv67 is the integer constant for serv67.
	Serv67 int64 = 67

	// Serv68 is the integer constant for serv68.
	Serv68 int64 = 68

	// Serv69 is the integer constant for serv69.
	Serv69 int64 = 69

	// Serv70 is the integer constant for serv70.
	Serv70 int64 = 70

	// Serv71 is the integer constant for serv71.
	Serv71 int64 = 71

	// Serv72 is the integer constant for serv72.
	Serv72 int64 = 72

	// Serv73 is the integer constant for serv73.
	Serv73 int64 = 73

	// Serv74 is the integer constant for serv74.
	Serv74 int64 = 74

	// Serv75 is the integer constant for serv75.
	Serv75 int64 = 75

	// Serv76 is the integer constant for serv76.
	Serv76 int64 = 76

	// Serv77 is the integer constant for serv77.
	Serv77 int64 = 77

	// Serv78 is the integer constant for serv78.
	Serv78 int64 = 78

	// Serv79 is the integer constant for serv79.
	Serv79 int64 = 79

	// Serv80 is the integer constant for serv80.
	Serv80 int64 = 80

	// Serv81 is the integer constant for serv81.
	Serv81 int64 = 81

	// Serv82 is the integer constant for serv82.
	Serv82 int64 = 82

	// Serv83 is the integer constant for serv83.
	Serv83 int64 = 83

	// Serv84 is the integer constant for serv84.
	Serv84 int64 = 84

	// Serv85 is the integer constant for serv85.
	Serv85 int64 = 85

	// Serv86 is the integer constant for serv86.
	Serv86 int64 = 86

	// Serv87 is the integer constant for serv87.
	Serv87 int64 = 87

	// Serv88 is the integer constant for serv88.
	Serv88 int64 = 88

	// Serv89 is the integer constant for serv89.
	Serv89 int64 = 89

	// Serv90 is the integer constant for serv90.
	Serv90 int64 = 90

	// Serv91 is the integer constant for serv91.
	Serv91 int64 = 91

	// Serv92 is the integer constant for serv92.
	Serv92 int64 = 92

	// Serv93 is the integer constant for serv93.
	Serv93 int64 = 93

	// Serv94 is the integer constant for serv94.
	Serv94 int64 = 94

	// Serv95 is the integer constant for serv95.
	Serv95 int64 = 95

	// Serv96 is the integer constant for serv96.
	Serv96 int64 = 96

	// Serv97 is the integer constant for serv97.
	Serv97 int64 = 97

	// Serv98 is the integer constant for serv98.
	Serv98 int64 = 98

	// Serv99 is the integer constant for serv99.
	Serv99 int64 = 99

	// Serv100 is the integer constant for serv100.
	Serv100 int64 = 100

	// Serv101 is the integer constant for serv101.
	Serv101 int64 = 101

	// Serv102 is the integer constant for serv102.
	Serv102 int64 = 102

	// Serv103 is the integer constant for serv103.
	Serv103 int64 = 103

	// Serv104 is the integer constant for serv104.
	Serv104 int64 = 104

	// Serv105 is the integer constant for serv105.
	Serv105 int64 = 105

	// Serv106 is the integer constant for serv106.
	Serv106 int64 = 106

	// Serv107 is the integer constant for serv107.
	Serv107 int64 = 107

	// Serv108 is the integer constant for serv108.
	Serv108 int64 = 108

	// Serv109 is the integer constant for serv109.
	Serv109 int64 = 109

	// Serv110 is the integer constant for serv110.
	Serv110 int64 = 110

	// Serv111 is the integer constant for serv111.
	Serv111 int64 = 111

	// Serv112 is the integer constant for serv112.
	Serv112 int64 = 112

	// Serv113 is the integer constant for serv113.
	Serv113 int64 = 113

	// Serv114 is the integer constant for serv114.
	Serv114 int64 = 114

	// Serv115 is the integer constant for serv115.
	Serv115 int64 = 115

	// Serv116 is the integer constant for serv116.
	Serv116 int64 = 116

	// Serv117 is the integer constant for serv117.
	Serv117 int64 = 117

	// Serv118 is the integer constant for serv118.
	Serv118 int64 = 118

	// Serv119 is the integer constant for serv119.
	Serv119 int64 = 119

	// Serv120 is the integer constant for serv120.
	Serv120 int64 = 120

	// Serv121 is the integer constant for serv121.
	Serv121 int64 = 121

	// Serv122 is the integer constant for serv122.
	Serv122 int64 = 122

	// Serv123 is the integer constant for serv123.
	Serv123 int64 = 123

	// Serv124 is the integer constant for serv124.
	Serv124 int64 = 124

	// Serv125 is the integer constant for serv125.
	Serv125 int64 = 125

	// Serv126 is the integer constant for serv126.
	Serv126 int64 = 126

	// Serv127 is the integer constant for serv127.
	Serv127 int64 = 127

	// PriorityLevelA is the integer constant for priorityLevelA.
	PriorityLevelA int64 = 6

	// PriorityLevelB is the integer constant for priorityLevelB.
	PriorityLevelB int64 = 5

	// PriorityLevel0 is the integer constant for priorityLevel0.
	PriorityLevel0 int64 = 0

	// PriorityLevel1 is the integer constant for priorityLevel1.
	PriorityLevel1 int64 = 1

	// PriorityLevel2 is the integer constant for priorityLevel2.
	PriorityLevel2 int64 = 2

	// PriorityLevel3 is the integer constant for priorityLevel3.
	PriorityLevel3 int64 = 3

	// PriorityLevel4 is the integer constant for priorityLevel4.
	PriorityLevel4 int64 = 4

	// MaxNumOfMCBearers is the integer constant for maxNumOfMC-Bearers.
	MaxNumOfMCBearers int64 = 7
)

// TBCDSTRING represents the ASN.1 type TBCD-STRING (OCTET_STRING).
type TBCDSTRING = []byte

// DiameterIdentity represents the ASN.1 type DiameterIdentity (OCTET_STRING).
type DiameterIdentity = []byte

// AddressString represents the ASN.1 type AddressString (OCTET_STRING).
type AddressString = []byte

// ISDNAddressString represents the ASN.1 type ISDN-AddressString (OCTET_STRING).
type ISDNAddressString = AddressString

// FTNAddressString represents the ASN.1 type FTN-AddressString (OCTET_STRING).
type FTNAddressString = AddressString

// ISDNSubaddressString represents the ASN.1 type ISDN-SubaddressString (OCTET_STRING).
type ISDNSubaddressString = []byte

// ExternalSignalInfo represents the ASN.1 type ExternalSignalInfo (SEQUENCE).
type ExternalSignalInfo struct {
	ProtocolId         ProtocolId          `asn1:""`
	SignalInfo         SignalInfo          `asn1:""`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SignalInfo represents the ASN.1 type SignalInfo (OCTET_STRING).
type SignalInfo = []byte

// ProtocolId represents the ASN.1 ENUMERATED type ProtocolId.
type ProtocolId int64

const (
	ProtocolIdGsm0408    ProtocolId = 1
	ProtocolIdGsm0806    ProtocolId = 2
	ProtocolIdGsmBSSMAP  ProtocolId = 3
	ProtocolIdEts3001021 ProtocolId = 4
)

func (v ProtocolId) String() string {
	switch v {
	case ProtocolIdGsm0408:
		return "gsm-0408"
	case ProtocolIdGsm0806:
		return "gsm-0806"
	case ProtocolIdGsmBSSMAP:
		return "gsm-BSSMAP"
	case ProtocolIdEts3001021:
		return "ets-300102-1"
	default:
		return "unknown"
	}
}

// ExtExternalSignalInfo represents the ASN.1 type Ext-ExternalSignalInfo (SEQUENCE).
type ExtExternalSignalInfo struct {
	ExtProtocolId      ExtProtocolId       `asn1:""`
	SignalInfo         SignalInfo          `asn1:""`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ExtProtocolId represents the ASN.1 ENUMERATED type Ext-ProtocolId.
type ExtProtocolId int64

const (
	ExtProtocolIdEts300356 ExtProtocolId = 1
)

func (v ExtProtocolId) String() string {
	switch v {
	case ExtProtocolIdEts300356:
		return "ets-300356"
	default:
		return "unknown"
	}
}

// AccessNetworkSignalInfo represents the ASN.1 type AccessNetworkSignalInfo (SEQUENCE).
type AccessNetworkSignalInfo struct {
	AccessNetworkProtocolId AccessNetworkProtocolId `asn1:""`
	SignalInfo              LongSignalInfo          `asn1:""`
	ExtensionContainer      *ExtensionContainer     `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                   `asn1:"-" json:"-"`
	ExtPresent_             []bool                  `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LongSignalInfo represents the ASN.1 type LongSignalInfo (OCTET_STRING).
type LongSignalInfo = []byte

// AccessNetworkProtocolId represents the ASN.1 ENUMERATED type AccessNetworkProtocolId.
type AccessNetworkProtocolId int64

const (
	AccessNetworkProtocolIdTs3G48006 AccessNetworkProtocolId = 1
	AccessNetworkProtocolIdTs3G25413 AccessNetworkProtocolId = 2
)

func (v AccessNetworkProtocolId) String() string {
	switch v {
	case AccessNetworkProtocolIdTs3G48006:
		return "ts3G-48006"
	case AccessNetworkProtocolIdTs3G25413:
		return "ts3G-25413"
	default:
		return "unknown"
	}
}

// AlertingPattern represents the ASN.1 type AlertingPattern (OCTET_STRING).
type AlertingPattern = []byte

// GSNAddress represents the ASN.1 type GSN-Address (OCTET_STRING).
type GSNAddress = []byte

// Time represents the ASN.1 type Time (OCTET_STRING).
type Time = []byte

// IMSI represents the ASN.1 type IMSI (OCTET_STRING).
type IMSI = TBCDSTRING

// Identity choice constants.
const (
	IdentityChoiceImsi         = 1
	IdentityChoiceImsiWithLMSI = 2
)

// Identity represents the ASN.1 CHOICE type Identity.
type Identity struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Imsi           *IMSI           `json:"Imsi,omitempty"`
	ImsiWithLMSI   *IMSIWithLMSI   `json:"ImsiWithLMSI,omitempty"`
}

// NewIdentityImsi creates a Identity with the imsi alternative.
func NewIdentityImsi(v IMSI) Identity {
	return Identity{
		Choice: IdentityChoiceImsi,
		Imsi:   &v,
	}
}

// NewIdentityImsiWithLMSI creates a Identity with the imsi-WithLMSI alternative.
func NewIdentityImsiWithLMSI(v IMSIWithLMSI) Identity {
	return Identity{
		Choice:       IdentityChoiceImsiWithLMSI,
		ImsiWithLMSI: &v,
	}
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

// ASCICallReference represents the ASN.1 type ASCI-CallReference (OCTET_STRING).
type ASCICallReference = TBCDSTRING

// TMSI represents the ASN.1 type TMSI (OCTET_STRING).
type TMSI = []byte

// SubscriberId choice constants.
const (
	SubscriberIdChoiceImsi = 1
	SubscriberIdChoiceTmsi = 2
)

// SubscriberId represents the ASN.1 CHOICE type SubscriberId.
type SubscriberId struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Imsi           *IMSI           `json:"Imsi,omitempty"`
	Tmsi           *TMSI           `json:"Tmsi,omitempty"`
}

// NewSubscriberIdImsi creates a SubscriberId with the imsi alternative.
func NewSubscriberIdImsi(v IMSI) SubscriberId {
	return SubscriberId{
		Choice: SubscriberIdChoiceImsi,
		Imsi:   &v,
	}
}

// NewSubscriberIdTmsi creates a SubscriberId with the tmsi alternative.
func NewSubscriberIdTmsi(v TMSI) SubscriberId {
	return SubscriberId{
		Choice: SubscriberIdChoiceTmsi,
		Tmsi:   &v,
	}
}

// IMEI represents the ASN.1 type IMEI (OCTET_STRING).
type IMEI = TBCDSTRING

// HLRId represents the ASN.1 type HLR-Id (OCTET_STRING).
type HLRId = IMSI

// HLRList represents the ASN.1 type HLR-List (SEQUENCE_OF).
type HLRList struct {
	Values         []HLRId         `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// LMSI represents the ASN.1 type LMSI (OCTET_STRING).
type LMSI = []byte

// GlobalCellId represents the ASN.1 type GlobalCellId (OCTET_STRING).
type GlobalCellId = []byte

// NetworkResource represents the ASN.1 ENUMERATED type NetworkResource.
type NetworkResource int64

const (
	NetworkResourcePlmn           NetworkResource = 0
	NetworkResourceHlr            NetworkResource = 1
	NetworkResourceVlr            NetworkResource = 2
	NetworkResourcePvlr           NetworkResource = 3
	NetworkResourceControllingMSC NetworkResource = 4
	NetworkResourceVmsc           NetworkResource = 5
	NetworkResourceEir            NetworkResource = 6
	NetworkResourceRss            NetworkResource = 7
)

func (v NetworkResource) String() string {
	switch v {
	case NetworkResourcePlmn:
		return "plmn"
	case NetworkResourceHlr:
		return "hlr"
	case NetworkResourceVlr:
		return "vlr"
	case NetworkResourcePvlr:
		return "pvlr"
	case NetworkResourceControllingMSC:
		return "controllingMSC"
	case NetworkResourceVmsc:
		return "vmsc"
	case NetworkResourceEir:
		return "eir"
	case NetworkResourceRss:
		return "rss"
	default:
		return "unknown"
	}
}

// AdditionalNetworkResource represents the ASN.1 ENUMERATED type AdditionalNetworkResource.
type AdditionalNetworkResource int64

const (
	AdditionalNetworkResourceSgsn   AdditionalNetworkResource = 0
	AdditionalNetworkResourceGgsn   AdditionalNetworkResource = 1
	AdditionalNetworkResourceGmlc   AdditionalNetworkResource = 2
	AdditionalNetworkResourceGsmSCF AdditionalNetworkResource = 3
	AdditionalNetworkResourceNplr   AdditionalNetworkResource = 4
	AdditionalNetworkResourceAuc    AdditionalNetworkResource = 5
	AdditionalNetworkResourceUe     AdditionalNetworkResource = 6
	AdditionalNetworkResourceMme    AdditionalNetworkResource = 7
)

func (v AdditionalNetworkResource) String() string {
	switch v {
	case AdditionalNetworkResourceSgsn:
		return "sgsn"
	case AdditionalNetworkResourceGgsn:
		return "ggsn"
	case AdditionalNetworkResourceGmlc:
		return "gmlc"
	case AdditionalNetworkResourceGsmSCF:
		return "gsmSCF"
	case AdditionalNetworkResourceNplr:
		return "nplr"
	case AdditionalNetworkResourceAuc:
		return "auc"
	case AdditionalNetworkResourceUe:
		return "ue"
	case AdditionalNetworkResourceMme:
		return "mme"
	default:
		return "unknown"
	}
}

// NAEAPreferredCI represents the ASN.1 type NAEA-PreferredCI (SEQUENCE).
type NAEAPreferredCI struct {
	NaeaPreferredCIC   NAEACIC             `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// NAEACIC represents the ASN.1 type NAEA-CIC (OCTET_STRING).
type NAEACIC = []byte

// SubscriberIdentity choice constants.
const (
	SubscriberIdentityChoiceImsi   = 1
	SubscriberIdentityChoiceMsisdn = 2
)

// SubscriberIdentity represents the ASN.1 CHOICE type SubscriberIdentity.
type SubscriberIdentity struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode    `json:"-"`
	Imsi           *IMSI              `json:"Imsi,omitempty"`
	Msisdn         *ISDNAddressString `json:"Msisdn,omitempty"`
}

// NewSubscriberIdentityImsi creates a SubscriberIdentity with the imsi alternative.
func NewSubscriberIdentityImsi(v IMSI) SubscriberIdentity {
	return SubscriberIdentity{
		Choice: SubscriberIdentityChoiceImsi,
		Imsi:   &v,
	}
}

// NewSubscriberIdentityMsisdn creates a SubscriberIdentity with the msisdn alternative.
func NewSubscriberIdentityMsisdn(v ISDNAddressString) SubscriberIdentity {
	return SubscriberIdentity{
		Choice: SubscriberIdentityChoiceMsisdn,
		Msisdn: &v,
	}
}

// LCSClientExternalID represents the ASN.1 type LCSClientExternalID (SEQUENCE).
type LCSClientExternalID struct {
	ExternalAddress    *ISDNAddressString  `asn1:"tag:0,context,implicit,optional" json:"ExternalAddress,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSClientInternalID represents the ASN.1 ENUMERATED type LCSClientInternalID.
type LCSClientInternalID int64

const (
	LCSClientInternalIDBroadcastService          LCSClientInternalID = 0
	LCSClientInternalIDOAndMHPLMN                LCSClientInternalID = 1
	LCSClientInternalIDOAndMVPLMN                LCSClientInternalID = 2
	LCSClientInternalIDAnonymousLocation         LCSClientInternalID = 3
	LCSClientInternalIDTargetMSsubscribedService LCSClientInternalID = 4
)

func (v LCSClientInternalID) String() string {
	switch v {
	case LCSClientInternalIDBroadcastService:
		return "broadcastService"
	case LCSClientInternalIDOAndMHPLMN:
		return "o-andM-HPLMN"
	case LCSClientInternalIDOAndMVPLMN:
		return "o-andM-VPLMN"
	case LCSClientInternalIDAnonymousLocation:
		return "anonymousLocation"
	case LCSClientInternalIDTargetMSsubscribedService:
		return "targetMSsubscribedService"
	default:
		return "unknown"
	}
}

// LCSServiceTypeID represents the ASN.1 type LCSServiceTypeID (INTEGER).
type LCSServiceTypeID = int64

// PLMNId represents the ASN.1 type PLMN-Id (OCTET_STRING).
type PLMNId = []byte

// EUTRANCGI represents the ASN.1 type E-UTRAN-CGI (OCTET_STRING).
type EUTRANCGI = []byte

// NRCGI represents the ASN.1 type NR-CGI (OCTET_STRING).
type NRCGI = []byte

// TAId represents the ASN.1 type TA-Id (OCTET_STRING).
type TAId = []byte

// NRTAId represents the ASN.1 type NR-TA-Id (OCTET_STRING).
type NRTAId = []byte

// RAIdentity represents the ASN.1 type RAIdentity (OCTET_STRING).
type RAIdentity = []byte

// NetworkNodeDiameterAddress represents the ASN.1 type NetworkNodeDiameterAddress (SEQUENCE).
type NetworkNodeDiameterAddress struct {
	DiameterName   DiameterIdentity `asn1:"tag:0,context,implicit"`
	DiameterRealm  DiameterIdentity `asn1:"tag:1,context,implicit"`
	berReplayNode_ *ber.ReplayNode  `asn1:"-" json:"-"`
}

// CellGlobalIdOrServiceAreaIdOrLAI choice constants.
const (
	CellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength = 1
	CellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength                         = 2
)

// CellGlobalIdOrServiceAreaIdOrLAI represents the ASN.1 CHOICE type CellGlobalIdOrServiceAreaIdOrLAI.
type CellGlobalIdOrServiceAreaIdOrLAI struct {
	Choice                                 int
	berReplayNode_                         *ber.ReplayNode                         `json:"-"`
	CellGlobalIdOrServiceAreaIdFixedLength *CellGlobalIdOrServiceAreaIdFixedLength `json:"CellGlobalIdOrServiceAreaIdFixedLength,omitempty"`
	LaiFixedLength                         *LAIFixedLength                         `json:"LaiFixedLength,omitempty"`
}

// NewCellGlobalIdOrServiceAreaIdOrLAICellGlobalIdOrServiceAreaIdFixedLength creates a CellGlobalIdOrServiceAreaIdOrLAI with the cellGlobalIdOrServiceAreaIdFixedLength alternative.
func NewCellGlobalIdOrServiceAreaIdOrLAICellGlobalIdOrServiceAreaIdFixedLength(v CellGlobalIdOrServiceAreaIdFixedLength) CellGlobalIdOrServiceAreaIdOrLAI {
	return CellGlobalIdOrServiceAreaIdOrLAI{
		Choice:                                 CellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength,
		CellGlobalIdOrServiceAreaIdFixedLength: &v,
	}
}

// NewCellGlobalIdOrServiceAreaIdOrLAILaiFixedLength creates a CellGlobalIdOrServiceAreaIdOrLAI with the laiFixedLength alternative.
func NewCellGlobalIdOrServiceAreaIdOrLAILaiFixedLength(v LAIFixedLength) CellGlobalIdOrServiceAreaIdOrLAI {
	return CellGlobalIdOrServiceAreaIdOrLAI{
		Choice:         CellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength,
		LaiFixedLength: &v,
	}
}

// CellGlobalIdOrServiceAreaIdFixedLength represents the ASN.1 type CellGlobalIdOrServiceAreaIdFixedLength (OCTET_STRING).
type CellGlobalIdOrServiceAreaIdFixedLength = []byte

// LAIFixedLength represents the ASN.1 type LAIFixedLength (OCTET_STRING).
type LAIFixedLength = []byte

// BasicServiceCode choice constants.
const (
	BasicServiceCodeChoiceBearerService = 1
	BasicServiceCodeChoiceTeleservice   = 2
)

// BasicServiceCode represents the ASN.1 CHOICE type BasicServiceCode.
type BasicServiceCode struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode    `json:"-"`
	BearerService  *BearerServiceCode `json:"BearerService,omitempty"`
	Teleservice    *TeleserviceCode   `json:"Teleservice,omitempty"`
}

// NewBasicServiceCodeBearerService creates a BasicServiceCode with the bearerService alternative.
func NewBasicServiceCodeBearerService(v BearerServiceCode) BasicServiceCode {
	return BasicServiceCode{
		Choice:        BasicServiceCodeChoiceBearerService,
		BearerService: &v,
	}
}

// NewBasicServiceCodeTeleservice creates a BasicServiceCode with the teleservice alternative.
func NewBasicServiceCodeTeleservice(v TeleserviceCode) BasicServiceCode {
	return BasicServiceCode{
		Choice:      BasicServiceCodeChoiceTeleservice,
		Teleservice: &v,
	}
}

// ExtBasicServiceCode choice constants.
const (
	ExtBasicServiceCodeChoiceExtBearerService = 1
	ExtBasicServiceCodeChoiceExtTeleservice   = 2
)

// ExtBasicServiceCode represents the ASN.1 CHOICE type Ext-BasicServiceCode.
type ExtBasicServiceCode struct {
	Choice           int
	berReplayNode_   *ber.ReplayNode       `json:"-"`
	ExtBearerService *ExtBearerServiceCode `json:"ExtBearerService,omitempty"`
	ExtTeleservice   *ExtTeleserviceCode   `json:"ExtTeleservice,omitempty"`
}

// NewExtBasicServiceCodeExtBearerService creates a ExtBasicServiceCode with the ext-BearerService alternative.
func NewExtBasicServiceCodeExtBearerService(v ExtBearerServiceCode) ExtBasicServiceCode {
	return ExtBasicServiceCode{
		Choice:           ExtBasicServiceCodeChoiceExtBearerService,
		ExtBearerService: &v,
	}
}

// NewExtBasicServiceCodeExtTeleservice creates a ExtBasicServiceCode with the ext-Teleservice alternative.
func NewExtBasicServiceCodeExtTeleservice(v ExtTeleserviceCode) ExtBasicServiceCode {
	return ExtBasicServiceCode{
		Choice:         ExtBasicServiceCodeChoiceExtTeleservice,
		ExtTeleservice: &v,
	}
}

// EMLPPInfo represents the ASN.1 type EMLPP-Info (SEQUENCE).
type EMLPPInfo struct {
	MaximumentitledPriority EMLPPPriority       `asn1:""`
	DefaultPriority         EMLPPPriority       `asn1:""`
	ExtensionContainer      *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64               `asn1:"-" json:"-"`
	ExtPresent_             []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// EMLPPPriority represents the ASN.1 type EMLPP-Priority (INTEGER).
type EMLPPPriority = int64

// MCSSInfo represents the ASN.1 type MC-SS-Info (SEQUENCE).
type MCSSInfo struct {
	SsCode             SSCode              `asn1:"tag:0,context,implicit"`
	SsStatus           ExtSSStatus         `asn1:"tag:1,context,implicit"`
	NbrSB              MaxMCBearers        `asn1:"tag:2,context,implicit"`
	NbrUser            MCBearers           `asn1:"tag:3,context,implicit"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MaxMCBearers represents the ASN.1 type MaxMC-Bearers (INTEGER).
type MaxMCBearers = int64

// MCBearers represents the ASN.1 type MC-Bearers (INTEGER).
type MCBearers = int64

// ExtSSStatus represents the ASN.1 type Ext-SS-Status (OCTET_STRING).
type ExtSSStatus = []byte

// AgeOfLocationInformation represents the ASN.1 type AgeOfLocationInformation (INTEGER).
type AgeOfLocationInformation = int64

// MarshalBERISDNAddressString encodes a typed standalone ISDNAddressString, preserving unchanged received BER.
func MarshalBERISDNAddressString(value *BERValue[ISDNAddressString], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required ISDNAddressString is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERISDNAddressString, marshalBERISDNAddressString, false)

}
func marshalBERISDNAddressString(value *BERValue[ISDNAddressString], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value ISDNAddressString }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 9 {
		if constraintErr := checkEncodedLength(opts, "MAP-CommonDataTypes.marshalBERISDNAddressString", "51.5", "ISDN-AddressString", "SIZE (1..9)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 20 {
		if constraintErr := checkEncodedLength(opts, "MAP-CommonDataTypes.marshalBERISDNAddressString", "51.5", "ISDN-AddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ISDN-AddressString", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERISDNAddressString encodes a typed standalone ISDNAddressString using DER.
func MarshalDERISDNAddressString(value *BERValue[ISDNAddressString]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required ISDNAddressString is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value ISDNAddressString }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 9 {
		if constraintErr := checkEncodedLength(nil, s6f8409_0, "51.5", "ISDN-AddressString", "SIZE (1..9)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 20 {
		if constraintErr := checkEncodedLength(nil, s6f8409_0, "51.5", "ISDN-AddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ISDN-AddressString", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERISDNAddressString decodes one complete typed standalone ISDNAddressString from BER/DER.
func UnmarshalBERISDNAddressString(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[ISDNAddressString], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, s6f8409_0, "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERISDNAddressString(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	v := &struct{ Value ISDNAddressString }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "ISDN-AddressString", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding ISDN-AddressString", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = ISDNAddressString(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 1 || len(v.Value) > 9 {
			if constraintErr := checkDecodedLength(opts, s6f8409_0, "51.5", "ISDN-AddressString", "SIZE (1..9)", len(v.Value)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Value) < 1 || len(v.Value) > 20 {
			if constraintErr := checkDecodedLength(opts, s6f8409_0, "51.5", "ISDN-AddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[ISDNAddressString]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERISDNAddressString); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERFTNAddressString encodes a typed standalone FTNAddressString, preserving unchanged received BER.
func MarshalBERFTNAddressString(value *BERValue[FTNAddressString], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required FTNAddressString is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERFTNAddressString, marshalBERFTNAddressString, false)

}
func marshalBERFTNAddressString(value *BERValue[FTNAddressString], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value FTNAddressString }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 15 {
		if constraintErr := checkEncodedLength(opts, "MAP-CommonDataTypes.marshalBERFTNAddressString", "51.5", "FTN-AddressString", "SIZE (1..15)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 20 {
		if constraintErr := checkEncodedLength(opts, "MAP-CommonDataTypes.marshalBERFTNAddressString", "51.5", "FTN-AddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding FTN-AddressString", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERFTNAddressString encodes a typed standalone FTNAddressString using DER.
func MarshalDERFTNAddressString(value *BERValue[FTNAddressString]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required FTNAddressString is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value FTNAddressString }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 15 {
		if constraintErr := checkEncodedLength(nil, s6f8409_1, "51.5", "FTN-AddressString", "SIZE (1..15)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 20 {
		if constraintErr := checkEncodedLength(nil, s6f8409_1, "51.5", "FTN-AddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding FTN-AddressString", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERFTNAddressString decodes one complete typed standalone FTNAddressString from BER/DER.
func UnmarshalBERFTNAddressString(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[FTNAddressString], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, s6f8409_1, "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERFTNAddressString(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	v := &struct{ Value FTNAddressString }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "FTN-AddressString", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding FTN-AddressString", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = FTNAddressString(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 1 || len(v.Value) > 15 {
			if constraintErr := checkDecodedLength(opts, s6f8409_1, "51.5", "FTN-AddressString", "SIZE (1..15)", len(v.Value)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Value) < 1 || len(v.Value) > 20 {
			if constraintErr := checkDecodedLength(opts, s6f8409_1, "51.5", "FTN-AddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[FTNAddressString]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERFTNAddressString); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes ExternalSignalInfo to BER format.
func (v *ExternalSignalInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExternalSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExternalSignalInfo).MarshalBER, (*ExternalSignalInfo).marshalBER, true)

}
func (v *ExternalSignalInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := checkEncodedValue(opts, s6f8409_2, "20", "protocolId", "ENUMERATED {1, 2, 3, 4}", ber.ObserveInteger(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := checkEncodedLength(opts, s6f8409_2, "51.5", "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
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
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s6f8409_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ExternalSignalInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ExternalSignalInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExternalSignalInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExternalSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := checkEncodedValue(nil, s6f8409_2, "20", "protocolId", "ENUMERATED {1, 2, 3, 4}", ber.ObserveInteger(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := checkEncodedLength(nil, s6f8409_2, "51.5", "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s6f8409_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ExternalSignalInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ExternalSignalInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExternalSignalInfo from BER/DER format.
func (destination *ExternalSignalInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExternalSignalInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExternalSignalInfo)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_2, "child", (*ExternalSignalInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExternalSignalInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExternalSignalInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ExternalSignalInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExternalSignalInfo", Cause: ber.ErrExtraData}
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
		v.ProtocolId = ProtocolId(val_protocolid)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
			if constraintErr := checkDecodedValue(opts, s6f8409_2, "20", "protocolId", "ENUMERATED {1, 2, 3, 4}", ber.ObserveInteger(int64(v.ProtocolId))); constraintErr != nil {
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
		v.SignalInfo = SignalInfo(val_signalinfo)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
			if constraintErr := checkDecodedLength(opts, s6f8409_2, "51.5", "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s6f8409_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ExtExternalSignalInfo to BER format.
func (v *ExtExternalSignalInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExtExternalSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExtExternalSignalInfo).MarshalBER, (*ExtExternalSignalInfo).marshalBER, true)

}
func (v *ExtExternalSignalInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_extprotocolid := ber.EncodeEnumerated(int64(v.ExtProtocolId))
	children = append(children, enc_extprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := checkEncodedLength(opts, s6f8409_3, "51.5", "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
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
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s6f8409_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ExtExternalSignalInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ExtExternalSignalInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExtExternalSignalInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtExternalSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_extprotocolid := ber.EncodeEnumerated(int64(v.ExtProtocolId))
	children = append(children, enc_extprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := checkEncodedLength(nil, s6f8409_3, "51.5", "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s6f8409_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ExtExternalSignalInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ExtExternalSignalInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExtExternalSignalInfo from BER/DER format.
func (destination *ExtExternalSignalInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExtExternalSignalInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExtExternalSignalInfo)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_3, "child", (*ExtExternalSignalInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExtExternalSignalInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExtExternalSignalInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ExtExternalSignalInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtExternalSignalInfo", Cause: ber.ErrExtraData}
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
		v.ExtProtocolId = ExtProtocolId(val_extprotocolid)
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
		v.SignalInfo = SignalInfo(val_signalinfo)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
			if constraintErr := checkDecodedLength(opts, s6f8409_3, "51.5", "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtExternalSignalInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExtExternalSignalInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s6f8409_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes AccessNetworkSignalInfo to BER format.
func (v *AccessNetworkSignalInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: AccessNetworkSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*AccessNetworkSignalInfo).MarshalBER, (*AccessNetworkSignalInfo).marshalBER, true)

}
func (v *AccessNetworkSignalInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_accessnetworkprotocolid := ber.EncodeEnumerated(int64(v.AccessNetworkProtocolId))
	children = append(children, enc_accessnetworkprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 2560 {
		if constraintErr := checkEncodedLength(opts, s6f8409_4, "51.5", "signalInfo", "SIZE (1..2560)", len(v.SignalInfo)); constraintErr != nil {
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
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s6f8409_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *AccessNetworkSignalInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes AccessNetworkSignalInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *AccessNetworkSignalInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AccessNetworkSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_accessnetworkprotocolid := ber.EncodeEnumerated(int64(v.AccessNetworkProtocolId))
	children = append(children, enc_accessnetworkprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 2560 {
		if constraintErr := checkEncodedLength(nil, s6f8409_4, "51.5", "signalInfo", "SIZE (1..2560)", len(v.SignalInfo)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s6f8409_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding AccessNetworkSignalInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *AccessNetworkSignalInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes AccessNetworkSignalInfo from BER/DER format.
func (destination *AccessNetworkSignalInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: AccessNetworkSignalInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(AccessNetworkSignalInfo)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_4, "child", (*AccessNetworkSignalInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = AccessNetworkSignalInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*AccessNetworkSignalInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding AccessNetworkSignalInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AccessNetworkSignalInfo", Cause: ber.ErrExtraData}
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
		v.AccessNetworkProtocolId = AccessNetworkProtocolId(val_accessnetworkprotocolid)
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
		v.SignalInfo = LongSignalInfo(val_signalinfo)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 2560 {
			if constraintErr := checkDecodedLength(opts, s6f8409_4, "51.5", "signalInfo", "SIZE (1..2560)", len(v.SignalInfo)); constraintErr != nil {
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "AccessNetworkSignalInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "AccessNetworkSignalInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s6f8409_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBERIMSI encodes a typed standalone IMSI, preserving unchanged received BER.
func MarshalBERIMSI(value *BERValue[IMSI], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required IMSI is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERIMSI, marshalBERIMSI, false)

}
func marshalBERIMSI(value *BERValue[IMSI], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value IMSI }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 3 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(opts, "MAP-CommonDataTypes.marshalBERIMSI", "51.5", "IMSI", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IMSI", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERIMSI encodes a typed standalone IMSI using DER.
func MarshalDERIMSI(value *BERValue[IMSI]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required IMSI is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value IMSI }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 3 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(nil, "MAP-CommonDataTypes.IMSI", "51.5", "IMSI", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IMSI", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERIMSI decodes one complete typed standalone IMSI from BER/DER.
func UnmarshalBERIMSI(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[IMSI], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-CommonDataTypes.IMSI", "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERIMSI(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	v := &struct{ Value IMSI }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "IMSI", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding IMSI", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = IMSI(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 3 || len(v.Value) > 8 {
			if constraintErr := checkDecodedLength(opts, "MAP-CommonDataTypes.IMSI", "51.5", "IMSI", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[IMSI]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERIMSI); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes Identity to BER format.
func (v *Identity) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: Identity receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*Identity).MarshalBER, (*Identity).marshalBER, true)

}
func (v *Identity) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *Identity) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case IdentityChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice Identity: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, "MAP-CommonDataTypes.Identity", "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case IdentityChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice Identity: imsi-WithLMSI is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ImsiWithLMSI.MarshalBER(ber.ChildEncodeOptions(opts, "imsi-WithLMSI")...)
		if err != nil {
			return nil, qualifyBERError(err, "imsi-WithLMSI", "encoding", false)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Identity", v.Choice)
	}
}

// MarshalDER encodes Identity to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *Identity) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Identity receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case IdentityChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice Identity: imsi-WithLMSI is nil", ber.ErrInvalidValue)
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
		case IdentityChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case IdentityChoiceImsiWithLMSI:
			return nil, qualifyBERError(err, "imsi-WithLMSI", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding Identity as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *Identity) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes Identity from BER/DER format.
func (destination *Identity) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: Identity destination is nil", ber.ErrInvalidValue)
	}
	v := new(Identity)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "MAP-CommonDataTypes.Identity", "child", (*Identity).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*Identity).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Identity{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Identity CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Identity: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding Identity CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Identity", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "Identity.imsi-WithLMSI", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = IdentityChoiceImsi
		ber.MarkPreflightTarget(opts, "imsi", choiceData)
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return qualifyBERError(osErr, "imsi", "decoding", false)
		}
		tmp := IMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, "MAP-CommonDataTypes.Identity", "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = IdentityChoiceImsiWithLMSI
		ber.MarkPreflightTarget(opts, "imsi-WithLMSI", choiceData)
		var dec IMSIWithLMSI
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "imsi-WithLMSI")...); unmErr != nil {
			return qualifyBERError(unmErr, "imsi-WithLMSI", "decoding", false)
		}
		v.ImsiWithLMSI = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Identity CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes IMSIWithLMSI to BER format.
func (v *IMSIWithLMSI) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: IMSIWithLMSI receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*IMSIWithLMSI).MarshalBER, (*IMSIWithLMSI).marshalBER, true)

}
func (v *IMSIWithLMSI) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, s6f8409_5, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
		if constraintErr := checkEncodedLength(opts, s6f8409_5, "51.5", "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(v.Lmsi))
	if encodeErr_enc_lmsi != nil {
		return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", false)
	}
	children = append(children, enc_lmsi...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if constraintErr := checkEncodedLength(nil, s6f8409_5, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
		if constraintErr := checkEncodedLength(nil, s6f8409_5, "51.5", "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
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
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_5, "child", (*IMSIWithLMSI).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

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
		return fmt.Errorf("missing required field imsi")
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
			if constraintErr := checkDecodedLength(opts, s6f8409_5, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
		v.Lmsi = LMSI(val_lmsi)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
			if constraintErr := checkDecodedLength(opts, s6f8409_5, "51.5", "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
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

// MarshalBERASCICallReference encodes a typed standalone ASCICallReference, preserving unchanged received BER.
func MarshalBERASCICallReference(value *BERValue[ASCICallReference], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required ASCICallReference is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERASCICallReference, marshalBERASCICallReference, false)

}
func marshalBERASCICallReference(value *BERValue[ASCICallReference], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value ASCICallReference }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(opts, "MAP-CommonDataTypes.marshalBERASCICallReference", "51.5", "ASCI-CallReference", "SIZE (1..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ASCI-CallReference", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERASCICallReference encodes a typed standalone ASCICallReference using DER.
func MarshalDERASCICallReference(value *BERValue[ASCICallReference]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required ASCICallReference is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value ASCICallReference }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(nil, "MAP-CommonDataTypes.ASCI-CallReference", "51.5", "ASCI-CallReference", "SIZE (1..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ASCI-CallReference", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERASCICallReference decodes one complete typed standalone ASCICallReference from BER/DER.
func UnmarshalBERASCICallReference(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[ASCICallReference], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-CommonDataTypes.ASCI-CallReference", "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERASCICallReference(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	v := &struct{ Value ASCICallReference }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "ASCI-CallReference", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding ASCI-CallReference", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = ASCICallReference(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 1 || len(v.Value) > 8 {
			if constraintErr := checkDecodedLength(opts, "MAP-CommonDataTypes.ASCI-CallReference", "51.5", "ASCI-CallReference", "SIZE (1..8)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[ASCICallReference]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERASCICallReference); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SubscriberId to BER format.
func (v *SubscriberId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberId receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SubscriberId).MarshalBER, (*SubscriberId).marshalBER, true)

}
func (v *SubscriberId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SubscriberId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SubscriberIdChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberId: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s6f8409_6, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "imsi", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SubscriberIdChoiceTmsi:
		if v.Tmsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberId: tmsi is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Tmsi))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "tmsi", "encoding", false)
		}
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := checkEncodedLength(opts, s6f8409_6, "51.5", "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
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
		return nil, fmt.Errorf("unknown choice %d for SubscriberId", v.Choice)
	}
}

// MarshalDER encodes SubscriberId to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SubscriberId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SubscriberIdChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case SubscriberIdChoiceTmsi:
			return nil, qualifyBERError(err, "tmsi", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SubscriberId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SubscriberId) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SubscriberId from BER/DER format.
func (destination *SubscriberId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SubscriberId destination is nil", ber.ErrInvalidValue)
	}
	v := new(SubscriberId)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_6, "child", (*SubscriberId).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SubscriberId).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SubscriberId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SubscriberId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberIdChoiceImsi
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
			if constraintErr := checkDecodedLength(opts, s6f8409_6, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberIdChoiceTmsi
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
		tmp := TMSI(decVal)
		v.Tmsi = &tmp
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := checkDecodedLength(opts, s6f8409_6, "51.5", "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberId CHOICE", peekTag)
	}
	return nil
}

// MarshalBERIMEI encodes a typed standalone IMEI, preserving unchanged received BER.
func MarshalBERIMEI(value *BERValue[IMEI], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required IMEI is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERIMEI, marshalBERIMEI, false)

}
func marshalBERIMEI(value *BERValue[IMEI], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value IMEI }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 8 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(opts, "MAP-CommonDataTypes.marshalBERIMEI", "51.5", "IMEI", "SIZE (8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IMEI", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERIMEI encodes a typed standalone IMEI using DER.
func MarshalDERIMEI(value *BERValue[IMEI]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required IMEI is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value IMEI }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 8 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(nil, "MAP-CommonDataTypes.IMEI", "51.5", "IMEI", "SIZE (8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IMEI", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERIMEI decodes one complete typed standalone IMEI from BER/DER.
func UnmarshalBERIMEI(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[IMEI], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-CommonDataTypes.IMEI", "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERIMEI(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	v := &struct{ Value IMEI }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "IMEI", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding IMEI", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = IMEI(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 8 || len(v.Value) > 8 {
			if constraintErr := checkDecodedLength(opts, "MAP-CommonDataTypes.IMEI", "51.5", "IMEI", "SIZE (8)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[IMEI]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERIMEI); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERHLRId encodes a typed standalone HLRId, preserving unchanged received BER.
func MarshalBERHLRId(value *BERValue[HLRId], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required HLRId is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERHLRId, marshalBERHLRId, false)

}
func marshalBERHLRId(value *BERValue[HLRId], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value HLRId }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 3 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(opts, "MAP-CommonDataTypes.marshalBERHLRId", "51.5", "HLR-Id", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding HLR-Id", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERHLRId encodes a typed standalone HLRId using DER.
func MarshalDERHLRId(value *BERValue[HLRId]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required HLRId is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value HLRId }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 3 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(nil, "MAP-CommonDataTypes.HLR-Id", "51.5", "HLR-Id", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding HLR-Id", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERHLRId decodes one complete typed standalone HLRId from BER/DER.
func UnmarshalBERHLRId(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[HLRId], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-CommonDataTypes.HLR-Id", "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERHLRId(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	v := &struct{ Value HLRId }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "HLR-Id", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding HLR-Id", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = HLRId(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 3 || len(v.Value) > 8 {
			if constraintErr := checkDecodedLength(opts, "MAP-CommonDataTypes.HLR-Id", "51.5", "HLR-Id", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[HLRId]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERHLRId); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERHLRList encodes a HLRList list to BER.
func MarshalBERHLRList(collection *HLRList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERHLRList, marshalBERHLRList, true)

}
func marshalBERHLRList(collection *HLRList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-CommonDataTypes.marshalBERHLRList", "51.5", "HLR-List", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 3 || len(elem) > 8 {
			if constraintErr := checkEncodedLength(opts, "MAP-CommonDataTypes.marshalBERHLRList", "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (3..8)", len(elem)); constraintErr != nil {
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

func appendBERLinearHLRList(encoder *ber.LinearEncoder, collection *HLRList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERHLRList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERHLRList encodes a HLRList list to DER.
func MarshalDERHLRList(collection *HLRList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := checkEncodedCollectionLength(nil, s6f8409_7, "51.5", "HLR-List", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 3 || len(elem) > 8 {
			if constraintErr := checkEncodedLength(nil, s6f8409_7, "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (3..8)", len(elem)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding HLRList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearHLRList(encoder *ber.LinearEncoder, collection *HLRList) ([]byte, error) {
	encoded, err := MarshalDERHLRList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERHLRList decodes a HLRList list from BER.
func UnmarshalBERHLRList(data []byte, opts ...ber.DecodeOption) (returnValue *HLRList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, s6f8409_7, "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERHLRList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding HLRList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "HLRList", Cause: ber.ErrExtraData}
	}
	var result []HLRId
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
			if constraintErr := checkDecodedLength(opts, s6f8409_7, "51.5", fmt.Sprintf("element[%d]", len(result)), "SIZE (3..8)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, HLRId(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := checkDecodedCollectionLength(opts, s6f8409_7, "51.5", "HLR-List", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &HLRList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERHLRList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes NAEAPreferredCI to BER format.
func (v *NAEAPreferredCI) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: NAEAPreferredCI receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*NAEAPreferredCI).MarshalBER, (*NAEAPreferredCI).marshalBER, true)

}
func (v *NAEAPreferredCI) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.NaeaPreferredCIC) < 3 || len(v.NaeaPreferredCIC) > 3 {
		if constraintErr := checkEncodedLength(opts, s6f8409_8, "51.5", "naea-PreferredCIC", "SIZE (3)", len(v.NaeaPreferredCIC)); constraintErr != nil {
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
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s6f8409_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *NAEAPreferredCI) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes NAEAPreferredCI to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *NAEAPreferredCI) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NAEAPreferredCI receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.NaeaPreferredCIC) < 3 || len(v.NaeaPreferredCIC) > 3 {
		if constraintErr := checkEncodedLength(nil, s6f8409_8, "51.5", "naea-PreferredCIC", "SIZE (3)", len(v.NaeaPreferredCIC)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s6f8409_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding NAEAPreferredCI as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *NAEAPreferredCI) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes NAEAPreferredCI from BER/DER format.
func (destination *NAEAPreferredCI) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: NAEAPreferredCI destination is nil", ber.ErrInvalidValue)
	}
	v := new(NAEAPreferredCI)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_8, "child", (*NAEAPreferredCI).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = NAEAPreferredCI{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*NAEAPreferredCI).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding NAEAPreferredCI SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NAEAPreferredCI", Cause: ber.ErrExtraData}
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
		v.NaeaPreferredCIC = NAEACIC(decVal_naeapreferredcic)
		if offset > len(content) || n_naeapreferredcic < 0 || n_naeapreferredcic > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_naeapreferredcic
		if len(v.NaeaPreferredCIC) < 3 || len(v.NaeaPreferredCIC) > 3 {
			if constraintErr := checkDecodedLength(opts, s6f8409_8, "51.5", "naea-PreferredCIC", "SIZE (3)", len(v.NaeaPreferredCIC)); constraintErr != nil {
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
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "NAEAPreferredCI", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "NAEAPreferredCI", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s6f8409_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SubscriberIdentity to BER format.
func (v *SubscriberIdentity) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberIdentity receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SubscriberIdentity).MarshalBER, (*SubscriberIdentity).marshalBER, true)

}
func (v *SubscriberIdentity) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SubscriberIdentity) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SubscriberIdentityChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberIdentity: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s6f8409_9, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "imsi", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SubscriberIdentityChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("%w: choice SubscriberIdentity: msisdn is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "msisdn", "encoding", false)
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkEncodedLength(opts, s6f8409_9, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkEncodedLength(opts, s6f8409_9, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
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
		return nil, fmt.Errorf("unknown choice %d for SubscriberIdentity", v.Choice)
	}
}

// MarshalDER encodes SubscriberIdentity to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SubscriberIdentity) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberIdentity receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SubscriberIdentityChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case SubscriberIdentityChoiceMsisdn:
			return nil, qualifyBERError(err, "msisdn", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SubscriberIdentity as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SubscriberIdentity) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SubscriberIdentity from BER/DER format.
func (destination *SubscriberIdentity) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SubscriberIdentity destination is nil", ber.ErrInvalidValue)
	}
	v := new(SubscriberIdentity)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_9, "child", (*SubscriberIdentity).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SubscriberIdentity).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SubscriberIdentity{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberIdentity CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberIdentity: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SubscriberIdentity CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberIdentity", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberIdentityChoiceImsi
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
			if constraintErr := checkDecodedLength(opts, s6f8409_9, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberIdentityChoiceMsisdn
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
		tmp := ISDNAddressString(decVal)
		v.Msisdn = &tmp
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkDecodedLength(opts, s6f8409_9, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkDecodedLength(opts, s6f8409_9, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberIdentity CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes LCSClientExternalID to BER format.
func (v *LCSClientExternalID) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: LCSClientExternalID receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*LCSClientExternalID).MarshalBER, (*LCSClientExternalID).marshalBER, true)

}
func (v *LCSClientExternalID) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExternalAddress != nil {
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 9 {
			if constraintErr := checkEncodedLength(opts, s6f8409_10, "51.5", "externalAddress", "SIZE (1..9)", len(*v.ExternalAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 20 {
			if constraintErr := checkEncodedLength(opts, s6f8409_10, "51.5", "externalAddress", "SIZE (1..20)", len(*v.ExternalAddress)); constraintErr != nil {
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
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s6f8409_10, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSClientExternalID) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSClientExternalID to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSClientExternalID) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSClientExternalID receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExternalAddress != nil {
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 9 {
			if constraintErr := checkEncodedLength(nil, s6f8409_10, "51.5", "externalAddress", "SIZE (1..9)", len(*v.ExternalAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 20 {
			if constraintErr := checkEncodedLength(nil, s6f8409_10, "51.5", "externalAddress", "SIZE (1..20)", len(*v.ExternalAddress)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s6f8409_10, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSClientExternalID as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSClientExternalID) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSClientExternalID from BER/DER format.
func (destination *LCSClientExternalID) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSClientExternalID destination is nil", ber.ErrInvalidValue)
	}
	v := new(LCSClientExternalID)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_10, "child", (*LCSClientExternalID).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSClientExternalID{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*LCSClientExternalID).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSClientExternalID SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSClientExternalID", Cause: ber.ErrExtraData}
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
				tmp_externaladdress := ISDNAddressString(decVal_externaladdress)
				v.ExternalAddress = &tmp_externaladdress
				if offset > len(content) || n_externaladdress < 0 || n_externaladdress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_externaladdress
				if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 9 {
					if constraintErr := checkDecodedLength(opts, s6f8409_10, "51.5", "externalAddress", "SIZE (1..9)", len(*v.ExternalAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 20 {
					if constraintErr := checkDecodedLength(opts, s6f8409_10, "51.5", "externalAddress", "SIZE (1..20)", len(*v.ExternalAddress)); constraintErr != nil {
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
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSClientExternalID", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSClientExternalID", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s6f8409_10, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes NetworkNodeDiameterAddress to BER format.
func (v *NetworkNodeDiameterAddress) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: NetworkNodeDiameterAddress receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*NetworkNodeDiameterAddress).MarshalBER, (*NetworkNodeDiameterAddress).marshalBER, true)

}
func (v *NetworkNodeDiameterAddress) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.DiameterName) < 9 || len(v.DiameterName) > 255 {
		if constraintErr := checkEncodedLength(opts, s6f8409_11, "51.5", "diameter-Name", "SIZE (9..255)", len(v.DiameterName)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(opts, s6f8409_11, "51.5", "diameter-Realm", "SIZE (9..255)", len(v.DiameterRealm)); constraintErr != nil {
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
func (v *NetworkNodeDiameterAddress) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes NetworkNodeDiameterAddress to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *NetworkNodeDiameterAddress) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NetworkNodeDiameterAddress receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.DiameterName) < 9 || len(v.DiameterName) > 255 {
		if constraintErr := checkEncodedLength(nil, s6f8409_11, "51.5", "diameter-Name", "SIZE (9..255)", len(v.DiameterName)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(nil, s6f8409_11, "51.5", "diameter-Realm", "SIZE (9..255)", len(v.DiameterRealm)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding NetworkNodeDiameterAddress as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *NetworkNodeDiameterAddress) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes NetworkNodeDiameterAddress from BER/DER format.
func (destination *NetworkNodeDiameterAddress) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: NetworkNodeDiameterAddress destination is nil", ber.ErrInvalidValue)
	}
	v := new(NetworkNodeDiameterAddress)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_11, "child", (*NetworkNodeDiameterAddress).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = NetworkNodeDiameterAddress{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*NetworkNodeDiameterAddress).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding NetworkNodeDiameterAddress SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NetworkNodeDiameterAddress", Cause: ber.ErrExtraData}
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
		v.DiameterName = DiameterIdentity(decVal_diametername)
		if offset > len(content) || n_diametername < 0 || n_diametername > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_diametername
		if len(v.DiameterName) < 9 || len(v.DiameterName) > 255 {
			if constraintErr := checkDecodedLength(opts, s6f8409_11, "51.5", "diameter-Name", "SIZE (9..255)", len(v.DiameterName)); constraintErr != nil {
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
		v.DiameterRealm = DiameterIdentity(decVal_diameterrealm)
		if offset < 0 || offset >
			len(content) || n_diameterrealm < 0 || n_diameterrealm > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_diameterrealm
		if len(v.DiameterRealm) < 9 || len(v.DiameterRealm) > 255 {
			if constraintErr := checkDecodedLength(opts, s6f8409_11, "51.5", "diameter-Realm", "SIZE (9..255)", len(v.DiameterRealm)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "NetworkNodeDiameterAddress", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CellGlobalIdOrServiceAreaIdOrLAI to BER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CellGlobalIdOrServiceAreaIdOrLAI).MarshalBER, (*CellGlobalIdOrServiceAreaIdOrLAI).marshalBER, true)

}
func (v *CellGlobalIdOrServiceAreaIdOrLAI) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *CellGlobalIdOrServiceAreaIdOrLAI) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength:
		if v.CellGlobalIdOrServiceAreaIdFixedLength == nil {
			return nil, fmt.Errorf("%w: choice CellGlobalIdOrServiceAreaIdOrLAI: cellGlobalIdOrServiceAreaIdFixedLength is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.CellGlobalIdOrServiceAreaIdFixedLength))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "cellGlobalIdOrServiceAreaIdFixedLength", "encoding", false)
		}
		if len(*v.CellGlobalIdOrServiceAreaIdFixedLength) < 7 || len(*v.CellGlobalIdOrServiceAreaIdFixedLength) > 7 {
			if constraintErr := checkEncodedLength(opts, s6f8409_12, "51.5", "cellGlobalIdOrServiceAreaIdFixedLength", "SIZE (7)", len(*v.CellGlobalIdOrServiceAreaIdFixedLength)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "cellGlobalIdOrServiceAreaIdFixedLength", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case CellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength:
		if v.LaiFixedLength == nil {
			return nil, fmt.Errorf("%w: choice CellGlobalIdOrServiceAreaIdOrLAI: laiFixedLength is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.LaiFixedLength))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "laiFixedLength", "encoding", false)
		}
		if len(*v.LaiFixedLength) < 5 || len(*v.LaiFixedLength) > 5 {
			if constraintErr := checkEncodedLength(opts, s6f8409_12, "51.5", "laiFixedLength", "SIZE (5)", len(*v.LaiFixedLength)); constraintErr != nil {
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
		return nil, fmt.Errorf("unknown choice %d for CellGlobalIdOrServiceAreaIdOrLAI", v.Choice)
	}
}

// MarshalDER encodes CellGlobalIdOrServiceAreaIdOrLAI to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CellGlobalIdOrServiceAreaIdOrLAI) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case CellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength:
			return nil, qualifyBERError(err, "cellGlobalIdOrServiceAreaIdFixedLength", "encoding", true)
		case CellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength:
			return nil, qualifyBERError(err, "laiFixedLength", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding CellGlobalIdOrServiceAreaIdOrLAI as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *CellGlobalIdOrServiceAreaIdOrLAI) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CellGlobalIdOrServiceAreaIdOrLAI from BER/DER format.
func (destination *CellGlobalIdOrServiceAreaIdOrLAI) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI destination is nil", ber.ErrInvalidValue)
	}
	v := new(CellGlobalIdOrServiceAreaIdOrLAI)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_12, "child", (*CellGlobalIdOrServiceAreaIdOrLAI).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CellGlobalIdOrServiceAreaIdOrLAI).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CellGlobalIdOrServiceAreaIdOrLAI{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CellGlobalIdOrServiceAreaIdOrLAI CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CellGlobalIdOrServiceAreaIdOrLAI: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding CellGlobalIdOrServiceAreaIdOrLAI CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CellGlobalIdOrServiceAreaIdOrLAI", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength
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
		tmp := CellGlobalIdOrServiceAreaIdFixedLength(decVal)
		v.CellGlobalIdOrServiceAreaIdFixedLength = &tmp
		if len(*v.CellGlobalIdOrServiceAreaIdFixedLength) < 7 || len(*v.CellGlobalIdOrServiceAreaIdFixedLength) > 7 {
			if constraintErr := checkDecodedLength(opts, s6f8409_12, "51.5", "cellGlobalIdOrServiceAreaIdFixedLength", "SIZE (7)", len(*v.CellGlobalIdOrServiceAreaIdFixedLength)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength
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
		tmp := LAIFixedLength(decVal)
		v.LaiFixedLength = &tmp
		if len(*v.LaiFixedLength) < 5 || len(*v.LaiFixedLength) > 5 {
			if constraintErr := checkDecodedLength(opts, s6f8409_12, "51.5", "laiFixedLength", "SIZE (5)", len(*v.LaiFixedLength)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for CellGlobalIdOrServiceAreaIdOrLAI CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes BasicServiceCode to BER format.
func (v *BasicServiceCode) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: BasicServiceCode receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*BasicServiceCode).MarshalBER, (*BasicServiceCode).marshalBER, true)

}
func (v *BasicServiceCode) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *BasicServiceCode) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case BasicServiceCodeChoiceBearerService:
		if v.BearerService == nil {
			return nil, fmt.Errorf("%w: choice BasicServiceCode: bearerService is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.BearerService))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "bearerService", "encoding", false)
		}
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := checkEncodedLength(opts, s6f8409_13, "51.5", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "bearerService", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case BasicServiceCodeChoiceTeleservice:
		if v.Teleservice == nil {
			return nil, fmt.Errorf("%w: choice BasicServiceCode: teleservice is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Teleservice))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "teleservice", "encoding", false)
		}
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := checkEncodedLength(opts, s6f8409_13, "51.5", "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
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
		return nil, fmt.Errorf("unknown choice %d for BasicServiceCode", v.Choice)
	}
}

// MarshalDER encodes BasicServiceCode to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *BasicServiceCode) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BasicServiceCode receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case BasicServiceCodeChoiceBearerService:
			return nil, qualifyBERError(err, "bearerService", "encoding", true)
		case BasicServiceCodeChoiceTeleservice:
			return nil, qualifyBERError(err, "teleservice", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding BasicServiceCode as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *BasicServiceCode) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes BasicServiceCode from BER/DER format.
func (destination *BasicServiceCode) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: BasicServiceCode destination is nil", ber.ErrInvalidValue)
	}
	v := new(BasicServiceCode)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_13, "child", (*BasicServiceCode).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*BasicServiceCode).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = BasicServiceCode{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for BasicServiceCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for BasicServiceCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding BasicServiceCode CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "BasicServiceCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = BasicServiceCodeChoiceBearerService
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
		tmp := BearerServiceCode(decVal)
		v.BearerService = &tmp
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := checkDecodedLength(opts, s6f8409_13, "51.5", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = BasicServiceCodeChoiceTeleservice
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
		tmp := TeleserviceCode(decVal)
		v.Teleservice = &tmp
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := checkDecodedLength(opts, s6f8409_13, "51.5", "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for BasicServiceCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtBasicServiceCode to BER format.
func (v *ExtBasicServiceCode) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExtBasicServiceCode receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExtBasicServiceCode).MarshalBER, (*ExtBasicServiceCode).marshalBER, true)

}
func (v *ExtBasicServiceCode) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *ExtBasicServiceCode) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ExtBasicServiceCodeChoiceExtBearerService:
		if v.ExtBearerService == nil {
			return nil, fmt.Errorf("%w: choice ExtBasicServiceCode: ext-BearerService is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.ExtBearerService))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "ext-BearerService", "encoding", false)
		}
		if len(*v.ExtBearerService) < 1 || len(*v.ExtBearerService) > 5 {
			if constraintErr := checkEncodedLength(opts, s6f8409_14, "51.5", "ext-BearerService", "SIZE (1..5)", len(*v.ExtBearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "ext-BearerService", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ExtBasicServiceCodeChoiceExtTeleservice:
		if v.ExtTeleservice == nil {
			return nil, fmt.Errorf("%w: choice ExtBasicServiceCode: ext-Teleservice is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.ExtTeleservice))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "ext-Teleservice", "encoding", false)
		}
		if len(*v.ExtTeleservice) < 1 || len(*v.ExtTeleservice) > 5 {
			if constraintErr := checkEncodedLength(opts, s6f8409_14, "51.5", "ext-Teleservice", "SIZE (1..5)", len(*v.ExtTeleservice)); constraintErr != nil {
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
		return nil, fmt.Errorf("unknown choice %d for ExtBasicServiceCode", v.Choice)
	}
}

// MarshalDER encodes ExtBasicServiceCode to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExtBasicServiceCode) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtBasicServiceCode receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ExtBasicServiceCodeChoiceExtBearerService:
			return nil, qualifyBERError(err, "ext-BearerService", "encoding", true)
		case ExtBasicServiceCodeChoiceExtTeleservice:
			return nil, qualifyBERError(err, "ext-Teleservice", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ExtBasicServiceCode as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *ExtBasicServiceCode) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExtBasicServiceCode from BER/DER format.
func (destination *ExtBasicServiceCode) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExtBasicServiceCode destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExtBasicServiceCode)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_14, "child", (*ExtBasicServiceCode).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExtBasicServiceCode).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExtBasicServiceCode{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtBasicServiceCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtBasicServiceCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ExtBasicServiceCode CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtBasicServiceCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ExtBasicServiceCodeChoiceExtBearerService
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
		tmp := ExtBearerServiceCode(decVal)
		v.ExtBearerService = &tmp
		if len(*v.ExtBearerService) < 1 || len(*v.ExtBearerService) > 5 {
			if constraintErr := checkDecodedLength(opts, s6f8409_14, "51.5", "ext-BearerService", "SIZE (1..5)", len(*v.ExtBearerService)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = ExtBasicServiceCodeChoiceExtTeleservice
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
		tmp := ExtTeleserviceCode(decVal)
		v.ExtTeleservice = &tmp
		if len(*v.ExtTeleservice) < 1 || len(*v.ExtTeleservice) > 5 {
			if constraintErr := checkDecodedLength(opts, s6f8409_14, "51.5", "ext-Teleservice", "SIZE (1..5)", len(*v.ExtTeleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for ExtBasicServiceCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EMLPPInfo to BER format.
func (v *EMLPPInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: EMLPPInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*EMLPPInfo).MarshalBER, (*EMLPPInfo).marshalBER, true)

}
func (v *EMLPPInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.MaximumentitledPriority) >= 0 && int64(v.MaximumentitledPriority) <= 15) {
		if constraintErr := checkEncodedValue(opts, s6f8409_15, "51.4", "maximumentitledPriority", "(0..15)", ber.ObserveInteger(int64(v.MaximumentitledPriority))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_maximumentitledpriority := ber.EncodeInteger(int64(v.MaximumentitledPriority))
	children = append(children, enc_maximumentitledpriority...)
	if !(int64(v.DefaultPriority) >= 0 && int64(v.DefaultPriority) <= 15) {
		if constraintErr := checkEncodedValue(opts, s6f8409_15, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(v.DefaultPriority))); constraintErr != nil {
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
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s6f8409_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *EMLPPInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes EMLPPInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *EMLPPInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EMLPPInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.MaximumentitledPriority) >= 0 && int64(v.MaximumentitledPriority) <= 15) {
		if constraintErr := checkEncodedValue(nil, s6f8409_15, "51.4", "maximumentitledPriority", "(0..15)", ber.ObserveInteger(int64(v.MaximumentitledPriority))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_maximumentitledpriority := ber.EncodeInteger(int64(v.MaximumentitledPriority))
	children = append(children, enc_maximumentitledpriority...)
	if !(int64(v.DefaultPriority) >= 0 && int64(v.DefaultPriority) <= 15) {
		if constraintErr := checkEncodedValue(nil, s6f8409_15, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(v.DefaultPriority))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s6f8409_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding EMLPPInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *EMLPPInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes EMLPPInfo from BER/DER format.
func (destination *EMLPPInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: EMLPPInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(EMLPPInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_15, "child", (*EMLPPInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = EMLPPInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*EMLPPInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding EMLPPInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EMLPPInfo", Cause: ber.ErrExtraData}
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
		v.MaximumentitledPriority = EMLPPPriority(val_maximumentitledpriority)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.MaximumentitledPriority) >= 0 && int64(v.MaximumentitledPriority) <= 15) {
			if constraintErr := checkDecodedValue(opts, s6f8409_15, "51.4", "maximumentitledPriority", "(0..15)", ber.ObserveInteger(int64(v.MaximumentitledPriority))); constraintErr != nil {
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
		v.DefaultPriority = EMLPPPriority(val_defaultpriority)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.DefaultPriority) >= 0 && int64(v.DefaultPriority) <= 15) {
			if constraintErr := checkDecodedValue(opts, s6f8409_15, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(v.DefaultPriority))); constraintErr != nil {
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "EMLPPInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "EMLPPInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s6f8409_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes MCSSInfo to BER format.
func (v *MCSSInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MCSSInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MCSSInfo).MarshalBER, (*MCSSInfo).marshalBER, true)

}
func (v *MCSSInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, s6f8409_16, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(opts, s6f8409_16, "51.5", "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
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
		if constraintErr := checkEncodedValue(opts, s6f8409_16, "51.4", "nbrSB", "(2..7)", ber.ObserveInteger(int64(v.NbrSB))); constraintErr != nil {
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
		if constraintErr := checkEncodedValue(opts, s6f8409_16, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(v.NbrUser))); constraintErr != nil {
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
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s6f8409_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MCSSInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MCSSInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MCSSInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MCSSInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, s6f8409_16, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(nil, s6f8409_16, "51.5", "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
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
		if constraintErr := checkEncodedValue(nil, s6f8409_16, "51.4", "nbrSB", "(2..7)", ber.ObserveInteger(int64(v.NbrSB))); constraintErr != nil {
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
		if constraintErr := checkEncodedValue(nil, s6f8409_16, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(v.NbrUser))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s6f8409_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MCSSInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MCSSInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MCSSInfo from BER/DER format.
func (destination *MCSSInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MCSSInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(MCSSInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6f8409_16, "child", (*MCSSInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MCSSInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MCSSInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MCSSInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MCSSInfo", Cause: ber.ErrExtraData}
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
		v.SsCode = SSCode(decVal_sscode)
		if offset > len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_sscode
		if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
			if constraintErr := checkDecodedLength(opts, s6f8409_16, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
		v.SsStatus = ExtSSStatus(decVal_ssstatus)
		if offset < 0 || offset >
			len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_ssstatus
		if len(v.SsStatus) < 1 || len(v.SsStatus) > 5 {
			if constraintErr := checkDecodedLength(opts, s6f8409_16, "51.5", "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
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
		v.NbrSB = MaxMCBearers(decVal_nbrsb)
		if offset < 0 || offset >
			len(content) || n_nbrsb < 0 || n_nbrsb > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_nbrsb
		if !(int64(v.NbrSB) >= 2 && int64(v.NbrSB) <= 7) {
			if constraintErr := checkDecodedValue(opts, s6f8409_16, "51.4", "nbrSB", "(2..7)", ber.ObserveInteger(int64(v.NbrSB))); constraintErr != nil {
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
		v.NbrUser = MCBearers(decVal_nbruser)
		if offset < 0 || offset >
			len(content) || n_nbruser < 0 || n_nbruser > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_nbruser
		if !(int64(v.NbrUser) >= 1 && int64(v.NbrUser) <= 7) {
			if constraintErr := checkDecodedValue(opts, s6f8409_16, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(v.NbrUser))); constraintErr != nil {
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "MCSSInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MCSSInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s6f8409_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

const (
	s6f8409_0  = "MAP-CommonDataTypes.ISDN-AddressString"
	s6f8409_1  = "MAP-CommonDataTypes.FTN-AddressString"
	s6f8409_2  = "MAP-CommonDataTypes.ExternalSignalInfo"
	s6f8409_3  = "MAP-CommonDataTypes.Ext-ExternalSignalInfo"
	s6f8409_4  = "MAP-CommonDataTypes.AccessNetworkSignalInfo"
	s6f8409_5  = "MAP-CommonDataTypes.IMSI-WithLMSI"
	s6f8409_6  = "MAP-CommonDataTypes.SubscriberId"
	s6f8409_7  = "MAP-CommonDataTypes.HLR-List"
	s6f8409_8  = "MAP-CommonDataTypes.NAEA-PreferredCI"
	s6f8409_9  = "MAP-CommonDataTypes.SubscriberIdentity"
	s6f8409_10 = "MAP-CommonDataTypes.LCSClientExternalID"
	s6f8409_11 = "MAP-CommonDataTypes.NetworkNodeDiameterAddress"
	s6f8409_12 = "MAP-CommonDataTypes.CellGlobalIdOrServiceAreaIdOrLAI"
	s6f8409_13 = "MAP-CommonDataTypes.BasicServiceCode"
	s6f8409_14 = "MAP-CommonDataTypes.Ext-BasicServiceCode"
	s6f8409_15 = "MAP-CommonDataTypes.EMLPP-Info"
	s6f8409_16 = "MAP-CommonDataTypes.MC-SS-Info"
)
