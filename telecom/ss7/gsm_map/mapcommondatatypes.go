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

	// MaxAddressLength is the integer constant for MaxAddressLength.
	MaxAddressLength int64 = 20

	// MaxISDNAddressLength is the integer constant for MaxISDNAddressLength.
	MaxISDNAddressLength int64 = 9

	// MaxFTNAddressLength is the integer constant for MaxFTNAddressLength.
	MaxFTNAddressLength int64 = 15

	// MaxISDNSubaddressLength is the integer constant for MaxISDNSubaddressLength.
	MaxISDNSubaddressLength int64 = 21

	// MaxSignalInfoLength is the integer constant for MaxSignalInfoLength.
	MaxSignalInfoLength int64 = 200

	// MaxLongSignalInfoLength is the integer constant for MaxLongSignalInfoLength.
	MaxLongSignalInfoLength int64 = 2560

	// AlertingLevel0 is the octet string constant for AlertingLevel0.
	AlertingLevel0 = "\x00"

	// AlertingLevel1 is the octet string constant for AlertingLevel1.
	AlertingLevel1 = "\x01"

	// AlertingLevel2 is the octet string constant for AlertingLevel2.
	AlertingLevel2 = "\x02"

	// AlertingCategory1 is the octet string constant for AlertingCategory1.
	AlertingCategory1 = "\x04"

	// AlertingCategory2 is the octet string constant for AlertingCategory2.
	AlertingCategory2 = "\x05"

	// AlertingCategory3 is the octet string constant for AlertingCategory3.
	AlertingCategory3 = "\x06"

	// AlertingCategory4 is the octet string constant for AlertingCategory4.
	AlertingCategory4 = "\x07"

	// AlertingCategory5 is the octet string constant for AlertingCategory5.
	AlertingCategory5 = "\x08"

	// MaxNumOfHLRId is the integer constant for MaxNumOfHLRId.
	MaxNumOfHLRId int64 = 50

	// EmergencyServices is the integer constant for EmergencyServices.
	EmergencyServices int64 = 0

	// EmergencyAlertServices is the integer constant for EmergencyAlertServices.
	EmergencyAlertServices int64 = 1

	// PersonTracking is the integer constant for PersonTracking.
	PersonTracking int64 = 2

	// FleetManagement is the integer constant for FleetManagement.
	FleetManagement int64 = 3

	// AssetManagement is the integer constant for AssetManagement.
	AssetManagement int64 = 4

	// TrafficCongestionReporting is the integer constant for TrafficCongestionReporting.
	TrafficCongestionReporting int64 = 5

	// RoadsideAssistance is the integer constant for RoadsideAssistance.
	RoadsideAssistance int64 = 6

	// RoutingToNearestCommercialEnterprise is the integer constant for RoutingToNearestCommercialEnterprise.
	RoutingToNearestCommercialEnterprise int64 = 7

	// Navigation is the integer constant for Navigation.
	Navigation int64 = 8

	// CitySightseeing is the integer constant for CitySightseeing.
	CitySightseeing int64 = 9

	// LocalizedAdvertising is the integer constant for LocalizedAdvertising.
	LocalizedAdvertising int64 = 10

	// MobileYellowPages is the integer constant for MobileYellowPages.
	MobileYellowPages int64 = 11

	// TrafficAndPublicTransportationInfo is the integer constant for TrafficAndPublicTransportationInfo.
	TrafficAndPublicTransportationInfo int64 = 12

	// Weather is the integer constant for Weather.
	Weather int64 = 13

	// AssetAndServiceFinding is the integer constant for AssetAndServiceFinding.
	AssetAndServiceFinding int64 = 14

	// Gaming is the integer constant for Gaming.
	Gaming int64 = 15

	// FindYourFriend is the integer constant for FindYourFriend.
	FindYourFriend int64 = 16

	// Dating is the integer constant for Dating.
	Dating int64 = 17

	// Chatting is the integer constant for Chatting.
	Chatting int64 = 18

	// RouteFinding is the integer constant for RouteFinding.
	RouteFinding int64 = 19

	// WhereAmI is the integer constant for WhereAmI.
	WhereAmI int64 = 20

	// Serv64 is the integer constant for Serv64.
	Serv64 int64 = 64

	// Serv65 is the integer constant for Serv65.
	Serv65 int64 = 65

	// Serv66 is the integer constant for Serv66.
	Serv66 int64 = 66

	// Serv67 is the integer constant for Serv67.
	Serv67 int64 = 67

	// Serv68 is the integer constant for Serv68.
	Serv68 int64 = 68

	// Serv69 is the integer constant for Serv69.
	Serv69 int64 = 69

	// Serv70 is the integer constant for Serv70.
	Serv70 int64 = 70

	// Serv71 is the integer constant for Serv71.
	Serv71 int64 = 71

	// Serv72 is the integer constant for Serv72.
	Serv72 int64 = 72

	// Serv73 is the integer constant for Serv73.
	Serv73 int64 = 73

	// Serv74 is the integer constant for Serv74.
	Serv74 int64 = 74

	// Serv75 is the integer constant for Serv75.
	Serv75 int64 = 75

	// Serv76 is the integer constant for Serv76.
	Serv76 int64 = 76

	// Serv77 is the integer constant for Serv77.
	Serv77 int64 = 77

	// Serv78 is the integer constant for Serv78.
	Serv78 int64 = 78

	// Serv79 is the integer constant for Serv79.
	Serv79 int64 = 79

	// Serv80 is the integer constant for Serv80.
	Serv80 int64 = 80

	// Serv81 is the integer constant for Serv81.
	Serv81 int64 = 81

	// Serv82 is the integer constant for Serv82.
	Serv82 int64 = 82

	// Serv83 is the integer constant for Serv83.
	Serv83 int64 = 83

	// Serv84 is the integer constant for Serv84.
	Serv84 int64 = 84

	// Serv85 is the integer constant for Serv85.
	Serv85 int64 = 85

	// Serv86 is the integer constant for Serv86.
	Serv86 int64 = 86

	// Serv87 is the integer constant for Serv87.
	Serv87 int64 = 87

	// Serv88 is the integer constant for Serv88.
	Serv88 int64 = 88

	// Serv89 is the integer constant for Serv89.
	Serv89 int64 = 89

	// Serv90 is the integer constant for Serv90.
	Serv90 int64 = 90

	// Serv91 is the integer constant for Serv91.
	Serv91 int64 = 91

	// Serv92 is the integer constant for Serv92.
	Serv92 int64 = 92

	// Serv93 is the integer constant for Serv93.
	Serv93 int64 = 93

	// Serv94 is the integer constant for Serv94.
	Serv94 int64 = 94

	// Serv95 is the integer constant for Serv95.
	Serv95 int64 = 95

	// Serv96 is the integer constant for Serv96.
	Serv96 int64 = 96

	// Serv97 is the integer constant for Serv97.
	Serv97 int64 = 97

	// Serv98 is the integer constant for Serv98.
	Serv98 int64 = 98

	// Serv99 is the integer constant for Serv99.
	Serv99 int64 = 99

	// Serv100 is the integer constant for Serv100.
	Serv100 int64 = 100

	// Serv101 is the integer constant for Serv101.
	Serv101 int64 = 101

	// Serv102 is the integer constant for Serv102.
	Serv102 int64 = 102

	// Serv103 is the integer constant for Serv103.
	Serv103 int64 = 103

	// Serv104 is the integer constant for Serv104.
	Serv104 int64 = 104

	// Serv105 is the integer constant for Serv105.
	Serv105 int64 = 105

	// Serv106 is the integer constant for Serv106.
	Serv106 int64 = 106

	// Serv107 is the integer constant for Serv107.
	Serv107 int64 = 107

	// Serv108 is the integer constant for Serv108.
	Serv108 int64 = 108

	// Serv109 is the integer constant for Serv109.
	Serv109 int64 = 109

	// Serv110 is the integer constant for Serv110.
	Serv110 int64 = 110

	// Serv111 is the integer constant for Serv111.
	Serv111 int64 = 111

	// Serv112 is the integer constant for Serv112.
	Serv112 int64 = 112

	// Serv113 is the integer constant for Serv113.
	Serv113 int64 = 113

	// Serv114 is the integer constant for Serv114.
	Serv114 int64 = 114

	// Serv115 is the integer constant for Serv115.
	Serv115 int64 = 115

	// Serv116 is the integer constant for Serv116.
	Serv116 int64 = 116

	// Serv117 is the integer constant for Serv117.
	Serv117 int64 = 117

	// Serv118 is the integer constant for Serv118.
	Serv118 int64 = 118

	// Serv119 is the integer constant for Serv119.
	Serv119 int64 = 119

	// Serv120 is the integer constant for Serv120.
	Serv120 int64 = 120

	// Serv121 is the integer constant for Serv121.
	Serv121 int64 = 121

	// Serv122 is the integer constant for Serv122.
	Serv122 int64 = 122

	// Serv123 is the integer constant for Serv123.
	Serv123 int64 = 123

	// Serv124 is the integer constant for Serv124.
	Serv124 int64 = 124

	// Serv125 is the integer constant for Serv125.
	Serv125 int64 = 125

	// Serv126 is the integer constant for Serv126.
	Serv126 int64 = 126

	// Serv127 is the integer constant for Serv127.
	Serv127 int64 = 127

	// PriorityLevelA is the integer constant for PriorityLevelA.
	PriorityLevelA int64 = 6

	// PriorityLevelB is the integer constant for PriorityLevelB.
	PriorityLevelB int64 = 5

	// PriorityLevel0 is the integer constant for PriorityLevel0.
	PriorityLevel0 int64 = 0

	// PriorityLevel1 is the integer constant for PriorityLevel1.
	PriorityLevel1 int64 = 1

	// PriorityLevel2 is the integer constant for PriorityLevel2.
	PriorityLevel2 int64 = 2

	// PriorityLevel3 is the integer constant for PriorityLevel3.
	PriorityLevel3 int64 = 3

	// PriorityLevel4 is the integer constant for PriorityLevel4.
	PriorityLevel4 int64 = 4

	// MaxNumOfMCBearers is the integer constant for MaxNumOfMCBearers.
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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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
	ExtData_                [][]byte                `asn1:"-" json:"-"`
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
	Choice       int
	Imsi         *IMSI         `json:"Imsi,omitempty"`
	ImsiWithLMSI *IMSIWithLMSI `json:"ImsiWithLMSI,omitempty"`
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
	Imsi        IMSI     `asn1:""`
	Lmsi        LMSI     `asn1:""`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
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
	Choice int
	Imsi   *IMSI `json:"Imsi,omitempty"`
	Tmsi   *TMSI `json:"Tmsi,omitempty"`
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
type HLRList = []HLRId

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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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
	Choice int
	Imsi   *IMSI              `json:"Imsi,omitempty"`
	Msisdn *ISDNAddressString `json:"Msisdn,omitempty"`
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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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
	DiameterName  DiameterIdentity `asn1:"tag:0,context,implicit"`
	DiameterRealm DiameterIdentity `asn1:"tag:1,context,implicit"`
}

// CellGlobalIdOrServiceAreaIdOrLAI choice constants.
const (
	CellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength = 1
	CellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength                         = 2
)

// CellGlobalIdOrServiceAreaIdOrLAI represents the ASN.1 CHOICE type CellGlobalIdOrServiceAreaIdOrLAI.
type CellGlobalIdOrServiceAreaIdOrLAI struct {
	Choice                                 int
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
	Choice        int
	BearerService *BearerServiceCode `json:"BearerService,omitempty"`
	Teleservice   *TeleserviceCode   `json:"Teleservice,omitempty"`
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
	ExtData_                [][]byte            `asn1:"-" json:"-"`
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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// MaxMCBearers represents the ASN.1 type MaxMC-Bearers (INTEGER).
type MaxMCBearers = int64

// MCBearers represents the ASN.1 type MC-Bearers (INTEGER).
type MCBearers = int64

// ExtSSStatus represents the ASN.1 type Ext-SS-Status (OCTET_STRING).
type ExtSSStatus = []byte

// AgeOfLocationInformation represents the ASN.1 type AgeOfLocationInformation (INTEGER).
type AgeOfLocationInformation = int64

// MarshalBER encodes ExternalSignalInfo to BER format.
func (v *ExternalSignalInfo) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ExternalSignalInfo to DER format.
func (v *ExternalSignalInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExternalSignalInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExternalSignalInfo from BER/DER format.
func (v *ExternalSignalInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExternalSignalInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExternalSignalInfo", Cause: ber.ErrExtraData}
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
	v.ProtocolId = ProtocolId(val_protocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ExtExternalSignalInfo to BER format.
func (v *ExtExternalSignalInfo) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ExtExternalSignalInfo to DER format.
func (v *ExtExternalSignalInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtExternalSignalInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtExternalSignalInfo from BER/DER format.
func (v *ExtExternalSignalInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExtExternalSignalInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtExternalSignalInfo", Cause: ber.ErrExtraData}
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
	v.ExtProtocolId = ExtProtocolId(val_extprotocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtExternalSignalInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AccessNetworkSignalInfo to BER format.
func (v *AccessNetworkSignalInfo) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes AccessNetworkSignalInfo to DER format.
func (v *AccessNetworkSignalInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AccessNetworkSignalInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AccessNetworkSignalInfo from BER/DER format.
func (v *AccessNetworkSignalInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AccessNetworkSignalInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AccessNetworkSignalInfo", Cause: ber.ErrExtraData}
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
	v.AccessNetworkProtocolId = AccessNetworkProtocolId(val_accessnetworkprotocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = LongSignalInfo(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "AccessNetworkSignalInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes Identity to BER format.
func (v *Identity) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case IdentityChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("choice Identity: imsi is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		return enc_0, nil
	case IdentityChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("choice Identity: imsi-WithLMSI is nil")
		}
		enc_1, err := v.ImsiWithLMSI.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Identity", v.Choice)
	}
}

// MarshalDER encodes Identity to DER format.
func (v *Identity) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case IdentityChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("choice Identity: imsi-WithLMSI is nil")
		}
		enc_der_1, err := v.ImsiWithLMSI.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI: %w", err)
		}
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Identity as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Identity from BER/DER format.
func (v *Identity) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Identity CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Identity: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Identity CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Identity", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = IdentityChoiceImsi
		decVal, _, osErr := ber.DecodeOctetString(choiceData)
		if osErr != nil {
			return fmt.Errorf("decoding imsi: %w", osErr)
		}
		tmp := IMSI(decVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = IdentityChoiceImsiWithLMSI
		var dec IMSIWithLMSI
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding imsi-WithLMSI: %w", unmErr)
		}
		v.ImsiWithLMSI = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Identity CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes IMSIWithLMSI to BER format.
func (v *IMSIWithLMSI) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes IMSIWithLMSI to DER format.
func (v *IMSIWithLMSI) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IMSIWithLMSI as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IMSIWithLMSI from BER/DER format.
func (v *IMSIWithLMSI) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IMSIWithLMSI SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IMSIWithLMSI", Cause: ber.ErrExtraData}
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
	v.Imsi = IMSI(val_imsi)
	offset += n
	// Decode lmsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field lmsi")
	}
	val_lmsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lmsi: %w", err)
	}
	v.Lmsi = LMSI(val_lmsi)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IMSIWithLMSI", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubscriberId to BER format.
func (v *SubscriberId) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SubscriberIdChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("choice SubscriberId: imsi is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SubscriberIdChoiceTmsi:
		if v.Tmsi == nil {
			return nil, fmt.Errorf("choice SubscriberId: tmsi is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.Tmsi))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding tmsi: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SubscriberId", v.Choice)
	}
}

// MarshalDER encodes SubscriberId to DER format.
func (v *SubscriberId) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberId as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberId from BER/DER format.
func (v *SubscriberId) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberIdChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := IMSI(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberIdChoiceTmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding tmsi: %w", tlvErr)
		}
		tmp := TMSI(rawVal)
		v.Tmsi = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberId CHOICE", peekTag)
	}
	return nil
}

// MarshalBERHLRList encodes a HLRList list to BER.
func MarshalBERHLRList(list HLRList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERHLRList decodes a HLRList list from BER.
func UnmarshalBERHLRList(data []byte) (HLRList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding HLRList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "HLRList", Cause: ber.ErrExtraData}
	}
	var result HLRList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, HLRId(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes NAEAPreferredCI to BER format.
func (v *NAEAPreferredCI) MarshalBER() ([]byte, error) {
	var children []byte
	enc_naeapreferredcic := ber.EncodeOctetString([]byte(v.NaeaPreferredCIC))
	retagged_enc_naeapreferredcic, tagErr_enc_naeapreferredcic := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naeapreferredcic)
	if tagErr_enc_naeapreferredcic != nil {
		return nil, fmt.Errorf("encoding naea-PreferredCIC: %w", tagErr_enc_naeapreferredcic)
	}
	enc_naeapreferredcic = retagged_enc_naeapreferredcic
	children = append(children, enc_naeapreferredcic...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
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

// MarshalDER encodes NAEAPreferredCI to DER format.
func (v *NAEAPreferredCI) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding NAEAPreferredCI as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NAEAPreferredCI from BER/DER format.
func (v *NAEAPreferredCI) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NAEAPreferredCI SEQUENCE: %w", err)
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
	decodedTag_naeapreferredcic, n_naeapreferredcic, rawVal_naeapreferredcic, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding naea-PreferredCIC: %w", err)
	}
	if decodedTag_naeapreferredcic.Class != tag.ClassContextSpecific || decodedTag_naeapreferredcic.Number != 0 {
		return fmt.Errorf("decoding naea-PreferredCIC: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naeapreferredcic)
	}
	v.NaeaPreferredCIC = NAEACIC(rawVal_naeapreferredcic)
	offset += n_naeapreferredcic
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "NAEAPreferredCI", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubscriberIdentity to BER format.
func (v *SubscriberIdentity) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SubscriberIdentityChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("choice SubscriberIdentity: imsi is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SubscriberIdentityChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("choice SubscriberIdentity: msisdn is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.Msisdn))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SubscriberIdentity", v.Choice)
	}
}

// MarshalDER encodes SubscriberIdentity to DER format.
func (v *SubscriberIdentity) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberIdentity as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberIdentity from BER/DER format.
func (v *SubscriberIdentity) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberIdentity CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberIdentity: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberIdentity CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberIdentity", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberIdentityChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := IMSI(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberIdentityChoiceMsisdn
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msisdn: %w", tlvErr)
		}
		tmp := ISDNAddressString(rawVal)
		v.Msisdn = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberIdentity CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes LCSClientExternalID to BER format.
func (v *LCSClientExternalID) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExternalAddress != nil {
		enc_externaladdress := ber.EncodeOctetString([]byte(*v.ExternalAddress))
		retagged_enc_externaladdress, tagErr_enc_externaladdress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_externaladdress)
		if tagErr_enc_externaladdress != nil {
			return nil, fmt.Errorf("encoding externalAddress: %w", tagErr_enc_externaladdress)
		}
		enc_externaladdress = retagged_enc_externaladdress
		children = append(children, enc_externaladdress...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
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

// MarshalDER encodes LCSClientExternalID to DER format.
func (v *LCSClientExternalID) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding LCSClientExternalID as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSClientExternalID from BER/DER format.
func (v *LCSClientExternalID) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSClientExternalID SEQUENCE: %w", err)
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
				decodedTag_externaladdress, n_externaladdress, rawVal_externaladdress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding externalAddress: %w", err)
				}
				if decodedTag_externaladdress.Class != tag.ClassContextSpecific || decodedTag_externaladdress.Number != 0 {
					return fmt.Errorf("decoding externalAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_externaladdress)
				}
				tmp_externaladdress := ISDNAddressString(rawVal_externaladdress)
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
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSClientExternalID", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NetworkNodeDiameterAddress to BER format.
func (v *NetworkNodeDiameterAddress) MarshalBER() ([]byte, error) {
	var children []byte
	enc_diametername := ber.EncodeOctetString([]byte(v.DiameterName))
	retagged_enc_diametername, tagErr_enc_diametername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_diametername)
	if tagErr_enc_diametername != nil {
		return nil, fmt.Errorf("encoding diameter-Name: %w", tagErr_enc_diametername)
	}
	enc_diametername = retagged_enc_diametername
	children = append(children, enc_diametername...)
	enc_diameterrealm := ber.EncodeOctetString([]byte(v.DiameterRealm))
	retagged_enc_diameterrealm, tagErr_enc_diameterrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_diameterrealm)
	if tagErr_enc_diameterrealm != nil {
		return nil, fmt.Errorf("encoding diameter-Realm: %w", tagErr_enc_diameterrealm)
	}
	enc_diameterrealm = retagged_enc_diameterrealm
	children = append(children, enc_diameterrealm...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes NetworkNodeDiameterAddress to DER format.
func (v *NetworkNodeDiameterAddress) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding NetworkNodeDiameterAddress as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NetworkNodeDiameterAddress from BER/DER format.
func (v *NetworkNodeDiameterAddress) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NetworkNodeDiameterAddress SEQUENCE: %w", err)
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
	decodedTag_diametername, n_diametername, rawVal_diametername, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding diameter-Name: %w", err)
	}
	if decodedTag_diametername.Class != tag.ClassContextSpecific || decodedTag_diametername.Number != 0 {
		return fmt.Errorf("decoding diameter-Name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_diametername)
	}
	v.DiameterName = DiameterIdentity(rawVal_diametername)
	offset += n_diametername
	// Decode diameter-Realm
	if offset >= len(content) {
		return fmt.Errorf("missing required field diameter-Realm")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for diameter-Realm, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_diameterrealm, n_diameterrealm, rawVal_diameterrealm, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding diameter-Realm: %w", err)
	}
	if decodedTag_diameterrealm.Class != tag.ClassContextSpecific || decodedTag_diameterrealm.Number != 1 {
		return fmt.Errorf("decoding diameter-Realm: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_diameterrealm)
	}
	v.DiameterRealm = DiameterIdentity(rawVal_diameterrealm)
	offset += n_diameterrealm
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "NetworkNodeDiameterAddress", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CellGlobalIdOrServiceAreaIdOrLAI to BER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength:
		if v.CellGlobalIdOrServiceAreaIdFixedLength == nil {
			return nil, fmt.Errorf("choice CellGlobalIdOrServiceAreaIdOrLAI: cellGlobalIdOrServiceAreaIdFixedLength is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.CellGlobalIdOrServiceAreaIdFixedLength))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding cellGlobalIdOrServiceAreaIdFixedLength: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case CellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength:
		if v.LaiFixedLength == nil {
			return nil, fmt.Errorf("choice CellGlobalIdOrServiceAreaIdOrLAI: laiFixedLength is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.LaiFixedLength))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding laiFixedLength: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CellGlobalIdOrServiceAreaIdOrLAI", v.Choice)
	}
}

// MarshalDER encodes CellGlobalIdOrServiceAreaIdOrLAI to DER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CellGlobalIdOrServiceAreaIdOrLAI as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CellGlobalIdOrServiceAreaIdOrLAI from BER/DER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CellGlobalIdOrServiceAreaIdOrLAI CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CellGlobalIdOrServiceAreaIdOrLAI: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CellGlobalIdOrServiceAreaIdOrLAI CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CellGlobalIdOrServiceAreaIdOrLAI", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAIChoiceCellGlobalIdOrServiceAreaIdFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cellGlobalIdOrServiceAreaIdFixedLength: %w", tlvErr)
		}
		tmp := CellGlobalIdOrServiceAreaIdFixedLength(rawVal)
		v.CellGlobalIdOrServiceAreaIdFixedLength = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAIChoiceLaiFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding laiFixedLength: %w", tlvErr)
		}
		tmp := LAIFixedLength(rawVal)
		v.LaiFixedLength = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for CellGlobalIdOrServiceAreaIdOrLAI CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes BasicServiceCode to BER format.
func (v *BasicServiceCode) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case BasicServiceCodeChoiceBearerService:
		if v.BearerService == nil {
			return nil, fmt.Errorf("choice BasicServiceCode: bearerService is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.BearerService))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding bearerService: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case BasicServiceCodeChoiceTeleservice:
		if v.Teleservice == nil {
			return nil, fmt.Errorf("choice BasicServiceCode: teleservice is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.Teleservice))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding teleservice: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for BasicServiceCode", v.Choice)
	}
}

// MarshalDER encodes BasicServiceCode to DER format.
func (v *BasicServiceCode) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BasicServiceCode as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BasicServiceCode from BER/DER format.
func (v *BasicServiceCode) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for BasicServiceCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for BasicServiceCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding BasicServiceCode CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "BasicServiceCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = BasicServiceCodeChoiceBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding bearerService: %w", tlvErr)
		}
		tmp := BearerServiceCode(rawVal)
		v.BearerService = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = BasicServiceCodeChoiceTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding teleservice: %w", tlvErr)
		}
		tmp := TeleserviceCode(rawVal)
		v.Teleservice = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for BasicServiceCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtBasicServiceCode to BER format.
func (v *ExtBasicServiceCode) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ExtBasicServiceCodeChoiceExtBearerService:
		if v.ExtBearerService == nil {
			return nil, fmt.Errorf("choice ExtBasicServiceCode: ext-BearerService is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.ExtBearerService))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding ext-BearerService: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ExtBasicServiceCodeChoiceExtTeleservice:
		if v.ExtTeleservice == nil {
			return nil, fmt.Errorf("choice ExtBasicServiceCode: ext-Teleservice is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.ExtTeleservice))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding ext-Teleservice: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ExtBasicServiceCode", v.Choice)
	}
}

// MarshalDER encodes ExtBasicServiceCode to DER format.
func (v *ExtBasicServiceCode) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtBasicServiceCode as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtBasicServiceCode from BER/DER format.
func (v *ExtBasicServiceCode) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtBasicServiceCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtBasicServiceCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ExtBasicServiceCode CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtBasicServiceCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ExtBasicServiceCodeChoiceExtBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-BearerService: %w", tlvErr)
		}
		tmp := ExtBearerServiceCode(rawVal)
		v.ExtBearerService = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = ExtBasicServiceCodeChoiceExtTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-Teleservice: %w", tlvErr)
		}
		tmp := ExtTeleserviceCode(rawVal)
		v.ExtTeleservice = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for ExtBasicServiceCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EMLPPInfo to BER format.
func (v *EMLPPInfo) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes EMLPPInfo to DER format.
func (v *EMLPPInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding EMLPPInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EMLPPInfo from BER/DER format.
func (v *EMLPPInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EMLPPInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EMLPPInfo", Cause: ber.ErrExtraData}
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
	v.MaximumentitledPriority = EMLPPPriority(val_maximumentitledpriority)
	offset += n
	// Decode defaultPriority
	if offset >= len(content) {
		return fmt.Errorf("missing required field defaultPriority")
	}
	val_defaultpriority, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding defaultPriority: %w", err)
	}
	v.DefaultPriority = EMLPPPriority(val_defaultpriority)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "EMLPPInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MCSSInfo to BER format.
func (v *MCSSInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	enc_nbrsb := ber.EncodeInteger(int64(v.NbrSB))
	retagged_enc_nbrsb, tagErr_enc_nbrsb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_nbrsb)
	if tagErr_enc_nbrsb != nil {
		return nil, fmt.Errorf("encoding nbrSB: %w", tagErr_enc_nbrsb)
	}
	enc_nbrsb = retagged_enc_nbrsb
	children = append(children, enc_nbrsb...)
	enc_nbruser := ber.EncodeInteger(int64(v.NbrUser))
	retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_nbruser)
	if tagErr_enc_nbruser != nil {
		return nil, fmt.Errorf("encoding nbrUser: %w", tagErr_enc_nbruser)
	}
	enc_nbruser = retagged_enc_nbruser
	children = append(children, enc_nbruser...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
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

// MarshalDER encodes MCSSInfo to DER format.
func (v *MCSSInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MCSSInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MCSSInfo from BER/DER format.
func (v *MCSSInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MCSSInfo SEQUENCE: %w", err)
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
	decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
		return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
	}
	v.SsCode = SSCode(rawVal_sscode)
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
	decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Status: %w", err)
	}
	if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 1 {
		return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
	}
	v.SsStatus = ExtSSStatus(rawVal_ssstatus)
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
	decodedTag_nbrsb, n_nbrsb, rawVal_nbrsb, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding nbrSB: %w", err)
	}
	if decodedTag_nbrsb.Class != tag.ClassContextSpecific || decodedTag_nbrsb.Number != 2 || decodedTag_nbrsb.Constructed != false {
		return fmt.Errorf("decoding nbrSB: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbrsb)
	}
	decVal_nbrsb, intErr := ber.DecodeIntegerValue(rawVal_nbrsb)
	if intErr != nil {
		return fmt.Errorf("decoding nbrSB: %w", intErr)
	}
	v.NbrSB = MaxMCBearers(decVal_nbrsb)
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
	decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding nbrUser: %w", err)
	}
	if decodedTag_nbruser.Class != tag.ClassContextSpecific || decodedTag_nbruser.Number != 3 || decodedTag_nbruser.Constructed != false {
		return fmt.Errorf("decoding nbrUser: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbruser)
	}
	decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
	if intErr != nil {
		return fmt.Errorf("decoding nbrUser: %w", intErr)
	}
	v.NbrUser = MCBearers(decVal_nbruser)
	offset += n_nbruser
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "MCSSInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
