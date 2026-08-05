// Code generated from ASN.1 module "SGP32Definitions". DO NOT EDIT.

package sgp32

import (
	"fmt"
	"math/big"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
	"github.com/gomaja/go-asn1/telecom/esim/sgp22"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

// EuiccPackageRequest represents the ASN.1 type EuiccPackageRequest (SEQUENCE).
type EuiccPackageRequest struct {
	EuiccPackageSigned EuiccPackageSigned `asn1:""`
	EimSignature       []byte             `asn1:"tag:55,application,implicit"`
}

// EuiccPackageSigned represents the ASN.1 type EuiccPackageSigned (SEQUENCE).
type EuiccPackageSigned struct {
	EimId            string               `asn1:"tag:0,context,implicit"`
	EidValue         sgp22.Octet16        `asn1:"tag:26,application,implicit"`
	CounterValue     *big.Int             `asn1:"tag:1,context,implicit"`
	EimTransactionId *sgp22.TransactionId `asn1:"tag:2,context,implicit,optional" json:"EimTransactionId,omitempty"`
	EuiccPackage     EuiccPackage         `asn1:""`
}

// EuiccPackage choice constants.
const (
	EuiccPackageChoicePsmoList = 1
	EuiccPackageChoiceEcoList  = 2
)

// EuiccPackage represents the ASN.1 CHOICE type EuiccPackage.
type EuiccPackage struct {
	Choice   int
	PsmoList EuiccPackagePsmoList `json:"PsmoList,omitempty"`
	EcoList  EuiccPackageEcoList  `json:"EcoList,omitempty"`
}

// NewEuiccPackagePsmoList creates a EuiccPackage with the psmoList alternative.
func NewEuiccPackagePsmoList(v EuiccPackagePsmoList) EuiccPackage {
	return EuiccPackage{
		Choice:   EuiccPackageChoicePsmoList,
		PsmoList: v,
	}
}

// NewEuiccPackageEcoList creates a EuiccPackage with the ecoList alternative.
func NewEuiccPackageEcoList(v EuiccPackageEcoList) EuiccPackage {
	return EuiccPackage{
		Choice:  EuiccPackageChoiceEcoList,
		EcoList: v,
	}
}

// EimConfigurationData represents the ASN.1 type EimConfigurationData (SEQUENCE).
type EimConfigurationData struct {
	EimId                                     string                                       `asn1:"tag:0,context,implicit"`
	EimFqdn                                   *string                                      `asn1:"tag:1,context,implicit,optional" json:"EimFqdn,omitempty"`
	EimIdType                                 *EimIdType                                   `asn1:"tag:2,context,implicit,optional" json:"EimIdType,omitempty"`
	CounterValue                              *big.Int                                     `asn1:"tag:3,context,implicit,optional" json:"CounterValue,omitempty"`
	AssociationToken                          *big.Int                                     `asn1:"tag:4,context,implicit,optional" json:"AssociationToken,omitempty"`
	EimPublicKeyData                          *EimConfigurationDataEimPublicKeyData        `asn1:"tag:5,context,explicit,optional" json:"EimPublicKeyData,omitempty"`
	TrustedPublicKeyDataTls                   *EimConfigurationDataTrustedPublicKeyDataTls `asn1:"tag:6,context,explicit,optional" json:"TrustedPublicKeyDataTls,omitempty"`
	EimSupportedProtocol                      *EimSupportedProtocol                        `asn1:"tag:7,context,implicit,optional" json:"EimSupportedProtocol,omitempty"`
	EuiccCiPKId                               *sgp22.SubjectKeyIdentifier                  `asn1:"tag:8,context,implicit,optional" json:"EuiccCiPKId,omitempty"`
	IndirectProfileDownload                   *struct{}                                    `asn1:"tag:9,context,implicit,optional" json:"IndirectProfileDownload,omitempty"`
	ESipaProprietaryProtocolInformation       sgp22.VendorSpecificExtension                `asn1:"tag:10,context,implicit,optional" json:"ESipaProprietaryProtocolInformation,omitempty"`
	ESipaProprietaryProtocolInformationIndef_ bool                                         `asn1:"-" json:"-"`
}

// EimIdType represents the ASN.1 INTEGER type EimIdType with named numbers.
type EimIdType int64

const (
	EimIdTypeEimIdTypeOid         EimIdType = 1
	EimIdTypeEimIdTypeFqdn        EimIdType = 2
	EimIdTypeEimIdTypeProprietary EimIdType = 3
)

func (v EimIdType) String() string {
	switch v {
	case EimIdTypeEimIdTypeOid:
		return "eimIdTypeOid"
	case EimIdTypeEimIdTypeFqdn:
		return "eimIdTypeFqdn"
	case EimIdTypeEimIdTypeProprietary:
		return "eimIdTypeProprietary"
	default:
		return "unknown"
	}
}

// EimSupportedProtocol represents the ASN.1 type EimSupportedProtocol (BIT_STRING).
type EimSupportedProtocol = runtime.BitString

// Eco choice constants.
const (
	EcoChoiceAddEim    = 1
	EcoChoiceDeleteEim = 2
	EcoChoiceUpdateEim = 3
	EcoChoiceListEim   = 4
)

// Eco represents the ASN.1 CHOICE type Eco.
type Eco struct {
	Choice    int
	AddEim    *EimConfigurationData `json:"AddEim,omitempty"`
	DeleteEim *EcoDeleteEim         `json:"DeleteEim,omitempty"`
	UpdateEim *EimConfigurationData `json:"UpdateEim,omitempty"`
	ListEim   *EcoListEim           `json:"ListEim,omitempty"`
}

// NewEcoAddEim creates a Eco with the addEim alternative.
func NewEcoAddEim(v EimConfigurationData) Eco {
	return Eco{
		Choice: EcoChoiceAddEim,
		AddEim: &v,
	}
}

// NewEcoDeleteEim creates a Eco with the deleteEim alternative.
func NewEcoDeleteEim(v EcoDeleteEim) Eco {
	return Eco{
		Choice:    EcoChoiceDeleteEim,
		DeleteEim: &v,
	}
}

// NewEcoUpdateEim creates a Eco with the updateEim alternative.
func NewEcoUpdateEim(v EimConfigurationData) Eco {
	return Eco{
		Choice:    EcoChoiceUpdateEim,
		UpdateEim: &v,
	}
}

// NewEcoListEim creates a Eco with the listEim alternative.
func NewEcoListEim(v EcoListEim) Eco {
	return Eco{
		Choice:  EcoChoiceListEim,
		ListEim: &v,
	}
}

// Psmo choice constants.
const (
	PsmoChoiceEnable                   = 1
	PsmoChoiceDisable                  = 2
	PsmoChoiceDelete                   = 3
	PsmoChoiceListProfileInfo          = 4
	PsmoChoiceGetRAT                   = 5
	PsmoChoiceConfigureImmediateEnable = 6
	PsmoChoiceSetFallbackAttribute     = 7
	PsmoChoiceUnsetFallbackAttribute   = 8
	PsmoChoiceSetDefaultDpAddress      = 9
)

// Psmo represents the ASN.1 CHOICE type Psmo.
type Psmo struct {
	Choice                   int
	Enable                   *PsmoEnable                   `json:"Enable,omitempty"`
	Disable                  *PsmoDisable                  `json:"Disable,omitempty"`
	Delete                   *PsmoDelete                   `json:"Delete,omitempty"`
	ListProfileInfo          *sgp22.ProfileInfoListRequest `json:"ListProfileInfo,omitempty"`
	GetRAT                   *PsmoGetRAT                   `json:"GetRAT,omitempty"`
	ConfigureImmediateEnable *PsmoConfigureImmediateEnable `json:"ConfigureImmediateEnable,omitempty"`
	SetFallbackAttribute     *PsmoSetFallbackAttribute     `json:"SetFallbackAttribute,omitempty"`
	UnsetFallbackAttribute   *PsmoUnsetFallbackAttribute   `json:"UnsetFallbackAttribute,omitempty"`
	SetDefaultDpAddress      *SetDefaultDpAddressRequest   `json:"SetDefaultDpAddress,omitempty"`
}

// NewPsmoEnable creates a Psmo with the enable alternative.
func NewPsmoEnable(v PsmoEnable) Psmo {
	return Psmo{
		Choice: PsmoChoiceEnable,
		Enable: &v,
	}
}

// NewPsmoDisable creates a Psmo with the disable alternative.
func NewPsmoDisable(v PsmoDisable) Psmo {
	return Psmo{
		Choice:  PsmoChoiceDisable,
		Disable: &v,
	}
}

// NewPsmoDelete creates a Psmo with the delete alternative.
func NewPsmoDelete(v PsmoDelete) Psmo {
	return Psmo{
		Choice: PsmoChoiceDelete,
		Delete: &v,
	}
}

// NewPsmoListProfileInfo creates a Psmo with the listProfileInfo alternative.
func NewPsmoListProfileInfo(v sgp22.ProfileInfoListRequest) Psmo {
	return Psmo{
		Choice:          PsmoChoiceListProfileInfo,
		ListProfileInfo: &v,
	}
}

// NewPsmoGetRAT creates a Psmo with the getRAT alternative.
func NewPsmoGetRAT(v PsmoGetRAT) Psmo {
	return Psmo{
		Choice: PsmoChoiceGetRAT,
		GetRAT: &v,
	}
}

// NewPsmoConfigureImmediateEnable creates a Psmo with the configureImmediateEnable alternative.
func NewPsmoConfigureImmediateEnable(v PsmoConfigureImmediateEnable) Psmo {
	return Psmo{
		Choice:                   PsmoChoiceConfigureImmediateEnable,
		ConfigureImmediateEnable: &v,
	}
}

// NewPsmoSetFallbackAttribute creates a Psmo with the setFallbackAttribute alternative.
func NewPsmoSetFallbackAttribute(v PsmoSetFallbackAttribute) Psmo {
	return Psmo{
		Choice:               PsmoChoiceSetFallbackAttribute,
		SetFallbackAttribute: &v,
	}
}

// NewPsmoUnsetFallbackAttribute creates a Psmo with the unsetFallbackAttribute alternative.
func NewPsmoUnsetFallbackAttribute(v PsmoUnsetFallbackAttribute) Psmo {
	return Psmo{
		Choice:                 PsmoChoiceUnsetFallbackAttribute,
		UnsetFallbackAttribute: &v,
	}
}

// NewPsmoSetDefaultDpAddress creates a Psmo with the setDefaultDpAddress alternative.
func NewPsmoSetDefaultDpAddress(v SetDefaultDpAddressRequest) Psmo {
	return Psmo{
		Choice:              PsmoChoiceSetDefaultDpAddress,
		SetDefaultDpAddress: &v,
	}
}

// IpaEuiccDataRequest represents the ASN.1 type IpaEuiccDataRequest (SEQUENCE).
type IpaEuiccDataRequest struct {
	TagList                          []byte                                               `asn1:"tag:28,application,implicit"`
	EuiccCiPKIdentifierToBeUsed      []byte                                               `asn1:",optional" json:"EuiccCiPKIdentifierToBeUsed,omitempty"`
	SearchCriteriaNotification       *IpaEuiccDataRequestSearchCriteriaNotification       `asn1:"tag:1,context,explicit,optional" json:"SearchCriteriaNotification,omitempty"`
	SearchCriteriaEuiccPackageResult *IpaEuiccDataRequestSearchCriteriaEuiccPackageResult `asn1:"tag:2,context,explicit,optional" json:"SearchCriteriaEuiccPackageResult,omitempty"`
	EimTransactionId                 *sgp22.TransactionId                                 `asn1:"tag:3,context,implicit,optional" json:"EimTransactionId,omitempty"`
}

// ProfileDownloadTriggerRequest represents the ASN.1 type ProfileDownloadTriggerRequest (SEQUENCE).
type ProfileDownloadTriggerRequest struct {
	ProfileDownloadData *ProfileDownloadData `asn1:"tag:0,context,explicit,optional" json:"ProfileDownloadData,omitempty"`
	EimTransactionId    *sgp22.TransactionId `asn1:"tag:2,context,implicit,optional" json:"EimTransactionId,omitempty"`
}

// ProfileDownloadData choice constants.
const (
	ProfileDownloadDataChoiceActivationCode     = 1
	ProfileDownloadDataChoiceContactDefaultSmdp = 2
	ProfileDownloadDataChoiceContactSmds        = 3
)

// ProfileDownloadData represents the ASN.1 CHOICE type ProfileDownloadData.
type ProfileDownloadData struct {
	Choice             int
	ActivationCode     *string                         `json:"ActivationCode,omitempty"`
	ContactDefaultSmdp *struct{}                       `json:"ContactDefaultSmdp,omitempty"`
	ContactSmds        *ProfileDownloadDataContactSmds `json:"ContactSmds,omitempty"`
}

// NewProfileDownloadDataActivationCode creates a ProfileDownloadData with the activationCode alternative.
func NewProfileDownloadDataActivationCode(v string) ProfileDownloadData {
	return ProfileDownloadData{
		Choice:         ProfileDownloadDataChoiceActivationCode,
		ActivationCode: &v,
	}
}

// NewProfileDownloadDataContactDefaultSmdp creates a ProfileDownloadData with the contactDefaultSmdp alternative.
func NewProfileDownloadDataContactDefaultSmdp(v struct{}) ProfileDownloadData {
	return ProfileDownloadData{
		Choice:             ProfileDownloadDataChoiceContactDefaultSmdp,
		ContactDefaultSmdp: &v,
	}
}

// NewProfileDownloadDataContactSmds creates a ProfileDownloadData with the contactSmds alternative.
func NewProfileDownloadDataContactSmds(v ProfileDownloadDataContactSmds) ProfileDownloadData {
	return ProfileDownloadData{
		Choice:      ProfileDownloadDataChoiceContactSmds,
		ContactSmds: &v,
	}
}

// EimAcknowledgements represents the ASN.1 type EimAcknowledgements (SEQUENCE_OF).
type EimAcknowledgements = []SequenceNumber

// SequenceNumber represents the ASN.1 type SequenceNumber (INTEGER).
type SequenceNumber = *big.Int

// EuiccPackageResult choice constants.
const (
	EuiccPackageResultChoiceEuiccPackageResultSigned  = 1
	EuiccPackageResultChoiceEuiccPackageErrorSigned   = 2
	EuiccPackageResultChoiceEuiccPackageErrorUnsigned = 3
)

// EuiccPackageResult represents the ASN.1 CHOICE type EuiccPackageResult.
type EuiccPackageResult struct {
	Choice                    int
	EuiccPackageResultSigned  *EuiccPackageResultSigned  `json:"EuiccPackageResultSigned,omitempty"`
	EuiccPackageErrorSigned   *EuiccPackageErrorSigned   `json:"EuiccPackageErrorSigned,omitempty"`
	EuiccPackageErrorUnsigned *EuiccPackageErrorUnsigned `json:"EuiccPackageErrorUnsigned,omitempty"`
}

// NewEuiccPackageResultEuiccPackageResultSigned creates a EuiccPackageResult with the euiccPackageResultSigned alternative.
func NewEuiccPackageResultEuiccPackageResultSigned(v EuiccPackageResultSigned) EuiccPackageResult {
	return EuiccPackageResult{
		Choice:                   EuiccPackageResultChoiceEuiccPackageResultSigned,
		EuiccPackageResultSigned: &v,
	}
}

// NewEuiccPackageResultEuiccPackageErrorSigned creates a EuiccPackageResult with the euiccPackageErrorSigned alternative.
func NewEuiccPackageResultEuiccPackageErrorSigned(v EuiccPackageErrorSigned) EuiccPackageResult {
	return EuiccPackageResult{
		Choice:                  EuiccPackageResultChoiceEuiccPackageErrorSigned,
		EuiccPackageErrorSigned: &v,
	}
}

// NewEuiccPackageResultEuiccPackageErrorUnsigned creates a EuiccPackageResult with the euiccPackageErrorUnsigned alternative.
func NewEuiccPackageResultEuiccPackageErrorUnsigned(v EuiccPackageErrorUnsigned) EuiccPackageResult {
	return EuiccPackageResult{
		Choice:                    EuiccPackageResultChoiceEuiccPackageErrorUnsigned,
		EuiccPackageErrorUnsigned: &v,
	}
}

// EuiccPackageResultSigned represents the ASN.1 type EuiccPackageResultSigned (SEQUENCE).
type EuiccPackageResultSigned struct {
	EuiccPackageResultDataSigned EuiccPackageResultDataSigned `asn1:""`
	EuiccSignEPR                 []byte                       `asn1:"tag:55,application,implicit"`
}

// EuiccPackageResultDataSigned represents the ASN.1 type EuiccPackageResultDataSigned (SEQUENCE).
type EuiccPackageResultDataSigned struct {
	EimId             string                                  `asn1:"tag:0,context,implicit"`
	CounterValue      *big.Int                                `asn1:"tag:1,context,implicit"`
	EimTransactionId  *sgp22.TransactionId                    `asn1:"tag:2,context,implicit,optional" json:"EimTransactionId,omitempty"`
	SeqNumber         *big.Int                                `asn1:"tag:3,context,implicit"`
	EuiccResult       EuiccPackageResultDataSignedEuiccResult `asn1:""`
	EuiccResultIndef_ bool                                    `asn1:"-" json:"-"`
}

// EuiccResultData choice constants.
const (
	EuiccResultDataChoiceEnableResult                   = 1
	EuiccResultDataChoiceDisableResult                  = 2
	EuiccResultDataChoiceDeleteResult                   = 3
	EuiccResultDataChoiceListProfileInfoResult          = 4
	EuiccResultDataChoiceGetRATResult                   = 5
	EuiccResultDataChoiceConfigureImmediateEnableResult = 6
	EuiccResultDataChoiceAddEimResult                   = 7
	EuiccResultDataChoiceDeleteEimResult                = 8
	EuiccResultDataChoiceUpdateEimResult                = 9
	EuiccResultDataChoiceListEimResult                  = 10
	EuiccResultDataChoiceRollbackResult                 = 11
	EuiccResultDataChoiceSetFallbackAttributeResult     = 12
	EuiccResultDataChoiceUnsetFallbackAttributeResult   = 13
	EuiccResultDataChoiceProcessingTerminated           = 14
	EuiccResultDataChoiceSetDefaultDpAddressResult      = 15
)

// EuiccResultData represents the ASN.1 CHOICE type EuiccResultData.
type EuiccResultData struct {
	Choice                         int
	EnableResult                   *EnableProfileResult            `json:"EnableResult,omitempty"`
	DisableResult                  *DisableProfileResult           `json:"DisableResult,omitempty"`
	DeleteResult                   *DeleteProfileResult            `json:"DeleteResult,omitempty"`
	ListProfileInfoResult          *ProfileInfoListResponse        `json:"ListProfileInfoResult,omitempty"`
	GetRATResult                   sgp22.RulesAuthorisationTable   `json:"GetRATResult,omitempty"`
	ConfigureImmediateEnableResult *ConfigureImmediateEnableResult `json:"ConfigureImmediateEnableResult,omitempty"`
	AddEimResult                   *AddEimResult                   `json:"AddEimResult,omitempty"`
	DeleteEimResult                *DeleteEimResult                `json:"DeleteEimResult,omitempty"`
	UpdateEimResult                *UpdateEimResult                `json:"UpdateEimResult,omitempty"`
	ListEimResult                  *ListEimResult                  `json:"ListEimResult,omitempty"`
	RollbackResult                 *RollbackProfileResult          `json:"RollbackResult,omitempty"`
	SetFallbackAttributeResult     *SetFallbackAttributeResult     `json:"SetFallbackAttributeResult,omitempty"`
	UnsetFallbackAttributeResult   *UnsetFallbackAttributeResult   `json:"UnsetFallbackAttributeResult,omitempty"`
	ProcessingTerminated           *int64                          `json:"ProcessingTerminated,omitempty"`
	SetDefaultDpAddressResult      *SetDefaultDpAddressResponse    `json:"SetDefaultDpAddressResult,omitempty"`
}

// NewEuiccResultDataEnableResult creates a EuiccResultData with the enableResult alternative.
func NewEuiccResultDataEnableResult(v EnableProfileResult) EuiccResultData {
	return EuiccResultData{
		Choice:       EuiccResultDataChoiceEnableResult,
		EnableResult: &v,
	}
}

// NewEuiccResultDataDisableResult creates a EuiccResultData with the disableResult alternative.
func NewEuiccResultDataDisableResult(v DisableProfileResult) EuiccResultData {
	return EuiccResultData{
		Choice:        EuiccResultDataChoiceDisableResult,
		DisableResult: &v,
	}
}

// NewEuiccResultDataDeleteResult creates a EuiccResultData with the deleteResult alternative.
func NewEuiccResultDataDeleteResult(v DeleteProfileResult) EuiccResultData {
	return EuiccResultData{
		Choice:       EuiccResultDataChoiceDeleteResult,
		DeleteResult: &v,
	}
}

// NewEuiccResultDataListProfileInfoResult creates a EuiccResultData with the listProfileInfoResult alternative.
func NewEuiccResultDataListProfileInfoResult(v ProfileInfoListResponse) EuiccResultData {
	return EuiccResultData{
		Choice:                EuiccResultDataChoiceListProfileInfoResult,
		ListProfileInfoResult: &v,
	}
}

// NewEuiccResultDataGetRATResult creates a EuiccResultData with the getRATResult alternative.
func NewEuiccResultDataGetRATResult(v sgp22.RulesAuthorisationTable) EuiccResultData {
	return EuiccResultData{
		Choice:       EuiccResultDataChoiceGetRATResult,
		GetRATResult: v,
	}
}

// NewEuiccResultDataConfigureImmediateEnableResult creates a EuiccResultData with the configureImmediateEnableResult alternative.
func NewEuiccResultDataConfigureImmediateEnableResult(v ConfigureImmediateEnableResult) EuiccResultData {
	return EuiccResultData{
		Choice:                         EuiccResultDataChoiceConfigureImmediateEnableResult,
		ConfigureImmediateEnableResult: &v,
	}
}

// NewEuiccResultDataAddEimResult creates a EuiccResultData with the addEimResult alternative.
func NewEuiccResultDataAddEimResult(v AddEimResult) EuiccResultData {
	return EuiccResultData{
		Choice:       EuiccResultDataChoiceAddEimResult,
		AddEimResult: &v,
	}
}

// NewEuiccResultDataDeleteEimResult creates a EuiccResultData with the deleteEimResult alternative.
func NewEuiccResultDataDeleteEimResult(v DeleteEimResult) EuiccResultData {
	return EuiccResultData{
		Choice:          EuiccResultDataChoiceDeleteEimResult,
		DeleteEimResult: &v,
	}
}

// NewEuiccResultDataUpdateEimResult creates a EuiccResultData with the updateEimResult alternative.
func NewEuiccResultDataUpdateEimResult(v UpdateEimResult) EuiccResultData {
	return EuiccResultData{
		Choice:          EuiccResultDataChoiceUpdateEimResult,
		UpdateEimResult: &v,
	}
}

// NewEuiccResultDataListEimResult creates a EuiccResultData with the listEimResult alternative.
func NewEuiccResultDataListEimResult(v ListEimResult) EuiccResultData {
	return EuiccResultData{
		Choice:        EuiccResultDataChoiceListEimResult,
		ListEimResult: &v,
	}
}

// NewEuiccResultDataRollbackResult creates a EuiccResultData with the rollbackResult alternative.
func NewEuiccResultDataRollbackResult(v RollbackProfileResult) EuiccResultData {
	return EuiccResultData{
		Choice:         EuiccResultDataChoiceRollbackResult,
		RollbackResult: &v,
	}
}

// NewEuiccResultDataSetFallbackAttributeResult creates a EuiccResultData with the setFallbackAttributeResult alternative.
func NewEuiccResultDataSetFallbackAttributeResult(v SetFallbackAttributeResult) EuiccResultData {
	return EuiccResultData{
		Choice:                     EuiccResultDataChoiceSetFallbackAttributeResult,
		SetFallbackAttributeResult: &v,
	}
}

// NewEuiccResultDataUnsetFallbackAttributeResult creates a EuiccResultData with the unsetFallbackAttributeResult alternative.
func NewEuiccResultDataUnsetFallbackAttributeResult(v UnsetFallbackAttributeResult) EuiccResultData {
	return EuiccResultData{
		Choice:                       EuiccResultDataChoiceUnsetFallbackAttributeResult,
		UnsetFallbackAttributeResult: &v,
	}
}

// NewEuiccResultDataProcessingTerminated creates a EuiccResultData with the processingTerminated alternative.
func NewEuiccResultDataProcessingTerminated(v int64) EuiccResultData {
	return EuiccResultData{
		Choice:               EuiccResultDataChoiceProcessingTerminated,
		ProcessingTerminated: &v,
	}
}

// NewEuiccResultDataSetDefaultDpAddressResult creates a EuiccResultData with the setDefaultDpAddressResult alternative.
func NewEuiccResultDataSetDefaultDpAddressResult(v SetDefaultDpAddressResponse) EuiccResultData {
	return EuiccResultData{
		Choice:                    EuiccResultDataChoiceSetDefaultDpAddressResult,
		SetDefaultDpAddressResult: &v,
	}
}

// EuiccPackageErrorSigned represents the ASN.1 type EuiccPackageErrorSigned (SEQUENCE).
type EuiccPackageErrorSigned struct {
	EuiccPackageErrorDataSigned EuiccPackageErrorDataSigned `asn1:""`
	EuiccSignEPE                []byte                      `asn1:"tag:55,application,implicit"`
}

// EuiccPackageErrorDataSigned represents the ASN.1 type EuiccPackageErrorDataSigned (SEQUENCE).
type EuiccPackageErrorDataSigned struct {
	EimId                 string                `asn1:"tag:0,context,implicit"`
	CounterValue          *big.Int              `asn1:"tag:1,context,implicit"`
	EimTransactionId      *sgp22.TransactionId  `asn1:"tag:2,context,implicit,optional" json:"EimTransactionId,omitempty"`
	EuiccPackageErrorCode EuiccPackageErrorCode `asn1:""`
}

// EuiccPackageErrorCode represents the ASN.1 INTEGER type EuiccPackageErrorCode with named numbers.
type EuiccPackageErrorCode int64

const (
	EuiccPackageErrorCodeInvalidEid             EuiccPackageErrorCode = 3
	EuiccPackageErrorCodeReplayError            EuiccPackageErrorCode = 4
	EuiccPackageErrorCodeCounterValueOutOfRange EuiccPackageErrorCode = 6
	EuiccPackageErrorCodeSizeOverflow           EuiccPackageErrorCode = 15
	EuiccPackageErrorCodeEcallActive            EuiccPackageErrorCode = 104
	EuiccPackageErrorCodeUndefinedError         EuiccPackageErrorCode = 127
)

func (v EuiccPackageErrorCode) String() string {
	switch v {
	case EuiccPackageErrorCodeInvalidEid:
		return "invalidEid"
	case EuiccPackageErrorCodeReplayError:
		return "replayError"
	case EuiccPackageErrorCodeCounterValueOutOfRange:
		return "counterValueOutOfRange"
	case EuiccPackageErrorCodeSizeOverflow:
		return "sizeOverflow"
	case EuiccPackageErrorCodeEcallActive:
		return "ecallActive"
	case EuiccPackageErrorCodeUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// EuiccPackageUnsignedErrorCode represents the ASN.1 INTEGER type EuiccPackageUnsignedErrorCode with named numbers.
type EuiccPackageUnsignedErrorCode int64

const (
	EuiccPackageUnsignedErrorCodeSizeOverflow   EuiccPackageUnsignedErrorCode = 15
	EuiccPackageUnsignedErrorCodeUndefinedError EuiccPackageUnsignedErrorCode = 127
)

func (v EuiccPackageUnsignedErrorCode) String() string {
	switch v {
	case EuiccPackageUnsignedErrorCodeSizeOverflow:
		return "sizeOverflow"
	case EuiccPackageUnsignedErrorCodeUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// EuiccPackageErrorUnsigned represents the ASN.1 type EuiccPackageErrorUnsigned (SEQUENCE).
type EuiccPackageErrorUnsigned struct {
	EimId                         string                         `asn1:"tag:0,context,implicit"`
	EimTransactionId              *sgp22.TransactionId           `asn1:"tag:2,context,implicit,optional" json:"EimTransactionId,omitempty"`
	AssociationToken              *big.Int                       `asn1:"tag:4,context,implicit,optional" json:"AssociationToken,omitempty"`
	EuiccPackageUnsignedErrorCode *EuiccPackageUnsignedErrorCode `asn1:"tag:15,context,implicit,optional" json:"EuiccPackageUnsignedErrorCode,omitempty"`
}

// ConfigureImmediateEnableResult represents the ASN.1 INTEGER type ConfigureImmediateEnableResult with named numbers.
type ConfigureImmediateEnableResult int64

const (
	ConfigureImmediateEnableResultOk                 ConfigureImmediateEnableResult = 0
	ConfigureImmediateEnableResultInsufficientMemory ConfigureImmediateEnableResult = 1
	ConfigureImmediateEnableResultCommandError       ConfigureImmediateEnableResult = 7
	ConfigureImmediateEnableResultUndefinedError     ConfigureImmediateEnableResult = 127
)

func (v ConfigureImmediateEnableResult) String() string {
	switch v {
	case ConfigureImmediateEnableResultOk:
		return "ok"
	case ConfigureImmediateEnableResultInsufficientMemory:
		return "insufficientMemory"
	case ConfigureImmediateEnableResultCommandError:
		return "commandError"
	case ConfigureImmediateEnableResultUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// EnableProfileResult represents the ASN.1 INTEGER type EnableProfileResult with named numbers.
type EnableProfileResult int64

const (
	EnableProfileResultOk                        EnableProfileResult = 0
	EnableProfileResultIccidOrAidNotFound        EnableProfileResult = 1
	EnableProfileResultProfileNotInDisabledState EnableProfileResult = 2
	EnableProfileResultDisallowedByPolicy        EnableProfileResult = 3
	EnableProfileResultCatBusy                   EnableProfileResult = 5
	EnableProfileResultRollbackNotAvailable      EnableProfileResult = 20
	EnableProfileResultUndefinedError            EnableProfileResult = 127
)

func (v EnableProfileResult) String() string {
	switch v {
	case EnableProfileResultOk:
		return "ok"
	case EnableProfileResultIccidOrAidNotFound:
		return "iccidOrAidNotFound"
	case EnableProfileResultProfileNotInDisabledState:
		return "profileNotInDisabledState"
	case EnableProfileResultDisallowedByPolicy:
		return "disallowedByPolicy"
	case EnableProfileResultCatBusy:
		return "catBusy"
	case EnableProfileResultRollbackNotAvailable:
		return "rollbackNotAvailable"
	case EnableProfileResultUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// DisableProfileResult represents the ASN.1 INTEGER type DisableProfileResult with named numbers.
type DisableProfileResult int64

const (
	DisableProfileResultOk                       DisableProfileResult = 0
	DisableProfileResultIccidOrAidNotFound       DisableProfileResult = 1
	DisableProfileResultProfileNotInEnabledState DisableProfileResult = 2
	DisableProfileResultDisallowedByPolicy       DisableProfileResult = 3
	DisableProfileResultCatBusy                  DisableProfileResult = 5
	DisableProfileResultUndefinedError           DisableProfileResult = 127
)

func (v DisableProfileResult) String() string {
	switch v {
	case DisableProfileResultOk:
		return "ok"
	case DisableProfileResultIccidOrAidNotFound:
		return "iccidOrAidNotFound"
	case DisableProfileResultProfileNotInEnabledState:
		return "profileNotInEnabledState"
	case DisableProfileResultDisallowedByPolicy:
		return "disallowedByPolicy"
	case DisableProfileResultCatBusy:
		return "catBusy"
	case DisableProfileResultUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// DeleteProfileResult represents the ASN.1 INTEGER type DeleteProfileResult with named numbers.
type DeleteProfileResult int64

const (
	DeleteProfileResultOk                        DeleteProfileResult = 0
	DeleteProfileResultIccidOrAidNotFound        DeleteProfileResult = 1
	DeleteProfileResultProfileNotInDisabledState DeleteProfileResult = 2
	DeleteProfileResultDisallowedByPolicy        DeleteProfileResult = 3
	DeleteProfileResultRollbackNotAvailable      DeleteProfileResult = 20
	DeleteProfileResultReturnFallbackProfile     DeleteProfileResult = 21
	DeleteProfileResultUndefinedError            DeleteProfileResult = 127
)

func (v DeleteProfileResult) String() string {
	switch v {
	case DeleteProfileResultOk:
		return "ok"
	case DeleteProfileResultIccidOrAidNotFound:
		return "iccidOrAidNotFound"
	case DeleteProfileResultProfileNotInDisabledState:
		return "profileNotInDisabledState"
	case DeleteProfileResultDisallowedByPolicy:
		return "disallowedByPolicy"
	case DeleteProfileResultRollbackNotAvailable:
		return "rollbackNotAvailable"
	case DeleteProfileResultReturnFallbackProfile:
		return "returnFallbackProfile"
	case DeleteProfileResultUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// ProfileInfoListResponse choice constants.
const (
	ProfileInfoListResponseChoiceProfileInfoListOk    = 1
	ProfileInfoListResponseChoiceProfileInfoListError = 2
)

// ProfileInfoListResponse represents the ASN.1 CHOICE type ProfileInfoListResponse.
type ProfileInfoListResponse struct {
	Choice               int
	ProfileInfoListOk    ProfileInfoListResponseProfileInfoListOk `json:"ProfileInfoListOk,omitempty"`
	ProfileInfoListError *ProfileInfoListError                    `json:"ProfileInfoListError,omitempty"`
}

// NewProfileInfoListResponseProfileInfoListOk creates a ProfileInfoListResponse with the profileInfoListOk alternative.
func NewProfileInfoListResponseProfileInfoListOk(v ProfileInfoListResponseProfileInfoListOk) ProfileInfoListResponse {
	return ProfileInfoListResponse{
		Choice:            ProfileInfoListResponseChoiceProfileInfoListOk,
		ProfileInfoListOk: v,
	}
}

// NewProfileInfoListResponseProfileInfoListError creates a ProfileInfoListResponse with the profileInfoListError alternative.
func NewProfileInfoListResponseProfileInfoListError(v ProfileInfoListError) ProfileInfoListResponse {
	return ProfileInfoListResponse{
		Choice:               ProfileInfoListResponseChoiceProfileInfoListError,
		ProfileInfoListError: &v,
	}
}

// ProfileInfoListError represents the ASN.1 INTEGER type ProfileInfoListError with named numbers.
type ProfileInfoListError int64

const (
	ProfileInfoListErrorIncorrectInputValues ProfileInfoListError = 1
	ProfileInfoListErrorProfileChangeOngoing ProfileInfoListError = 11
	ProfileInfoListErrorUndefinedError       ProfileInfoListError = 127
)

func (v ProfileInfoListError) String() string {
	switch v {
	case ProfileInfoListErrorIncorrectInputValues:
		return "incorrectInputValues"
	case ProfileInfoListErrorProfileChangeOngoing:
		return "profileChangeOngoing"
	case ProfileInfoListErrorUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// RollbackProfileResult represents the ASN.1 INTEGER type RollbackProfileResult with named numbers.
type RollbackProfileResult int64

const (
	RollbackProfileResultOk             RollbackProfileResult = 0
	RollbackProfileResultUndefinedError RollbackProfileResult = 127
)

func (v RollbackProfileResult) String() string {
	switch v {
	case RollbackProfileResultOk:
		return "ok"
	case RollbackProfileResultUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// SetFallbackAttributeResult represents the ASN.1 INTEGER type SetFallbackAttributeResult with named numbers.
type SetFallbackAttributeResult int64

const (
	SetFallbackAttributeResultOk                     SetFallbackAttributeResult = 0
	SetFallbackAttributeResultIccidOrAidNotFound     SetFallbackAttributeResult = 1
	SetFallbackAttributeResultFallbackNotAllowed     SetFallbackAttributeResult = 2
	SetFallbackAttributeResultFallbackProfileEnabled SetFallbackAttributeResult = 3
	SetFallbackAttributeResultUndefinedError         SetFallbackAttributeResult = 127
)

func (v SetFallbackAttributeResult) String() string {
	switch v {
	case SetFallbackAttributeResultOk:
		return "ok"
	case SetFallbackAttributeResultIccidOrAidNotFound:
		return "iccidOrAidNotFound"
	case SetFallbackAttributeResultFallbackNotAllowed:
		return "fallbackNotAllowed"
	case SetFallbackAttributeResultFallbackProfileEnabled:
		return "fallbackProfileEnabled"
	case SetFallbackAttributeResultUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// UnsetFallbackAttributeResult represents the ASN.1 INTEGER type UnsetFallbackAttributeResult with named numbers.
type UnsetFallbackAttributeResult int64

const (
	UnsetFallbackAttributeResultOk                     UnsetFallbackAttributeResult = 0
	UnsetFallbackAttributeResultNoFallbackAttribute    UnsetFallbackAttributeResult = 2
	UnsetFallbackAttributeResultFallbackProfileEnabled UnsetFallbackAttributeResult = 3
	UnsetFallbackAttributeResultCommandError           UnsetFallbackAttributeResult = 7
	UnsetFallbackAttributeResultUndefinedError         UnsetFallbackAttributeResult = 127
)

func (v UnsetFallbackAttributeResult) String() string {
	switch v {
	case UnsetFallbackAttributeResultOk:
		return "ok"
	case UnsetFallbackAttributeResultNoFallbackAttribute:
		return "noFallbackAttribute"
	case UnsetFallbackAttributeResultFallbackProfileEnabled:
		return "fallbackProfileEnabled"
	case UnsetFallbackAttributeResultCommandError:
		return "commandError"
	case UnsetFallbackAttributeResultUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// AddEimResult choice constants.
const (
	AddEimResultChoiceAssociationToken = 1
	AddEimResultChoiceAddEimResultCode = 2
)

// AddEimResult represents the ASN.1 CHOICE type AddEimResult.
type AddEimResult struct {
	Choice           int
	AssociationToken *big.Int `json:"AssociationToken,omitempty"`
	AddEimResultCode *int64   `json:"AddEimResultCode,omitempty"`
}

// NewAddEimResultAssociationToken creates a AddEimResult with the associationToken alternative.
func NewAddEimResultAssociationToken(v *big.Int) AddEimResult {
	return AddEimResult{
		Choice:           AddEimResultChoiceAssociationToken,
		AssociationToken: v,
	}
}

// NewAddEimResultAddEimResultCode creates a AddEimResult with the addEimResultCode alternative.
func NewAddEimResultAddEimResultCode(v int64) AddEimResult {
	return AddEimResult{
		Choice:           AddEimResultChoiceAddEimResultCode,
		AddEimResultCode: &v,
	}
}

// DeleteEimResult represents the ASN.1 INTEGER type DeleteEimResult with named numbers.
type DeleteEimResult int64

const (
	DeleteEimResultOk             DeleteEimResult = 0
	DeleteEimResultEimNotFound    DeleteEimResult = 1
	DeleteEimResultLastEimDeleted DeleteEimResult = 2
	DeleteEimResultCommandError   DeleteEimResult = 7
	DeleteEimResultUndefinedError DeleteEimResult = 127
)

func (v DeleteEimResult) String() string {
	switch v {
	case DeleteEimResultOk:
		return "ok"
	case DeleteEimResultEimNotFound:
		return "eimNotFound"
	case DeleteEimResultLastEimDeleted:
		return "lastEimDeleted"
	case DeleteEimResultCommandError:
		return "commandError"
	case DeleteEimResultUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// UpdateEimResult represents the ASN.1 INTEGER type UpdateEimResult with named numbers.
type UpdateEimResult int64

const (
	UpdateEimResultOk                     UpdateEimResult = 0
	UpdateEimResultEimNotFound            UpdateEimResult = 1
	UpdateEimResultCiPKUnknown            UpdateEimResult = 3
	UpdateEimResultCounterValueOutOfRange UpdateEimResult = 6
	UpdateEimResultCommandError           UpdateEimResult = 7
	UpdateEimResultUndefinedError         UpdateEimResult = 127
)

func (v UpdateEimResult) String() string {
	switch v {
	case UpdateEimResultOk:
		return "ok"
	case UpdateEimResultEimNotFound:
		return "eimNotFound"
	case UpdateEimResultCiPKUnknown:
		return "ciPKUnknown"
	case UpdateEimResultCounterValueOutOfRange:
		return "counterValueOutOfRange"
	case UpdateEimResultCommandError:
		return "commandError"
	case UpdateEimResultUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// ListEimResult choice constants.
const (
	ListEimResultChoiceEimIdList    = 1
	ListEimResultChoiceListEimError = 2
)

// ListEimResult represents the ASN.1 CHOICE type ListEimResult.
type ListEimResult struct {
	Choice       int
	EimIdList    ListEimResultEimIdList `json:"EimIdList,omitempty"`
	ListEimError *int64                 `json:"ListEimError,omitempty"`
}

// NewListEimResultEimIdList creates a ListEimResult with the eimIdList alternative.
func NewListEimResultEimIdList(v ListEimResultEimIdList) ListEimResult {
	return ListEimResult{
		Choice:    ListEimResultChoiceEimIdList,
		EimIdList: v,
	}
}

// NewListEimResultListEimError creates a ListEimResult with the listEimError alternative.
func NewListEimResultListEimError(v int64) ListEimResult {
	return ListEimResult{
		Choice:       ListEimResultChoiceListEimError,
		ListEimError: &v,
	}
}

// EimIdInfo represents the ASN.1 type EimIdInfo (SEQUENCE).
type EimIdInfo struct {
	EimId     string     `asn1:"tag:0,context,implicit"`
	EimIdType *EimIdType `asn1:"tag:2,context,implicit,optional" json:"EimIdType,omitempty"`
}

// IpaEuiccDataErrorCode represents the ASN.1 INTEGER type IpaEuiccDataErrorCode with named numbers.
type IpaEuiccDataErrorCode int64

const (
	IpaEuiccDataErrorCodeIncorrectTagList    IpaEuiccDataErrorCode = 1
	IpaEuiccDataErrorCodeEuiccCiPKIdNotFound IpaEuiccDataErrorCode = 5
	IpaEuiccDataErrorCodeEcallActive         IpaEuiccDataErrorCode = 104
	IpaEuiccDataErrorCodeUndefinedError      IpaEuiccDataErrorCode = 127
)

func (v IpaEuiccDataErrorCode) String() string {
	switch v {
	case IpaEuiccDataErrorCodeIncorrectTagList:
		return "incorrectTagList"
	case IpaEuiccDataErrorCodeEuiccCiPKIdNotFound:
		return "euiccCiPKIdNotFound"
	case IpaEuiccDataErrorCodeEcallActive:
		return "ecallActive"
	case IpaEuiccDataErrorCodeUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// IpaEuiccDataResponseError represents the ASN.1 type IpaEuiccDataResponseError (SEQUENCE).
type IpaEuiccDataResponseError struct {
	EimTransactionId      *sgp22.TransactionId  `asn1:"tag:0,context,implicit,optional" json:"EimTransactionId,omitempty"`
	IpaEuiccDataErrorCode IpaEuiccDataErrorCode `asn1:""`
}

// IpaEuiccDataResponse choice constants.
const (
	IpaEuiccDataResponseChoiceIpaEuiccData              = 1
	IpaEuiccDataResponseChoiceIpaEuiccDataResponseError = 2
)

// IpaEuiccDataResponse represents the ASN.1 CHOICE type IpaEuiccDataResponse.
type IpaEuiccDataResponse struct {
	Choice                    int
	IpaEuiccData              *IpaEuiccData              `json:"IpaEuiccData,omitempty"`
	IpaEuiccDataResponseError *IpaEuiccDataResponseError `json:"IpaEuiccDataResponseError,omitempty"`
}

// NewIpaEuiccDataResponseIpaEuiccData creates a IpaEuiccDataResponse with the ipaEuiccData alternative.
func NewIpaEuiccDataResponseIpaEuiccData(v IpaEuiccData) IpaEuiccDataResponse {
	return IpaEuiccDataResponse{
		Choice:       IpaEuiccDataResponseChoiceIpaEuiccData,
		IpaEuiccData: &v,
	}
}

// NewIpaEuiccDataResponseIpaEuiccDataResponseError creates a IpaEuiccDataResponse with the ipaEuiccDataResponseError alternative.
func NewIpaEuiccDataResponseIpaEuiccDataResponseError(v IpaEuiccDataResponseError) IpaEuiccDataResponse {
	return IpaEuiccDataResponse{
		Choice:                    IpaEuiccDataResponseChoiceIpaEuiccDataResponseError,
		IpaEuiccDataResponseError: &v,
	}
}

// PendingNotificationList represents the ASN.1 type PendingNotificationList (SEQUENCE_OF).
type PendingNotificationList = []PendingNotification

// EuiccPackageResultList represents the ASN.1 type EuiccPackageResultList (SEQUENCE_OF).
type EuiccPackageResultList = []EuiccPackageResult

// IpaEuiccData represents the ASN.1 type IpaEuiccData (SEQUENCE).
type IpaEuiccData struct {
	NotificationsList            PendingNotificationList `asn1:"tag:0,context,implicit,optional" json:"NotificationsList,omitempty"`
	NotificationsListIndef_      bool                    `asn1:"-" json:"-"`
	DefaultSmdpAddress           *string                 `asn1:"tag:1,context,implicit,optional" json:"DefaultSmdpAddress,omitempty"`
	EuiccPackageResultList       EuiccPackageResultList  `asn1:"tag:2,context,implicit,optional" json:"EuiccPackageResultList,omitempty"`
	EuiccPackageResultListIndef_ bool                    `asn1:"-" json:"-"`
	EuiccInfo1                   *sgp22.EUICCInfo1       `asn1:"tag:32,context,implicit,optional" json:"EuiccInfo1,omitempty"`
	EuiccInfo2                   *EUICCInfo2             `asn1:"tag:34,context,implicit,optional" json:"EuiccInfo2,omitempty"`
	RootSmdsAddress              *string                 `asn1:"tag:3,context,implicit,optional" json:"RootSmdsAddress,omitempty"`
	AssociationToken             *big.Int                `asn1:"tag:4,context,implicit,optional" json:"AssociationToken,omitempty"`
	EumCertificate               *sgp22.Certificate      `asn1:"tag:5,context,implicit,optional" json:"EumCertificate,omitempty"`
	EuiccCertificate             *sgp22.Certificate      `asn1:"tag:6,context,implicit,optional" json:"EuiccCertificate,omitempty"`
	EimTransactionId             *sgp22.TransactionId    `asn1:"tag:7,context,implicit,optional" json:"EimTransactionId,omitempty"`
	IpaCapabilities              *IpaCapabilities        `asn1:"tag:8,context,implicit,optional" json:"IpaCapabilities,omitempty"`
	DeviceInfo                   *sgp22.DeviceInfo       `asn1:"tag:9,context,implicit,optional" json:"DeviceInfo,omitempty"`
}

// ProfileDownloadTriggerResult represents the ASN.1 type ProfileDownloadTriggerResult (SEQUENCE).
type ProfileDownloadTriggerResult struct {
	EimTransactionId                 *sgp22.TransactionId                                         `asn1:"tag:2,context,implicit,optional" json:"EimTransactionId,omitempty"`
	ProfileDownloadTriggerResultData ProfileDownloadTriggerResultProfileDownloadTriggerResultData `asn1:""`
}

// ISDRProprietaryApplicationTemplateIoT represents the ASN.1 type ISDRProprietaryApplicationTemplateIoT (SEQUENCE).
type ISDRProprietaryApplicationTemplateIoT struct {
	EuiccConfiguration runtime.BitString `asn1:"tag:0,context,implicit"`
}

// IpaeActivationRequest represents the ASN.1 type IpaeActivationRequest (SEQUENCE).
type IpaeActivationRequest struct {
	IpaeOption runtime.BitString `asn1:"tag:0,context,implicit"`
}

// IpaeActivationResponse represents the ASN.1 type IpaeActivationResponse (SEQUENCE).
type IpaeActivationResponse struct {
	IpaeActivationResult int64 `asn1:"tag:0,context,implicit"`
}

// IpaCapabilities represents the ASN.1 type IpaCapabilities (SEQUENCE).
type IpaCapabilities struct {
	IpaFeatures                               runtime.BitString             `asn1:"tag:0,context,implicit"`
	IpaSupportedProtocols                     *runtime.BitString            `asn1:"tag:1,context,implicit,optional" json:"IpaSupportedProtocols,omitempty"`
	ESipaProprietaryProtocolInformation       sgp22.VendorSpecificExtension `asn1:"tag:2,context,implicit,optional" json:"ESipaProprietaryProtocolInformation,omitempty"`
	ESipaProprietaryProtocolInformationIndef_ bool                          `asn1:"-" json:"-"`
}

// ProfileInfo represents the ASN.1 type ProfileInfo (SEQUENCE).
type ProfileInfo struct {
	Iccid                                  *sgp22.Iccid                             `asn1:",optional" json:"Iccid,omitempty"`
	IsdpAid                                *sgp22.OctetTo16                         `asn1:"tag:15,application,implicit,optional" json:"IsdpAid,omitempty"`
	ProfileState                           *sgp22.ProfileState                      `asn1:"tag:112,context,implicit,optional" json:"ProfileState,omitempty"`
	ProfileNickname                        *string                                  `asn1:"tag:16,context,implicit,optional" json:"ProfileNickname,omitempty"`
	ServiceProviderName                    *string                                  `asn1:"tag:17,context,implicit,optional" json:"ServiceProviderName,omitempty"`
	ProfileName                            *string                                  `asn1:"tag:18,context,implicit,optional" json:"ProfileName,omitempty"`
	IconType                               *sgp22.IconType                          `asn1:"tag:19,context,implicit,optional" json:"IconType,omitempty"`
	Icon                                   []byte                                   `asn1:"tag:20,context,implicit,optional" json:"Icon,omitempty"`
	ProfileClass                           *sgp22.ProfileClass                      `asn1:"tag:21,context,implicit,optional" json:"ProfileClass,omitempty"`
	NotificationConfigurationInfo          ProfileInfoNotificationConfigurationInfo `asn1:"tag:22,context,implicit,optional" json:"NotificationConfigurationInfo,omitempty"`
	NotificationConfigurationInfoIndef_    bool                                     `asn1:"-" json:"-"`
	ProfileOwner                           *sgp22.OperatorId                        `asn1:"tag:23,context,implicit,optional" json:"ProfileOwner,omitempty"`
	DpProprietaryData                      *sgp22.DpProprietaryData                 `asn1:"tag:24,context,implicit,optional" json:"DpProprietaryData,omitempty"`
	ProfilePolicyRules                     *sgp22.PprIds                            `asn1:"tag:25,context,implicit,optional" json:"ProfilePolicyRules,omitempty"`
	ServiceSpecificDataStoredInEuicc       sgp22.VendorSpecificExtension            `asn1:"tag:34,context,implicit,optional" json:"ServiceSpecificDataStoredInEuicc,omitempty"`
	ServiceSpecificDataStoredInEuiccIndef_ bool                                     `asn1:"-" json:"-"`
	EcallIndication                        *bool                                    `asn1:"tag:123,context,implicit,optional" json:"EcallIndication,omitempty"`
	EcallIndicationRaw_                    byte                                     `asn1:"-" json:"-"`
	FallbackAttribute                      *bool                                    `asn1:"tag:38,context,implicit,optional" json:"FallbackAttribute,omitempty"`
	FallbackAttributeRaw_                  byte                                     `asn1:"-" json:"-"`
	FallbackAllowed                        *bool                                    `asn1:"tag:103,context,implicit,optional" json:"FallbackAllowed,omitempty"`
	FallbackAllowedRaw_                    byte                                     `asn1:"-" json:"-"`
	IotSpecificProfileInfo                 *ProfileInfoIotSpecificProfileInfo       `asn1:"tag:100,context,implicit,optional" json:"IotSpecificProfileInfo,omitempty"`
}

// UpdateMetadataRequest represents the ASN.1 type UpdateMetadataRequest (SEQUENCE).
type UpdateMetadataRequest struct {
	ServiceProviderName                    *string                       `asn1:"tag:17,context,implicit,optional" json:"ServiceProviderName,omitempty"`
	ProfileName                            *string                       `asn1:"tag:18,context,implicit,optional" json:"ProfileName,omitempty"`
	IconType                               *sgp22.IconType               `asn1:"tag:19,context,implicit,optional" json:"IconType,omitempty"`
	Icon                                   []byte                        `asn1:"tag:20,context,implicit,optional" json:"Icon,omitempty"`
	ProfilePolicyRules                     *sgp22.PprIds                 `asn1:"tag:25,context,implicit,optional" json:"ProfilePolicyRules,omitempty"`
	ServiceSpecificDataStoredInEuicc       sgp22.VendorSpecificExtension `asn1:"tag:34,context,implicit,optional" json:"ServiceSpecificDataStoredInEuicc,omitempty"`
	ServiceSpecificDataStoredInEuiccIndef_ bool                          `asn1:"-" json:"-"`
	FallbackAllowed                        *bool                         `asn1:"tag:103,context,implicit,optional" json:"FallbackAllowed,omitempty"`
	FallbackAllowedRaw_                    byte                          `asn1:"-" json:"-"`
}

// StoreMetadataRequest represents the ASN.1 type StoreMetadataRequest (SEQUENCE).
type StoreMetadataRequest struct {
	Iccid                                     sgp22.Iccid                                       `asn1:""`
	ServiceProviderName                       string                                            `asn1:"tag:17,context,implicit"`
	ProfileName                               string                                            `asn1:"tag:18,context,implicit"`
	IconType                                  *sgp22.IconType                                   `asn1:"tag:19,context,implicit,optional" json:"IconType,omitempty"`
	Icon                                      []byte                                            `asn1:"tag:20,context,implicit,optional" json:"Icon,omitempty"`
	ProfileClass                              *sgp22.ProfileClass                               `asn1:"tag:21,context,implicit,optional" json:"ProfileClass,omitempty"`
	NotificationConfigurationInfo             StoreMetadataRequestNotificationConfigurationInfo `asn1:"tag:22,context,implicit,optional" json:"NotificationConfigurationInfo,omitempty"`
	NotificationConfigurationInfoIndef_       bool                                              `asn1:"-" json:"-"`
	ProfileOwner                              *sgp22.OperatorId                                 `asn1:"tag:23,context,implicit,optional" json:"ProfileOwner,omitempty"`
	ProfilePolicyRules                        *sgp22.PprIds                                     `asn1:"tag:25,context,implicit,optional" json:"ProfilePolicyRules,omitempty"`
	ServiceSpecificDataStoredInEuicc          sgp22.VendorSpecificExtension                     `asn1:"tag:34,context,implicit,optional" json:"ServiceSpecificDataStoredInEuicc,omitempty"`
	ServiceSpecificDataStoredInEuiccIndef_    bool                                              `asn1:"-" json:"-"`
	ServiceSpecificDataNotStoredInEuicc       sgp22.VendorSpecificExtension                     `asn1:"tag:35,context,implicit,optional" json:"ServiceSpecificDataNotStoredInEuicc,omitempty"`
	ServiceSpecificDataNotStoredInEuiccIndef_ bool                                              `asn1:"-" json:"-"`
	EcallIndication                           *bool                                             `asn1:"tag:123,context,implicit,optional" json:"EcallIndication,omitempty"`
	EcallIndicationRaw_                       byte                                              `asn1:"-" json:"-"`
	FallbackAllowed                           *bool                                             `asn1:"tag:103,context,implicit,optional" json:"FallbackAllowed,omitempty"`
	FallbackAllowedRaw_                       byte                                              `asn1:"-" json:"-"`
	IotSpecificMetadata                       *StoreMetadataRequestIotSpecificMetadata          `asn1:"tag:100,context,implicit,optional" json:"IotSpecificMetadata,omitempty"`
}

// AuthenticateClientRequest represents the ASN.1 type AuthenticateClientRequest (SEQUENCE).
type AuthenticateClientRequest struct {
	TransactionId              sgp22.TransactionId        `asn1:"tag:0,context,implicit"`
	AuthenticateServerResponse AuthenticateServerResponse `asn1:"tag:56,context,explicit"`
}

// EUICCInfo2 represents the ASN.1 type EUICCInfo2 (SEQUENCE).
type EUICCInfo2 struct {
	ProfileVersion                              sgp22.VersionType                               `asn1:"tag:1,context,implicit"`
	Svn                                         sgp22.VersionType                               `asn1:"tag:2,context,implicit"`
	EuiccFirmwareVer                            sgp22.VersionType                               `asn1:"tag:3,context,implicit"`
	ExtCardResource                             []byte                                          `asn1:"tag:4,context,implicit"`
	UiccCapability                              runtime.BitString                               `asn1:"tag:5,context,implicit"`
	Ts102241Version                             *sgp22.VersionType                              `asn1:"tag:6,context,implicit,optional" json:"Ts102241Version,omitempty"`
	GlobalplatformVersion                       *sgp22.VersionType                              `asn1:"tag:7,context,implicit,optional" json:"GlobalplatformVersion,omitempty"`
	RspCapability                               sgp22.RspCapability                             `asn1:"tag:8,context,implicit"`
	EuiccCiPKIdListForVerification              EUICCInfo2EuiccCiPKIdListForVerification        `asn1:"tag:9,context,implicit"`
	EuiccCiPKIdListForVerificationIndef_        bool                                            `asn1:"-" json:"-"`
	EuiccCiPKIdListForSigning                   EUICCInfo2EuiccCiPKIdListForSigning             `asn1:"tag:10,context,implicit"`
	EuiccCiPKIdListForSigningIndef_             bool                                            `asn1:"-" json:"-"`
	EuiccCategory                               *int64                                          `asn1:"tag:11,context,implicit,optional" json:"EuiccCategory,omitempty"`
	ForbiddenProfilePolicyRules                 *sgp22.PprIds                                   `asn1:"tag:25,context,implicit,optional" json:"ForbiddenProfilePolicyRules,omitempty"`
	PpVersion                                   sgp22.VersionType                               `asn1:""`
	SasAcreditationNumber                       string                                          `asn1:""`
	CertificationDataObject                     *sgp22.CertificationDataObject                  `asn1:"tag:12,context,implicit,optional" json:"CertificationDataObject,omitempty"`
	TreProperties                               *runtime.BitString                              `asn1:"tag:13,context,implicit,optional" json:"TreProperties,omitempty"`
	TreProductReference                         *string                                         `asn1:"tag:14,context,implicit,optional" json:"TreProductReference,omitempty"`
	AdditionalEuiccProfilePackageVersions       EUICCInfo2AdditionalEuiccProfilePackageVersions `asn1:"tag:15,context,implicit,optional" json:"AdditionalEuiccProfilePackageVersions,omitempty"`
	AdditionalEuiccProfilePackageVersionsIndef_ bool                                            `asn1:"-" json:"-"`
	IpaMode                                     *IpaMode                                        `asn1:"tag:16,context,implicit,optional" json:"IpaMode,omitempty"`
	EuiccCiPKIdListForSigningV3                 EUICCInfo2EuiccCiPKIdListForSigningV3           `asn1:"tag:17,context,implicit,optional" json:"EuiccCiPKIdListForSigningV3,omitempty"`
	EuiccCiPKIdListForSigningV3Indef_           bool                                            `asn1:"-" json:"-"`
	AdditionalEuiccInfo                         []byte                                          `asn1:"tag:18,context,implicit,optional" json:"AdditionalEuiccInfo,omitempty"`
	HighestSvn                                  *sgp22.VersionType                              `asn1:"tag:19,context,implicit,optional" json:"HighestSvn,omitempty"`
	IotSpecificInfo                             *IoTSpecificInfo                                `asn1:"tag:20,context,implicit,optional" json:"IotSpecificInfo,omitempty"`
	EuiccMinimumSecurityLevel                   []byte                                          `asn1:"tag:21,context,implicit,optional" json:"EuiccMinimumSecurityLevel,omitempty"`
}

// IoTSpecificInfo represents the ASN.1 type IoTSpecificInfo (SEQUENCE).
type IoTSpecificInfo struct {
	IotVersion                     IoTSpecificInfoIotVersion `asn1:"tag:0,context,implicit"`
	IotVersionIndef_               bool                      `asn1:"-" json:"-"`
	EcallSupported                 *struct{}                 `asn1:"tag:1,context,implicit,optional" json:"EcallSupported,omitempty"`
	FallbackSupported              *struct{}                 `asn1:"tag:2,context,implicit,optional" json:"FallbackSupported,omitempty"`
	FallbackAllowedUpdateSupported *struct{}                 `asn1:"tag:3,context,implicit,optional" json:"FallbackAllowedUpdateSupported,omitempty"`
}

// IpaMode represents the ASN.1 INTEGER type IpaMode with named numbers.
type IpaMode int64

const (
	IpaModeIpad IpaMode = 0
	IpaModeIpae IpaMode = 1
)

func (v IpaMode) String() string {
	switch v {
	case IpaModeIpad:
		return "ipad"
	case IpaModeIpae:
		return "ipae"
	default:
		return "unknown"
	}
}

// AddInitialEimRequest represents the ASN.1 type AddInitialEimRequest (SEQUENCE).
type AddInitialEimRequest struct {
	EimConfigurationDataList       AddInitialEimRequestEimConfigurationDataList `asn1:"tag:0,context,implicit"`
	EimConfigurationDataListIndef_ bool                                         `asn1:"-" json:"-"`
}

// AddInitialEimResponse choice constants.
const (
	AddInitialEimResponseChoiceAddInitialEimOk    = 1
	AddInitialEimResponseChoiceAddInitialEimError = 2
)

// AddInitialEimResponse represents the ASN.1 CHOICE type AddInitialEimResponse.
type AddInitialEimResponse struct {
	Choice             int
	AddInitialEimOk    AddInitialEimResponseAddInitialEimOk `json:"AddInitialEimOk,omitempty"`
	AddInitialEimError *int64                               `json:"AddInitialEimError,omitempty"`
}

// NewAddInitialEimResponseAddInitialEimOk creates a AddInitialEimResponse with the addInitialEimOk alternative.
func NewAddInitialEimResponseAddInitialEimOk(v AddInitialEimResponseAddInitialEimOk) AddInitialEimResponse {
	return AddInitialEimResponse{
		Choice:          AddInitialEimResponseChoiceAddInitialEimOk,
		AddInitialEimOk: v,
	}
}

// NewAddInitialEimResponseAddInitialEimError creates a AddInitialEimResponse with the addInitialEimError alternative.
func NewAddInitialEimResponseAddInitialEimError(v int64) AddInitialEimResponse {
	return AddInitialEimResponse{
		Choice:             AddInitialEimResponseChoiceAddInitialEimError,
		AddInitialEimError: &v,
	}
}

// EuiccMemoryResetRequest represents the ASN.1 type EuiccMemoryResetRequest (SEQUENCE).
type EuiccMemoryResetRequest struct {
	ResetOptions runtime.BitString `asn1:"tag:2,context,implicit"`
}

// EuiccMemoryResetResponse represents the ASN.1 type EuiccMemoryResetResponse (SEQUENCE).
type EuiccMemoryResetResponse struct {
	ResetResult                      int64  `asn1:"tag:0,context,implicit"`
	ResetEimResult                   *int64 `asn1:"tag:1,context,implicit,optional" json:"ResetEimResult,omitempty"`
	ResetImmediateEnableConfigResult *int64 `asn1:"tag:2,context,implicit,optional" json:"ResetImmediateEnableConfigResult,omitempty"`
}

// GetCertsRequest represents the ASN.1 type GetCertsRequest (SEQUENCE).
type GetCertsRequest struct {
	EuiccCiPKId *sgp22.SubjectKeyIdentifier `asn1:"tag:0,context,implicit,optional" json:"EuiccCiPKId,omitempty"`
}

// GetCertsResponse choice constants.
const (
	GetCertsResponseChoiceCerts         = 1
	GetCertsResponseChoiceGetCertsError = 2
)

// GetCertsResponse represents the ASN.1 CHOICE type GetCertsResponse.
type GetCertsResponse struct {
	Choice        int
	Certs         *GetCertsResponseCerts `json:"Certs,omitempty"`
	GetCertsError *int64                 `json:"GetCertsError,omitempty"`
}

// NewGetCertsResponseCerts creates a GetCertsResponse with the certs alternative.
func NewGetCertsResponseCerts(v GetCertsResponseCerts) GetCertsResponse {
	return GetCertsResponse{
		Choice: GetCertsResponseChoiceCerts,
		Certs:  &v,
	}
}

// NewGetCertsResponseGetCertsError creates a GetCertsResponse with the getCertsError alternative.
func NewGetCertsResponseGetCertsError(v int64) GetCertsResponse {
	return GetCertsResponse{
		Choice:        GetCertsResponseChoiceGetCertsError,
		GetCertsError: &v,
	}
}

// RetrieveNotificationsListRequest represents the ASN.1 type RetrieveNotificationsListRequest (SEQUENCE).
type RetrieveNotificationsListRequest struct {
	SearchCriteria *RetrieveNotificationsListRequestSearchCriteria `asn1:"tag:0,context,explicit,optional" json:"SearchCriteria,omitempty"`
}

// RetrieveNotificationsListResponse choice constants.
const (
	RetrieveNotificationsListResponseChoiceNotificationList             = 1
	RetrieveNotificationsListResponseChoiceNotificationsListResultError = 2
	RetrieveNotificationsListResponseChoiceEuiccPackageResultList       = 3
)

// RetrieveNotificationsListResponse represents the ASN.1 CHOICE type RetrieveNotificationsListResponse.
type RetrieveNotificationsListResponse struct {
	Choice                       int
	NotificationList             PendingNotificationList `json:"NotificationList,omitempty"`
	NotificationsListResultError *int64                  `json:"NotificationsListResultError,omitempty"`
	EuiccPackageResultList       EuiccPackageResultList  `json:"EuiccPackageResultList,omitempty"`
}

// NewRetrieveNotificationsListResponseNotificationList creates a RetrieveNotificationsListResponse with the notificationList alternative.
func NewRetrieveNotificationsListResponseNotificationList(v PendingNotificationList) RetrieveNotificationsListResponse {
	return RetrieveNotificationsListResponse{
		Choice:           RetrieveNotificationsListResponseChoiceNotificationList,
		NotificationList: v,
	}
}

// NewRetrieveNotificationsListResponseNotificationsListResultError creates a RetrieveNotificationsListResponse with the notificationsListResultError alternative.
func NewRetrieveNotificationsListResponseNotificationsListResultError(v int64) RetrieveNotificationsListResponse {
	return RetrieveNotificationsListResponse{
		Choice:                       RetrieveNotificationsListResponseChoiceNotificationsListResultError,
		NotificationsListResultError: &v,
	}
}

// NewRetrieveNotificationsListResponseEuiccPackageResultList creates a RetrieveNotificationsListResponse with the euiccPackageResultList alternative.
func NewRetrieveNotificationsListResponseEuiccPackageResultList(v EuiccPackageResultList) RetrieveNotificationsListResponse {
	return RetrieveNotificationsListResponse{
		Choice:                 RetrieveNotificationsListResponseChoiceEuiccPackageResultList,
		EuiccPackageResultList: v,
	}
}

// ImmediateEnableRequest represents the ASN.1 type ImmediateEnableRequest (SEQUENCE).
type ImmediateEnableRequest struct {
	RefreshFlag     bool `asn1:"tag:0,context,implicit"`
	RefreshFlagRaw_ byte `asn1:"-" json:"-"`
}

// ImmediateEnableResponse represents the ASN.1 type ImmediateEnableResponse (SEQUENCE).
type ImmediateEnableResponse struct {
	ImmediateEnableResult int64 `asn1:"tag:0,context,implicit"`
}

// ProfileRollbackRequest represents the ASN.1 type ProfileRollbackRequest (SEQUENCE).
type ProfileRollbackRequest struct {
	RefreshFlag     bool `asn1:"tag:0,context,implicit"`
	RefreshFlagRaw_ byte `asn1:"-" json:"-"`
}

// ProfileRollbackResponse represents the ASN.1 type ProfileRollbackResponse (SEQUENCE).
type ProfileRollbackResponse struct {
	CmdResult          int64               `asn1:""`
	EUICCPackageResult *EuiccPackageResult `asn1:"tag:81,context,explicit,optional" json:"EUICCPackageResult,omitempty"`
}

// ConfigureImmediateProfileEnablingRequest represents the ASN.1 type ConfigureImmediateProfileEnablingRequest (SEQUENCE).
type ConfigureImmediateProfileEnablingRequest struct {
	ImmediateEnableFlag *struct{}                `asn1:"tag:0,context,implicit,optional" json:"ImmediateEnableFlag,omitempty"`
	DefaultSmdpOid      runtime.ObjectIdentifier `asn1:"tag:1,context,implicit,optional" json:"DefaultSmdpOid,omitempty"`
	DefaultSmdpAddress  *string                  `asn1:"tag:2,context,implicit,optional" json:"DefaultSmdpAddress,omitempty"`
}

// ConfigureImmediateProfileEnablingResponse represents the ASN.1 type ConfigureImmediateProfileEnablingResponse (SEQUENCE).
type ConfigureImmediateProfileEnablingResponse struct {
	ConfigImmediateEnableResult int64 `asn1:"tag:0,context,implicit"`
}

// GetEimConfigurationDataRequest represents the ASN.1 type GetEimConfigurationDataRequest (SEQUENCE).
type GetEimConfigurationDataRequest struct {
	SearchCriteria *GetEimConfigurationDataRequestSearchCriteria `asn1:"tag:0,context,explicit,optional" json:"SearchCriteria,omitempty"`
}

// GetEimConfigurationDataResponse represents the ASN.1 type GetEimConfigurationDataResponse (SEQUENCE).
type GetEimConfigurationDataResponse struct {
	EimConfigurationDataList       GetEimConfigurationDataResponseEimConfigurationDataList `asn1:"tag:0,context,implicit"`
	EimConfigurationDataListIndef_ bool                                                    `asn1:"-" json:"-"`
}

// ExecuteFallbackMechanismRequest represents the ASN.1 type ExecuteFallbackMechanismRequest (SEQUENCE).
type ExecuteFallbackMechanismRequest struct {
	RefreshFlag     bool `asn1:"tag:0,context,implicit"`
	RefreshFlagRaw_ byte `asn1:"-" json:"-"`
}

// ExecuteFallbackMechanismResponse represents the ASN.1 type ExecuteFallbackMechanismResponse (SEQUENCE).
type ExecuteFallbackMechanismResponse struct {
	ExecuteFallbackMechanismResult int64 `asn1:"tag:0,context,implicit"`
}

// ReturnFromFallbackRequest represents the ASN.1 type ReturnFromFallbackRequest (SEQUENCE).
type ReturnFromFallbackRequest struct {
	RefreshFlag     bool `asn1:"tag:0,context,implicit"`
	RefreshFlagRaw_ byte `asn1:"-" json:"-"`
}

// ReturnFromFallbackResponse represents the ASN.1 type ReturnFromFallbackResponse (SEQUENCE).
type ReturnFromFallbackResponse struct {
	ReturnFromFallbackResult int64 `asn1:"tag:0,context,implicit"`
}

// EnableEmergencyProfileRequest represents the ASN.1 type EnableEmergencyProfileRequest (SEQUENCE).
type EnableEmergencyProfileRequest struct {
	RefreshFlag     bool `asn1:"tag:0,context,implicit"`
	RefreshFlagRaw_ byte `asn1:"-" json:"-"`
}

// EnableEmergencyProfileResponse represents the ASN.1 type EnableEmergencyProfileResponse (SEQUENCE).
type EnableEmergencyProfileResponse struct {
	EnableEmergencyProfileResult int64 `asn1:"tag:0,context,implicit"`
}

// DisableEmergencyProfileRequest represents the ASN.1 type DisableEmergencyProfileRequest (SEQUENCE).
type DisableEmergencyProfileRequest struct {
	RefreshFlag     bool `asn1:"tag:0,context,implicit"`
	RefreshFlagRaw_ byte `asn1:"-" json:"-"`
}

// DisableEmergencyProfileResponse represents the ASN.1 type DisableEmergencyProfileResponse (SEQUENCE).
type DisableEmergencyProfileResponse struct {
	DisableEmergencyProfileResult int64 `asn1:"tag:0,context,implicit"`
}

// GetConnectivityParametersRequest represents the ASN.1 type GetConnectivityParametersRequest (SEQUENCE).
type GetConnectivityParametersRequest struct {
}

// GetConnectivityParametersResponse choice constants.
const (
	GetConnectivityParametersResponseChoiceConnectivityParameters      = 1
	GetConnectivityParametersResponseChoiceConnectivityParametersError = 2
)

// GetConnectivityParametersResponse represents the ASN.1 CHOICE type GetConnectivityParametersResponse.
type GetConnectivityParametersResponse struct {
	Choice                      int
	ConnectivityParameters      *ConnectivityParameters      `json:"ConnectivityParameters,omitempty"`
	ConnectivityParametersError *ConnectivityParametersError `json:"ConnectivityParametersError,omitempty"`
}

// NewGetConnectivityParametersResponseConnectivityParameters creates a GetConnectivityParametersResponse with the connectivityParameters alternative.
func NewGetConnectivityParametersResponseConnectivityParameters(v ConnectivityParameters) GetConnectivityParametersResponse {
	return GetConnectivityParametersResponse{
		Choice:                 GetConnectivityParametersResponseChoiceConnectivityParameters,
		ConnectivityParameters: &v,
	}
}

// NewGetConnectivityParametersResponseConnectivityParametersError creates a GetConnectivityParametersResponse with the connectivityParametersError alternative.
func NewGetConnectivityParametersResponseConnectivityParametersError(v ConnectivityParametersError) GetConnectivityParametersResponse {
	return GetConnectivityParametersResponse{
		Choice:                      GetConnectivityParametersResponseChoiceConnectivityParametersError,
		ConnectivityParametersError: &v,
	}
}

// ConnectivityParameters represents the ASN.1 type ConnectivityParameters (SEQUENCE).
type ConnectivityParameters struct {
	HttpParams []byte `asn1:"tag:1,context,implicit,optional" json:"HttpParams,omitempty"`
}

// ConnectivityParametersError represents the ASN.1 INTEGER type ConnectivityParametersError with named numbers.
type ConnectivityParametersError int64

const (
	ConnectivityParametersErrorParametersNotAvailable ConnectivityParametersError = 1
	ConnectivityParametersErrorUndefinedError         ConnectivityParametersError = 127
)

func (v ConnectivityParametersError) String() string {
	switch v {
	case ConnectivityParametersErrorParametersNotAvailable:
		return "parametersNotAvailable"
	case ConnectivityParametersErrorUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// SetDefaultDpAddressRequest represents the ASN.1 type SetDefaultDpAddressRequest (SEQUENCE).
type SetDefaultDpAddressRequest struct {
	DefaultDpAddress string `asn1:"tag:0,context,implicit"`
}

// SetDefaultDpAddressResponse represents the ASN.1 type SetDefaultDpAddressResponse (SEQUENCE).
type SetDefaultDpAddressResponse struct {
	SetDefaultDpAddressResult int64 `asn1:"tag:0,context,implicit"`
}

// PrepareDownloadResponse choice constants.
const (
	PrepareDownloadResponseChoiceDownloadResponseOk        = 1
	PrepareDownloadResponseChoiceDownloadResponseError     = 2
	PrepareDownloadResponseChoiceCompactDownloadResponseOk = 3
)

// PrepareDownloadResponse represents the ASN.1 CHOICE type PrepareDownloadResponse.
type PrepareDownloadResponse struct {
	Choice                    int
	DownloadResponseOk        *sgp22.PrepareDownloadResponseOk    `json:"DownloadResponseOk,omitempty"`
	DownloadResponseError     *sgp22.PrepareDownloadResponseError `json:"DownloadResponseError,omitempty"`
	CompactDownloadResponseOk *CompactPrepareDownloadResponseOk   `json:"CompactDownloadResponseOk,omitempty"`
}

// NewPrepareDownloadResponseDownloadResponseOk creates a PrepareDownloadResponse with the downloadResponseOk alternative.
func NewPrepareDownloadResponseDownloadResponseOk(v sgp22.PrepareDownloadResponseOk) PrepareDownloadResponse {
	return PrepareDownloadResponse{
		Choice:             PrepareDownloadResponseChoiceDownloadResponseOk,
		DownloadResponseOk: &v,
	}
}

// NewPrepareDownloadResponseDownloadResponseError creates a PrepareDownloadResponse with the downloadResponseError alternative.
func NewPrepareDownloadResponseDownloadResponseError(v sgp22.PrepareDownloadResponseError) PrepareDownloadResponse {
	return PrepareDownloadResponse{
		Choice:                PrepareDownloadResponseChoiceDownloadResponseError,
		DownloadResponseError: &v,
	}
}

// NewPrepareDownloadResponseCompactDownloadResponseOk creates a PrepareDownloadResponse with the compactDownloadResponseOk alternative.
func NewPrepareDownloadResponseCompactDownloadResponseOk(v CompactPrepareDownloadResponseOk) PrepareDownloadResponse {
	return PrepareDownloadResponse{
		Choice:                    PrepareDownloadResponseChoiceCompactDownloadResponseOk,
		CompactDownloadResponseOk: &v,
	}
}

// CompactPrepareDownloadResponseOk represents the ASN.1 type CompactPrepareDownloadResponseOk (SEQUENCE).
type CompactPrepareDownloadResponseOk struct {
	CompactEuiccSigned2 CompactEuiccSigned2 `asn1:""`
	EuiccSignature2     []byte              `asn1:"tag:55,application,implicit"`
}

// CompactEuiccSigned2 represents the ASN.1 type CompactEuiccSigned2 (SEQUENCE).
type CompactEuiccSigned2 struct {
	EuiccOtpk []byte         `asn1:"tag:73,application,implicit,optional" json:"EuiccOtpk,omitempty"`
	HashCc    *sgp22.Octet32 `asn1:",optional" json:"HashCc,omitempty"`
}

// EuiccSigned1 represents the ASN.1 type EuiccSigned1 (SEQUENCE).
type EuiccSigned1 struct {
	TransactionId   sgp22.TransactionId `asn1:"tag:0,context,implicit"`
	ServerAddress   string              `asn1:"tag:3,context,implicit"`
	ServerChallenge sgp22.Octet16       `asn1:"tag:4,context,implicit"`
	EuiccInfo2      EUICCInfo2          `asn1:"tag:34,context,implicit"`
	CtxParams1      sgp22.CtxParams1    `asn1:""`
}

// AuthenticateResponseOk represents the ASN.1 type AuthenticateResponseOk (SEQUENCE).
type AuthenticateResponseOk struct {
	EuiccSigned1     EuiccSigned1      `asn1:""`
	EuiccSignature1  []byte            `asn1:"tag:55,application,implicit"`
	EuiccCertificate sgp22.Certificate `asn1:""`
	EumCertificate   sgp22.Certificate `asn1:""`
}

// AuthenticateServerResponse choice constants.
const (
	AuthenticateServerResponseChoiceAuthenticateResponseOk        = 1
	AuthenticateServerResponseChoiceAuthenticateResponseError     = 2
	AuthenticateServerResponseChoiceCompactAuthenticateResponseOk = 3
)

// AuthenticateServerResponse represents the ASN.1 CHOICE type AuthenticateServerResponse.
type AuthenticateServerResponse struct {
	Choice                        int
	AuthenticateResponseOk        *AuthenticateResponseOk          `json:"AuthenticateResponseOk,omitempty"`
	AuthenticateResponseError     *sgp22.AuthenticateResponseError `json:"AuthenticateResponseError,omitempty"`
	CompactAuthenticateResponseOk *CompactAuthenticateResponseOk   `json:"CompactAuthenticateResponseOk,omitempty"`
}

// NewAuthenticateServerResponseAuthenticateResponseOk creates a AuthenticateServerResponse with the authenticateResponseOk alternative.
func NewAuthenticateServerResponseAuthenticateResponseOk(v AuthenticateResponseOk) AuthenticateServerResponse {
	return AuthenticateServerResponse{
		Choice:                 AuthenticateServerResponseChoiceAuthenticateResponseOk,
		AuthenticateResponseOk: &v,
	}
}

// NewAuthenticateServerResponseAuthenticateResponseError creates a AuthenticateServerResponse with the authenticateResponseError alternative.
func NewAuthenticateServerResponseAuthenticateResponseError(v sgp22.AuthenticateResponseError) AuthenticateServerResponse {
	return AuthenticateServerResponse{
		Choice:                    AuthenticateServerResponseChoiceAuthenticateResponseError,
		AuthenticateResponseError: &v,
	}
}

// NewAuthenticateServerResponseCompactAuthenticateResponseOk creates a AuthenticateServerResponse with the compactAuthenticateResponseOk alternative.
func NewAuthenticateServerResponseCompactAuthenticateResponseOk(v CompactAuthenticateResponseOk) AuthenticateServerResponse {
	return AuthenticateServerResponse{
		Choice:                        AuthenticateServerResponseChoiceCompactAuthenticateResponseOk,
		CompactAuthenticateResponseOk: &v,
	}
}

// CompactAuthenticateResponseOk represents the ASN.1 type CompactAuthenticateResponseOk (SEQUENCE).
type CompactAuthenticateResponseOk struct {
	SignedData       CompactAuthenticateResponseOkSignedData `asn1:""`
	EuiccSignature1  []byte                                  `asn1:"tag:55,application,implicit"`
	EuiccCertificate *sgp22.Certificate                      `asn1:"tag:1,context,implicit,optional" json:"EuiccCertificate,omitempty"`
	EumCertificate   *sgp22.Certificate                      `asn1:"tag:2,context,implicit,optional" json:"EumCertificate,omitempty"`
}

// CompactEuiccSigned1 represents the ASN.1 type CompactEuiccSigned1 (SEQUENCE).
type CompactEuiccSigned1 struct {
	ExtCardResource []byte            `asn1:"tag:4,context,implicit"`
	CtxParams1      *sgp22.CtxParams1 `asn1:"tag:2,context,explicit,optional" json:"CtxParams1,omitempty"`
}

// PendingNotification choice constants.
const (
	PendingNotificationChoiceProfileInstallationResult        = 1
	PendingNotificationChoiceOtherSignedNotification          = 2
	PendingNotificationChoiceCompactProfileInstallationResult = 3
	PendingNotificationChoiceCompactOtherSignedNotification   = 4
)

// PendingNotification represents the ASN.1 CHOICE type PendingNotification.
type PendingNotification struct {
	Choice                           int
	ProfileInstallationResult        *ProfileInstallationResult        `json:"ProfileInstallationResult,omitempty"`
	OtherSignedNotification          *sgp22.OtherSignedNotification    `json:"OtherSignedNotification,omitempty"`
	CompactProfileInstallationResult *CompactProfileInstallationResult `json:"CompactProfileInstallationResult,omitempty"`
	CompactOtherSignedNotification   *CompactOtherSignedNotification   `json:"CompactOtherSignedNotification,omitempty"`
}

// NewPendingNotificationProfileInstallationResult creates a PendingNotification with the profileInstallationResult alternative.
func NewPendingNotificationProfileInstallationResult(v ProfileInstallationResult) PendingNotification {
	return PendingNotification{
		Choice:                    PendingNotificationChoiceProfileInstallationResult,
		ProfileInstallationResult: &v,
	}
}

// NewPendingNotificationOtherSignedNotification creates a PendingNotification with the otherSignedNotification alternative.
func NewPendingNotificationOtherSignedNotification(v sgp22.OtherSignedNotification) PendingNotification {
	return PendingNotification{
		Choice:                  PendingNotificationChoiceOtherSignedNotification,
		OtherSignedNotification: &v,
	}
}

// NewPendingNotificationCompactProfileInstallationResult creates a PendingNotification with the compactProfileInstallationResult alternative.
func NewPendingNotificationCompactProfileInstallationResult(v CompactProfileInstallationResult) PendingNotification {
	return PendingNotification{
		Choice:                           PendingNotificationChoiceCompactProfileInstallationResult,
		CompactProfileInstallationResult: &v,
	}
}

// NewPendingNotificationCompactOtherSignedNotification creates a PendingNotification with the compactOtherSignedNotification alternative.
func NewPendingNotificationCompactOtherSignedNotification(v CompactOtherSignedNotification) PendingNotification {
	return PendingNotification{
		Choice:                         PendingNotificationChoiceCompactOtherSignedNotification,
		CompactOtherSignedNotification: &v,
	}
}

// ProfileInstallationResult represents the ASN.1 type ProfileInstallationResult (SEQUENCE).
type ProfileInstallationResult struct {
	ProfileInstallationResultData sgp22.ProfileInstallationResultData `asn1:"tag:39,context,implicit"`
	EuiccSignPIR                  sgp22.EuiccSignPIR                  `asn1:""`
}

// CompactProfileInstallationResult represents the ASN.1 type CompactProfileInstallationResult (SEQUENCE).
type CompactProfileInstallationResult struct {
	CompactProfileInstallationResultData CompactProfileInstallationResultData `asn1:"tag:0,context,implicit"`
	EuiccSignPIR                         sgp22.EuiccSignPIR                   `asn1:""`
}

// CompactProfileInstallationResultData represents the ASN.1 type CompactProfileInstallationResultData (SEQUENCE).
type CompactProfileInstallationResultData struct {
	TransactionId      sgp22.TransactionId                                    `asn1:"tag:0,context,implicit"`
	SeqNumber          *big.Int                                               `asn1:""`
	IccidPresent       *bool                                                  `asn1:",optional" json:"IccidPresent,omitempty"`
	IccidPresentRaw_   byte                                                   `asn1:"-" json:"-"`
	CompactFinalResult CompactProfileInstallationResultDataCompactFinalResult `asn1:"tag:2,context,explicit"`
}

// CompactSuccessResult represents the ASN.1 type CompactSuccessResult (SEQUENCE).
type CompactSuccessResult struct {
	CompactAid   []byte `asn1:"tag:15,application,implicit"`
	SimaResponse []byte `asn1:",optional" json:"SimaResponse,omitempty"`
}

// CompactOtherSignedNotification represents the ASN.1 type CompactOtherSignedNotification (SEQUENCE).
type CompactOtherSignedNotification struct {
	EidValue                    *sgp22.Octet16             `asn1:"tag:26,application,implicit,optional" json:"EidValue,omitempty"`
	TbsOtherNotification        sgp22.NotificationMetadata `asn1:""`
	EuiccNotificationSignature  []byte                     `asn1:"tag:55,application,implicit"`
	EuiccCiPKIdentifierToBeUsed []byte                     `asn1:",optional" json:"EuiccCiPKIdentifierToBeUsed,omitempty"`
}

// CancelSessionResponse choice constants.
const (
	CancelSessionResponseChoiceCancelSessionResponseOk        = 1
	CancelSessionResponseChoiceCancelSessionResponseError     = 2
	CancelSessionResponseChoiceCompactCancelSessionResponseOk = 3
)

// CancelSessionResponse represents the ASN.1 CHOICE type CancelSessionResponse.
type CancelSessionResponse struct {
	Choice                         int
	CancelSessionResponseOk        *sgp22.CancelSessionResponseOk  `json:"CancelSessionResponseOk,omitempty"`
	CancelSessionResponseError     *int64                          `json:"CancelSessionResponseError,omitempty"`
	CompactCancelSessionResponseOk *CompactCancelSessionResponseOk `json:"CompactCancelSessionResponseOk,omitempty"`
}

// NewCancelSessionResponseCancelSessionResponseOk creates a CancelSessionResponse with the cancelSessionResponseOk alternative.
func NewCancelSessionResponseCancelSessionResponseOk(v sgp22.CancelSessionResponseOk) CancelSessionResponse {
	return CancelSessionResponse{
		Choice:                  CancelSessionResponseChoiceCancelSessionResponseOk,
		CancelSessionResponseOk: &v,
	}
}

// NewCancelSessionResponseCancelSessionResponseError creates a CancelSessionResponse with the cancelSessionResponseError alternative.
func NewCancelSessionResponseCancelSessionResponseError(v int64) CancelSessionResponse {
	return CancelSessionResponse{
		Choice:                     CancelSessionResponseChoiceCancelSessionResponseError,
		CancelSessionResponseError: &v,
	}
}

// NewCancelSessionResponseCompactCancelSessionResponseOk creates a CancelSessionResponse with the compactCancelSessionResponseOk alternative.
func NewCancelSessionResponseCompactCancelSessionResponseOk(v CompactCancelSessionResponseOk) CancelSessionResponse {
	return CancelSessionResponse{
		Choice:                         CancelSessionResponseChoiceCompactCancelSessionResponseOk,
		CompactCancelSessionResponseOk: &v,
	}
}

// CompactCancelSessionResponseOk represents the ASN.1 type CompactCancelSessionResponseOk (SEQUENCE).
type CompactCancelSessionResponseOk struct {
	CompactEuiccCancelSessionSigned CompactEuiccCancelSessionSigned `asn1:""`
	EuiccCancelSessionSignature     []byte                          `asn1:"tag:55,application,implicit"`
}

// CompactEuiccCancelSessionSigned represents the ASN.1 type CompactEuiccCancelSessionSigned (SEQUENCE).
type CompactEuiccCancelSessionSigned struct {
	Reason *sgp22.CancelSessionReason `asn1:"tag:0,context,implicit,optional" json:"Reason,omitempty"`
}

// EsipaMessageFromIpaToEim choice constants.
const (
	EsipaMessageFromIpaToEimChoiceInitiateAuthenticationRequestEsipa = 1
	EsipaMessageFromIpaToEimChoiceAuthenticateClientRequestEsipa     = 2
	EsipaMessageFromIpaToEimChoiceGetBoundProfilePackageRequestEsipa = 3
	EsipaMessageFromIpaToEimChoiceCancelSessionRequestEsipa          = 4
	EsipaMessageFromIpaToEimChoiceHandleNotificationEsipa            = 5
	EsipaMessageFromIpaToEimChoiceTransferEimPackageResponse         = 6
	EsipaMessageFromIpaToEimChoiceGetEimPackageRequest               = 7
	EsipaMessageFromIpaToEimChoiceProvideEimPackageResult            = 8
)

// EsipaMessageFromIpaToEim represents the ASN.1 CHOICE type EsipaMessageFromIpaToEim.
type EsipaMessageFromIpaToEim struct {
	Choice                             int
	InitiateAuthenticationRequestEsipa *InitiateAuthenticationRequestEsipa `json:"InitiateAuthenticationRequestEsipa,omitempty"`
	AuthenticateClientRequestEsipa     *AuthenticateClientRequestEsipa     `json:"AuthenticateClientRequestEsipa,omitempty"`
	GetBoundProfilePackageRequestEsipa *GetBoundProfilePackageRequestEsipa `json:"GetBoundProfilePackageRequestEsipa,omitempty"`
	CancelSessionRequestEsipa          *CancelSessionRequestEsipa          `json:"CancelSessionRequestEsipa,omitempty"`
	HandleNotificationEsipa            *HandleNotificationEsipa            `json:"HandleNotificationEsipa,omitempty"`
	TransferEimPackageResponse         *TransferEimPackageResponse         `json:"TransferEimPackageResponse,omitempty"`
	GetEimPackageRequest               *GetEimPackageRequest               `json:"GetEimPackageRequest,omitempty"`
	ProvideEimPackageResult            *ProvideEimPackageResult            `json:"ProvideEimPackageResult,omitempty"`
}

// NewEsipaMessageFromIpaToEimInitiateAuthenticationRequestEsipa creates a EsipaMessageFromIpaToEim with the initiateAuthenticationRequestEsipa alternative.
func NewEsipaMessageFromIpaToEimInitiateAuthenticationRequestEsipa(v InitiateAuthenticationRequestEsipa) EsipaMessageFromIpaToEim {
	return EsipaMessageFromIpaToEim{
		Choice:                             EsipaMessageFromIpaToEimChoiceInitiateAuthenticationRequestEsipa,
		InitiateAuthenticationRequestEsipa: &v,
	}
}

// NewEsipaMessageFromIpaToEimAuthenticateClientRequestEsipa creates a EsipaMessageFromIpaToEim with the authenticateClientRequestEsipa alternative.
func NewEsipaMessageFromIpaToEimAuthenticateClientRequestEsipa(v AuthenticateClientRequestEsipa) EsipaMessageFromIpaToEim {
	return EsipaMessageFromIpaToEim{
		Choice:                         EsipaMessageFromIpaToEimChoiceAuthenticateClientRequestEsipa,
		AuthenticateClientRequestEsipa: &v,
	}
}

// NewEsipaMessageFromIpaToEimGetBoundProfilePackageRequestEsipa creates a EsipaMessageFromIpaToEim with the getBoundProfilePackageRequestEsipa alternative.
func NewEsipaMessageFromIpaToEimGetBoundProfilePackageRequestEsipa(v GetBoundProfilePackageRequestEsipa) EsipaMessageFromIpaToEim {
	return EsipaMessageFromIpaToEim{
		Choice:                             EsipaMessageFromIpaToEimChoiceGetBoundProfilePackageRequestEsipa,
		GetBoundProfilePackageRequestEsipa: &v,
	}
}

// NewEsipaMessageFromIpaToEimCancelSessionRequestEsipa creates a EsipaMessageFromIpaToEim with the cancelSessionRequestEsipa alternative.
func NewEsipaMessageFromIpaToEimCancelSessionRequestEsipa(v CancelSessionRequestEsipa) EsipaMessageFromIpaToEim {
	return EsipaMessageFromIpaToEim{
		Choice:                    EsipaMessageFromIpaToEimChoiceCancelSessionRequestEsipa,
		CancelSessionRequestEsipa: &v,
	}
}

// NewEsipaMessageFromIpaToEimHandleNotificationEsipa creates a EsipaMessageFromIpaToEim with the handleNotificationEsipa alternative.
func NewEsipaMessageFromIpaToEimHandleNotificationEsipa(v HandleNotificationEsipa) EsipaMessageFromIpaToEim {
	return EsipaMessageFromIpaToEim{
		Choice:                  EsipaMessageFromIpaToEimChoiceHandleNotificationEsipa,
		HandleNotificationEsipa: &v,
	}
}

// NewEsipaMessageFromIpaToEimTransferEimPackageResponse creates a EsipaMessageFromIpaToEim with the transferEimPackageResponse alternative.
func NewEsipaMessageFromIpaToEimTransferEimPackageResponse(v TransferEimPackageResponse) EsipaMessageFromIpaToEim {
	return EsipaMessageFromIpaToEim{
		Choice:                     EsipaMessageFromIpaToEimChoiceTransferEimPackageResponse,
		TransferEimPackageResponse: &v,
	}
}

// NewEsipaMessageFromIpaToEimGetEimPackageRequest creates a EsipaMessageFromIpaToEim with the getEimPackageRequest alternative.
func NewEsipaMessageFromIpaToEimGetEimPackageRequest(v GetEimPackageRequest) EsipaMessageFromIpaToEim {
	return EsipaMessageFromIpaToEim{
		Choice:               EsipaMessageFromIpaToEimChoiceGetEimPackageRequest,
		GetEimPackageRequest: &v,
	}
}

// NewEsipaMessageFromIpaToEimProvideEimPackageResult creates a EsipaMessageFromIpaToEim with the provideEimPackageResult alternative.
func NewEsipaMessageFromIpaToEimProvideEimPackageResult(v ProvideEimPackageResult) EsipaMessageFromIpaToEim {
	return EsipaMessageFromIpaToEim{
		Choice:                  EsipaMessageFromIpaToEimChoiceProvideEimPackageResult,
		ProvideEimPackageResult: &v,
	}
}

// EsipaMessageFromEimToIpa choice constants.
const (
	EsipaMessageFromEimToIpaChoiceInitiateAuthenticationResponseEsipa = 1
	EsipaMessageFromEimToIpaChoiceAuthenticateClientResponseEsipa     = 2
	EsipaMessageFromEimToIpaChoiceGetBoundProfilePackageResponseEsipa = 3
	EsipaMessageFromEimToIpaChoiceCancelSessionResponseEsipa          = 4
	EsipaMessageFromEimToIpaChoiceTransferEimPackageRequest           = 5
	EsipaMessageFromEimToIpaChoiceGetEimPackageResponse               = 6
	EsipaMessageFromEimToIpaChoiceProvideEimPackageResultResponse     = 7
)

// EsipaMessageFromEimToIpa represents the ASN.1 CHOICE type EsipaMessageFromEimToIpa.
type EsipaMessageFromEimToIpa struct {
	Choice                              int
	InitiateAuthenticationResponseEsipa *InitiateAuthenticationResponseEsipa `json:"InitiateAuthenticationResponseEsipa,omitempty"`
	AuthenticateClientResponseEsipa     *AuthenticateClientResponseEsipa     `json:"AuthenticateClientResponseEsipa,omitempty"`
	GetBoundProfilePackageResponseEsipa *GetBoundProfilePackageResponseEsipa `json:"GetBoundProfilePackageResponseEsipa,omitempty"`
	CancelSessionResponseEsipa          *CancelSessionResponseEsipa          `json:"CancelSessionResponseEsipa,omitempty"`
	TransferEimPackageRequest           *TransferEimPackageRequest           `json:"TransferEimPackageRequest,omitempty"`
	GetEimPackageResponse               *GetEimPackageResponse               `json:"GetEimPackageResponse,omitempty"`
	ProvideEimPackageResultResponse     *ProvideEimPackageResultResponse     `json:"ProvideEimPackageResultResponse,omitempty"`
}

// NewEsipaMessageFromEimToIpaInitiateAuthenticationResponseEsipa creates a EsipaMessageFromEimToIpa with the initiateAuthenticationResponseEsipa alternative.
func NewEsipaMessageFromEimToIpaInitiateAuthenticationResponseEsipa(v InitiateAuthenticationResponseEsipa) EsipaMessageFromEimToIpa {
	return EsipaMessageFromEimToIpa{
		Choice:                              EsipaMessageFromEimToIpaChoiceInitiateAuthenticationResponseEsipa,
		InitiateAuthenticationResponseEsipa: &v,
	}
}

// NewEsipaMessageFromEimToIpaAuthenticateClientResponseEsipa creates a EsipaMessageFromEimToIpa with the authenticateClientResponseEsipa alternative.
func NewEsipaMessageFromEimToIpaAuthenticateClientResponseEsipa(v AuthenticateClientResponseEsipa) EsipaMessageFromEimToIpa {
	return EsipaMessageFromEimToIpa{
		Choice:                          EsipaMessageFromEimToIpaChoiceAuthenticateClientResponseEsipa,
		AuthenticateClientResponseEsipa: &v,
	}
}

// NewEsipaMessageFromEimToIpaGetBoundProfilePackageResponseEsipa creates a EsipaMessageFromEimToIpa with the getBoundProfilePackageResponseEsipa alternative.
func NewEsipaMessageFromEimToIpaGetBoundProfilePackageResponseEsipa(v GetBoundProfilePackageResponseEsipa) EsipaMessageFromEimToIpa {
	return EsipaMessageFromEimToIpa{
		Choice:                              EsipaMessageFromEimToIpaChoiceGetBoundProfilePackageResponseEsipa,
		GetBoundProfilePackageResponseEsipa: &v,
	}
}

// NewEsipaMessageFromEimToIpaCancelSessionResponseEsipa creates a EsipaMessageFromEimToIpa with the cancelSessionResponseEsipa alternative.
func NewEsipaMessageFromEimToIpaCancelSessionResponseEsipa(v CancelSessionResponseEsipa) EsipaMessageFromEimToIpa {
	return EsipaMessageFromEimToIpa{
		Choice:                     EsipaMessageFromEimToIpaChoiceCancelSessionResponseEsipa,
		CancelSessionResponseEsipa: &v,
	}
}

// NewEsipaMessageFromEimToIpaTransferEimPackageRequest creates a EsipaMessageFromEimToIpa with the transferEimPackageRequest alternative.
func NewEsipaMessageFromEimToIpaTransferEimPackageRequest(v TransferEimPackageRequest) EsipaMessageFromEimToIpa {
	return EsipaMessageFromEimToIpa{
		Choice:                    EsipaMessageFromEimToIpaChoiceTransferEimPackageRequest,
		TransferEimPackageRequest: &v,
	}
}

// NewEsipaMessageFromEimToIpaGetEimPackageResponse creates a EsipaMessageFromEimToIpa with the getEimPackageResponse alternative.
func NewEsipaMessageFromEimToIpaGetEimPackageResponse(v GetEimPackageResponse) EsipaMessageFromEimToIpa {
	return EsipaMessageFromEimToIpa{
		Choice:                EsipaMessageFromEimToIpaChoiceGetEimPackageResponse,
		GetEimPackageResponse: &v,
	}
}

// NewEsipaMessageFromEimToIpaProvideEimPackageResultResponse creates a EsipaMessageFromEimToIpa with the provideEimPackageResultResponse alternative.
func NewEsipaMessageFromEimToIpaProvideEimPackageResultResponse(v ProvideEimPackageResultResponse) EsipaMessageFromEimToIpa {
	return EsipaMessageFromEimToIpa{
		Choice:                          EsipaMessageFromEimToIpaChoiceProvideEimPackageResultResponse,
		ProvideEimPackageResultResponse: &v,
	}
}

// InitiateAuthenticationRequestEsipa represents the ASN.1 type InitiateAuthenticationRequestEsipa (SEQUENCE).
type InitiateAuthenticationRequestEsipa struct {
	EuiccChallenge   sgp22.Octet16        `asn1:"tag:1,context,implicit"`
	SmdpAddress      *string              `asn1:"tag:3,context,implicit,optional" json:"SmdpAddress,omitempty"`
	EuiccInfo1       *sgp22.EUICCInfo1    `asn1:",optional" json:"EuiccInfo1,omitempty"`
	EimTransactionId *sgp22.TransactionId `asn1:"tag:2,context,implicit,optional" json:"EimTransactionId,omitempty"`
}

// InitiateAuthenticationResponseEsipa choice constants.
const (
	InitiateAuthenticationResponseEsipaChoiceInitiateAuthenticationOkEsipa    = 1
	InitiateAuthenticationResponseEsipaChoiceInitiateAuthenticationErrorEsipa = 2
)

// InitiateAuthenticationResponseEsipa represents the ASN.1 CHOICE type InitiateAuthenticationResponseEsipa.
type InitiateAuthenticationResponseEsipa struct {
	Choice                           int
	InitiateAuthenticationOkEsipa    *InitiateAuthenticationOkEsipa `json:"InitiateAuthenticationOkEsipa,omitempty"`
	InitiateAuthenticationErrorEsipa *int64                         `json:"InitiateAuthenticationErrorEsipa,omitempty"`
}

// NewInitiateAuthenticationResponseEsipaInitiateAuthenticationOkEsipa creates a InitiateAuthenticationResponseEsipa with the initiateAuthenticationOkEsipa alternative.
func NewInitiateAuthenticationResponseEsipaInitiateAuthenticationOkEsipa(v InitiateAuthenticationOkEsipa) InitiateAuthenticationResponseEsipa {
	return InitiateAuthenticationResponseEsipa{
		Choice:                        InitiateAuthenticationResponseEsipaChoiceInitiateAuthenticationOkEsipa,
		InitiateAuthenticationOkEsipa: &v,
	}
}

// NewInitiateAuthenticationResponseEsipaInitiateAuthenticationErrorEsipa creates a InitiateAuthenticationResponseEsipa with the initiateAuthenticationErrorEsipa alternative.
func NewInitiateAuthenticationResponseEsipaInitiateAuthenticationErrorEsipa(v int64) InitiateAuthenticationResponseEsipa {
	return InitiateAuthenticationResponseEsipa{
		Choice:                           InitiateAuthenticationResponseEsipaChoiceInitiateAuthenticationErrorEsipa,
		InitiateAuthenticationErrorEsipa: &v,
	}
}

// InitiateAuthenticationOkEsipa represents the ASN.1 type InitiateAuthenticationOkEsipa (SEQUENCE).
type InitiateAuthenticationOkEsipa struct {
	TransactionId               *sgp22.TransactionId `asn1:"tag:0,context,implicit,optional" json:"TransactionId,omitempty"`
	ServerSigned1               sgp22.ServerSigned1  `asn1:""`
	ServerSignature1            []byte               `asn1:"tag:55,application,implicit"`
	EuiccCiPKIdentifierToBeUsed []byte               `asn1:""`
	ServerCertificate           sgp22.Certificate    `asn1:""`
	MatchingId                  *string              `asn1:",optional" json:"MatchingId,omitempty"`
	CtxParams1                  *sgp22.CtxParams1    `asn1:"tag:2,context,explicit,optional" json:"CtxParams1,omitempty"`
}

// AuthenticateClientRequestEsipa represents the ASN.1 type AuthenticateClientRequestEsipa (SEQUENCE).
type AuthenticateClientRequestEsipa struct {
	TransactionId              sgp22.TransactionId        `asn1:"tag:0,context,implicit"`
	AuthenticateServerResponse AuthenticateServerResponse `asn1:"tag:56,context,explicit"`
}

// AuthenticateClientResponseEsipa choice constants.
const (
	AuthenticateClientResponseEsipaChoiceAuthenticateClientOkDPEsipa  = 1
	AuthenticateClientResponseEsipaChoiceAuthenticateClientOkDSEsipa  = 2
	AuthenticateClientResponseEsipaChoiceAuthenticateClientErrorEsipa = 3
)

// AuthenticateClientResponseEsipa represents the ASN.1 CHOICE type AuthenticateClientResponseEsipa.
type AuthenticateClientResponseEsipa struct {
	Choice                       int
	AuthenticateClientOkDPEsipa  *AuthenticateClientOkDPEsipa `json:"AuthenticateClientOkDPEsipa,omitempty"`
	AuthenticateClientOkDSEsipa  *AuthenticateClientOkDSEsipa `json:"AuthenticateClientOkDSEsipa,omitempty"`
	AuthenticateClientErrorEsipa *int64                       `json:"AuthenticateClientErrorEsipa,omitempty"`
}

// NewAuthenticateClientResponseEsipaAuthenticateClientOkDPEsipa creates a AuthenticateClientResponseEsipa with the authenticateClientOkDPEsipa alternative.
func NewAuthenticateClientResponseEsipaAuthenticateClientOkDPEsipa(v AuthenticateClientOkDPEsipa) AuthenticateClientResponseEsipa {
	return AuthenticateClientResponseEsipa{
		Choice:                      AuthenticateClientResponseEsipaChoiceAuthenticateClientOkDPEsipa,
		AuthenticateClientOkDPEsipa: &v,
	}
}

// NewAuthenticateClientResponseEsipaAuthenticateClientOkDSEsipa creates a AuthenticateClientResponseEsipa with the authenticateClientOkDSEsipa alternative.
func NewAuthenticateClientResponseEsipaAuthenticateClientOkDSEsipa(v AuthenticateClientOkDSEsipa) AuthenticateClientResponseEsipa {
	return AuthenticateClientResponseEsipa{
		Choice:                      AuthenticateClientResponseEsipaChoiceAuthenticateClientOkDSEsipa,
		AuthenticateClientOkDSEsipa: &v,
	}
}

// NewAuthenticateClientResponseEsipaAuthenticateClientErrorEsipa creates a AuthenticateClientResponseEsipa with the authenticateClientErrorEsipa alternative.
func NewAuthenticateClientResponseEsipaAuthenticateClientErrorEsipa(v int64) AuthenticateClientResponseEsipa {
	return AuthenticateClientResponseEsipa{
		Choice:                       AuthenticateClientResponseEsipaChoiceAuthenticateClientErrorEsipa,
		AuthenticateClientErrorEsipa: &v,
	}
}

// AuthenticateClientOkDPEsipa represents the ASN.1 type AuthenticateClientOkDPEsipa (SEQUENCE).
type AuthenticateClientOkDPEsipa struct {
	TransactionId   *sgp22.TransactionId  `asn1:"tag:0,context,implicit,optional" json:"TransactionId,omitempty"`
	ProfileMetaData *StoreMetadataRequest `asn1:"tag:37,context,implicit,optional" json:"ProfileMetaData,omitempty"`
	SmdpSigned2     sgp22.SmdpSigned2     `asn1:""`
	SmdpSignature2  []byte                `asn1:"tag:55,application,implicit"`
	SmdpCertificate sgp22.Certificate     `asn1:""`
	HashCc          *sgp22.Octet32        `asn1:",optional" json:"HashCc,omitempty"`
}

// AuthenticateClientOkDSEsipa represents the ASN.1 type AuthenticateClientOkDSEsipa (SEQUENCE).
type AuthenticateClientOkDSEsipa struct {
	TransactionId          sgp22.TransactionId            `asn1:"tag:0,context,implicit"`
	ProfileDownloadTrigger *ProfileDownloadTriggerRequest `asn1:"tag:84,context,implicit,optional" json:"ProfileDownloadTrigger,omitempty"`
}

// GetBoundProfilePackageRequestEsipa represents the ASN.1 type GetBoundProfilePackageRequestEsipa (SEQUENCE).
type GetBoundProfilePackageRequestEsipa struct {
	TransactionId           sgp22.TransactionId     `asn1:"tag:0,context,implicit"`
	PrepareDownloadResponse PrepareDownloadResponse `asn1:"tag:33,context,explicit"`
}

// GetBoundProfilePackageResponseEsipa choice constants.
const (
	GetBoundProfilePackageResponseEsipaChoiceGetBoundProfilePackageOkEsipa    = 1
	GetBoundProfilePackageResponseEsipaChoiceGetBoundProfilePackageErrorEsipa = 2
)

// GetBoundProfilePackageResponseEsipa represents the ASN.1 CHOICE type GetBoundProfilePackageResponseEsipa.
type GetBoundProfilePackageResponseEsipa struct {
	Choice                           int
	GetBoundProfilePackageOkEsipa    *GetBoundProfilePackageOkEsipa `json:"GetBoundProfilePackageOkEsipa,omitempty"`
	GetBoundProfilePackageErrorEsipa *int64                         `json:"GetBoundProfilePackageErrorEsipa,omitempty"`
}

// NewGetBoundProfilePackageResponseEsipaGetBoundProfilePackageOkEsipa creates a GetBoundProfilePackageResponseEsipa with the getBoundProfilePackageOkEsipa alternative.
func NewGetBoundProfilePackageResponseEsipaGetBoundProfilePackageOkEsipa(v GetBoundProfilePackageOkEsipa) GetBoundProfilePackageResponseEsipa {
	return GetBoundProfilePackageResponseEsipa{
		Choice:                        GetBoundProfilePackageResponseEsipaChoiceGetBoundProfilePackageOkEsipa,
		GetBoundProfilePackageOkEsipa: &v,
	}
}

// NewGetBoundProfilePackageResponseEsipaGetBoundProfilePackageErrorEsipa creates a GetBoundProfilePackageResponseEsipa with the getBoundProfilePackageErrorEsipa alternative.
func NewGetBoundProfilePackageResponseEsipaGetBoundProfilePackageErrorEsipa(v int64) GetBoundProfilePackageResponseEsipa {
	return GetBoundProfilePackageResponseEsipa{
		Choice:                           GetBoundProfilePackageResponseEsipaChoiceGetBoundProfilePackageErrorEsipa,
		GetBoundProfilePackageErrorEsipa: &v,
	}
}

// GetBoundProfilePackageOkEsipa represents the ASN.1 type GetBoundProfilePackageOkEsipa (SEQUENCE).
type GetBoundProfilePackageOkEsipa struct {
	TransactionId       *sgp22.TransactionId      `asn1:"tag:0,context,implicit,optional" json:"TransactionId,omitempty"`
	BoundProfilePackage sgp22.BoundProfilePackage `asn1:"tag:54,context,implicit"`
}

// HandleNotificationEsipa choice constants.
const (
	HandleNotificationEsipaChoicePendingNotification     = 1
	HandleNotificationEsipaChoiceProvideEimPackageResult = 2
)

// HandleNotificationEsipa represents the ASN.1 CHOICE type HandleNotificationEsipa.
type HandleNotificationEsipa struct {
	Choice                  int
	PendingNotification     *PendingNotification     `json:"PendingNotification,omitempty"`
	ProvideEimPackageResult *ProvideEimPackageResult `json:"ProvideEimPackageResult,omitempty"`
}

// NewHandleNotificationEsipaPendingNotification creates a HandleNotificationEsipa with the pendingNotification alternative.
func NewHandleNotificationEsipaPendingNotification(v PendingNotification) HandleNotificationEsipa {
	return HandleNotificationEsipa{
		Choice:              HandleNotificationEsipaChoicePendingNotification,
		PendingNotification: &v,
	}
}

// NewHandleNotificationEsipaProvideEimPackageResult creates a HandleNotificationEsipa with the provideEimPackageResult alternative.
func NewHandleNotificationEsipaProvideEimPackageResult(v ProvideEimPackageResult) HandleNotificationEsipa {
	return HandleNotificationEsipa{
		Choice:                  HandleNotificationEsipaChoiceProvideEimPackageResult,
		ProvideEimPackageResult: &v,
	}
}

// CancelSessionRequestEsipa represents the ASN.1 type CancelSessionRequestEsipa (SEQUENCE).
type CancelSessionRequestEsipa struct {
	TransactionId         sgp22.TransactionId   `asn1:"tag:0,context,implicit"`
	CancelSessionResponse CancelSessionResponse `asn1:"tag:1,context,explicit"`
}

// CancelSessionResponseEsipa choice constants.
const (
	CancelSessionResponseEsipaChoiceCancelSessionOk    = 1
	CancelSessionResponseEsipaChoiceCancelSessionError = 2
)

// CancelSessionResponseEsipa represents the ASN.1 CHOICE type CancelSessionResponseEsipa.
type CancelSessionResponseEsipa struct {
	Choice             int
	CancelSessionOk    *CancelSessionOk `json:"CancelSessionOk,omitempty"`
	CancelSessionError *int64           `json:"CancelSessionError,omitempty"`
}

// NewCancelSessionResponseEsipaCancelSessionOk creates a CancelSessionResponseEsipa with the cancelSessionOk alternative.
func NewCancelSessionResponseEsipaCancelSessionOk(v CancelSessionOk) CancelSessionResponseEsipa {
	return CancelSessionResponseEsipa{
		Choice:          CancelSessionResponseEsipaChoiceCancelSessionOk,
		CancelSessionOk: &v,
	}
}

// NewCancelSessionResponseEsipaCancelSessionError creates a CancelSessionResponseEsipa with the cancelSessionError alternative.
func NewCancelSessionResponseEsipaCancelSessionError(v int64) CancelSessionResponseEsipa {
	return CancelSessionResponseEsipa{
		Choice:             CancelSessionResponseEsipaChoiceCancelSessionError,
		CancelSessionError: &v,
	}
}

// CancelSessionOk represents the ASN.1 type CancelSessionOk (SEQUENCE).
type CancelSessionOk struct {
}

// StateChangeCause represents the ASN.1 INTEGER type StateChangeCause with named numbers.
type StateChangeCause int64

const (
	StateChangeCauseOtherEim               StateChangeCause = 0
	StateChangeCauseFallback               StateChangeCause = 1
	StateChangeCauseEmergencyProfile       StateChangeCause = 2
	StateChangeCauseLocal                  StateChangeCause = 3
	StateChangeCauseReset                  StateChangeCause = 4
	StateChangeCauseImmediateEnableProfile StateChangeCause = 5
	StateChangeCauseDeviceChange           StateChangeCause = 6
	StateChangeCauseUndefined              StateChangeCause = 127
)

func (v StateChangeCause) String() string {
	switch v {
	case StateChangeCauseOtherEim:
		return "otherEim"
	case StateChangeCauseFallback:
		return "fallback"
	case StateChangeCauseEmergencyProfile:
		return "emergencyProfile"
	case StateChangeCauseLocal:
		return "local"
	case StateChangeCauseReset:
		return "reset"
	case StateChangeCauseImmediateEnableProfile:
		return "immediateEnableProfile"
	case StateChangeCauseDeviceChange:
		return "deviceChange"
	case StateChangeCauseUndefined:
		return "undefined"
	default:
		return "unknown"
	}
}

// GetEimPackageRequest represents the ASN.1 type GetEimPackageRequest (SEQUENCE).
type GetEimPackageRequest struct {
	EidValue          sgp22.Octet16     `asn1:"tag:26,application,implicit"`
	NotifyStateChange *struct{}         `asn1:"tag:0,context,implicit,optional" json:"NotifyStateChange,omitempty"`
	StateChangeCause  *StateChangeCause `asn1:"tag:1,context,implicit,optional" json:"StateChangeCause,omitempty"`
	RPLMN             []byte            `asn1:"tag:2,context,implicit,optional" json:"RPLMN,omitempty"`
}

// GetEimPackageResponse choice constants.
const (
	GetEimPackageResponseChoiceEuiccPackageRequest           = 1
	GetEimPackageResponseChoiceIpaEuiccDataRequest           = 2
	GetEimPackageResponseChoiceProfileDownloadTriggerRequest = 3
	GetEimPackageResponseChoiceEimPackageError               = 4
)

// GetEimPackageResponse represents the ASN.1 CHOICE type GetEimPackageResponse.
type GetEimPackageResponse struct {
	Choice                        int
	EuiccPackageRequest           *EuiccPackageRequest           `json:"EuiccPackageRequest,omitempty"`
	IpaEuiccDataRequest           *IpaEuiccDataRequest           `json:"IpaEuiccDataRequest,omitempty"`
	ProfileDownloadTriggerRequest *ProfileDownloadTriggerRequest `json:"ProfileDownloadTriggerRequest,omitempty"`
	EimPackageError               *int64                         `json:"EimPackageError,omitempty"`
}

// NewGetEimPackageResponseEuiccPackageRequest creates a GetEimPackageResponse with the euiccPackageRequest alternative.
func NewGetEimPackageResponseEuiccPackageRequest(v EuiccPackageRequest) GetEimPackageResponse {
	return GetEimPackageResponse{
		Choice:              GetEimPackageResponseChoiceEuiccPackageRequest,
		EuiccPackageRequest: &v,
	}
}

// NewGetEimPackageResponseIpaEuiccDataRequest creates a GetEimPackageResponse with the ipaEuiccDataRequest alternative.
func NewGetEimPackageResponseIpaEuiccDataRequest(v IpaEuiccDataRequest) GetEimPackageResponse {
	return GetEimPackageResponse{
		Choice:              GetEimPackageResponseChoiceIpaEuiccDataRequest,
		IpaEuiccDataRequest: &v,
	}
}

// NewGetEimPackageResponseProfileDownloadTriggerRequest creates a GetEimPackageResponse with the profileDownloadTriggerRequest alternative.
func NewGetEimPackageResponseProfileDownloadTriggerRequest(v ProfileDownloadTriggerRequest) GetEimPackageResponse {
	return GetEimPackageResponse{
		Choice:                        GetEimPackageResponseChoiceProfileDownloadTriggerRequest,
		ProfileDownloadTriggerRequest: &v,
	}
}

// NewGetEimPackageResponseEimPackageError creates a GetEimPackageResponse with the eimPackageError alternative.
func NewGetEimPackageResponseEimPackageError(v int64) GetEimPackageResponse {
	return GetEimPackageResponse{
		Choice:          GetEimPackageResponseChoiceEimPackageError,
		EimPackageError: &v,
	}
}

// EimPackageResultErrorCode represents the ASN.1 INTEGER type EimPackageResultErrorCode with named numbers.
type EimPackageResultErrorCode int64

const (
	EimPackageResultErrorCodeInvalidPackageFormat EimPackageResultErrorCode = 1
	EimPackageResultErrorCodeUnknownPackage       EimPackageResultErrorCode = 2
	EimPackageResultErrorCodeUndefinedError       EimPackageResultErrorCode = 127
)

func (v EimPackageResultErrorCode) String() string {
	switch v {
	case EimPackageResultErrorCodeInvalidPackageFormat:
		return "invalidPackageFormat"
	case EimPackageResultErrorCodeUnknownPackage:
		return "unknownPackage"
	case EimPackageResultErrorCodeUndefinedError:
		return "undefinedError"
	default:
		return "unknown"
	}
}

// EimPackageResultResponseError represents the ASN.1 type EimPackageResultResponseError (SEQUENCE).
type EimPackageResultResponseError struct {
	EimTransactionId          *sgp22.TransactionId      `asn1:"tag:0,context,implicit,optional" json:"EimTransactionId,omitempty"`
	EimPackageResultErrorCode EimPackageResultErrorCode `asn1:""`
}

// EimPackageResult choice constants.
const (
	EimPackageResultChoiceEuiccPackageResult            = 1
	EimPackageResultChoiceEPRAndNotifications           = 2
	EimPackageResultChoiceIpaEuiccDataResponse          = 3
	EimPackageResultChoiceProfileDownloadTriggerResult  = 4
	EimPackageResultChoiceEimPackageResultResponseError = 5
)

// EimPackageResult represents the ASN.1 CHOICE type EimPackageResult.
type EimPackageResult struct {
	Choice                        int
	EuiccPackageResult            *EuiccPackageResult                  `json:"EuiccPackageResult,omitempty"`
	EPRAndNotifications           *EimPackageResultEPRAndNotifications `json:"EPRAndNotifications,omitempty"`
	IpaEuiccDataResponse          *IpaEuiccDataResponse                `json:"IpaEuiccDataResponse,omitempty"`
	ProfileDownloadTriggerResult  *ProfileDownloadTriggerResult        `json:"ProfileDownloadTriggerResult,omitempty"`
	EimPackageResultResponseError *EimPackageResultResponseError       `json:"EimPackageResultResponseError,omitempty"`
}

// NewEimPackageResultEuiccPackageResult creates a EimPackageResult with the euiccPackageResult alternative.
func NewEimPackageResultEuiccPackageResult(v EuiccPackageResult) EimPackageResult {
	return EimPackageResult{
		Choice:             EimPackageResultChoiceEuiccPackageResult,
		EuiccPackageResult: &v,
	}
}

// NewEimPackageResultEPRAndNotifications creates a EimPackageResult with the ePRAndNotifications alternative.
func NewEimPackageResultEPRAndNotifications(v EimPackageResultEPRAndNotifications) EimPackageResult {
	return EimPackageResult{
		Choice:              EimPackageResultChoiceEPRAndNotifications,
		EPRAndNotifications: &v,
	}
}

// NewEimPackageResultIpaEuiccDataResponse creates a EimPackageResult with the ipaEuiccDataResponse alternative.
func NewEimPackageResultIpaEuiccDataResponse(v IpaEuiccDataResponse) EimPackageResult {
	return EimPackageResult{
		Choice:               EimPackageResultChoiceIpaEuiccDataResponse,
		IpaEuiccDataResponse: &v,
	}
}

// NewEimPackageResultProfileDownloadTriggerResult creates a EimPackageResult with the profileDownloadTriggerResult alternative.
func NewEimPackageResultProfileDownloadTriggerResult(v ProfileDownloadTriggerResult) EimPackageResult {
	return EimPackageResult{
		Choice:                       EimPackageResultChoiceProfileDownloadTriggerResult,
		ProfileDownloadTriggerResult: &v,
	}
}

// NewEimPackageResultEimPackageResultResponseError creates a EimPackageResult with the eimPackageResultResponseError alternative.
func NewEimPackageResultEimPackageResultResponseError(v EimPackageResultResponseError) EimPackageResult {
	return EimPackageResult{
		Choice:                        EimPackageResultChoiceEimPackageResultResponseError,
		EimPackageResultResponseError: &v,
	}
}

// ProvideEimPackageResult represents the ASN.1 type ProvideEimPackageResult (SEQUENCE).
type ProvideEimPackageResult struct {
	EidValue         *sgp22.Octet16   `asn1:"tag:26,application,implicit,optional" json:"EidValue,omitempty"`
	EimPackageResult EimPackageResult `asn1:""`
}

// ProvideEimPackageResultResponse choice constants.
const (
	ProvideEimPackageResultResponseChoiceEimAcknowledgements          = 1
	ProvideEimPackageResultResponseChoiceEmptyResponse                = 2
	ProvideEimPackageResultResponseChoiceProvideEimPackageResultError = 3
)

// ProvideEimPackageResultResponse represents the ASN.1 CHOICE type ProvideEimPackageResultResponse.
type ProvideEimPackageResultResponse struct {
	Choice                       int
	EimAcknowledgements          EimAcknowledgements                           `json:"EimAcknowledgements,omitempty"`
	EmptyResponse                *ProvideEimPackageResultResponseEmptyResponse `json:"EmptyResponse,omitempty"`
	ProvideEimPackageResultError *int64                                        `json:"ProvideEimPackageResultError,omitempty"`
}

// NewProvideEimPackageResultResponseEimAcknowledgements creates a ProvideEimPackageResultResponse with the eimAcknowledgements alternative.
func NewProvideEimPackageResultResponseEimAcknowledgements(v EimAcknowledgements) ProvideEimPackageResultResponse {
	return ProvideEimPackageResultResponse{
		Choice:              ProvideEimPackageResultResponseChoiceEimAcknowledgements,
		EimAcknowledgements: v,
	}
}

// NewProvideEimPackageResultResponseEmptyResponse creates a ProvideEimPackageResultResponse with the emptyResponse alternative.
func NewProvideEimPackageResultResponseEmptyResponse(v ProvideEimPackageResultResponseEmptyResponse) ProvideEimPackageResultResponse {
	return ProvideEimPackageResultResponse{
		Choice:        ProvideEimPackageResultResponseChoiceEmptyResponse,
		EmptyResponse: &v,
	}
}

// NewProvideEimPackageResultResponseProvideEimPackageResultError creates a ProvideEimPackageResultResponse with the provideEimPackageResultError alternative.
func NewProvideEimPackageResultResponseProvideEimPackageResultError(v int64) ProvideEimPackageResultResponse {
	return ProvideEimPackageResultResponse{
		Choice:                       ProvideEimPackageResultResponseChoiceProvideEimPackageResultError,
		ProvideEimPackageResultError: &v,
	}
}

// TransferEimPackageRequest choice constants.
const (
	TransferEimPackageRequestChoiceEuiccPackageRequest           = 1
	TransferEimPackageRequestChoiceIpaEuiccDataRequest           = 2
	TransferEimPackageRequestChoiceEimAcknowledgements           = 3
	TransferEimPackageRequestChoiceProfileDownloadTriggerRequest = 4
)

// TransferEimPackageRequest represents the ASN.1 CHOICE type TransferEimPackageRequest.
type TransferEimPackageRequest struct {
	Choice                        int
	EuiccPackageRequest           *EuiccPackageRequest           `json:"EuiccPackageRequest,omitempty"`
	IpaEuiccDataRequest           *IpaEuiccDataRequest           `json:"IpaEuiccDataRequest,omitempty"`
	EimAcknowledgements           EimAcknowledgements            `json:"EimAcknowledgements,omitempty"`
	ProfileDownloadTriggerRequest *ProfileDownloadTriggerRequest `json:"ProfileDownloadTriggerRequest,omitempty"`
}

// NewTransferEimPackageRequestEuiccPackageRequest creates a TransferEimPackageRequest with the euiccPackageRequest alternative.
func NewTransferEimPackageRequestEuiccPackageRequest(v EuiccPackageRequest) TransferEimPackageRequest {
	return TransferEimPackageRequest{
		Choice:              TransferEimPackageRequestChoiceEuiccPackageRequest,
		EuiccPackageRequest: &v,
	}
}

// NewTransferEimPackageRequestIpaEuiccDataRequest creates a TransferEimPackageRequest with the ipaEuiccDataRequest alternative.
func NewTransferEimPackageRequestIpaEuiccDataRequest(v IpaEuiccDataRequest) TransferEimPackageRequest {
	return TransferEimPackageRequest{
		Choice:              TransferEimPackageRequestChoiceIpaEuiccDataRequest,
		IpaEuiccDataRequest: &v,
	}
}

// NewTransferEimPackageRequestEimAcknowledgements creates a TransferEimPackageRequest with the eimAcknowledgements alternative.
func NewTransferEimPackageRequestEimAcknowledgements(v EimAcknowledgements) TransferEimPackageRequest {
	return TransferEimPackageRequest{
		Choice:              TransferEimPackageRequestChoiceEimAcknowledgements,
		EimAcknowledgements: v,
	}
}

// NewTransferEimPackageRequestProfileDownloadTriggerRequest creates a TransferEimPackageRequest with the profileDownloadTriggerRequest alternative.
func NewTransferEimPackageRequestProfileDownloadTriggerRequest(v ProfileDownloadTriggerRequest) TransferEimPackageRequest {
	return TransferEimPackageRequest{
		Choice:                        TransferEimPackageRequestChoiceProfileDownloadTriggerRequest,
		ProfileDownloadTriggerRequest: &v,
	}
}

// TransferEimPackageResponse choice constants.
const (
	TransferEimPackageResponseChoiceEuiccPackageResult        = 1
	TransferEimPackageResponseChoiceEPRAndNotifications       = 2
	TransferEimPackageResponseChoiceIpaEuiccDataResponse      = 3
	TransferEimPackageResponseChoiceEimPackageReceived        = 4
	TransferEimPackageResponseChoiceEimPackageReceivedWithCid = 5
	TransferEimPackageResponseChoiceEimPackageError           = 6
	TransferEimPackageResponseChoiceEimPackageErrorWithCid    = 7
)

// TransferEimPackageResponse represents the ASN.1 CHOICE type TransferEimPackageResponse.
type TransferEimPackageResponse struct {
	Choice                    int
	EuiccPackageResult        *EuiccPackageResult                            `json:"EuiccPackageResult,omitempty"`
	EPRAndNotifications       *TransferEimPackageResponseEPRAndNotifications `json:"EPRAndNotifications,omitempty"`
	IpaEuiccDataResponse      *IpaEuiccDataResponse                          `json:"IpaEuiccDataResponse,omitempty"`
	EimPackageReceived        *struct{}                                      `json:"EimPackageReceived,omitempty"`
	EimPackageReceivedWithCid *EimPackageReceivedWithCid                     `json:"EimPackageReceivedWithCid,omitempty"`
	EimPackageError           *int64                                         `json:"EimPackageError,omitempty"`
	EimPackageErrorWithCid    *EimPackageErrorWithCid                        `json:"EimPackageErrorWithCid,omitempty"`
}

// NewTransferEimPackageResponseEuiccPackageResult creates a TransferEimPackageResponse with the euiccPackageResult alternative.
func NewTransferEimPackageResponseEuiccPackageResult(v EuiccPackageResult) TransferEimPackageResponse {
	return TransferEimPackageResponse{
		Choice:             TransferEimPackageResponseChoiceEuiccPackageResult,
		EuiccPackageResult: &v,
	}
}

// NewTransferEimPackageResponseEPRAndNotifications creates a TransferEimPackageResponse with the ePRAndNotifications alternative.
func NewTransferEimPackageResponseEPRAndNotifications(v TransferEimPackageResponseEPRAndNotifications) TransferEimPackageResponse {
	return TransferEimPackageResponse{
		Choice:              TransferEimPackageResponseChoiceEPRAndNotifications,
		EPRAndNotifications: &v,
	}
}

// NewTransferEimPackageResponseIpaEuiccDataResponse creates a TransferEimPackageResponse with the ipaEuiccDataResponse alternative.
func NewTransferEimPackageResponseIpaEuiccDataResponse(v IpaEuiccDataResponse) TransferEimPackageResponse {
	return TransferEimPackageResponse{
		Choice:               TransferEimPackageResponseChoiceIpaEuiccDataResponse,
		IpaEuiccDataResponse: &v,
	}
}

// NewTransferEimPackageResponseEimPackageReceived creates a TransferEimPackageResponse with the eimPackageReceived alternative.
func NewTransferEimPackageResponseEimPackageReceived(v struct{}) TransferEimPackageResponse {
	return TransferEimPackageResponse{
		Choice:             TransferEimPackageResponseChoiceEimPackageReceived,
		EimPackageReceived: &v,
	}
}

// NewTransferEimPackageResponseEimPackageReceivedWithCid creates a TransferEimPackageResponse with the eimPackageReceivedWithCid alternative.
func NewTransferEimPackageResponseEimPackageReceivedWithCid(v EimPackageReceivedWithCid) TransferEimPackageResponse {
	return TransferEimPackageResponse{
		Choice:                    TransferEimPackageResponseChoiceEimPackageReceivedWithCid,
		EimPackageReceivedWithCid: &v,
	}
}

// NewTransferEimPackageResponseEimPackageError creates a TransferEimPackageResponse with the eimPackageError alternative.
func NewTransferEimPackageResponseEimPackageError(v int64) TransferEimPackageResponse {
	return TransferEimPackageResponse{
		Choice:          TransferEimPackageResponseChoiceEimPackageError,
		EimPackageError: &v,
	}
}

// NewTransferEimPackageResponseEimPackageErrorWithCid creates a TransferEimPackageResponse with the eimPackageErrorWithCid alternative.
func NewTransferEimPackageResponseEimPackageErrorWithCid(v EimPackageErrorWithCid) TransferEimPackageResponse {
	return TransferEimPackageResponse{
		Choice:                 TransferEimPackageResponseChoiceEimPackageErrorWithCid,
		EimPackageErrorWithCid: &v,
	}
}

// EimPackageReceivedWithCid represents the ASN.1 type EimPackageReceivedWithCid (SEQUENCE).
type EimPackageReceivedWithCid struct {
	CorrelationId *EimPackageReceivedWithCidCorrelationId `asn1:"tag:0,context,explicit,optional" json:"CorrelationId,omitempty"`
}

// EimPackageErrorWithCid represents the ASN.1 type EimPackageErrorWithCid (SEQUENCE).
type EimPackageErrorWithCid struct {
	CorrelationId   *EimPackageErrorWithCidCorrelationId `asn1:"tag:0,context,explicit,optional" json:"CorrelationId,omitempty"`
	EimPackageError EimPackageResultErrorCode            `asn1:"tag:1,context,implicit"`
}

// EuiccPackagePsmoList represents the ASN.1 type EuiccPackage-psmoList (SEQUENCE_OF).
type EuiccPackagePsmoList = []Psmo

// EuiccPackageEcoList represents the ASN.1 type EuiccPackage-ecoList (SEQUENCE_OF).
type EuiccPackageEcoList = []Eco

// EimConfigurationDataEimPublicKeyData choice constants.
const (
	EimConfigurationDataEimPublicKeyDataChoiceEimPublicKey   = 1
	EimConfigurationDataEimPublicKeyDataChoiceEimCertificate = 2
)

// EimConfigurationDataEimPublicKeyData represents the ASN.1 CHOICE type EimConfigurationData-eimPublicKeyData.
type EimConfigurationDataEimPublicKeyData struct {
	Choice         int
	EimPublicKey   *sgp22.SubjectPublicKeyInfo `json:"EimPublicKey,omitempty"`
	EimCertificate *sgp22.Certificate          `json:"EimCertificate,omitempty"`
}

// NewEimConfigurationDataEimPublicKeyDataEimPublicKey creates a EimConfigurationData-eimPublicKeyData with the eimPublicKey alternative.
func NewEimConfigurationDataEimPublicKeyDataEimPublicKey(v sgp22.SubjectPublicKeyInfo) EimConfigurationDataEimPublicKeyData {
	return EimConfigurationDataEimPublicKeyData{
		Choice:       EimConfigurationDataEimPublicKeyDataChoiceEimPublicKey,
		EimPublicKey: &v,
	}
}

// NewEimConfigurationDataEimPublicKeyDataEimCertificate creates a EimConfigurationData-eimPublicKeyData with the eimCertificate alternative.
func NewEimConfigurationDataEimPublicKeyDataEimCertificate(v sgp22.Certificate) EimConfigurationDataEimPublicKeyData {
	return EimConfigurationDataEimPublicKeyData{
		Choice:         EimConfigurationDataEimPublicKeyDataChoiceEimCertificate,
		EimCertificate: &v,
	}
}

// EimConfigurationDataTrustedPublicKeyDataTls choice constants.
const (
	EimConfigurationDataTrustedPublicKeyDataTlsChoiceTrustedEimPkTls       = 1
	EimConfigurationDataTrustedPublicKeyDataTlsChoiceTrustedCertificateTls = 2
)

// EimConfigurationDataTrustedPublicKeyDataTls represents the ASN.1 CHOICE type EimConfigurationData-trustedPublicKeyDataTls.
type EimConfigurationDataTrustedPublicKeyDataTls struct {
	Choice                int
	TrustedEimPkTls       *sgp22.SubjectPublicKeyInfo `json:"TrustedEimPkTls,omitempty"`
	TrustedCertificateTls *sgp22.Certificate          `json:"TrustedCertificateTls,omitempty"`
}

// NewEimConfigurationDataTrustedPublicKeyDataTlsTrustedEimPkTls creates a EimConfigurationData-trustedPublicKeyDataTls with the trustedEimPkTls alternative.
func NewEimConfigurationDataTrustedPublicKeyDataTlsTrustedEimPkTls(v sgp22.SubjectPublicKeyInfo) EimConfigurationDataTrustedPublicKeyDataTls {
	return EimConfigurationDataTrustedPublicKeyDataTls{
		Choice:          EimConfigurationDataTrustedPublicKeyDataTlsChoiceTrustedEimPkTls,
		TrustedEimPkTls: &v,
	}
}

// NewEimConfigurationDataTrustedPublicKeyDataTlsTrustedCertificateTls creates a EimConfigurationData-trustedPublicKeyDataTls with the trustedCertificateTls alternative.
func NewEimConfigurationDataTrustedPublicKeyDataTlsTrustedCertificateTls(v sgp22.Certificate) EimConfigurationDataTrustedPublicKeyDataTls {
	return EimConfigurationDataTrustedPublicKeyDataTls{
		Choice:                EimConfigurationDataTrustedPublicKeyDataTlsChoiceTrustedCertificateTls,
		TrustedCertificateTls: &v,
	}
}

// EcoDeleteEim represents the ASN.1 type Eco-deleteEim (SEQUENCE).
type EcoDeleteEim struct {
	EimId string `asn1:"tag:0,context,implicit"`
}

// EcoListEim represents the ASN.1 type Eco-listEim (SEQUENCE).
type EcoListEim struct {
}

// PsmoEnable represents the ASN.1 type Psmo-enable (SEQUENCE).
type PsmoEnable struct {
	Iccid        sgp22.Iccid `asn1:"tag:26,application,implicit"`
	RollbackFlag *struct{}   `asn1:",optional" json:"RollbackFlag,omitempty"`
}

// PsmoDisable represents the ASN.1 type Psmo-disable (SEQUENCE).
type PsmoDisable struct {
	Iccid sgp22.Iccid `asn1:"tag:26,application,implicit"`
}

// PsmoDelete represents the ASN.1 type Psmo-delete (SEQUENCE).
type PsmoDelete struct {
	Iccid sgp22.Iccid `asn1:"tag:26,application,implicit"`
}

// PsmoGetRAT represents the ASN.1 type Psmo-getRAT (SEQUENCE).
type PsmoGetRAT struct {
}

// PsmoConfigureImmediateEnable represents the ASN.1 type Psmo-configureImmediateEnable (SEQUENCE).
type PsmoConfigureImmediateEnable struct {
	ImmediateEnableFlag *struct{}                `asn1:"tag:0,context,implicit,optional" json:"ImmediateEnableFlag,omitempty"`
	DefaultSmdpOid      runtime.ObjectIdentifier `asn1:"tag:1,context,implicit,optional" json:"DefaultSmdpOid,omitempty"`
	DefaultSmdpAddress  *string                  `asn1:"tag:2,context,implicit,optional" json:"DefaultSmdpAddress,omitempty"`
}

// PsmoSetFallbackAttribute represents the ASN.1 type Psmo-setFallbackAttribute (SEQUENCE).
type PsmoSetFallbackAttribute struct {
	Iccid sgp22.Iccid `asn1:"tag:26,application,implicit"`
}

// PsmoUnsetFallbackAttribute represents the ASN.1 type Psmo-unsetFallbackAttribute (SEQUENCE).
type PsmoUnsetFallbackAttribute struct {
}

// IpaEuiccDataRequestSearchCriteriaNotification choice constants.
const (
	IpaEuiccDataRequestSearchCriteriaNotificationChoiceSeqNumber                  = 1
	IpaEuiccDataRequestSearchCriteriaNotificationChoiceProfileManagementOperation = 2
)

// IpaEuiccDataRequestSearchCriteriaNotification represents the ASN.1 CHOICE type IpaEuiccDataRequest-searchCriteriaNotification.
type IpaEuiccDataRequestSearchCriteriaNotification struct {
	Choice                     int
	SeqNumber                  *big.Int                 `json:"SeqNumber,omitempty"`
	ProfileManagementOperation *sgp22.NotificationEvent `json:"ProfileManagementOperation,omitempty"`
}

// NewIpaEuiccDataRequestSearchCriteriaNotificationSeqNumber creates a IpaEuiccDataRequest-searchCriteriaNotification with the seqNumber alternative.
func NewIpaEuiccDataRequestSearchCriteriaNotificationSeqNumber(v *big.Int) IpaEuiccDataRequestSearchCriteriaNotification {
	return IpaEuiccDataRequestSearchCriteriaNotification{
		Choice:    IpaEuiccDataRequestSearchCriteriaNotificationChoiceSeqNumber,
		SeqNumber: v,
	}
}

// NewIpaEuiccDataRequestSearchCriteriaNotificationProfileManagementOperation creates a IpaEuiccDataRequest-searchCriteriaNotification with the profileManagementOperation alternative.
func NewIpaEuiccDataRequestSearchCriteriaNotificationProfileManagementOperation(v sgp22.NotificationEvent) IpaEuiccDataRequestSearchCriteriaNotification {
	return IpaEuiccDataRequestSearchCriteriaNotification{
		Choice:                     IpaEuiccDataRequestSearchCriteriaNotificationChoiceProfileManagementOperation,
		ProfileManagementOperation: &v,
	}
}

// IpaEuiccDataRequestSearchCriteriaEuiccPackageResult choice constants.
const (
	IpaEuiccDataRequestSearchCriteriaEuiccPackageResultChoiceSeqNumber = 1
)

// IpaEuiccDataRequestSearchCriteriaEuiccPackageResult represents the ASN.1 CHOICE type IpaEuiccDataRequest-searchCriteriaEuiccPackageResult.
type IpaEuiccDataRequestSearchCriteriaEuiccPackageResult struct {
	Choice    int
	SeqNumber *big.Int `json:"SeqNumber,omitempty"`
}

// NewIpaEuiccDataRequestSearchCriteriaEuiccPackageResultSeqNumber creates a IpaEuiccDataRequest-searchCriteriaEuiccPackageResult with the seqNumber alternative.
func NewIpaEuiccDataRequestSearchCriteriaEuiccPackageResultSeqNumber(v *big.Int) IpaEuiccDataRequestSearchCriteriaEuiccPackageResult {
	return IpaEuiccDataRequestSearchCriteriaEuiccPackageResult{
		Choice:    IpaEuiccDataRequestSearchCriteriaEuiccPackageResultChoiceSeqNumber,
		SeqNumber: v,
	}
}

// ProfileDownloadDataContactSmds represents the ASN.1 type ProfileDownloadData-contactSmds (SEQUENCE).
type ProfileDownloadDataContactSmds struct {
	SmdsAddress *string `asn1:"tag:0,context,implicit,optional" json:"SmdsAddress,omitempty"`
}

// EuiccPackageResultDataSignedEuiccResult represents the ASN.1 type EuiccPackageResultDataSigned-euiccResult (SEQUENCE_OF).
type EuiccPackageResultDataSignedEuiccResult = []EuiccResultData

// ProfileInfoListResponseProfileInfoListOk represents the ASN.1 type ProfileInfoListResponse-profileInfoListOk (SEQUENCE_OF).
type ProfileInfoListResponseProfileInfoListOk = []ProfileInfo

// ListEimResultEimIdList represents the ASN.1 type ListEimResult-eimIdList (SEQUENCE_OF).
type ListEimResultEimIdList = []EimIdInfo

// ProfileDownloadTriggerResultProfileDownloadTriggerResultData choice constants.
const (
	ProfileDownloadTriggerResultProfileDownloadTriggerResultDataChoiceProfileInstallationResult = 1
	ProfileDownloadTriggerResultProfileDownloadTriggerResultDataChoiceProfileDownloadError      = 2
)

// ProfileDownloadTriggerResultProfileDownloadTriggerResultData represents the ASN.1 CHOICE type ProfileDownloadTriggerResult-profileDownloadTriggerResultData.
type ProfileDownloadTriggerResultProfileDownloadTriggerResultData struct {
	Choice                    int
	ProfileInstallationResult *ProfileInstallationResult                                                        `json:"ProfileInstallationResult,omitempty"`
	ProfileDownloadError      *ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError `json:"ProfileDownloadError,omitempty"`
}

// NewProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileInstallationResult creates a ProfileDownloadTriggerResult-profileDownloadTriggerResultData with the profileInstallationResult alternative.
func NewProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileInstallationResult(v ProfileInstallationResult) ProfileDownloadTriggerResultProfileDownloadTriggerResultData {
	return ProfileDownloadTriggerResultProfileDownloadTriggerResultData{
		Choice:                    ProfileDownloadTriggerResultProfileDownloadTriggerResultDataChoiceProfileInstallationResult,
		ProfileInstallationResult: &v,
	}
}

// NewProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError creates a ProfileDownloadTriggerResult-profileDownloadTriggerResultData with the profileDownloadError alternative.
func NewProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError(v ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError) ProfileDownloadTriggerResultProfileDownloadTriggerResultData {
	return ProfileDownloadTriggerResultProfileDownloadTriggerResultData{
		Choice:               ProfileDownloadTriggerResultProfileDownloadTriggerResultDataChoiceProfileDownloadError,
		ProfileDownloadError: &v,
	}
}

// ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError represents the ASN.1 type ProfileDownloadTriggerResult-profileDownloadTriggerResultData-profileDownloadError (SEQUENCE).
type ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError struct {
	ProfileDownloadErrorReason int64  `asn1:"tag:0,context,implicit"`
	ErrorResponse              []byte `asn1:",optional" json:"ErrorResponse,omitempty"`
}

// ProfileInfoNotificationConfigurationInfo represents the ASN.1 type ProfileInfo-notificationConfigurationInfo (SEQUENCE_OF).
type ProfileInfoNotificationConfigurationInfo = []sgp22.NotificationConfigurationInformation

// ProfileInfoIotSpecificProfileInfo represents the ASN.1 type ProfileInfo-iotSpecificProfileInfo (SEQUENCE).
type ProfileInfoIotSpecificProfileInfo struct {
}

// StoreMetadataRequestNotificationConfigurationInfo represents the ASN.1 type StoreMetadataRequest-notificationConfigurationInfo (SEQUENCE_OF).
type StoreMetadataRequestNotificationConfigurationInfo = []sgp22.NotificationConfigurationInformation

// StoreMetadataRequestIotSpecificMetadata represents the ASN.1 type StoreMetadataRequest-iotSpecificMetadata (SEQUENCE).
type StoreMetadataRequestIotSpecificMetadata struct {
}

// EUICCInfo2EuiccCiPKIdListForVerification represents the ASN.1 type EUICCInfo2-euiccCiPKIdListForVerification (SEQUENCE_OF).
type EUICCInfo2EuiccCiPKIdListForVerification = []sgp22.SubjectKeyIdentifier

// EUICCInfo2EuiccCiPKIdListForSigning represents the ASN.1 type EUICCInfo2-euiccCiPKIdListForSigning (SEQUENCE_OF).
type EUICCInfo2EuiccCiPKIdListForSigning = []sgp22.SubjectKeyIdentifier

// EUICCInfo2AdditionalEuiccProfilePackageVersions represents the ASN.1 type EUICCInfo2-additionalEuiccProfilePackageVersions (SEQUENCE_OF).
type EUICCInfo2AdditionalEuiccProfilePackageVersions = []sgp22.VersionType

// EUICCInfo2EuiccCiPKIdListForSigningV3 represents the ASN.1 type EUICCInfo2-euiccCiPKIdListForSigningV3 (SEQUENCE_OF).
type EUICCInfo2EuiccCiPKIdListForSigningV3 = []sgp22.SubjectKeyIdentifier

// IoTSpecificInfoIotVersion represents the ASN.1 type IoTSpecificInfo-iotVersion (SEQUENCE_OF).
type IoTSpecificInfoIotVersion = []sgp22.VersionType

// AddInitialEimRequestEimConfigurationDataList represents the ASN.1 type AddInitialEimRequest-eimConfigurationDataList (SEQUENCE_OF).
type AddInitialEimRequestEimConfigurationDataList = []EimConfigurationData

// AddInitialEimResponseAddInitialEimOkElem choice constants.
const (
	AddInitialEimResponseAddInitialEimOkElemChoiceAssociationToken = 1
	AddInitialEimResponseAddInitialEimOkElemChoiceAddOk            = 2
)

// AddInitialEimResponseAddInitialEimOkElem represents the ASN.1 CHOICE type AddInitialEimResponse-addInitialEimOk-Elem.
type AddInitialEimResponseAddInitialEimOkElem struct {
	Choice           int
	AssociationToken *big.Int  `json:"AssociationToken,omitempty"`
	AddOk            *struct{} `json:"AddOk,omitempty"`
}

// NewAddInitialEimResponseAddInitialEimOkElemAssociationToken creates a AddInitialEimResponse-addInitialEimOk-Elem with the associationToken alternative.
func NewAddInitialEimResponseAddInitialEimOkElemAssociationToken(v *big.Int) AddInitialEimResponseAddInitialEimOkElem {
	return AddInitialEimResponseAddInitialEimOkElem{
		Choice:           AddInitialEimResponseAddInitialEimOkElemChoiceAssociationToken,
		AssociationToken: v,
	}
}

// NewAddInitialEimResponseAddInitialEimOkElemAddOk creates a AddInitialEimResponse-addInitialEimOk-Elem with the addOk alternative.
func NewAddInitialEimResponseAddInitialEimOkElemAddOk(v struct{}) AddInitialEimResponseAddInitialEimOkElem {
	return AddInitialEimResponseAddInitialEimOkElem{
		Choice: AddInitialEimResponseAddInitialEimOkElemChoiceAddOk,
		AddOk:  &v,
	}
}

// AddInitialEimResponseAddInitialEimOk represents the ASN.1 type AddInitialEimResponse-addInitialEimOk (SEQUENCE_OF).
type AddInitialEimResponseAddInitialEimOk = []AddInitialEimResponseAddInitialEimOkElem

// GetCertsResponseCerts represents the ASN.1 type GetCertsResponse-certs (SEQUENCE).
type GetCertsResponseCerts struct {
	EumCertificate   sgp22.Certificate `asn1:"tag:5,context,implicit"`
	EuiccCertificate sgp22.Certificate `asn1:"tag:6,context,implicit"`
}

// RetrieveNotificationsListRequestSearchCriteria choice constants.
const (
	RetrieveNotificationsListRequestSearchCriteriaChoiceSeqNumber                  = 1
	RetrieveNotificationsListRequestSearchCriteriaChoiceProfileManagementOperation = 2
	RetrieveNotificationsListRequestSearchCriteriaChoiceEuiccPackageResults        = 3
)

// RetrieveNotificationsListRequestSearchCriteria represents the ASN.1 CHOICE type RetrieveNotificationsListRequest-searchCriteria.
type RetrieveNotificationsListRequestSearchCriteria struct {
	Choice                     int
	SeqNumber                  *big.Int                 `json:"SeqNumber,omitempty"`
	ProfileManagementOperation *sgp22.NotificationEvent `json:"ProfileManagementOperation,omitempty"`
	EuiccPackageResults        *struct{}                `json:"EuiccPackageResults,omitempty"`
}

// NewRetrieveNotificationsListRequestSearchCriteriaSeqNumber creates a RetrieveNotificationsListRequest-searchCriteria with the seqNumber alternative.
func NewRetrieveNotificationsListRequestSearchCriteriaSeqNumber(v *big.Int) RetrieveNotificationsListRequestSearchCriteria {
	return RetrieveNotificationsListRequestSearchCriteria{
		Choice:    RetrieveNotificationsListRequestSearchCriteriaChoiceSeqNumber,
		SeqNumber: v,
	}
}

// NewRetrieveNotificationsListRequestSearchCriteriaProfileManagementOperation creates a RetrieveNotificationsListRequest-searchCriteria with the profileManagementOperation alternative.
func NewRetrieveNotificationsListRequestSearchCriteriaProfileManagementOperation(v sgp22.NotificationEvent) RetrieveNotificationsListRequestSearchCriteria {
	return RetrieveNotificationsListRequestSearchCriteria{
		Choice:                     RetrieveNotificationsListRequestSearchCriteriaChoiceProfileManagementOperation,
		ProfileManagementOperation: &v,
	}
}

// NewRetrieveNotificationsListRequestSearchCriteriaEuiccPackageResults creates a RetrieveNotificationsListRequest-searchCriteria with the euiccPackageResults alternative.
func NewRetrieveNotificationsListRequestSearchCriteriaEuiccPackageResults(v struct{}) RetrieveNotificationsListRequestSearchCriteria {
	return RetrieveNotificationsListRequestSearchCriteria{
		Choice:              RetrieveNotificationsListRequestSearchCriteriaChoiceEuiccPackageResults,
		EuiccPackageResults: &v,
	}
}

// GetEimConfigurationDataRequestSearchCriteria choice constants.
const (
	GetEimConfigurationDataRequestSearchCriteriaChoiceEimId = 1
)

// GetEimConfigurationDataRequestSearchCriteria represents the ASN.1 CHOICE type GetEimConfigurationDataRequest-searchCriteria.
type GetEimConfigurationDataRequestSearchCriteria struct {
	Choice int
	EimId  *string `json:"EimId,omitempty"`
}

// NewGetEimConfigurationDataRequestSearchCriteriaEimId creates a GetEimConfigurationDataRequest-searchCriteria with the eimId alternative.
func NewGetEimConfigurationDataRequestSearchCriteriaEimId(v string) GetEimConfigurationDataRequestSearchCriteria {
	return GetEimConfigurationDataRequestSearchCriteria{
		Choice: GetEimConfigurationDataRequestSearchCriteriaChoiceEimId,
		EimId:  &v,
	}
}

// GetEimConfigurationDataResponseEimConfigurationDataList represents the ASN.1 type GetEimConfigurationDataResponse-eimConfigurationDataList (SEQUENCE_OF).
type GetEimConfigurationDataResponseEimConfigurationDataList = []EimConfigurationData

// CompactAuthenticateResponseOkSignedData choice constants.
const (
	CompactAuthenticateResponseOkSignedDataChoiceEuiccSigned1        = 1
	CompactAuthenticateResponseOkSignedDataChoiceCompactEuiccSigned1 = 2
)

// CompactAuthenticateResponseOkSignedData represents the ASN.1 CHOICE type CompactAuthenticateResponseOk-signedData.
type CompactAuthenticateResponseOkSignedData struct {
	Choice              int
	EuiccSigned1        *EuiccSigned1        `json:"EuiccSigned1,omitempty"`
	CompactEuiccSigned1 *CompactEuiccSigned1 `json:"CompactEuiccSigned1,omitempty"`
}

// NewCompactAuthenticateResponseOkSignedDataEuiccSigned1 creates a CompactAuthenticateResponseOk-signedData with the euiccSigned1 alternative.
func NewCompactAuthenticateResponseOkSignedDataEuiccSigned1(v EuiccSigned1) CompactAuthenticateResponseOkSignedData {
	return CompactAuthenticateResponseOkSignedData{
		Choice:       CompactAuthenticateResponseOkSignedDataChoiceEuiccSigned1,
		EuiccSigned1: &v,
	}
}

// NewCompactAuthenticateResponseOkSignedDataCompactEuiccSigned1 creates a CompactAuthenticateResponseOk-signedData with the compactEuiccSigned1 alternative.
func NewCompactAuthenticateResponseOkSignedDataCompactEuiccSigned1(v CompactEuiccSigned1) CompactAuthenticateResponseOkSignedData {
	return CompactAuthenticateResponseOkSignedData{
		Choice:              CompactAuthenticateResponseOkSignedDataChoiceCompactEuiccSigned1,
		CompactEuiccSigned1: &v,
	}
}

// CompactProfileInstallationResultDataCompactFinalResult choice constants.
const (
	CompactProfileInstallationResultDataCompactFinalResultChoiceCompactSuccessResult = 1
	CompactProfileInstallationResultDataCompactFinalResultChoiceErrorResult          = 2
)

// CompactProfileInstallationResultDataCompactFinalResult represents the ASN.1 CHOICE type CompactProfileInstallationResultData-compactFinalResult.
type CompactProfileInstallationResultDataCompactFinalResult struct {
	Choice               int
	CompactSuccessResult *CompactSuccessResult `json:"CompactSuccessResult,omitempty"`
	ErrorResult          *sgp22.ErrorResult    `json:"ErrorResult,omitempty"`
}

// NewCompactProfileInstallationResultDataCompactFinalResultCompactSuccessResult creates a CompactProfileInstallationResultData-compactFinalResult with the compactSuccessResult alternative.
func NewCompactProfileInstallationResultDataCompactFinalResultCompactSuccessResult(v CompactSuccessResult) CompactProfileInstallationResultDataCompactFinalResult {
	return CompactProfileInstallationResultDataCompactFinalResult{
		Choice:               CompactProfileInstallationResultDataCompactFinalResultChoiceCompactSuccessResult,
		CompactSuccessResult: &v,
	}
}

// NewCompactProfileInstallationResultDataCompactFinalResultErrorResult creates a CompactProfileInstallationResultData-compactFinalResult with the errorResult alternative.
func NewCompactProfileInstallationResultDataCompactFinalResultErrorResult(v sgp22.ErrorResult) CompactProfileInstallationResultDataCompactFinalResult {
	return CompactProfileInstallationResultDataCompactFinalResult{
		Choice:      CompactProfileInstallationResultDataCompactFinalResultChoiceErrorResult,
		ErrorResult: &v,
	}
}

// EimPackageResultEPRAndNotifications represents the ASN.1 type EimPackageResult-ePRAndNotifications (SEQUENCE).
type EimPackageResultEPRAndNotifications struct {
	EuiccPackageResult     EuiccPackageResult      `asn1:"tag:81,context,explicit"`
	NotificationList       PendingNotificationList `asn1:"tag:0,context,implicit"`
	NotificationListIndef_ bool                    `asn1:"-" json:"-"`
}

// ProvideEimPackageResultResponseEmptyResponse represents the ASN.1 type ProvideEimPackageResultResponse-emptyResponse (SEQUENCE).
type ProvideEimPackageResultResponseEmptyResponse struct {
}

// TransferEimPackageResponseEPRAndNotifications represents the ASN.1 type TransferEimPackageResponse-ePRAndNotifications (SEQUENCE).
type TransferEimPackageResponseEPRAndNotifications struct {
	EuiccPackageResult     EuiccPackageResult      `asn1:"tag:81,context,explicit"`
	NotificationList       PendingNotificationList `asn1:"tag:0,context,implicit"`
	NotificationListIndef_ bool                    `asn1:"-" json:"-"`
}

// EimPackageReceivedWithCidCorrelationId choice constants.
const (
	EimPackageReceivedWithCidCorrelationIdChoiceEimTransactionId = 1
	EimPackageReceivedWithCidCorrelationIdChoiceEidValue         = 2
)

// EimPackageReceivedWithCidCorrelationId represents the ASN.1 CHOICE type EimPackageReceivedWithCid-correlationId.
type EimPackageReceivedWithCidCorrelationId struct {
	Choice           int
	EimTransactionId *sgp22.TransactionId `json:"EimTransactionId,omitempty"`
	EidValue         *sgp22.Octet16       `json:"EidValue,omitempty"`
}

// NewEimPackageReceivedWithCidCorrelationIdEimTransactionId creates a EimPackageReceivedWithCid-correlationId with the eimTransactionId alternative.
func NewEimPackageReceivedWithCidCorrelationIdEimTransactionId(v sgp22.TransactionId) EimPackageReceivedWithCidCorrelationId {
	return EimPackageReceivedWithCidCorrelationId{
		Choice:           EimPackageReceivedWithCidCorrelationIdChoiceEimTransactionId,
		EimTransactionId: &v,
	}
}

// NewEimPackageReceivedWithCidCorrelationIdEidValue creates a EimPackageReceivedWithCid-correlationId with the eidValue alternative.
func NewEimPackageReceivedWithCidCorrelationIdEidValue(v sgp22.Octet16) EimPackageReceivedWithCidCorrelationId {
	return EimPackageReceivedWithCidCorrelationId{
		Choice:   EimPackageReceivedWithCidCorrelationIdChoiceEidValue,
		EidValue: &v,
	}
}

// EimPackageErrorWithCidCorrelationId choice constants.
const (
	EimPackageErrorWithCidCorrelationIdChoiceEimTransactionId = 1
	EimPackageErrorWithCidCorrelationIdChoiceEidValue         = 2
)

// EimPackageErrorWithCidCorrelationId represents the ASN.1 CHOICE type EimPackageErrorWithCid-correlationId.
type EimPackageErrorWithCidCorrelationId struct {
	Choice           int
	EimTransactionId *sgp22.TransactionId `json:"EimTransactionId,omitempty"`
	EidValue         *sgp22.Octet16       `json:"EidValue,omitempty"`
}

// NewEimPackageErrorWithCidCorrelationIdEimTransactionId creates a EimPackageErrorWithCid-correlationId with the eimTransactionId alternative.
func NewEimPackageErrorWithCidCorrelationIdEimTransactionId(v sgp22.TransactionId) EimPackageErrorWithCidCorrelationId {
	return EimPackageErrorWithCidCorrelationId{
		Choice:           EimPackageErrorWithCidCorrelationIdChoiceEimTransactionId,
		EimTransactionId: &v,
	}
}

// NewEimPackageErrorWithCidCorrelationIdEidValue creates a EimPackageErrorWithCid-correlationId with the eidValue alternative.
func NewEimPackageErrorWithCidCorrelationIdEidValue(v sgp22.Octet16) EimPackageErrorWithCidCorrelationId {
	return EimPackageErrorWithCidCorrelationId{
		Choice:   EimPackageErrorWithCidCorrelationIdChoiceEidValue,
		EidValue: &v,
	}
}

// MarshalBER encodes EuiccPackageRequest to BER format.
func (v *EuiccPackageRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccpackagesigned, err := v.EuiccPackageSigned.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccPackageSigned: %w", err)
	}
	children = append(children, enc_euiccpackagesigned...)
	enc_eimsignature := ber.EncodeOctetString(v.EimSignature)
	enc_eimsignature = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_eimsignature)
	children = append(children, enc_eimsignature...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 81, Constructed: true}, children), nil
}

// MarshalDER encodes EuiccPackageRequest to DER format.
func (v *EuiccPackageRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccPackageRequest from BER/DER format.
func (v *EuiccPackageRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccPackageRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 81 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EuiccPackageRequest: %w: expected tag [CONTEXT 81], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccPackageRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccPackageSigned
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccPackageSigned")
	}
	// Decode nested SEQUENCE (EuiccPackageSigned)
	_, n_euiccpackagesigned, _, tlvErr_euiccpackagesigned := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccpackagesigned != nil {
		return fmt.Errorf("decoding euiccPackageSigned: %w", tlvErr_euiccpackagesigned)
	}
	if unmErr := v.EuiccPackageSigned.UnmarshalBER(content[offset : offset+n_euiccpackagesigned]); unmErr != nil {
		return fmt.Errorf("decoding euiccPackageSigned: %w", unmErr)
	}
	offset += n_euiccpackagesigned
	// Decode eimSignature
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimSignature")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for eimSignature, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_eimsignature, rawVal_eimsignature, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimSignature: %w", err)
	}
	v.EimSignature = rawVal_eimsignature
	offset += n_eimsignature
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EuiccPackageRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EuiccPackageSigned to BER format.
func (v *EuiccPackageSigned) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eimid := ber.EncodeStringTag(12, v.EimId)
	enc_eimid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_eimid)
	children = append(children, enc_eimid...)
	enc_eidvalue := ber.EncodeOctetString([]byte(v.EidValue))
	enc_eidvalue = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_eidvalue)
	children = append(children, enc_eidvalue...)
	if v.CounterValue == nil {
		return nil, fmt.Errorf("encoding counterValue: required INTEGER is nil")
	}
	enc_countervalue := ber.EncodeBigInt(v.CounterValue)
	enc_countervalue = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_countervalue)
	children = append(children, enc_countervalue...)
	if v.EimTransactionId != nil {
		enc_eimtransactionid := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_eimtransactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_eimtransactionid)
		children = append(children, enc_eimtransactionid...)
	}
	enc_euiccpackage, err := v.EuiccPackage.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccPackage: %w", err)
	}
	children = append(children, enc_euiccpackage...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EuiccPackageSigned to DER format.
func (v *EuiccPackageSigned) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccPackageSigned from BER/DER format.
func (v *EuiccPackageSigned) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccPackageSigned SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccPackageSigned", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimId
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for eimId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_eimid, rawVal_eimid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimId: %w", err)
	}
	decVal_eimid := ber.DecodeStringValue(rawVal_eimid)
	v.EimId = decVal_eimid
	offset += n_eimid
	// Decode eidValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field eidValue")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 26 {
			return fmt.Errorf("expected tag [%s %d] for eidValue, got %s", "APPLICATION", 26, reqTag_)
		}
	}
	_, n_eidvalue, rawVal_eidvalue, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eidValue: %w", err)
	}
	v.EidValue = sgp22.Octet16(rawVal_eidvalue)
	offset += n_eidvalue
	// Decode counterValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field counterValue")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for counterValue, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_countervalue, rawVal_countervalue, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding counterValue: %w", err)
	}
	decVal_countervalue, intErr := ber.DecodeBigIntValue(rawVal_countervalue)
	if intErr != nil {
		return fmt.Errorf("decoding counterValue: %w", intErr)
	}
	v.CounterValue = decVal_countervalue
	offset += n_countervalue
	// Decode eimTransactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eimtransactionid, rawVal_eimtransactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimTransactionId: %w", err)
				}
				tmp_eimtransactionid := sgp22.TransactionId(rawVal_eimtransactionid)
				v.EimTransactionId = &tmp_eimtransactionid
				offset += n_eimtransactionid
			}
		}
	}
	// Decode euiccPackage
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccPackage")
	}
	// Decode nested CHOICE (EuiccPackage)
	_, n_euiccpackage, _, tlvErr_euiccpackage := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccpackage != nil {
		return fmt.Errorf("decoding euiccPackage: %w", tlvErr_euiccpackage)
	}
	if unmErr := v.EuiccPackage.UnmarshalBER(content[offset : offset+n_euiccpackage]); unmErr != nil {
		return fmt.Errorf("decoding euiccPackage: %w", unmErr)
	}
	offset += n_euiccpackage
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EuiccPackageSigned", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EuiccPackage to BER format.
func (v *EuiccPackage) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EuiccPackageChoicePsmoList:
		if v.PsmoList == nil {
			return nil, fmt.Errorf("choice EuiccPackage: psmoList is nil")
		}
		enc_0, err := MarshalBEREuiccPackagePsmoList(v.PsmoList)
		if err != nil {
			return nil, fmt.Errorf("encoding psmoList: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case EuiccPackageChoiceEcoList:
		if v.EcoList == nil {
			return nil, fmt.Errorf("choice EuiccPackage: ecoList is nil")
		}
		enc_1, err := MarshalBEREuiccPackageEcoList(v.EcoList)
		if err != nil {
			return nil, fmt.Errorf("encoding ecoList: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EuiccPackage", v.Choice)
	}
}

// MarshalDER encodes EuiccPackage to DER format.
func (v *EuiccPackage) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccPackage from BER/DER format.
func (v *EuiccPackage) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for EuiccPackage CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EuiccPackage: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding EuiccPackage CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccPackage", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = EuiccPackageChoicePsmoList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding psmoList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBEREuiccPackagePsmoList(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding psmoList: %w", unmErr)
		}
		v.PsmoList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = EuiccPackageChoiceEcoList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ecoList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBEREuiccPackageEcoList(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding ecoList: %w", unmErr)
		}
		v.EcoList = dec
	} else {
		return fmt.Errorf("unknown tag %s for EuiccPackage CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EimConfigurationData to BER format.
func (v *EimConfigurationData) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eimid := ber.EncodeStringTag(12, v.EimId)
	enc_eimid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_eimid)
	children = append(children, enc_eimid...)
	if v.EimFqdn != nil {
		enc_eimfqdn := ber.EncodeStringTag(12, *v.EimFqdn)
		enc_eimfqdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_eimfqdn)
		children = append(children, enc_eimfqdn...)
	}
	if v.EimIdType != nil {
		enc_eimidtype := ber.EncodeInteger(int64(*v.EimIdType))
		enc_eimidtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_eimidtype)
		children = append(children, enc_eimidtype...)
	}
	if v.CounterValue != nil {
		enc_countervalue := ber.EncodeBigInt(v.CounterValue)
		enc_countervalue = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_countervalue)
		children = append(children, enc_countervalue...)
	}
	if v.AssociationToken != nil {
		enc_associationtoken := ber.EncodeBigInt(v.AssociationToken)
		enc_associationtoken = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_associationtoken)
		children = append(children, enc_associationtoken...)
	}
	if v.EimPublicKeyData != nil {
		enc_eimpublickeydata, err := v.EimPublicKeyData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding eimPublicKeyData: %w", err)
		}
		enc_eimpublickeydata = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 5, enc_eimpublickeydata)
		children = append(children, enc_eimpublickeydata...)
	}
	if v.TrustedPublicKeyDataTls != nil {
		enc_trustedpublickeydatatls, err := v.TrustedPublicKeyDataTls.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding trustedPublicKeyDataTls: %w", err)
		}
		enc_trustedpublickeydatatls = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 6, enc_trustedpublickeydatatls)
		children = append(children, enc_trustedpublickeydatatls...)
	}
	if v.EimSupportedProtocol != nil {
		enc_eimsupportedprotocol := ber.EncodeBitString(v.EimSupportedProtocol.Bytes, (8-(v.EimSupportedProtocol.BitLength%8))%8)
		enc_eimsupportedprotocol = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_eimsupportedprotocol)
		children = append(children, enc_eimsupportedprotocol...)
	}
	if v.EuiccCiPKId != nil {
		enc_euicccipkid := ber.EncodeOctetString([]byte(*v.EuiccCiPKId))
		enc_euicccipkid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_euicccipkid)
		children = append(children, enc_euicccipkid...)
	}
	if v.IndirectProfileDownload != nil {
		enc_indirectprofiledownload := ber.EncodeNull()
		enc_indirectprofiledownload = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_indirectprofiledownload)
		children = append(children, enc_indirectprofiledownload...)
	}
	if v.ESipaProprietaryProtocolInformation != nil {
		enc_esipaproprietaryprotocolinformation, err := sgp22.MarshalBERVendorSpecificExtension(v.ESipaProprietaryProtocolInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding eSipaProprietaryProtocolInformation: %w", err)
		}
		if v.ESipaProprietaryProtocolInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_esipaproprietaryprotocolinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_esipaproprietaryprotocolinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 10}, seqContent_)
		} else {
			enc_esipaproprietaryprotocolinformation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_esipaproprietaryprotocolinformation)
		}
		children = append(children, enc_esipaproprietaryprotocolinformation...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EimConfigurationData to DER format.
func (v *EimConfigurationData) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ESipaProprietaryProtocolInformationIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes EimConfigurationData from BER/DER format.
func (v *EimConfigurationData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EimConfigurationData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EimConfigurationData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimId
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for eimId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_eimid, rawVal_eimid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimId: %w", err)
	}
	decVal_eimid := ber.DecodeStringValue(rawVal_eimid)
	v.EimId = decVal_eimid
	offset += n_eimid
	// Decode eimFqdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_eimfqdn, rawVal_eimfqdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimFqdn: %w", err)
				}
				decVal_eimfqdn := ber.DecodeStringValue(rawVal_eimfqdn)
				v.EimFqdn = &decVal_eimfqdn
				offset += n_eimfqdn
			}
		}
	}
	// Decode eimIdType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eimidtype, rawVal_eimidtype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimIdType: %w", err)
				}
				decVal_eimidtype, intErr := ber.DecodeIntegerValue(rawVal_eimidtype)
				if intErr != nil {
					return fmt.Errorf("decoding eimIdType: %w", intErr)
				}
				tmp_eimidtype := EimIdType(decVal_eimidtype)
				v.EimIdType = &tmp_eimidtype
				offset += n_eimidtype
			}
		}
	}
	// Decode counterValue
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_countervalue, rawVal_countervalue, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding counterValue: %w", err)
				}
				decVal_countervalue, intErr := ber.DecodeBigIntValue(rawVal_countervalue)
				if intErr != nil {
					return fmt.Errorf("decoding counterValue: %w", intErr)
				}
				v.CounterValue = decVal_countervalue
				offset += n_countervalue
			}
		}
	}
	// Decode associationToken
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_associationtoken, rawVal_associationtoken, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding associationToken: %w", err)
				}
				decVal_associationtoken, intErr := ber.DecodeBigIntValue(rawVal_associationtoken)
				if intErr != nil {
					return fmt.Errorf("decoding associationToken: %w", intErr)
				}
				v.AssociationToken = decVal_associationtoken
				offset += n_associationtoken
			}
		}
	}
	// Decode eimPublicKeyData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_eimpublickeydata, innerData_eimpublickeydata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimPublicKeyData: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_eimpublickeydata EimConfigurationDataEimPublicKeyData
				if unmErr := dec_eimpublickeydata.UnmarshalBER(innerData_eimpublickeydata); unmErr != nil {
					return fmt.Errorf("decoding eimPublicKeyData: %w", unmErr)
				}
				v.EimPublicKeyData = &dec_eimpublickeydata
				offset += n_eimpublickeydata
			}
		}
	}
	// Decode trustedPublicKeyDataTls
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_trustedpublickeydatatls, innerData_trustedpublickeydatatls, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding trustedPublicKeyDataTls: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_trustedpublickeydatatls EimConfigurationDataTrustedPublicKeyDataTls
				if unmErr := dec_trustedpublickeydatatls.UnmarshalBER(innerData_trustedpublickeydatatls); unmErr != nil {
					return fmt.Errorf("decoding trustedPublicKeyDataTls: %w", unmErr)
				}
				v.TrustedPublicKeyDataTls = &dec_trustedpublickeydatatls
				offset += n_trustedpublickeydatatls
			}
		}
	}
	// Decode eimSupportedProtocol
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_eimsupportedprotocol, rawVal_eimsupportedprotocol, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimSupportedProtocol: %w", err)
				}
				bsBytes_eimsupportedprotocol, bsUnused_eimsupportedprotocol, bsErr := ber.DecodeBitStringValue(rawVal_eimsupportedprotocol)
				if bsErr != nil {
					return fmt.Errorf("decoding eimSupportedProtocol: %w", bsErr)
				}
				tmp_eimsupportedprotocol := runtime.BitString{Bytes: bsBytes_eimsupportedprotocol, BitLength: len(bsBytes_eimsupportedprotocol)*8 - bsUnused_eimsupportedprotocol}
				v.EimSupportedProtocol = &tmp_eimsupportedprotocol
				offset += n_eimsupportedprotocol
			}
		}
	}
	// Decode euiccCiPKId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_euicccipkid, rawVal_euicccipkid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccCiPKId: %w", err)
				}
				tmp_euicccipkid := sgp22.SubjectKeyIdentifier(rawVal_euicccipkid)
				v.EuiccCiPKId = &tmp_euicccipkid
				offset += n_euicccipkid
			}
		}
	}
	// Decode indirectProfileDownload
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_indirectprofiledownload, rawVal_indirectprofiledownload, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding indirectProfileDownload: %w", err)
				}
				_ = rawVal_indirectprofiledownload
				v.IndirectProfileDownload = &struct{}{}
				offset += n_indirectprofiledownload
			}
		}
	}
	// Decode eSipaProprietaryProtocolInformation
	v.ESipaProprietaryProtocolInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				_, n_esipaproprietaryprotocolinformation, rawVal_esipaproprietaryprotocolinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eSipaProprietaryProtocolInformation: %w", err)
				}
				reconstructed_esipaproprietaryprotocolinformation := ber.EncodeSequence(rawVal_esipaproprietaryprotocolinformation)
				dec_esipaproprietaryprotocolinformation, unmErr := sgp22.UnmarshalBERVendorSpecificExtension(reconstructed_esipaproprietaryprotocolinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding eSipaProprietaryProtocolInformation: %w", unmErr)
				}
				v.ESipaProprietaryProtocolInformation = dec_esipaproprietaryprotocolinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ESipaProprietaryProtocolInformationIndef_ = true
					}
				}
				offset += n_esipaproprietaryprotocolinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EimConfigurationData", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Eco to BER format.
func (v *Eco) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EcoChoiceAddEim:
		if v.AddEim == nil {
			return nil, fmt.Errorf("choice Eco: addEim is nil")
		}
		enc_0, err := v.AddEim.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding addEim: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_0)
		return enc_0, nil
	case EcoChoiceDeleteEim:
		if v.DeleteEim == nil {
			return nil, fmt.Errorf("choice Eco: deleteEim is nil")
		}
		enc_1, err := v.DeleteEim.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding deleteEim: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_1)
		return enc_1, nil
	case EcoChoiceUpdateEim:
		if v.UpdateEim == nil {
			return nil, fmt.Errorf("choice Eco: updateEim is nil")
		}
		enc_2, err := v.UpdateEim.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding updateEim: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_2)
		return enc_2, nil
	case EcoChoiceListEim:
		if v.ListEim == nil {
			return nil, fmt.Errorf("choice Eco: listEim is nil")
		}
		enc_3, err := v.ListEim.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding listEim: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, true, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Eco", v.Choice)
	}
}

// MarshalDER encodes Eco to DER format.
func (v *Eco) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case EcoChoiceAddEim:
		if v.AddEim == nil {
			return nil, fmt.Errorf("choice Eco: addEim is nil")
		}
		enc_der_0, err := v.AddEim.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding addEim: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_der_0)
		return enc_der_0, nil
	case EcoChoiceDeleteEim:
		if v.DeleteEim == nil {
			return nil, fmt.Errorf("choice Eco: deleteEim is nil")
		}
		enc_der_1, err := v.DeleteEim.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding deleteEim: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_der_1)
		return enc_der_1, nil
	case EcoChoiceUpdateEim:
		if v.UpdateEim == nil {
			return nil, fmt.Errorf("choice Eco: updateEim is nil")
		}
		enc_der_2, err := v.UpdateEim.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding updateEim: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_der_2)
		return enc_der_2, nil
	case EcoChoiceListEim:
		if v.ListEim == nil {
			return nil, fmt.Errorf("choice Eco: listEim is nil")
		}
		enc_der_3, err := v.ListEim.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding listEim: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, true, enc_der_3)
		return enc_der_3, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes Eco from BER/DER format.
func (v *Eco) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Eco CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Eco: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Eco CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Eco", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
		v.Choice = EcoChoiceAddEim
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding addEim: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec EimConfigurationData
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding addEim: %w", unmErr)
		}
		v.AddEim = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
		v.Choice = EcoChoiceDeleteEim
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding deleteEim: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec EcoDeleteEim
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding deleteEim: %w", unmErr)
		}
		v.DeleteEim = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
		v.Choice = EcoChoiceUpdateEim
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding updateEim: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec EimConfigurationData
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding updateEim: %w", unmErr)
		}
		v.UpdateEim = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
		v.Choice = EcoChoiceListEim
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding listEim: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec EcoListEim
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding listEim: %w", unmErr)
		}
		v.ListEim = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Eco CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Psmo to BER format.
func (v *Psmo) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case PsmoChoiceEnable:
		if v.Enable == nil {
			return nil, fmt.Errorf("choice Psmo: enable is nil")
		}
		enc_0, err := v.Enable.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding enable: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_0)
		return enc_0, nil
	case PsmoChoiceDisable:
		if v.Disable == nil {
			return nil, fmt.Errorf("choice Psmo: disable is nil")
		}
		enc_1, err := v.Disable.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding disable: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_1)
		return enc_1, nil
	case PsmoChoiceDelete:
		if v.Delete == nil {
			return nil, fmt.Errorf("choice Psmo: delete is nil")
		}
		enc_2, err := v.Delete.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding delete: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_2)
		return enc_2, nil
	case PsmoChoiceListProfileInfo:
		if v.ListProfileInfo == nil {
			return nil, fmt.Errorf("choice Psmo: listProfileInfo is nil")
		}
		enc_3, err := v.ListProfileInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding listProfileInfo: %w", err)
		}
		return enc_3, nil
	case PsmoChoiceGetRAT:
		if v.GetRAT == nil {
			return nil, fmt.Errorf("choice Psmo: getRAT is nil")
		}
		enc_4, err := v.GetRAT.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding getRAT: %w", err)
		}
		enc_4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_4)
		return enc_4, nil
	case PsmoChoiceConfigureImmediateEnable:
		if v.ConfigureImmediateEnable == nil {
			return nil, fmt.Errorf("choice Psmo: configureImmediateEnable is nil")
		}
		enc_5, err := v.ConfigureImmediateEnable.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding configureImmediateEnable: %w", err)
		}
		enc_5 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_5)
		return enc_5, nil
	case PsmoChoiceSetFallbackAttribute:
		if v.SetFallbackAttribute == nil {
			return nil, fmt.Errorf("choice Psmo: setFallbackAttribute is nil")
		}
		enc_6, err := v.SetFallbackAttribute.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding setFallbackAttribute: %w", err)
		}
		enc_6 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_6)
		return enc_6, nil
	case PsmoChoiceUnsetFallbackAttribute:
		if v.UnsetFallbackAttribute == nil {
			return nil, fmt.Errorf("choice Psmo: unsetFallbackAttribute is nil")
		}
		enc_7, err := v.UnsetFallbackAttribute.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding unsetFallbackAttribute: %w", err)
		}
		enc_7 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_7)
		return enc_7, nil
	case PsmoChoiceSetDefaultDpAddress:
		if v.SetDefaultDpAddress == nil {
			return nil, fmt.Errorf("choice Psmo: setDefaultDpAddress is nil")
		}
		enc_8, err := v.SetDefaultDpAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding setDefaultDpAddress: %w", err)
		}
		return enc_8, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Psmo", v.Choice)
	}
}

// MarshalDER encodes Psmo to DER format.
func (v *Psmo) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case PsmoChoiceEnable:
		if v.Enable == nil {
			return nil, fmt.Errorf("choice Psmo: enable is nil")
		}
		enc_der_0, err := v.Enable.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding enable: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_der_0)
		return enc_der_0, nil
	case PsmoChoiceDisable:
		if v.Disable == nil {
			return nil, fmt.Errorf("choice Psmo: disable is nil")
		}
		enc_der_1, err := v.Disable.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding disable: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_der_1)
		return enc_der_1, nil
	case PsmoChoiceDelete:
		if v.Delete == nil {
			return nil, fmt.Errorf("choice Psmo: delete is nil")
		}
		enc_der_2, err := v.Delete.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding delete: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_der_2)
		return enc_der_2, nil
	case PsmoChoiceListProfileInfo:
		if v.ListProfileInfo == nil {
			return nil, fmt.Errorf("choice Psmo: listProfileInfo is nil")
		}
		enc_der_3, err := v.ListProfileInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding listProfileInfo: %w", err)
		}
		return enc_der_3, nil
	case PsmoChoiceGetRAT:
		if v.GetRAT == nil {
			return nil, fmt.Errorf("choice Psmo: getRAT is nil")
		}
		enc_der_4, err := v.GetRAT.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding getRAT: %w", err)
		}
		enc_der_4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_der_4)
		return enc_der_4, nil
	case PsmoChoiceConfigureImmediateEnable:
		if v.ConfigureImmediateEnable == nil {
			return nil, fmt.Errorf("choice Psmo: configureImmediateEnable is nil")
		}
		enc_der_5, err := v.ConfigureImmediateEnable.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding configureImmediateEnable: %w", err)
		}
		enc_der_5 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_der_5)
		return enc_der_5, nil
	case PsmoChoiceSetFallbackAttribute:
		if v.SetFallbackAttribute == nil {
			return nil, fmt.Errorf("choice Psmo: setFallbackAttribute is nil")
		}
		enc_der_6, err := v.SetFallbackAttribute.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding setFallbackAttribute: %w", err)
		}
		enc_der_6 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_der_6)
		return enc_der_6, nil
	case PsmoChoiceUnsetFallbackAttribute:
		if v.UnsetFallbackAttribute == nil {
			return nil, fmt.Errorf("choice Psmo: unsetFallbackAttribute is nil")
		}
		enc_der_7, err := v.UnsetFallbackAttribute.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding unsetFallbackAttribute: %w", err)
		}
		enc_der_7 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_der_7)
		return enc_der_7, nil
	case PsmoChoiceSetDefaultDpAddress:
		if v.SetDefaultDpAddress == nil {
			return nil, fmt.Errorf("choice Psmo: setDefaultDpAddress is nil")
		}
		enc_der_8, err := v.SetDefaultDpAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding setDefaultDpAddress: %w", err)
		}
		return enc_der_8, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes Psmo from BER/DER format.
func (v *Psmo) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Psmo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Psmo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Psmo CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Psmo", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = PsmoChoiceEnable
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding enable: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec PsmoEnable
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding enable: %w", unmErr)
		}
		v.Enable = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = PsmoChoiceDisable
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding disable: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec PsmoDisable
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding disable: %w", unmErr)
		}
		v.Disable = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
		v.Choice = PsmoChoiceDelete
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding delete: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec PsmoDelete
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding delete: %w", unmErr)
		}
		v.Delete = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 45 {
		v.Choice = PsmoChoiceListProfileInfo
		var dec sgp22.ProfileInfoListRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding listProfileInfo: %w", unmErr)
		}
		v.ListProfileInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
		v.Choice = PsmoChoiceGetRAT
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding getRAT: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec PsmoGetRAT
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding getRAT: %w", unmErr)
		}
		v.GetRAT = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
		v.Choice = PsmoChoiceConfigureImmediateEnable
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding configureImmediateEnable: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec PsmoConfigureImmediateEnable
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding configureImmediateEnable: %w", unmErr)
		}
		v.ConfigureImmediateEnable = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
		v.Choice = PsmoChoiceSetFallbackAttribute
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding setFallbackAttribute: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec PsmoSetFallbackAttribute
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding setFallbackAttribute: %w", unmErr)
		}
		v.SetFallbackAttribute = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
		v.Choice = PsmoChoiceUnsetFallbackAttribute
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding unsetFallbackAttribute: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec PsmoUnsetFallbackAttribute
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding unsetFallbackAttribute: %w", unmErr)
		}
		v.UnsetFallbackAttribute = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 101 {
		v.Choice = PsmoChoiceSetDefaultDpAddress
		var dec SetDefaultDpAddressRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding setDefaultDpAddress: %w", unmErr)
		}
		v.SetDefaultDpAddress = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Psmo CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes IpaEuiccDataRequest to BER format.
func (v *IpaEuiccDataRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_taglist := ber.EncodeOctetString(v.TagList)
	enc_taglist = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 28, false, enc_taglist)
	children = append(children, enc_taglist...)
	if v.EuiccCiPKIdentifierToBeUsed != nil {
		enc_euicccipkidentifiertobeused := ber.EncodeOctetString(v.EuiccCiPKIdentifierToBeUsed)
		children = append(children, enc_euicccipkidentifiertobeused...)
	}
	if v.SearchCriteriaNotification != nil {
		enc_searchcriterianotification, err := v.SearchCriteriaNotification.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding searchCriteriaNotification: %w", err)
		}
		enc_searchcriterianotification = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_searchcriterianotification)
		children = append(children, enc_searchcriterianotification...)
	}
	if v.SearchCriteriaEuiccPackageResult != nil {
		enc_searchcriteriaeuiccpackageresult, err := v.SearchCriteriaEuiccPackageResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding searchCriteriaEuiccPackageResult: %w", err)
		}
		enc_searchcriteriaeuiccpackageresult = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_searchcriteriaeuiccpackageresult)
		children = append(children, enc_searchcriteriaeuiccpackageresult...)
	}
	if v.EimTransactionId != nil {
		enc_eimtransactionid := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_eimtransactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_eimtransactionid)
		children = append(children, enc_eimtransactionid...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 82, Constructed: true}, children), nil
}

// MarshalDER encodes IpaEuiccDataRequest to DER format.
func (v *IpaEuiccDataRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IpaEuiccDataRequest from BER/DER format.
func (v *IpaEuiccDataRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding IpaEuiccDataRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 82 || !decodedTag.Constructed {
		return fmt.Errorf("decoding IpaEuiccDataRequest: %w: expected tag [CONTEXT 82], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IpaEuiccDataRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode tagList
	if offset >= len(content) {
		return fmt.Errorf("missing required field tagList")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 28 {
			return fmt.Errorf("expected tag [%s %d] for tagList, got %s", "APPLICATION", 28, reqTag_)
		}
	}
	_, n_taglist, rawVal_taglist, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding tagList: %w", err)
	}
	v.TagList = rawVal_taglist
	offset += n_taglist
	// Decode euiccCiPKIdentifierToBeUsed
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_euicccipkidentifiertobeused, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccCiPKIdentifierToBeUsed: %w", err)
				}
				tmp_euicccipkidentifiertobeused := val_euicccipkidentifiertobeused
				v.EuiccCiPKIdentifierToBeUsed = tmp_euicccipkidentifiertobeused
				offset += n
			}
		}
	}
	// Decode searchCriteriaNotification
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_searchcriterianotification, innerData_searchcriterianotification, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding searchCriteriaNotification: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_searchcriterianotification IpaEuiccDataRequestSearchCriteriaNotification
				if unmErr := dec_searchcriterianotification.UnmarshalBER(innerData_searchcriterianotification); unmErr != nil {
					return fmt.Errorf("decoding searchCriteriaNotification: %w", unmErr)
				}
				v.SearchCriteriaNotification = &dec_searchcriterianotification
				offset += n_searchcriterianotification
			}
		}
	}
	// Decode searchCriteriaEuiccPackageResult
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_searchcriteriaeuiccpackageresult, innerData_searchcriteriaeuiccpackageresult, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding searchCriteriaEuiccPackageResult: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_searchcriteriaeuiccpackageresult IpaEuiccDataRequestSearchCriteriaEuiccPackageResult
				if unmErr := dec_searchcriteriaeuiccpackageresult.UnmarshalBER(innerData_searchcriteriaeuiccpackageresult); unmErr != nil {
					return fmt.Errorf("decoding searchCriteriaEuiccPackageResult: %w", unmErr)
				}
				v.SearchCriteriaEuiccPackageResult = &dec_searchcriteriaeuiccpackageresult
				offset += n_searchcriteriaeuiccpackageresult
			}
		}
	}
	// Decode eimTransactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_eimtransactionid, rawVal_eimtransactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimTransactionId: %w", err)
				}
				tmp_eimtransactionid := sgp22.TransactionId(rawVal_eimtransactionid)
				v.EimTransactionId = &tmp_eimtransactionid
				offset += n_eimtransactionid
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "IpaEuiccDataRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ProfileDownloadTriggerRequest to BER format.
func (v *ProfileDownloadTriggerRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ProfileDownloadData != nil {
		enc_profiledownloaddata, err := v.ProfileDownloadData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileDownloadData: %w", err)
		}
		enc_profiledownloaddata = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_profiledownloaddata)
		children = append(children, enc_profiledownloaddata...)
	}
	if v.EimTransactionId != nil {
		enc_eimtransactionid := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_eimtransactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_eimtransactionid)
		children = append(children, enc_eimtransactionid...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 84, Constructed: true}, children), nil
}

// MarshalDER encodes ProfileDownloadTriggerRequest to DER format.
func (v *ProfileDownloadTriggerRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileDownloadTriggerRequest from BER/DER format.
func (v *ProfileDownloadTriggerRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileDownloadTriggerRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 84 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileDownloadTriggerRequest: %w: expected tag [CONTEXT 84], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileDownloadTriggerRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode profileDownloadData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_profiledownloaddata, innerData_profiledownloaddata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileDownloadData: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_profiledownloaddata ProfileDownloadData
				if unmErr := dec_profiledownloaddata.UnmarshalBER(innerData_profiledownloaddata); unmErr != nil {
					return fmt.Errorf("decoding profileDownloadData: %w", unmErr)
				}
				v.ProfileDownloadData = &dec_profiledownloaddata
				offset += n_profiledownloaddata
			}
		}
	}
	// Decode eimTransactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eimtransactionid, rawVal_eimtransactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimTransactionId: %w", err)
				}
				tmp_eimtransactionid := sgp22.TransactionId(rawVal_eimtransactionid)
				v.EimTransactionId = &tmp_eimtransactionid
				offset += n_eimtransactionid
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProfileDownloadTriggerRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ProfileDownloadData to BER format.
func (v *ProfileDownloadData) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ProfileDownloadDataChoiceActivationCode:
		if v.ActivationCode == nil {
			return nil, fmt.Errorf("choice ProfileDownloadData: activationCode is nil")
		}
		enc_0 := ber.EncodeStringTag(12, *v.ActivationCode)
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case ProfileDownloadDataChoiceContactDefaultSmdp:
		enc_1 := ber.EncodeNull()
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	case ProfileDownloadDataChoiceContactSmds:
		if v.ContactSmds == nil {
			return nil, fmt.Errorf("choice ProfileDownloadData: contactSmds is nil")
		}
		enc_2, err := v.ContactSmds.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding contactSmds: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ProfileDownloadData", v.Choice)
	}
}

// MarshalDER encodes ProfileDownloadData to DER format.
func (v *ProfileDownloadData) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ProfileDownloadDataChoiceContactSmds:
		if v.ContactSmds == nil {
			return nil, fmt.Errorf("choice ProfileDownloadData: contactSmds is nil")
		}
		enc_der_2, err := v.ContactSmds.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding contactSmds: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_der_2)
		return enc_der_2, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileDownloadData from BER/DER format.
func (v *ProfileDownloadData) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ProfileDownloadData CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ProfileDownloadData: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ProfileDownloadData CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileDownloadData", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = ProfileDownloadDataChoiceActivationCode
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding activationCode: %w", tlvErr)
		}
		decVal := ber.DecodeStringValue(rawVal)
		v.ActivationCode = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = ProfileDownloadDataChoiceContactDefaultSmdp
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding contactDefaultSmdp: %w", tlvErr)
		}
		_ = rawVal // NULL has no content
		v.ContactDefaultSmdp = &struct{}{}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ProfileDownloadDataChoiceContactSmds
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding contactSmds: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ProfileDownloadDataContactSmds
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding contactSmds: %w", unmErr)
		}
		v.ContactSmds = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ProfileDownloadData CHOICE", peekTag)
	}
	return nil
}

// MarshalBEREimAcknowledgements encodes a EimAcknowledgements list to BER.
func MarshalBEREimAcknowledgements(list EimAcknowledgements) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeBigInt(elem)...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 83, Constructed: true}, children), nil
}

// UnmarshalBEREimAcknowledgements decodes a EimAcknowledgements list from BER.
func UnmarshalBEREimAcknowledgements(data []byte) (EimAcknowledgements, error) {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EimAcknowledgements: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 83 || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding EimAcknowledgements: %w: expected tag [CONTEXT 83], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EimAcknowledgements", Cause: ber.ErrExtraData}
	}
	var result EimAcknowledgements
	offset := 0
	for offset < len(content) {
		val, n, intErr := ber.DecodeBigInt(content[offset:])
		if intErr != nil {
			return nil, fmt.Errorf("decoding element: %w", intErr)
		}
		result = append(result, SequenceNumber(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes EuiccPackageResult to BER format.
func (v *EuiccPackageResult) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EuiccPackageResultChoiceEuiccPackageResultSigned:
		if v.EuiccPackageResultSigned == nil {
			return nil, fmt.Errorf("choice EuiccPackageResult: euiccPackageResultSigned is nil")
		}
		enc_0, err := v.EuiccPackageResultSigned.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageResultSigned: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 81, enc_0)
		return enc_0, nil
	case EuiccPackageResultChoiceEuiccPackageErrorSigned:
		if v.EuiccPackageErrorSigned == nil {
			return nil, fmt.Errorf("choice EuiccPackageResult: euiccPackageErrorSigned is nil")
		}
		enc_1, err := v.EuiccPackageErrorSigned.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageErrorSigned: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 81, enc_1)
		return enc_1, nil
	case EuiccPackageResultChoiceEuiccPackageErrorUnsigned:
		if v.EuiccPackageErrorUnsigned == nil {
			return nil, fmt.Errorf("choice EuiccPackageResult: euiccPackageErrorUnsigned is nil")
		}
		enc_2, err := v.EuiccPackageErrorUnsigned.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageErrorUnsigned: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_2)
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 81, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EuiccPackageResult", v.Choice)
	}
}

// MarshalDER encodes EuiccPackageResult to DER format.
func (v *EuiccPackageResult) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case EuiccPackageResultChoiceEuiccPackageResultSigned:
		if v.EuiccPackageResultSigned == nil {
			return nil, fmt.Errorf("choice EuiccPackageResult: euiccPackageResultSigned is nil")
		}
		enc_der_0, err := v.EuiccPackageResultSigned.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageResultSigned: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 81, enc_der_0)
		return enc_der_0, nil
	case EuiccPackageResultChoiceEuiccPackageErrorSigned:
		if v.EuiccPackageErrorSigned == nil {
			return nil, fmt.Errorf("choice EuiccPackageResult: euiccPackageErrorSigned is nil")
		}
		enc_der_1, err := v.EuiccPackageErrorSigned.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageErrorSigned: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 81, enc_der_1)
		return enc_der_1, nil
	case EuiccPackageResultChoiceEuiccPackageErrorUnsigned:
		if v.EuiccPackageErrorUnsigned == nil {
			return nil, fmt.Errorf("choice EuiccPackageResult: euiccPackageErrorUnsigned is nil")
		}
		enc_der_2, err := v.EuiccPackageErrorUnsigned.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageErrorUnsigned: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_der_2)
		enc_der_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 81, enc_der_2)
		return enc_der_2, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccPackageResult from BER/DER format.
func (v *EuiccPackageResult) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for EuiccPackageResult CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccPackageResult CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 81 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EuiccPackageResult CHOICE: %w: expected tag [CONTEXT 81], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccPackageResult", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for EuiccPackageResult CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EuiccPackageResult: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding EuiccPackageResult CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccPackageResult", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = EuiccPackageResultChoiceEuiccPackageResultSigned
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding euiccPackageResultSigned: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec EuiccPackageResultSigned
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding euiccPackageResultSigned: %w", unmErr)
		}
		v.EuiccPackageResultSigned = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = EuiccPackageResultChoiceEuiccPackageErrorSigned
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding euiccPackageErrorSigned: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec EuiccPackageErrorSigned
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding euiccPackageErrorSigned: %w", unmErr)
		}
		v.EuiccPackageErrorSigned = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = EuiccPackageResultChoiceEuiccPackageErrorUnsigned
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding euiccPackageErrorUnsigned: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec EuiccPackageErrorUnsigned
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding euiccPackageErrorUnsigned: %w", unmErr)
		}
		v.EuiccPackageErrorUnsigned = &dec
	} else {
		return fmt.Errorf("unknown tag %s for EuiccPackageResult CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EuiccPackageResultSigned to BER format.
func (v *EuiccPackageResultSigned) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccpackageresultdatasigned, err := v.EuiccPackageResultDataSigned.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccPackageResultDataSigned: %w", err)
	}
	children = append(children, enc_euiccpackageresultdatasigned...)
	enc_euiccsignepr := ber.EncodeOctetString(v.EuiccSignEPR)
	enc_euiccsignepr = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccsignepr)
	children = append(children, enc_euiccsignepr...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EuiccPackageResultSigned to DER format.
func (v *EuiccPackageResultSigned) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccPackageResultSigned from BER/DER format.
func (v *EuiccPackageResultSigned) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccPackageResultSigned SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccPackageResultSigned", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccPackageResultDataSigned
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccPackageResultDataSigned")
	}
	// Decode nested SEQUENCE (EuiccPackageResultDataSigned)
	_, n_euiccpackageresultdatasigned, _, tlvErr_euiccpackageresultdatasigned := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccpackageresultdatasigned != nil {
		return fmt.Errorf("decoding euiccPackageResultDataSigned: %w", tlvErr_euiccpackageresultdatasigned)
	}
	if unmErr := v.EuiccPackageResultDataSigned.UnmarshalBER(content[offset : offset+n_euiccpackageresultdatasigned]); unmErr != nil {
		return fmt.Errorf("decoding euiccPackageResultDataSigned: %w", unmErr)
	}
	offset += n_euiccpackageresultdatasigned
	// Decode euiccSignEPR
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSignEPR")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccSignEPR, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccsignepr, rawVal_euiccsignepr, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccSignEPR: %w", err)
	}
	v.EuiccSignEPR = rawVal_euiccsignepr
	offset += n_euiccsignepr
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EuiccPackageResultSigned", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EuiccPackageResultDataSigned to BER format.
func (v *EuiccPackageResultDataSigned) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eimid := ber.EncodeStringTag(12, v.EimId)
	enc_eimid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_eimid)
	children = append(children, enc_eimid...)
	if v.CounterValue == nil {
		return nil, fmt.Errorf("encoding counterValue: required INTEGER is nil")
	}
	enc_countervalue := ber.EncodeBigInt(v.CounterValue)
	enc_countervalue = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_countervalue)
	children = append(children, enc_countervalue...)
	if v.EimTransactionId != nil {
		enc_eimtransactionid := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_eimtransactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_eimtransactionid)
		children = append(children, enc_eimtransactionid...)
	}
	if v.SeqNumber == nil {
		return nil, fmt.Errorf("encoding seqNumber: required INTEGER is nil")
	}
	enc_seqnumber := ber.EncodeBigInt(v.SeqNumber)
	enc_seqnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_seqnumber)
	children = append(children, enc_seqnumber...)
	enc_euiccresult, err := MarshalBEREuiccPackageResultDataSignedEuiccResult(v.EuiccResult)
	if err != nil {
		return nil, fmt.Errorf("encoding euiccResult: %w", err)
	}
	children = append(children, enc_euiccresult...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EuiccPackageResultDataSigned to DER format.
func (v *EuiccPackageResultDataSigned) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.EuiccResultIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccPackageResultDataSigned from BER/DER format.
func (v *EuiccPackageResultDataSigned) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccPackageResultDataSigned SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccPackageResultDataSigned", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimId
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for eimId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_eimid, rawVal_eimid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimId: %w", err)
	}
	decVal_eimid := ber.DecodeStringValue(rawVal_eimid)
	v.EimId = decVal_eimid
	offset += n_eimid
	// Decode counterValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field counterValue")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for counterValue, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_countervalue, rawVal_countervalue, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding counterValue: %w", err)
	}
	decVal_countervalue, intErr := ber.DecodeBigIntValue(rawVal_countervalue)
	if intErr != nil {
		return fmt.Errorf("decoding counterValue: %w", intErr)
	}
	v.CounterValue = decVal_countervalue
	offset += n_countervalue
	// Decode eimTransactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eimtransactionid, rawVal_eimtransactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimTransactionId: %w", err)
				}
				tmp_eimtransactionid := sgp22.TransactionId(rawVal_eimtransactionid)
				v.EimTransactionId = &tmp_eimtransactionid
				offset += n_eimtransactionid
			}
		}
	}
	// Decode seqNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field seqNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for seqNumber, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_seqnumber, rawVal_seqnumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding seqNumber: %w", err)
	}
	decVal_seqnumber, intErr := ber.DecodeBigIntValue(rawVal_seqnumber)
	if intErr != nil {
		return fmt.Errorf("decoding seqNumber: %w", intErr)
	}
	v.SeqNumber = decVal_seqnumber
	offset += n_seqnumber
	// Decode euiccResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccResult")
	}
	v.EuiccResultIndef_ = false
	// Decode nested SEQUENCE_OF (EuiccPackageResultDataSignedEuiccResult)
	_, n_euiccresult, _, tlvErr_euiccresult := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccresult != nil {
		return fmt.Errorf("decoding euiccResult: %w", tlvErr_euiccresult)
	}
	tlv_euiccresult := content[offset : offset+n_euiccresult]
	{
		_, tagSz_, _ := ber.DecodeTag(tlv_euiccresult)
		if tagSz_ < len(tlv_euiccresult) && tlv_euiccresult[tagSz_] == 0x80 {
			v.EuiccResultIndef_ = true
		}
	}
	dec_euiccresult, unmErr := UnmarshalBEREuiccPackageResultDataSignedEuiccResult(tlv_euiccresult)
	if unmErr != nil {
		return fmt.Errorf("decoding euiccResult: %w", unmErr)
	}
	v.EuiccResult = dec_euiccresult
	offset += n_euiccresult
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EuiccPackageResultDataSigned", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EuiccResultData to BER format.
func (v *EuiccResultData) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EuiccResultDataChoiceEnableResult:
		if v.EnableResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: enableResult is nil")
		}
		enc_0 := ber.EncodeInteger(int64(*v.EnableResult))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_0)
		return enc_0, nil
	case EuiccResultDataChoiceDisableResult:
		if v.DisableResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: disableResult is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.DisableResult))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_1)
		return enc_1, nil
	case EuiccResultDataChoiceDeleteResult:
		if v.DeleteResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: deleteResult is nil")
		}
		enc_2 := ber.EncodeInteger(int64(*v.DeleteResult))
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_2)
		return enc_2, nil
	case EuiccResultDataChoiceListProfileInfoResult:
		if v.ListProfileInfoResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: listProfileInfoResult is nil")
		}
		enc_3, err := v.ListProfileInfoResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding listProfileInfoResult: %w", err)
		}
		return enc_3, nil
	case EuiccResultDataChoiceGetRATResult:
		if v.GetRATResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: getRATResult is nil")
		}
		enc_4, err := sgp22.MarshalBERRulesAuthorisationTable(v.GetRATResult)
		if err != nil {
			return nil, fmt.Errorf("encoding getRATResult: %w", err)
		}
		enc_4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_4)
		return enc_4, nil
	case EuiccResultDataChoiceConfigureImmediateEnableResult:
		if v.ConfigureImmediateEnableResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: configureImmediateEnableResult is nil")
		}
		enc_5 := ber.EncodeInteger(int64(*v.ConfigureImmediateEnableResult))
		enc_5 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_5)
		return enc_5, nil
	case EuiccResultDataChoiceAddEimResult:
		if v.AddEimResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: addEimResult is nil")
		}
		enc_6, err := v.AddEimResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding addEimResult: %w", err)
		}
		enc_6 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 8, enc_6)
		return enc_6, nil
	case EuiccResultDataChoiceDeleteEimResult:
		if v.DeleteEimResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: deleteEimResult is nil")
		}
		enc_7 := ber.EncodeInteger(int64(*v.DeleteEimResult))
		enc_7 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_7)
		return enc_7, nil
	case EuiccResultDataChoiceUpdateEimResult:
		if v.UpdateEimResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: updateEimResult is nil")
		}
		enc_8 := ber.EncodeInteger(int64(*v.UpdateEimResult))
		enc_8 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_8)
		return enc_8, nil
	case EuiccResultDataChoiceListEimResult:
		if v.ListEimResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: listEimResult is nil")
		}
		enc_9, err := v.ListEimResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding listEimResult: %w", err)
		}
		enc_9 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 11, enc_9)
		return enc_9, nil
	case EuiccResultDataChoiceRollbackResult:
		if v.RollbackResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: rollbackResult is nil")
		}
		enc_10 := ber.EncodeInteger(int64(*v.RollbackResult))
		enc_10 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, false, enc_10)
		return enc_10, nil
	case EuiccResultDataChoiceSetFallbackAttributeResult:
		if v.SetFallbackAttributeResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: setFallbackAttributeResult is nil")
		}
		enc_11 := ber.EncodeInteger(int64(*v.SetFallbackAttributeResult))
		enc_11 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, false, enc_11)
		return enc_11, nil
	case EuiccResultDataChoiceUnsetFallbackAttributeResult:
		if v.UnsetFallbackAttributeResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: unsetFallbackAttributeResult is nil")
		}
		enc_12 := ber.EncodeInteger(int64(*v.UnsetFallbackAttributeResult))
		enc_12 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, false, enc_12)
		return enc_12, nil
	case EuiccResultDataChoiceProcessingTerminated:
		if v.ProcessingTerminated == nil {
			return nil, fmt.Errorf("choice EuiccResultData: processingTerminated is nil")
		}
		enc_13 := ber.EncodeInteger(int64(*v.ProcessingTerminated))
		return enc_13, nil
	case EuiccResultDataChoiceSetDefaultDpAddressResult:
		if v.SetDefaultDpAddressResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: setDefaultDpAddressResult is nil")
		}
		enc_14, err := v.SetDefaultDpAddressResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding setDefaultDpAddressResult: %w", err)
		}
		return enc_14, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EuiccResultData", v.Choice)
	}
}

// MarshalDER encodes EuiccResultData to DER format.
func (v *EuiccResultData) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case EuiccResultDataChoiceListProfileInfoResult:
		if v.ListProfileInfoResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: listProfileInfoResult is nil")
		}
		enc_der_3, err := v.ListProfileInfoResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding listProfileInfoResult: %w", err)
		}
		return enc_der_3, nil
	case EuiccResultDataChoiceAddEimResult:
		if v.AddEimResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: addEimResult is nil")
		}
		enc_der_6, err := v.AddEimResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding addEimResult: %w", err)
		}
		enc_der_6 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 8, enc_der_6)
		return enc_der_6, nil
	case EuiccResultDataChoiceListEimResult:
		if v.ListEimResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: listEimResult is nil")
		}
		enc_der_9, err := v.ListEimResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding listEimResult: %w", err)
		}
		enc_der_9 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 11, enc_der_9)
		return enc_der_9, nil
	case EuiccResultDataChoiceSetDefaultDpAddressResult:
		if v.SetDefaultDpAddressResult == nil {
			return nil, fmt.Errorf("choice EuiccResultData: setDefaultDpAddressResult is nil")
		}
		enc_der_14, err := v.SetDefaultDpAddressResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding setDefaultDpAddressResult: %w", err)
		}
		return enc_der_14, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccResultData from BER/DER format.
func (v *EuiccResultData) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for EuiccResultData CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EuiccResultData: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding EuiccResultData CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccResultData", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = EuiccResultDataChoiceEnableResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding enableResult: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding enableResult: %w", intErr)
		}
		tmp := EnableProfileResult(decVal)
		v.EnableResult = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = EuiccResultDataChoiceDisableResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding disableResult: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding disableResult: %w", intErr)
		}
		tmp := DisableProfileResult(decVal)
		v.DisableResult = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
		v.Choice = EuiccResultDataChoiceDeleteResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding deleteResult: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding deleteResult: %w", intErr)
		}
		tmp := DeleteProfileResult(decVal)
		v.DeleteResult = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 45 {
		v.Choice = EuiccResultDataChoiceListProfileInfoResult
		var dec ProfileInfoListResponse
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding listProfileInfoResult: %w", unmErr)
		}
		v.ListProfileInfoResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
		v.Choice = EuiccResultDataChoiceGetRATResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding getRATResult: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := sgp22.UnmarshalBERRulesAuthorisationTable(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding getRATResult: %w", unmErr)
		}
		v.GetRATResult = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
		v.Choice = EuiccResultDataChoiceConfigureImmediateEnableResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding configureImmediateEnableResult: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding configureImmediateEnableResult: %w", intErr)
		}
		tmp := ConfigureImmediateEnableResult(decVal)
		v.ConfigureImmediateEnableResult = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
		v.Choice = EuiccResultDataChoiceAddEimResult
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding addEimResult: %w", tlvErr)
		}
		var dec AddEimResult
		if unmErr := dec.UnmarshalBER(innerData); unmErr != nil {
			return fmt.Errorf("decoding addEimResult: %w", unmErr)
		}
		v.AddEimResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
		v.Choice = EuiccResultDataChoiceDeleteEimResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding deleteEimResult: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding deleteEimResult: %w", intErr)
		}
		tmp := DeleteEimResult(decVal)
		v.DeleteEimResult = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
		v.Choice = EuiccResultDataChoiceUpdateEimResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding updateEimResult: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding updateEimResult: %w", intErr)
		}
		tmp := UpdateEimResult(decVal)
		v.UpdateEimResult = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
		v.Choice = EuiccResultDataChoiceListEimResult
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding listEimResult: %w", tlvErr)
		}
		var dec ListEimResult
		if unmErr := dec.UnmarshalBER(innerData); unmErr != nil {
			return fmt.Errorf("decoding listEimResult: %w", unmErr)
		}
		v.ListEimResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
		v.Choice = EuiccResultDataChoiceRollbackResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding rollbackResult: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding rollbackResult: %w", intErr)
		}
		tmp := RollbackProfileResult(decVal)
		v.RollbackResult = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
		v.Choice = EuiccResultDataChoiceSetFallbackAttributeResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding setFallbackAttributeResult: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding setFallbackAttributeResult: %w", intErr)
		}
		tmp := SetFallbackAttributeResult(decVal)
		v.SetFallbackAttributeResult = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
		v.Choice = EuiccResultDataChoiceUnsetFallbackAttributeResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding unsetFallbackAttributeResult: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding unsetFallbackAttributeResult: %w", intErr)
		}
		tmp := UnsetFallbackAttributeResult(decVal)
		v.UnsetFallbackAttributeResult = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = EuiccResultDataChoiceProcessingTerminated
		decVal, _, intErr := ber.DecodeInteger(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding processingTerminated: %w", intErr)
		}
		v.ProcessingTerminated = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 101 {
		v.Choice = EuiccResultDataChoiceSetDefaultDpAddressResult
		var dec SetDefaultDpAddressResponse
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding setDefaultDpAddressResult: %w", unmErr)
		}
		v.SetDefaultDpAddressResult = &dec
	} else {
		return fmt.Errorf("unknown tag %s for EuiccResultData CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EuiccPackageErrorSigned to BER format.
func (v *EuiccPackageErrorSigned) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccpackageerrordatasigned, err := v.EuiccPackageErrorDataSigned.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccPackageErrorDataSigned: %w", err)
	}
	children = append(children, enc_euiccpackageerrordatasigned...)
	enc_euiccsignepe := ber.EncodeOctetString(v.EuiccSignEPE)
	enc_euiccsignepe = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccsignepe)
	children = append(children, enc_euiccsignepe...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EuiccPackageErrorSigned to DER format.
func (v *EuiccPackageErrorSigned) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccPackageErrorSigned from BER/DER format.
func (v *EuiccPackageErrorSigned) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccPackageErrorSigned SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccPackageErrorSigned", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccPackageErrorDataSigned
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccPackageErrorDataSigned")
	}
	// Decode nested SEQUENCE (EuiccPackageErrorDataSigned)
	_, n_euiccpackageerrordatasigned, _, tlvErr_euiccpackageerrordatasigned := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccpackageerrordatasigned != nil {
		return fmt.Errorf("decoding euiccPackageErrorDataSigned: %w", tlvErr_euiccpackageerrordatasigned)
	}
	if unmErr := v.EuiccPackageErrorDataSigned.UnmarshalBER(content[offset : offset+n_euiccpackageerrordatasigned]); unmErr != nil {
		return fmt.Errorf("decoding euiccPackageErrorDataSigned: %w", unmErr)
	}
	offset += n_euiccpackageerrordatasigned
	// Decode euiccSignEPE
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSignEPE")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccSignEPE, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccsignepe, rawVal_euiccsignepe, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccSignEPE: %w", err)
	}
	v.EuiccSignEPE = rawVal_euiccsignepe
	offset += n_euiccsignepe
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EuiccPackageErrorSigned", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EuiccPackageErrorDataSigned to BER format.
func (v *EuiccPackageErrorDataSigned) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eimid := ber.EncodeStringTag(12, v.EimId)
	enc_eimid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_eimid)
	children = append(children, enc_eimid...)
	if v.CounterValue == nil {
		return nil, fmt.Errorf("encoding counterValue: required INTEGER is nil")
	}
	enc_countervalue := ber.EncodeBigInt(v.CounterValue)
	enc_countervalue = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_countervalue)
	children = append(children, enc_countervalue...)
	if v.EimTransactionId != nil {
		enc_eimtransactionid := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_eimtransactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_eimtransactionid)
		children = append(children, enc_eimtransactionid...)
	}
	enc_euiccpackageerrorcode := ber.EncodeInteger(int64(v.EuiccPackageErrorCode))
	children = append(children, enc_euiccpackageerrorcode...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EuiccPackageErrorDataSigned to DER format.
func (v *EuiccPackageErrorDataSigned) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccPackageErrorDataSigned from BER/DER format.
func (v *EuiccPackageErrorDataSigned) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccPackageErrorDataSigned SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccPackageErrorDataSigned", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimId
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for eimId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_eimid, rawVal_eimid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimId: %w", err)
	}
	decVal_eimid := ber.DecodeStringValue(rawVal_eimid)
	v.EimId = decVal_eimid
	offset += n_eimid
	// Decode counterValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field counterValue")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for counterValue, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_countervalue, rawVal_countervalue, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding counterValue: %w", err)
	}
	decVal_countervalue, intErr := ber.DecodeBigIntValue(rawVal_countervalue)
	if intErr != nil {
		return fmt.Errorf("decoding counterValue: %w", intErr)
	}
	v.CounterValue = decVal_countervalue
	offset += n_countervalue
	// Decode eimTransactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eimtransactionid, rawVal_eimtransactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimTransactionId: %w", err)
				}
				tmp_eimtransactionid := sgp22.TransactionId(rawVal_eimtransactionid)
				v.EimTransactionId = &tmp_eimtransactionid
				offset += n_eimtransactionid
			}
		}
	}
	// Decode euiccPackageErrorCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccPackageErrorCode")
	}
	val_euiccpackageerrorcode, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccPackageErrorCode: %w", err)
	}
	v.EuiccPackageErrorCode = EuiccPackageErrorCode(val_euiccpackageerrorcode)
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EuiccPackageErrorDataSigned", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EuiccPackageErrorUnsigned to BER format.
func (v *EuiccPackageErrorUnsigned) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eimid := ber.EncodeStringTag(12, v.EimId)
	enc_eimid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_eimid)
	children = append(children, enc_eimid...)
	if v.EimTransactionId != nil {
		enc_eimtransactionid := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_eimtransactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_eimtransactionid)
		children = append(children, enc_eimtransactionid...)
	}
	if v.AssociationToken != nil {
		enc_associationtoken := ber.EncodeBigInt(v.AssociationToken)
		enc_associationtoken = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_associationtoken)
		children = append(children, enc_associationtoken...)
	}
	if v.EuiccPackageUnsignedErrorCode != nil {
		enc_euiccpackageunsignederrorcode := ber.EncodeInteger(int64(*v.EuiccPackageUnsignedErrorCode))
		enc_euiccpackageunsignederrorcode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, false, enc_euiccpackageunsignederrorcode)
		children = append(children, enc_euiccpackageunsignederrorcode...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EuiccPackageErrorUnsigned to DER format.
func (v *EuiccPackageErrorUnsigned) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccPackageErrorUnsigned from BER/DER format.
func (v *EuiccPackageErrorUnsigned) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccPackageErrorUnsigned SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccPackageErrorUnsigned", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimId
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for eimId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_eimid, rawVal_eimid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimId: %w", err)
	}
	decVal_eimid := ber.DecodeStringValue(rawVal_eimid)
	v.EimId = decVal_eimid
	offset += n_eimid
	// Decode eimTransactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eimtransactionid, rawVal_eimtransactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimTransactionId: %w", err)
				}
				tmp_eimtransactionid := sgp22.TransactionId(rawVal_eimtransactionid)
				v.EimTransactionId = &tmp_eimtransactionid
				offset += n_eimtransactionid
			}
		}
	}
	// Decode associationToken
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_associationtoken, rawVal_associationtoken, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding associationToken: %w", err)
				}
				decVal_associationtoken, intErr := ber.DecodeBigIntValue(rawVal_associationtoken)
				if intErr != nil {
					return fmt.Errorf("decoding associationToken: %w", intErr)
				}
				v.AssociationToken = decVal_associationtoken
				offset += n_associationtoken
			}
		}
	}
	// Decode euiccPackageUnsignedErrorCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				_, n_euiccpackageunsignederrorcode, rawVal_euiccpackageunsignederrorcode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccPackageUnsignedErrorCode: %w", err)
				}
				decVal_euiccpackageunsignederrorcode, intErr := ber.DecodeIntegerValue(rawVal_euiccpackageunsignederrorcode)
				if intErr != nil {
					return fmt.Errorf("decoding euiccPackageUnsignedErrorCode: %w", intErr)
				}
				tmp_euiccpackageunsignederrorcode := EuiccPackageUnsignedErrorCode(decVal_euiccpackageunsignederrorcode)
				v.EuiccPackageUnsignedErrorCode = &tmp_euiccpackageunsignederrorcode
				offset += n_euiccpackageunsignederrorcode
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EuiccPackageErrorUnsigned", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ProfileInfoListResponse to BER format.
func (v *ProfileInfoListResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ProfileInfoListResponseChoiceProfileInfoListOk:
		if v.ProfileInfoListOk == nil {
			return nil, fmt.Errorf("choice ProfileInfoListResponse: profileInfoListOk is nil")
		}
		enc_0, err := MarshalBERProfileInfoListResponseProfileInfoListOk(v.ProfileInfoListOk)
		if err != nil {
			return nil, fmt.Errorf("encoding profileInfoListOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 45, enc_0)
		return enc_0, nil
	case ProfileInfoListResponseChoiceProfileInfoListError:
		if v.ProfileInfoListError == nil {
			return nil, fmt.Errorf("choice ProfileInfoListResponse: profileInfoListError is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.ProfileInfoListError))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 45, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ProfileInfoListResponse", v.Choice)
	}
}

// MarshalDER encodes ProfileInfoListResponse to DER format.
func (v *ProfileInfoListResponse) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInfoListResponse from BER/DER format.
func (v *ProfileInfoListResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ProfileInfoListResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileInfoListResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 45 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileInfoListResponse CHOICE: %w: expected tag [CONTEXT 45], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInfoListResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for ProfileInfoListResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ProfileInfoListResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ProfileInfoListResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInfoListResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = ProfileInfoListResponseChoiceProfileInfoListOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding profileInfoListOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERProfileInfoListResponseProfileInfoListOk(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding profileInfoListOk: %w", unmErr)
		}
		v.ProfileInfoListOk = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = ProfileInfoListResponseChoiceProfileInfoListError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding profileInfoListError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding profileInfoListError: %w", intErr)
		}
		tmp := ProfileInfoListError(decVal)
		v.ProfileInfoListError = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for ProfileInfoListResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AddEimResult to BER format.
func (v *AddEimResult) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AddEimResultChoiceAssociationToken:
		if v.AssociationToken == nil {
			return nil, fmt.Errorf("choice AddEimResult: associationToken is nil")
		}
		enc_0 := ber.EncodeBigInt(v.AssociationToken)
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_0)
		return enc_0, nil
	case AddEimResultChoiceAddEimResultCode:
		if v.AddEimResultCode == nil {
			return nil, fmt.Errorf("choice AddEimResult: addEimResultCode is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.AddEimResultCode))
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AddEimResult", v.Choice)
	}
}

// MarshalDER encodes AddEimResult to DER format.
func (v *AddEimResult) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes AddEimResult from BER/DER format.
func (v *AddEimResult) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AddEimResult CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AddEimResult: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AddEimResult CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AddEimResult", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = AddEimResultChoiceAssociationToken
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding associationToken: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding associationToken: %w", intErr)
		}
		v.AssociationToken = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = AddEimResultChoiceAddEimResultCode
		decVal, _, intErr := ber.DecodeInteger(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding addEimResultCode: %w", intErr)
		}
		v.AddEimResultCode = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for AddEimResult CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ListEimResult to BER format.
func (v *ListEimResult) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ListEimResultChoiceEimIdList:
		if v.EimIdList == nil {
			return nil, fmt.Errorf("choice ListEimResult: eimIdList is nil")
		}
		enc_0, err := MarshalBERListEimResultEimIdList(v.EimIdList)
		if err != nil {
			return nil, fmt.Errorf("encoding eimIdList: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case ListEimResultChoiceListEimError:
		if v.ListEimError == nil {
			return nil, fmt.Errorf("choice ListEimResult: listEimError is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.ListEimError))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ListEimResult", v.Choice)
	}
}

// MarshalDER encodes ListEimResult to DER format.
func (v *ListEimResult) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes ListEimResult from BER/DER format.
func (v *ListEimResult) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ListEimResult CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ListEimResult: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ListEimResult CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ListEimResult", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = ListEimResultChoiceEimIdList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding eimIdList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERListEimResultEimIdList(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding eimIdList: %w", unmErr)
		}
		v.EimIdList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = ListEimResultChoiceListEimError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding listEimError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding listEimError: %w", intErr)
		}
		v.ListEimError = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for ListEimResult CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EimIdInfo to BER format.
func (v *EimIdInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eimid := ber.EncodeStringTag(12, v.EimId)
	enc_eimid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_eimid)
	children = append(children, enc_eimid...)
	if v.EimIdType != nil {
		enc_eimidtype := ber.EncodeInteger(int64(*v.EimIdType))
		enc_eimidtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_eimidtype)
		children = append(children, enc_eimidtype...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EimIdInfo to DER format.
func (v *EimIdInfo) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EimIdInfo from BER/DER format.
func (v *EimIdInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EimIdInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EimIdInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimId
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for eimId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_eimid, rawVal_eimid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimId: %w", err)
	}
	decVal_eimid := ber.DecodeStringValue(rawVal_eimid)
	v.EimId = decVal_eimid
	offset += n_eimid
	// Decode eimIdType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eimidtype, rawVal_eimidtype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimIdType: %w", err)
				}
				decVal_eimidtype, intErr := ber.DecodeIntegerValue(rawVal_eimidtype)
				if intErr != nil {
					return fmt.Errorf("decoding eimIdType: %w", intErr)
				}
				tmp_eimidtype := EimIdType(decVal_eimidtype)
				v.EimIdType = &tmp_eimidtype
				offset += n_eimidtype
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EimIdInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes IpaEuiccDataResponseError to BER format.
func (v *IpaEuiccDataResponseError) MarshalBER() ([]byte, error) {
	var children []byte
	if v.EimTransactionId != nil {
		enc_eimtransactionid := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_eimtransactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_eimtransactionid)
		children = append(children, enc_eimtransactionid...)
	}
	enc_ipaeuiccdataerrorcode := ber.EncodeInteger(int64(v.IpaEuiccDataErrorCode))
	children = append(children, enc_ipaeuiccdataerrorcode...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes IpaEuiccDataResponseError to DER format.
func (v *IpaEuiccDataResponseError) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IpaEuiccDataResponseError from BER/DER format.
func (v *IpaEuiccDataResponseError) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IpaEuiccDataResponseError SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IpaEuiccDataResponseError", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimTransactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_eimtransactionid, rawVal_eimtransactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimTransactionId: %w", err)
				}
				tmp_eimtransactionid := sgp22.TransactionId(rawVal_eimtransactionid)
				v.EimTransactionId = &tmp_eimtransactionid
				offset += n_eimtransactionid
			}
		}
	}
	// Decode ipaEuiccDataErrorCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field ipaEuiccDataErrorCode")
	}
	val_ipaeuiccdataerrorcode, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ipaEuiccDataErrorCode: %w", err)
	}
	v.IpaEuiccDataErrorCode = IpaEuiccDataErrorCode(val_ipaeuiccdataerrorcode)
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "IpaEuiccDataResponseError", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes IpaEuiccDataResponse to BER format.
func (v *IpaEuiccDataResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case IpaEuiccDataResponseChoiceIpaEuiccData:
		if v.IpaEuiccData == nil {
			return nil, fmt.Errorf("choice IpaEuiccDataResponse: ipaEuiccData is nil")
		}
		enc_0, err := v.IpaEuiccData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccData: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 82, enc_0)
		return enc_0, nil
	case IpaEuiccDataResponseChoiceIpaEuiccDataResponseError:
		if v.IpaEuiccDataResponseError == nil {
			return nil, fmt.Errorf("choice IpaEuiccDataResponse: ipaEuiccDataResponseError is nil")
		}
		enc_1, err := v.IpaEuiccDataResponseError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccDataResponseError: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 82, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for IpaEuiccDataResponse", v.Choice)
	}
}

// MarshalDER encodes IpaEuiccDataResponse to DER format.
func (v *IpaEuiccDataResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case IpaEuiccDataResponseChoiceIpaEuiccData:
		if v.IpaEuiccData == nil {
			return nil, fmt.Errorf("choice IpaEuiccDataResponse: ipaEuiccData is nil")
		}
		enc_der_0, err := v.IpaEuiccData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccData: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 82, enc_der_0)
		return enc_der_0, nil
	case IpaEuiccDataResponseChoiceIpaEuiccDataResponseError:
		if v.IpaEuiccDataResponseError == nil {
			return nil, fmt.Errorf("choice IpaEuiccDataResponse: ipaEuiccDataResponseError is nil")
		}
		enc_der_1, err := v.IpaEuiccDataResponseError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccDataResponseError: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 82, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes IpaEuiccDataResponse from BER/DER format.
func (v *IpaEuiccDataResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for IpaEuiccDataResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding IpaEuiccDataResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 82 || !decodedTag.Constructed {
		return fmt.Errorf("decoding IpaEuiccDataResponse CHOICE: %w: expected tag [CONTEXT 82], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IpaEuiccDataResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for IpaEuiccDataResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for IpaEuiccDataResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding IpaEuiccDataResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "IpaEuiccDataResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = IpaEuiccDataResponseChoiceIpaEuiccData
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ipaEuiccData: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec IpaEuiccData
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding ipaEuiccData: %w", unmErr)
		}
		v.IpaEuiccData = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = IpaEuiccDataResponseChoiceIpaEuiccDataResponseError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ipaEuiccDataResponseError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec IpaEuiccDataResponseError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding ipaEuiccDataResponseError: %w", unmErr)
		}
		v.IpaEuiccDataResponseError = &dec
	} else {
		return fmt.Errorf("unknown tag %s for IpaEuiccDataResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBERPendingNotificationList encodes a PendingNotificationList list to BER.
func MarshalBERPendingNotificationList(list PendingNotificationList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERPendingNotificationList decodes a PendingNotificationList list from BER.
func UnmarshalBERPendingNotificationList(data []byte) (PendingNotificationList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding PendingNotificationList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PendingNotificationList", Cause: ber.ErrExtraData}
	}
	var result PendingNotificationList
	offset := 0
	for offset < len(content) {
		var elem PendingNotification
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBEREuiccPackageResultList encodes a EuiccPackageResultList list to BER.
func MarshalBEREuiccPackageResultList(list EuiccPackageResultList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREuiccPackageResultList decodes a EuiccPackageResultList list from BER.
func UnmarshalBEREuiccPackageResultList(data []byte) (EuiccPackageResultList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EuiccPackageResultList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EuiccPackageResultList", Cause: ber.ErrExtraData}
	}
	var result EuiccPackageResultList
	offset := 0
	for offset < len(content) {
		var elem EuiccPackageResult
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes IpaEuiccData to BER format.
func (v *IpaEuiccData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.NotificationsList != nil {
		enc_notificationslist, err := MarshalBERPendingNotificationList(v.NotificationsList)
		if err != nil {
			return nil, fmt.Errorf("encoding notificationsList: %w", err)
		}
		if v.NotificationsListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_notificationslist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_notificationslist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
		} else {
			enc_notificationslist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_notificationslist)
		}
		children = append(children, enc_notificationslist...)
	}
	if v.DefaultSmdpAddress != nil {
		enc_defaultsmdpaddress := ber.EncodeStringTag(12, *v.DefaultSmdpAddress)
		enc_defaultsmdpaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_defaultsmdpaddress)
		children = append(children, enc_defaultsmdpaddress...)
	}
	if v.EuiccPackageResultList != nil {
		enc_euiccpackageresultlist, err := MarshalBEREuiccPackageResultList(v.EuiccPackageResultList)
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageResultList: %w", err)
		}
		if v.EuiccPackageResultListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_euiccpackageresultlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_euiccpackageresultlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
		} else {
			enc_euiccpackageresultlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_euiccpackageresultlist)
		}
		children = append(children, enc_euiccpackageresultlist...)
	}
	if v.EuiccInfo1 != nil {
		enc_euiccinfo1, err := v.EuiccInfo1.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccInfo1: %w", err)
		}
		children = append(children, enc_euiccinfo1...)
	}
	if v.EuiccInfo2 != nil {
		enc_euiccinfo2, err := v.EuiccInfo2.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccInfo2: %w", err)
		}
		children = append(children, enc_euiccinfo2...)
	}
	if v.RootSmdsAddress != nil {
		enc_rootsmdsaddress := ber.EncodeStringTag(12, *v.RootSmdsAddress)
		enc_rootsmdsaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_rootsmdsaddress)
		children = append(children, enc_rootsmdsaddress...)
	}
	if v.AssociationToken != nil {
		enc_associationtoken := ber.EncodeBigInt(v.AssociationToken)
		enc_associationtoken = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_associationtoken)
		children = append(children, enc_associationtoken...)
	}
	if v.EumCertificate != nil {
		enc_eumcertificate, err := v.EumCertificate.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding eumCertificate: %w", err)
		}
		enc_eumcertificate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_eumcertificate)
		children = append(children, enc_eumcertificate...)
	}
	if v.EuiccCertificate != nil {
		enc_euicccertificate, err := v.EuiccCertificate.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccCertificate: %w", err)
		}
		enc_euicccertificate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_euicccertificate)
		children = append(children, enc_euicccertificate...)
	}
	if v.EimTransactionId != nil {
		enc_eimtransactionid := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_eimtransactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_eimtransactionid)
		children = append(children, enc_eimtransactionid...)
	}
	if v.IpaCapabilities != nil {
		enc_ipacapabilities, err := v.IpaCapabilities.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaCapabilities: %w", err)
		}
		enc_ipacapabilities = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_ipacapabilities)
		children = append(children, enc_ipacapabilities...)
	}
	if v.DeviceInfo != nil {
		enc_deviceinfo, err := v.DeviceInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding deviceInfo: %w", err)
		}
		enc_deviceinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_deviceinfo)
		children = append(children, enc_deviceinfo...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes IpaEuiccData to DER format.
func (v *IpaEuiccData) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.NotificationsListIndef_ = false
	derValue.EuiccPackageResultListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes IpaEuiccData from BER/DER format.
func (v *IpaEuiccData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IpaEuiccData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IpaEuiccData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode notificationsList
	v.NotificationsListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_notificationslist, rawVal_notificationslist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding notificationsList: %w", err)
				}
				reconstructed_notificationslist := ber.EncodeSequence(rawVal_notificationslist)
				dec_notificationslist, unmErr := UnmarshalBERPendingNotificationList(reconstructed_notificationslist)
				if unmErr != nil {
					return fmt.Errorf("decoding notificationsList: %w", unmErr)
				}
				v.NotificationsList = dec_notificationslist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.NotificationsListIndef_ = true
					}
				}
				offset += n_notificationslist
			}
		}
	}
	// Decode defaultSmdpAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_defaultsmdpaddress, rawVal_defaultsmdpaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding defaultSmdpAddress: %w", err)
				}
				decVal_defaultsmdpaddress := ber.DecodeStringValue(rawVal_defaultsmdpaddress)
				v.DefaultSmdpAddress = &decVal_defaultsmdpaddress
				offset += n_defaultsmdpaddress
			}
		}
	}
	// Decode euiccPackageResultList
	v.EuiccPackageResultListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_euiccpackageresultlist, rawVal_euiccpackageresultlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccPackageResultList: %w", err)
				}
				reconstructed_euiccpackageresultlist := ber.EncodeSequence(rawVal_euiccpackageresultlist)
				dec_euiccpackageresultlist, unmErr := UnmarshalBEREuiccPackageResultList(reconstructed_euiccpackageresultlist)
				if unmErr != nil {
					return fmt.Errorf("decoding euiccPackageResultList: %w", unmErr)
				}
				v.EuiccPackageResultList = dec_euiccpackageresultlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.EuiccPackageResultListIndef_ = true
					}
				}
				offset += n_euiccpackageresultlist
			}
		}
	}
	// Decode euiccInfo1
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 32 {
				// Decode nested SEQUENCE (sgp22.EUICCInfo1)
				_, n_euiccinfo1, _, tlvErr_euiccinfo1 := ber.DecodeTLV(content[offset:])
				if tlvErr_euiccinfo1 != nil {
					return fmt.Errorf("decoding euiccInfo1: %w", tlvErr_euiccinfo1)
				}
				var dec_euiccinfo1 sgp22.EUICCInfo1
				if unmErr := dec_euiccinfo1.UnmarshalBER(content[offset : offset+n_euiccinfo1]); unmErr != nil {
					return fmt.Errorf("decoding euiccInfo1: %w", unmErr)
				}
				v.EuiccInfo1 = &dec_euiccinfo1
				offset += n_euiccinfo1
			}
		}
	}
	// Decode euiccInfo2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 34 {
				// Decode nested SEQUENCE (EUICCInfo2)
				_, n_euiccinfo2, _, tlvErr_euiccinfo2 := ber.DecodeTLV(content[offset:])
				if tlvErr_euiccinfo2 != nil {
					return fmt.Errorf("decoding euiccInfo2: %w", tlvErr_euiccinfo2)
				}
				var dec_euiccinfo2 EUICCInfo2
				if unmErr := dec_euiccinfo2.UnmarshalBER(content[offset : offset+n_euiccinfo2]); unmErr != nil {
					return fmt.Errorf("decoding euiccInfo2: %w", unmErr)
				}
				v.EuiccInfo2 = &dec_euiccinfo2
				offset += n_euiccinfo2
			}
		}
	}
	// Decode rootSmdsAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_rootsmdsaddress, rawVal_rootsmdsaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rootSmdsAddress: %w", err)
				}
				decVal_rootsmdsaddress := ber.DecodeStringValue(rawVal_rootsmdsaddress)
				v.RootSmdsAddress = &decVal_rootsmdsaddress
				offset += n_rootsmdsaddress
			}
		}
	}
	// Decode associationToken
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_associationtoken, rawVal_associationtoken, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding associationToken: %w", err)
				}
				decVal_associationtoken, intErr := ber.DecodeBigIntValue(rawVal_associationtoken)
				if intErr != nil {
					return fmt.Errorf("decoding associationToken: %w", intErr)
				}
				v.AssociationToken = decVal_associationtoken
				offset += n_associationtoken
			}
		}
	}
	// Decode eumCertificate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_eumcertificate, rawVal_eumcertificate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eumCertificate: %w", err)
				}
				reconstructed_eumcertificate := ber.EncodeSequence(rawVal_eumcertificate)
				var dec_eumcertificate sgp22.Certificate
				if unmErr := dec_eumcertificate.UnmarshalBER(reconstructed_eumcertificate); unmErr != nil {
					return fmt.Errorf("decoding eumCertificate: %w", unmErr)
				}
				v.EumCertificate = &dec_eumcertificate
				offset += n_eumcertificate
			}
		}
	}
	// Decode euiccCertificate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_euicccertificate, rawVal_euicccertificate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccCertificate: %w", err)
				}
				reconstructed_euicccertificate := ber.EncodeSequence(rawVal_euicccertificate)
				var dec_euicccertificate sgp22.Certificate
				if unmErr := dec_euicccertificate.UnmarshalBER(reconstructed_euicccertificate); unmErr != nil {
					return fmt.Errorf("decoding euiccCertificate: %w", unmErr)
				}
				v.EuiccCertificate = &dec_euicccertificate
				offset += n_euicccertificate
			}
		}
	}
	// Decode eimTransactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_eimtransactionid, rawVal_eimtransactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimTransactionId: %w", err)
				}
				tmp_eimtransactionid := sgp22.TransactionId(rawVal_eimtransactionid)
				v.EimTransactionId = &tmp_eimtransactionid
				offset += n_eimtransactionid
			}
		}
	}
	// Decode ipaCapabilities
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_ipacapabilities, rawVal_ipacapabilities, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ipaCapabilities: %w", err)
				}
				reconstructed_ipacapabilities := ber.EncodeSequence(rawVal_ipacapabilities)
				var dec_ipacapabilities IpaCapabilities
				if unmErr := dec_ipacapabilities.UnmarshalBER(reconstructed_ipacapabilities); unmErr != nil {
					return fmt.Errorf("decoding ipaCapabilities: %w", unmErr)
				}
				v.IpaCapabilities = &dec_ipacapabilities
				offset += n_ipacapabilities
			}
		}
	}
	// Decode deviceInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_deviceinfo, rawVal_deviceinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding deviceInfo: %w", err)
				}
				reconstructed_deviceinfo := ber.EncodeSequence(rawVal_deviceinfo)
				var dec_deviceinfo sgp22.DeviceInfo
				if unmErr := dec_deviceinfo.UnmarshalBER(reconstructed_deviceinfo); unmErr != nil {
					return fmt.Errorf("decoding deviceInfo: %w", unmErr)
				}
				v.DeviceInfo = &dec_deviceinfo
				offset += n_deviceinfo
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "IpaEuiccData", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ProfileDownloadTriggerResult to BER format.
func (v *ProfileDownloadTriggerResult) MarshalBER() ([]byte, error) {
	var children []byte
	if v.EimTransactionId != nil {
		enc_eimtransactionid := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_eimtransactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_eimtransactionid)
		children = append(children, enc_eimtransactionid...)
	}
	enc_profiledownloadtriggerresultdata, err := v.ProfileDownloadTriggerResultData.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding profileDownloadTriggerResultData: %w", err)
	}
	children = append(children, enc_profiledownloadtriggerresultdata...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 84, Constructed: true}, children), nil
}

// MarshalDER encodes ProfileDownloadTriggerResult to DER format.
func (v *ProfileDownloadTriggerResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileDownloadTriggerResult from BER/DER format.
func (v *ProfileDownloadTriggerResult) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileDownloadTriggerResult: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 84 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileDownloadTriggerResult: %w: expected tag [CONTEXT 84], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileDownloadTriggerResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimTransactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eimtransactionid, rawVal_eimtransactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimTransactionId: %w", err)
				}
				tmp_eimtransactionid := sgp22.TransactionId(rawVal_eimtransactionid)
				v.EimTransactionId = &tmp_eimtransactionid
				offset += n_eimtransactionid
			}
		}
	}
	// Decode profileDownloadTriggerResultData
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileDownloadTriggerResultData")
	}
	// Decode nested CHOICE (ProfileDownloadTriggerResultProfileDownloadTriggerResultData)
	_, n_profiledownloadtriggerresultdata, _, tlvErr_profiledownloadtriggerresultdata := ber.DecodeTLV(content[offset:])
	if tlvErr_profiledownloadtriggerresultdata != nil {
		return fmt.Errorf("decoding profileDownloadTriggerResultData: %w", tlvErr_profiledownloadtriggerresultdata)
	}
	if unmErr := v.ProfileDownloadTriggerResultData.UnmarshalBER(content[offset : offset+n_profiledownloadtriggerresultdata]); unmErr != nil {
		return fmt.Errorf("decoding profileDownloadTriggerResultData: %w", unmErr)
	}
	offset += n_profiledownloadtriggerresultdata
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProfileDownloadTriggerResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ISDRProprietaryApplicationTemplateIoT to BER format.
func (v *ISDRProprietaryApplicationTemplateIoT) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccconfiguration := ber.EncodeBitString(v.EuiccConfiguration.Bytes, (8-(v.EuiccConfiguration.BitLength%8))%8)
	enc_euiccconfiguration = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_euiccconfiguration)
	children = append(children, enc_euiccconfiguration...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 1, Constructed: true}, children), nil
}

// MarshalDER encodes ISDRProprietaryApplicationTemplateIoT to DER format.
func (v *ISDRProprietaryApplicationTemplateIoT) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ISDRProprietaryApplicationTemplateIoT from BER/DER format.
func (v *ISDRProprietaryApplicationTemplateIoT) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ISDRProprietaryApplicationTemplateIoT: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 1 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ISDRProprietaryApplicationTemplateIoT: %w: expected tag [PRIVATE 1], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ISDRProprietaryApplicationTemplateIoT", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccConfiguration
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccConfiguration")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for euiccConfiguration, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_euiccconfiguration, rawVal_euiccconfiguration, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccConfiguration: %w", err)
	}
	bsBytes_euiccconfiguration, bsUnused_euiccconfiguration, bsErr := ber.DecodeBitStringValue(rawVal_euiccconfiguration)
	if bsErr != nil {
		return fmt.Errorf("decoding euiccConfiguration: %w", bsErr)
	}
	v.EuiccConfiguration = runtime.BitString{Bytes: bsBytes_euiccconfiguration, BitLength: len(bsBytes_euiccconfiguration)*8 - bsUnused_euiccconfiguration}
	offset += n_euiccconfiguration
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ISDRProprietaryApplicationTemplateIoT", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes IpaeActivationRequest to BER format.
func (v *IpaeActivationRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_ipaeoption := ber.EncodeBitString(v.IpaeOption.Bytes, (8-(v.IpaeOption.BitLength%8))%8)
	enc_ipaeoption = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_ipaeoption)
	children = append(children, enc_ipaeoption...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 66, Constructed: true}, children), nil
}

// MarshalDER encodes IpaeActivationRequest to DER format.
func (v *IpaeActivationRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IpaeActivationRequest from BER/DER format.
func (v *IpaeActivationRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding IpaeActivationRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 66 || !decodedTag.Constructed {
		return fmt.Errorf("decoding IpaeActivationRequest: %w: expected tag [CONTEXT 66], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IpaeActivationRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ipaeOption
	if offset >= len(content) {
		return fmt.Errorf("missing required field ipaeOption")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ipaeOption, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_ipaeoption, rawVal_ipaeoption, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ipaeOption: %w", err)
	}
	bsBytes_ipaeoption, bsUnused_ipaeoption, bsErr := ber.DecodeBitStringValue(rawVal_ipaeoption)
	if bsErr != nil {
		return fmt.Errorf("decoding ipaeOption: %w", bsErr)
	}
	v.IpaeOption = runtime.BitString{Bytes: bsBytes_ipaeoption, BitLength: len(bsBytes_ipaeoption)*8 - bsUnused_ipaeoption}
	offset += n_ipaeoption
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "IpaeActivationRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes IpaeActivationResponse to BER format.
func (v *IpaeActivationResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_ipaeactivationresult := ber.EncodeInteger(int64(v.IpaeActivationResult))
	enc_ipaeactivationresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_ipaeactivationresult)
	children = append(children, enc_ipaeactivationresult...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 66, Constructed: true}, children), nil
}

// MarshalDER encodes IpaeActivationResponse to DER format.
func (v *IpaeActivationResponse) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IpaeActivationResponse from BER/DER format.
func (v *IpaeActivationResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding IpaeActivationResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 66 || !decodedTag.Constructed {
		return fmt.Errorf("decoding IpaeActivationResponse: %w: expected tag [CONTEXT 66], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IpaeActivationResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ipaeActivationResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field ipaeActivationResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ipaeActivationResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_ipaeactivationresult, rawVal_ipaeactivationresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ipaeActivationResult: %w", err)
	}
	decVal_ipaeactivationresult, intErr := ber.DecodeIntegerValue(rawVal_ipaeactivationresult)
	if intErr != nil {
		return fmt.Errorf("decoding ipaeActivationResult: %w", intErr)
	}
	v.IpaeActivationResult = decVal_ipaeactivationresult
	offset += n_ipaeactivationresult
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "IpaeActivationResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes IpaCapabilities to BER format.
func (v *IpaCapabilities) MarshalBER() ([]byte, error) {
	var children []byte
	enc_ipafeatures := ber.EncodeBitString(v.IpaFeatures.Bytes, (8-(v.IpaFeatures.BitLength%8))%8)
	enc_ipafeatures = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_ipafeatures)
	children = append(children, enc_ipafeatures...)
	if v.IpaSupportedProtocols != nil {
		enc_ipasupportedprotocols := ber.EncodeBitString(v.IpaSupportedProtocols.Bytes, (8-(v.IpaSupportedProtocols.BitLength%8))%8)
		enc_ipasupportedprotocols = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_ipasupportedprotocols)
		children = append(children, enc_ipasupportedprotocols...)
	}
	if v.ESipaProprietaryProtocolInformation != nil {
		enc_esipaproprietaryprotocolinformation, err := sgp22.MarshalBERVendorSpecificExtension(v.ESipaProprietaryProtocolInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding eSipaProprietaryProtocolInformation: %w", err)
		}
		if v.ESipaProprietaryProtocolInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_esipaproprietaryprotocolinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_esipaproprietaryprotocolinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
		} else {
			enc_esipaproprietaryprotocolinformation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_esipaproprietaryprotocolinformation)
		}
		children = append(children, enc_esipaproprietaryprotocolinformation...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes IpaCapabilities to DER format.
func (v *IpaCapabilities) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ESipaProprietaryProtocolInformationIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes IpaCapabilities from BER/DER format.
func (v *IpaCapabilities) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IpaCapabilities SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IpaCapabilities", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ipaFeatures
	if offset >= len(content) {
		return fmt.Errorf("missing required field ipaFeatures")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ipaFeatures, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_ipafeatures, rawVal_ipafeatures, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ipaFeatures: %w", err)
	}
	bsBytes_ipafeatures, bsUnused_ipafeatures, bsErr := ber.DecodeBitStringValue(rawVal_ipafeatures)
	if bsErr != nil {
		return fmt.Errorf("decoding ipaFeatures: %w", bsErr)
	}
	v.IpaFeatures = runtime.BitString{Bytes: bsBytes_ipafeatures, BitLength: len(bsBytes_ipafeatures)*8 - bsUnused_ipafeatures}
	offset += n_ipafeatures
	// Decode ipaSupportedProtocols
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_ipasupportedprotocols, rawVal_ipasupportedprotocols, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ipaSupportedProtocols: %w", err)
				}
				bsBytes_ipasupportedprotocols, bsUnused_ipasupportedprotocols, bsErr := ber.DecodeBitStringValue(rawVal_ipasupportedprotocols)
				if bsErr != nil {
					return fmt.Errorf("decoding ipaSupportedProtocols: %w", bsErr)
				}
				tmp_ipasupportedprotocols := runtime.BitString{Bytes: bsBytes_ipasupportedprotocols, BitLength: len(bsBytes_ipasupportedprotocols)*8 - bsUnused_ipasupportedprotocols}
				v.IpaSupportedProtocols = &tmp_ipasupportedprotocols
				offset += n_ipasupportedprotocols
			}
		}
	}
	// Decode eSipaProprietaryProtocolInformation
	v.ESipaProprietaryProtocolInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_esipaproprietaryprotocolinformation, rawVal_esipaproprietaryprotocolinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eSipaProprietaryProtocolInformation: %w", err)
				}
				reconstructed_esipaproprietaryprotocolinformation := ber.EncodeSequence(rawVal_esipaproprietaryprotocolinformation)
				dec_esipaproprietaryprotocolinformation, unmErr := sgp22.UnmarshalBERVendorSpecificExtension(reconstructed_esipaproprietaryprotocolinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding eSipaProprietaryProtocolInformation: %w", unmErr)
				}
				v.ESipaProprietaryProtocolInformation = dec_esipaproprietaryprotocolinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ESipaProprietaryProtocolInformationIndef_ = true
					}
				}
				offset += n_esipaproprietaryprotocolinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "IpaCapabilities", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ProfileInfo to BER format.
func (v *ProfileInfo) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Iccid != nil {
		enc_iccid := ber.EncodeOctetString([]byte(*v.Iccid))
		enc_iccid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_iccid)
		children = append(children, enc_iccid...)
	}
	if v.IsdpAid != nil {
		enc_isdpaid := ber.EncodeOctetString([]byte(*v.IsdpAid))
		enc_isdpaid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 15, false, enc_isdpaid)
		children = append(children, enc_isdpaid...)
	}
	if v.ProfileState != nil {
		enc_profilestate := ber.EncodeInteger(int64(*v.ProfileState))
		enc_profilestate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 112, false, enc_profilestate)
		children = append(children, enc_profilestate...)
	}
	if v.ProfileNickname != nil {
		enc_profilenickname := ber.EncodeStringTag(12, *v.ProfileNickname)
		enc_profilenickname = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_profilenickname)
		children = append(children, enc_profilenickname...)
	}
	if v.ServiceProviderName != nil {
		enc_serviceprovidername := ber.EncodeStringTag(12, *v.ServiceProviderName)
		enc_serviceprovidername = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, false, enc_serviceprovidername)
		children = append(children, enc_serviceprovidername...)
	}
	if v.ProfileName != nil {
		enc_profilename := ber.EncodeStringTag(12, *v.ProfileName)
		enc_profilename = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_profilename)
		children = append(children, enc_profilename...)
	}
	if v.IconType != nil {
		enc_icontype := ber.EncodeInteger(int64(*v.IconType))
		enc_icontype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_icontype)
		children = append(children, enc_icontype...)
	}
	if v.Icon != nil {
		enc_icon := ber.EncodeOctetString(v.Icon)
		enc_icon = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, false, enc_icon)
		children = append(children, enc_icon...)
	}
	if v.ProfileClass != nil {
		enc_profileclass := ber.EncodeInteger(int64(*v.ProfileClass))
		enc_profileclass = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, false, enc_profileclass)
		children = append(children, enc_profileclass...)
	}
	if v.NotificationConfigurationInfo != nil {
		enc_notificationconfigurationinfo, err := MarshalBERProfileInfoNotificationConfigurationInfo(v.NotificationConfigurationInfo)
		if err != nil {
			return nil, fmt.Errorf("encoding notificationConfigurationInfo: %w", err)
		}
		if v.NotificationConfigurationInfoIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_notificationconfigurationinfo)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_notificationconfigurationinfo = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 22}, seqContent_)
		} else {
			enc_notificationconfigurationinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, true, enc_notificationconfigurationinfo)
		}
		children = append(children, enc_notificationconfigurationinfo...)
	}
	if v.ProfileOwner != nil {
		enc_profileowner, err := v.ProfileOwner.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileOwner: %w", err)
		}
		enc_profileowner = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, true, enc_profileowner)
		children = append(children, enc_profileowner...)
	}
	if v.DpProprietaryData != nil {
		enc_dpproprietarydata, err := v.DpProprietaryData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding dpProprietaryData: %w", err)
		}
		enc_dpproprietarydata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, true, enc_dpproprietarydata)
		children = append(children, enc_dpproprietarydata...)
	}
	if v.ProfilePolicyRules != nil {
		enc_profilepolicyrules := ber.EncodeBitString(v.ProfilePolicyRules.Bytes, (8-(v.ProfilePolicyRules.BitLength%8))%8)
		enc_profilepolicyrules = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, false, enc_profilepolicyrules)
		children = append(children, enc_profilepolicyrules...)
	}
	if v.ServiceSpecificDataStoredInEuicc != nil {
		enc_servicespecificdatastoredineuicc, err := sgp22.MarshalBERVendorSpecificExtension(v.ServiceSpecificDataStoredInEuicc)
		if err != nil {
			return nil, fmt.Errorf("encoding serviceSpecificDataStoredInEuicc: %w", err)
		}
		if v.ServiceSpecificDataStoredInEuiccIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_servicespecificdatastoredineuicc)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_servicespecificdatastoredineuicc = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 34}, seqContent_)
		} else {
			enc_servicespecificdatastoredineuicc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 34, true, enc_servicespecificdatastoredineuicc)
		}
		children = append(children, enc_servicespecificdatastoredineuicc...)
	}
	if v.EcallIndication != nil {
		var enc_ecallindication []byte
		if v.EcallIndicationRaw_ != 0 {
			enc_ecallindication = ber.EncodeBooleanRaw(v.EcallIndicationRaw_)
		} else {
			enc_ecallindication = ber.EncodeBoolean(*v.EcallIndication)
		}
		enc_ecallindication = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 123, false, enc_ecallindication)
		children = append(children, enc_ecallindication...)
	}
	if v.FallbackAttribute != nil {
		var enc_fallbackattribute []byte
		if v.FallbackAttributeRaw_ != 0 {
			enc_fallbackattribute = ber.EncodeBooleanRaw(v.FallbackAttributeRaw_)
		} else {
			enc_fallbackattribute = ber.EncodeBoolean(*v.FallbackAttribute)
		}
		enc_fallbackattribute = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 38, false, enc_fallbackattribute)
		children = append(children, enc_fallbackattribute...)
	}
	if v.FallbackAllowed != nil {
		var enc_fallbackallowed []byte
		if v.FallbackAllowedRaw_ != 0 {
			enc_fallbackallowed = ber.EncodeBooleanRaw(v.FallbackAllowedRaw_)
		} else {
			enc_fallbackallowed = ber.EncodeBoolean(*v.FallbackAllowed)
		}
		enc_fallbackallowed = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 103, false, enc_fallbackallowed)
		children = append(children, enc_fallbackallowed...)
	}
	if v.IotSpecificProfileInfo != nil {
		enc_iotspecificprofileinfo, err := v.IotSpecificProfileInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding iotSpecificProfileInfo: %w", err)
		}
		enc_iotspecificprofileinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 100, true, enc_iotspecificprofileinfo)
		children = append(children, enc_iotspecificprofileinfo...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 3, Constructed: true}, children), nil
}

// MarshalDER encodes ProfileInfo to DER format.
func (v *ProfileInfo) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.NotificationConfigurationInfoIndef_ = false
	derValue.ServiceSpecificDataStoredInEuiccIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInfo from BER/DER format.
func (v *ProfileInfo) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileInfo: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 3 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileInfo: %w: expected tag [PRIVATE 3], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode iccid
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 26 {
				_, n_iccid, rawVal_iccid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iccid: %w", err)
				}
				tmp_iccid := sgp22.Iccid(rawVal_iccid)
				v.Iccid = &tmp_iccid
				offset += n_iccid
			}
		}
	}
	// Decode isdpAid
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 15 {
				_, n_isdpaid, rawVal_isdpaid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding isdpAid: %w", err)
				}
				tmp_isdpaid := sgp22.OctetTo16(rawVal_isdpaid)
				v.IsdpAid = &tmp_isdpaid
				offset += n_isdpaid
			}
		}
	}
	// Decode profileState
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 112 {
				_, n_profilestate, rawVal_profilestate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileState: %w", err)
				}
				decVal_profilestate, intErr := ber.DecodeIntegerValue(rawVal_profilestate)
				if intErr != nil {
					return fmt.Errorf("decoding profileState: %w", intErr)
				}
				tmp_profilestate := sgp22.ProfileState(decVal_profilestate)
				v.ProfileState = &tmp_profilestate
				offset += n_profilestate
			}
		}
	}
	// Decode profileNickname
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				_, n_profilenickname, rawVal_profilenickname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileNickname: %w", err)
				}
				decVal_profilenickname := ber.DecodeStringValue(rawVal_profilenickname)
				v.ProfileNickname = &decVal_profilenickname
				offset += n_profilenickname
			}
		}
	}
	// Decode serviceProviderName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				_, n_serviceprovidername, rawVal_serviceprovidername, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceProviderName: %w", err)
				}
				decVal_serviceprovidername := ber.DecodeStringValue(rawVal_serviceprovidername)
				v.ServiceProviderName = &decVal_serviceprovidername
				offset += n_serviceprovidername
			}
		}
	}
	// Decode profileName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				_, n_profilename, rawVal_profilename, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileName: %w", err)
				}
				decVal_profilename := ber.DecodeStringValue(rawVal_profilename)
				v.ProfileName = &decVal_profilename
				offset += n_profilename
			}
		}
	}
	// Decode iconType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_icontype, rawVal_icontype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iconType: %w", err)
				}
				decVal_icontype, intErr := ber.DecodeIntegerValue(rawVal_icontype)
				if intErr != nil {
					return fmt.Errorf("decoding iconType: %w", intErr)
				}
				tmp_icontype := sgp22.IconType(decVal_icontype)
				v.IconType = &tmp_icontype
				offset += n_icontype
			}
		}
	}
	// Decode icon
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				_, n_icon, rawVal_icon, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding icon: %w", err)
				}
				tmp_icon := rawVal_icon
				v.Icon = tmp_icon
				offset += n_icon
			}
		}
	}
	// Decode profileClass
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				_, n_profileclass, rawVal_profileclass, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileClass: %w", err)
				}
				decVal_profileclass, intErr := ber.DecodeIntegerValue(rawVal_profileclass)
				if intErr != nil {
					return fmt.Errorf("decoding profileClass: %w", intErr)
				}
				tmp_profileclass := sgp22.ProfileClass(decVal_profileclass)
				v.ProfileClass = &tmp_profileclass
				offset += n_profileclass
			}
		}
	}
	// Decode notificationConfigurationInfo
	v.NotificationConfigurationInfoIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				_, n_notificationconfigurationinfo, rawVal_notificationconfigurationinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding notificationConfigurationInfo: %w", err)
				}
				reconstructed_notificationconfigurationinfo := ber.EncodeSequence(rawVal_notificationconfigurationinfo)
				dec_notificationconfigurationinfo, unmErr := UnmarshalBERProfileInfoNotificationConfigurationInfo(reconstructed_notificationconfigurationinfo)
				if unmErr != nil {
					return fmt.Errorf("decoding notificationConfigurationInfo: %w", unmErr)
				}
				v.NotificationConfigurationInfo = dec_notificationconfigurationinfo
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.NotificationConfigurationInfoIndef_ = true
					}
				}
				offset += n_notificationconfigurationinfo
			}
		}
	}
	// Decode profileOwner
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				_, n_profileowner, rawVal_profileowner, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileOwner: %w", err)
				}
				reconstructed_profileowner := ber.EncodeSequence(rawVal_profileowner)
				var dec_profileowner sgp22.OperatorId
				if unmErr := dec_profileowner.UnmarshalBER(reconstructed_profileowner); unmErr != nil {
					return fmt.Errorf("decoding profileOwner: %w", unmErr)
				}
				v.ProfileOwner = &dec_profileowner
				offset += n_profileowner
			}
		}
	}
	// Decode dpProprietaryData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24 {
				_, n_dpproprietarydata, rawVal_dpproprietarydata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dpProprietaryData: %w", err)
				}
				reconstructed_dpproprietarydata := ber.EncodeSequence(rawVal_dpproprietarydata)
				var dec_dpproprietarydata sgp22.DpProprietaryData
				if unmErr := dec_dpproprietarydata.UnmarshalBER(reconstructed_dpproprietarydata); unmErr != nil {
					return fmt.Errorf("decoding dpProprietaryData: %w", unmErr)
				}
				v.DpProprietaryData = &dec_dpproprietarydata
				offset += n_dpproprietarydata
			}
		}
	}
	// Decode profilePolicyRules
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				_, n_profilepolicyrules, rawVal_profilepolicyrules, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", err)
				}
				bsBytes_profilepolicyrules, bsUnused_profilepolicyrules, bsErr := ber.DecodeBitStringValue(rawVal_profilepolicyrules)
				if bsErr != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", bsErr)
				}
				tmp_profilepolicyrules := runtime.BitString{Bytes: bsBytes_profilepolicyrules, BitLength: len(bsBytes_profilepolicyrules)*8 - bsUnused_profilepolicyrules}
				v.ProfilePolicyRules = &tmp_profilepolicyrules
				offset += n_profilepolicyrules
			}
		}
	}
	// Decode serviceSpecificDataStoredInEuicc
	v.ServiceSpecificDataStoredInEuiccIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 34 {
				_, n_servicespecificdatastoredineuicc, rawVal_servicespecificdatastoredineuicc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", err)
				}
				reconstructed_servicespecificdatastoredineuicc := ber.EncodeSequence(rawVal_servicespecificdatastoredineuicc)
				dec_servicespecificdatastoredineuicc, unmErr := sgp22.UnmarshalBERVendorSpecificExtension(reconstructed_servicespecificdatastoredineuicc)
				if unmErr != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", unmErr)
				}
				v.ServiceSpecificDataStoredInEuicc = dec_servicespecificdatastoredineuicc
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ServiceSpecificDataStoredInEuiccIndef_ = true
					}
				}
				offset += n_servicespecificdatastoredineuicc
			}
		}
	}
	// Decode ecallIndication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 123 {
				_, n_ecallindication, rawVal_ecallindication, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ecallIndication: %w", err)
				}
				decVal_ecallindication, boolErr := ber.DecodeBooleanValue(rawVal_ecallindication)
				if boolErr != nil {
					return fmt.Errorf("decoding ecallIndication: %w", boolErr)
				}
				if len(rawVal_ecallindication) == 1 {
					v.EcallIndicationRaw_ = rawVal_ecallindication[0]
				}
				v.EcallIndication = &decVal_ecallindication
				offset += n_ecallindication
			}
		}
	}
	// Decode fallbackAttribute
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 38 {
				_, n_fallbackattribute, rawVal_fallbackattribute, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding fallbackAttribute: %w", err)
				}
				decVal_fallbackattribute, boolErr := ber.DecodeBooleanValue(rawVal_fallbackattribute)
				if boolErr != nil {
					return fmt.Errorf("decoding fallbackAttribute: %w", boolErr)
				}
				if len(rawVal_fallbackattribute) == 1 {
					v.FallbackAttributeRaw_ = rawVal_fallbackattribute[0]
				}
				v.FallbackAttribute = &decVal_fallbackattribute
				offset += n_fallbackattribute
			}
		}
	}
	// Decode fallbackAllowed
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 103 {
				_, n_fallbackallowed, rawVal_fallbackallowed, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding fallbackAllowed: %w", err)
				}
				decVal_fallbackallowed, boolErr := ber.DecodeBooleanValue(rawVal_fallbackallowed)
				if boolErr != nil {
					return fmt.Errorf("decoding fallbackAllowed: %w", boolErr)
				}
				if len(rawVal_fallbackallowed) == 1 {
					v.FallbackAllowedRaw_ = rawVal_fallbackallowed[0]
				}
				v.FallbackAllowed = &decVal_fallbackallowed
				offset += n_fallbackallowed
			}
		}
	}
	// Decode iotSpecificProfileInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 100 {
				_, n_iotspecificprofileinfo, rawVal_iotspecificprofileinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iotSpecificProfileInfo: %w", err)
				}
				reconstructed_iotspecificprofileinfo := ber.EncodeSequence(rawVal_iotspecificprofileinfo)
				var dec_iotspecificprofileinfo ProfileInfoIotSpecificProfileInfo
				if unmErr := dec_iotspecificprofileinfo.UnmarshalBER(reconstructed_iotspecificprofileinfo); unmErr != nil {
					return fmt.Errorf("decoding iotSpecificProfileInfo: %w", unmErr)
				}
				v.IotSpecificProfileInfo = &dec_iotspecificprofileinfo
				offset += n_iotspecificprofileinfo
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProfileInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes UpdateMetadataRequest to BER format.
func (v *UpdateMetadataRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ServiceProviderName != nil {
		enc_serviceprovidername := ber.EncodeStringTag(12, *v.ServiceProviderName)
		enc_serviceprovidername = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, false, enc_serviceprovidername)
		children = append(children, enc_serviceprovidername...)
	}
	if v.ProfileName != nil {
		enc_profilename := ber.EncodeStringTag(12, *v.ProfileName)
		enc_profilename = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_profilename)
		children = append(children, enc_profilename...)
	}
	if v.IconType != nil {
		enc_icontype := ber.EncodeInteger(int64(*v.IconType))
		enc_icontype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_icontype)
		children = append(children, enc_icontype...)
	}
	if v.Icon != nil {
		enc_icon := ber.EncodeOctetString(v.Icon)
		enc_icon = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, false, enc_icon)
		children = append(children, enc_icon...)
	}
	if v.ProfilePolicyRules != nil {
		enc_profilepolicyrules := ber.EncodeBitString(v.ProfilePolicyRules.Bytes, (8-(v.ProfilePolicyRules.BitLength%8))%8)
		enc_profilepolicyrules = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, false, enc_profilepolicyrules)
		children = append(children, enc_profilepolicyrules...)
	}
	if v.ServiceSpecificDataStoredInEuicc != nil {
		enc_servicespecificdatastoredineuicc, err := sgp22.MarshalBERVendorSpecificExtension(v.ServiceSpecificDataStoredInEuicc)
		if err != nil {
			return nil, fmt.Errorf("encoding serviceSpecificDataStoredInEuicc: %w", err)
		}
		if v.ServiceSpecificDataStoredInEuiccIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_servicespecificdatastoredineuicc)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_servicespecificdatastoredineuicc = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 34}, seqContent_)
		} else {
			enc_servicespecificdatastoredineuicc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 34, true, enc_servicespecificdatastoredineuicc)
		}
		children = append(children, enc_servicespecificdatastoredineuicc...)
	}
	if v.FallbackAllowed != nil {
		var enc_fallbackallowed []byte
		if v.FallbackAllowedRaw_ != 0 {
			enc_fallbackallowed = ber.EncodeBooleanRaw(v.FallbackAllowedRaw_)
		} else {
			enc_fallbackallowed = ber.EncodeBoolean(*v.FallbackAllowed)
		}
		enc_fallbackallowed = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 103, false, enc_fallbackallowed)
		children = append(children, enc_fallbackallowed...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 42, Constructed: true}, children), nil
}

// MarshalDER encodes UpdateMetadataRequest to DER format.
func (v *UpdateMetadataRequest) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ServiceSpecificDataStoredInEuiccIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes UpdateMetadataRequest from BER/DER format.
func (v *UpdateMetadataRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding UpdateMetadataRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 42 || !decodedTag.Constructed {
		return fmt.Errorf("decoding UpdateMetadataRequest: %w: expected tag [CONTEXT 42], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UpdateMetadataRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode serviceProviderName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				_, n_serviceprovidername, rawVal_serviceprovidername, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceProviderName: %w", err)
				}
				decVal_serviceprovidername := ber.DecodeStringValue(rawVal_serviceprovidername)
				v.ServiceProviderName = &decVal_serviceprovidername
				offset += n_serviceprovidername
			}
		}
	}
	// Decode profileName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				_, n_profilename, rawVal_profilename, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileName: %w", err)
				}
				decVal_profilename := ber.DecodeStringValue(rawVal_profilename)
				v.ProfileName = &decVal_profilename
				offset += n_profilename
			}
		}
	}
	// Decode iconType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_icontype, rawVal_icontype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iconType: %w", err)
				}
				decVal_icontype, intErr := ber.DecodeIntegerValue(rawVal_icontype)
				if intErr != nil {
					return fmt.Errorf("decoding iconType: %w", intErr)
				}
				tmp_icontype := sgp22.IconType(decVal_icontype)
				v.IconType = &tmp_icontype
				offset += n_icontype
			}
		}
	}
	// Decode icon
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				_, n_icon, rawVal_icon, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding icon: %w", err)
				}
				tmp_icon := rawVal_icon
				v.Icon = tmp_icon
				offset += n_icon
			}
		}
	}
	// Decode profilePolicyRules
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				_, n_profilepolicyrules, rawVal_profilepolicyrules, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", err)
				}
				bsBytes_profilepolicyrules, bsUnused_profilepolicyrules, bsErr := ber.DecodeBitStringValue(rawVal_profilepolicyrules)
				if bsErr != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", bsErr)
				}
				tmp_profilepolicyrules := runtime.BitString{Bytes: bsBytes_profilepolicyrules, BitLength: len(bsBytes_profilepolicyrules)*8 - bsUnused_profilepolicyrules}
				v.ProfilePolicyRules = &tmp_profilepolicyrules
				offset += n_profilepolicyrules
			}
		}
	}
	// Decode serviceSpecificDataStoredInEuicc
	v.ServiceSpecificDataStoredInEuiccIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 34 {
				_, n_servicespecificdatastoredineuicc, rawVal_servicespecificdatastoredineuicc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", err)
				}
				reconstructed_servicespecificdatastoredineuicc := ber.EncodeSequence(rawVal_servicespecificdatastoredineuicc)
				dec_servicespecificdatastoredineuicc, unmErr := sgp22.UnmarshalBERVendorSpecificExtension(reconstructed_servicespecificdatastoredineuicc)
				if unmErr != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", unmErr)
				}
				v.ServiceSpecificDataStoredInEuicc = dec_servicespecificdatastoredineuicc
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ServiceSpecificDataStoredInEuiccIndef_ = true
					}
				}
				offset += n_servicespecificdatastoredineuicc
			}
		}
	}
	// Decode fallbackAllowed
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 103 {
				_, n_fallbackallowed, rawVal_fallbackallowed, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding fallbackAllowed: %w", err)
				}
				decVal_fallbackallowed, boolErr := ber.DecodeBooleanValue(rawVal_fallbackallowed)
				if boolErr != nil {
					return fmt.Errorf("decoding fallbackAllowed: %w", boolErr)
				}
				if len(rawVal_fallbackallowed) == 1 {
					v.FallbackAllowedRaw_ = rawVal_fallbackallowed[0]
				}
				v.FallbackAllowed = &decVal_fallbackallowed
				offset += n_fallbackallowed
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "UpdateMetadataRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes StoreMetadataRequest to BER format.
func (v *StoreMetadataRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_iccid := ber.EncodeOctetString([]byte(v.Iccid))
	enc_iccid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_iccid)
	children = append(children, enc_iccid...)
	enc_serviceprovidername := ber.EncodeStringTag(12, v.ServiceProviderName)
	enc_serviceprovidername = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, false, enc_serviceprovidername)
	children = append(children, enc_serviceprovidername...)
	enc_profilename := ber.EncodeStringTag(12, v.ProfileName)
	enc_profilename = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_profilename)
	children = append(children, enc_profilename...)
	if v.IconType != nil {
		enc_icontype := ber.EncodeInteger(int64(*v.IconType))
		enc_icontype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_icontype)
		children = append(children, enc_icontype...)
	}
	if v.Icon != nil {
		enc_icon := ber.EncodeOctetString(v.Icon)
		enc_icon = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, false, enc_icon)
		children = append(children, enc_icon...)
	}
	if v.ProfileClass != nil {
		enc_profileclass := ber.EncodeInteger(int64(*v.ProfileClass))
		enc_profileclass = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, false, enc_profileclass)
		children = append(children, enc_profileclass...)
	}
	if v.NotificationConfigurationInfo != nil {
		enc_notificationconfigurationinfo, err := MarshalBERStoreMetadataRequestNotificationConfigurationInfo(v.NotificationConfigurationInfo)
		if err != nil {
			return nil, fmt.Errorf("encoding notificationConfigurationInfo: %w", err)
		}
		if v.NotificationConfigurationInfoIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_notificationconfigurationinfo)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_notificationconfigurationinfo = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 22}, seqContent_)
		} else {
			enc_notificationconfigurationinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, true, enc_notificationconfigurationinfo)
		}
		children = append(children, enc_notificationconfigurationinfo...)
	}
	if v.ProfileOwner != nil {
		enc_profileowner, err := v.ProfileOwner.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileOwner: %w", err)
		}
		enc_profileowner = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, true, enc_profileowner)
		children = append(children, enc_profileowner...)
	}
	if v.ProfilePolicyRules != nil {
		enc_profilepolicyrules := ber.EncodeBitString(v.ProfilePolicyRules.Bytes, (8-(v.ProfilePolicyRules.BitLength%8))%8)
		enc_profilepolicyrules = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, false, enc_profilepolicyrules)
		children = append(children, enc_profilepolicyrules...)
	}
	if v.ServiceSpecificDataStoredInEuicc != nil {
		enc_servicespecificdatastoredineuicc, err := sgp22.MarshalBERVendorSpecificExtension(v.ServiceSpecificDataStoredInEuicc)
		if err != nil {
			return nil, fmt.Errorf("encoding serviceSpecificDataStoredInEuicc: %w", err)
		}
		if v.ServiceSpecificDataStoredInEuiccIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_servicespecificdatastoredineuicc)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_servicespecificdatastoredineuicc = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 34}, seqContent_)
		} else {
			enc_servicespecificdatastoredineuicc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 34, true, enc_servicespecificdatastoredineuicc)
		}
		children = append(children, enc_servicespecificdatastoredineuicc...)
	}
	if v.ServiceSpecificDataNotStoredInEuicc != nil {
		enc_servicespecificdatanotstoredineuicc, err := sgp22.MarshalBERVendorSpecificExtension(v.ServiceSpecificDataNotStoredInEuicc)
		if err != nil {
			return nil, fmt.Errorf("encoding serviceSpecificDataNotStoredInEuicc: %w", err)
		}
		if v.ServiceSpecificDataNotStoredInEuiccIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_servicespecificdatanotstoredineuicc)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_servicespecificdatanotstoredineuicc = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 35}, seqContent_)
		} else {
			enc_servicespecificdatanotstoredineuicc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 35, true, enc_servicespecificdatanotstoredineuicc)
		}
		children = append(children, enc_servicespecificdatanotstoredineuicc...)
	}
	if v.EcallIndication != nil {
		var enc_ecallindication []byte
		if v.EcallIndicationRaw_ != 0 {
			enc_ecallindication = ber.EncodeBooleanRaw(v.EcallIndicationRaw_)
		} else {
			enc_ecallindication = ber.EncodeBoolean(*v.EcallIndication)
		}
		enc_ecallindication = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 123, false, enc_ecallindication)
		children = append(children, enc_ecallindication...)
	}
	if v.FallbackAllowed != nil {
		var enc_fallbackallowed []byte
		if v.FallbackAllowedRaw_ != 0 {
			enc_fallbackallowed = ber.EncodeBooleanRaw(v.FallbackAllowedRaw_)
		} else {
			enc_fallbackallowed = ber.EncodeBoolean(*v.FallbackAllowed)
		}
		enc_fallbackallowed = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 103, false, enc_fallbackallowed)
		children = append(children, enc_fallbackallowed...)
	}
	if v.IotSpecificMetadata != nil {
		enc_iotspecificmetadata, err := v.IotSpecificMetadata.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding iotSpecificMetadata: %w", err)
		}
		enc_iotspecificmetadata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 100, true, enc_iotspecificmetadata)
		children = append(children, enc_iotspecificmetadata...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 37, Constructed: true}, children), nil
}

// MarshalDER encodes StoreMetadataRequest to DER format.
func (v *StoreMetadataRequest) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.NotificationConfigurationInfoIndef_ = false
	derValue.ServiceSpecificDataStoredInEuiccIndef_ = false
	derValue.ServiceSpecificDataNotStoredInEuiccIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes StoreMetadataRequest from BER/DER format.
func (v *StoreMetadataRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding StoreMetadataRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 37 || !decodedTag.Constructed {
		return fmt.Errorf("decoding StoreMetadataRequest: %w: expected tag [CONTEXT 37], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "StoreMetadataRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode iccid
	if offset >= len(content) {
		return fmt.Errorf("missing required field iccid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 26 {
			return fmt.Errorf("expected tag [%s %d] for iccid, got %s", "APPLICATION", 26, reqTag_)
		}
	}
	_, n_iccid, rawVal_iccid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding iccid: %w", err)
	}
	v.Iccid = sgp22.Iccid(rawVal_iccid)
	offset += n_iccid
	// Decode serviceProviderName
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceProviderName")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 17 {
			return fmt.Errorf("expected tag [%s %d] for serviceProviderName, got %s", "CONTEXT", 17, reqTag_)
		}
	}
	_, n_serviceprovidername, rawVal_serviceprovidername, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serviceProviderName: %w", err)
	}
	decVal_serviceprovidername := ber.DecodeStringValue(rawVal_serviceprovidername)
	v.ServiceProviderName = decVal_serviceprovidername
	offset += n_serviceprovidername
	// Decode profileName
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileName")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 18 {
			return fmt.Errorf("expected tag [%s %d] for profileName, got %s", "CONTEXT", 18, reqTag_)
		}
	}
	_, n_profilename, rawVal_profilename, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding profileName: %w", err)
	}
	decVal_profilename := ber.DecodeStringValue(rawVal_profilename)
	v.ProfileName = decVal_profilename
	offset += n_profilename
	// Decode iconType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_icontype, rawVal_icontype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iconType: %w", err)
				}
				decVal_icontype, intErr := ber.DecodeIntegerValue(rawVal_icontype)
				if intErr != nil {
					return fmt.Errorf("decoding iconType: %w", intErr)
				}
				tmp_icontype := sgp22.IconType(decVal_icontype)
				v.IconType = &tmp_icontype
				offset += n_icontype
			}
		}
	}
	// Decode icon
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				_, n_icon, rawVal_icon, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding icon: %w", err)
				}
				tmp_icon := rawVal_icon
				v.Icon = tmp_icon
				offset += n_icon
			}
		}
	}
	// Decode profileClass
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				_, n_profileclass, rawVal_profileclass, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileClass: %w", err)
				}
				decVal_profileclass, intErr := ber.DecodeIntegerValue(rawVal_profileclass)
				if intErr != nil {
					return fmt.Errorf("decoding profileClass: %w", intErr)
				}
				tmp_profileclass := sgp22.ProfileClass(decVal_profileclass)
				v.ProfileClass = &tmp_profileclass
				offset += n_profileclass
			}
		}
	}
	// Decode notificationConfigurationInfo
	v.NotificationConfigurationInfoIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				_, n_notificationconfigurationinfo, rawVal_notificationconfigurationinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding notificationConfigurationInfo: %w", err)
				}
				reconstructed_notificationconfigurationinfo := ber.EncodeSequence(rawVal_notificationconfigurationinfo)
				dec_notificationconfigurationinfo, unmErr := UnmarshalBERStoreMetadataRequestNotificationConfigurationInfo(reconstructed_notificationconfigurationinfo)
				if unmErr != nil {
					return fmt.Errorf("decoding notificationConfigurationInfo: %w", unmErr)
				}
				v.NotificationConfigurationInfo = dec_notificationconfigurationinfo
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.NotificationConfigurationInfoIndef_ = true
					}
				}
				offset += n_notificationconfigurationinfo
			}
		}
	}
	// Decode profileOwner
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				_, n_profileowner, rawVal_profileowner, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileOwner: %w", err)
				}
				reconstructed_profileowner := ber.EncodeSequence(rawVal_profileowner)
				var dec_profileowner sgp22.OperatorId
				if unmErr := dec_profileowner.UnmarshalBER(reconstructed_profileowner); unmErr != nil {
					return fmt.Errorf("decoding profileOwner: %w", unmErr)
				}
				v.ProfileOwner = &dec_profileowner
				offset += n_profileowner
			}
		}
	}
	// Decode profilePolicyRules
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				_, n_profilepolicyrules, rawVal_profilepolicyrules, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", err)
				}
				bsBytes_profilepolicyrules, bsUnused_profilepolicyrules, bsErr := ber.DecodeBitStringValue(rawVal_profilepolicyrules)
				if bsErr != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", bsErr)
				}
				tmp_profilepolicyrules := runtime.BitString{Bytes: bsBytes_profilepolicyrules, BitLength: len(bsBytes_profilepolicyrules)*8 - bsUnused_profilepolicyrules}
				v.ProfilePolicyRules = &tmp_profilepolicyrules
				offset += n_profilepolicyrules
			}
		}
	}
	// Decode serviceSpecificDataStoredInEuicc
	v.ServiceSpecificDataStoredInEuiccIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 34 {
				_, n_servicespecificdatastoredineuicc, rawVal_servicespecificdatastoredineuicc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", err)
				}
				reconstructed_servicespecificdatastoredineuicc := ber.EncodeSequence(rawVal_servicespecificdatastoredineuicc)
				dec_servicespecificdatastoredineuicc, unmErr := sgp22.UnmarshalBERVendorSpecificExtension(reconstructed_servicespecificdatastoredineuicc)
				if unmErr != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", unmErr)
				}
				v.ServiceSpecificDataStoredInEuicc = dec_servicespecificdatastoredineuicc
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ServiceSpecificDataStoredInEuiccIndef_ = true
					}
				}
				offset += n_servicespecificdatastoredineuicc
			}
		}
	}
	// Decode serviceSpecificDataNotStoredInEuicc
	v.ServiceSpecificDataNotStoredInEuiccIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 35 {
				_, n_servicespecificdatanotstoredineuicc, rawVal_servicespecificdatanotstoredineuicc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceSpecificDataNotStoredInEuicc: %w", err)
				}
				reconstructed_servicespecificdatanotstoredineuicc := ber.EncodeSequence(rawVal_servicespecificdatanotstoredineuicc)
				dec_servicespecificdatanotstoredineuicc, unmErr := sgp22.UnmarshalBERVendorSpecificExtension(reconstructed_servicespecificdatanotstoredineuicc)
				if unmErr != nil {
					return fmt.Errorf("decoding serviceSpecificDataNotStoredInEuicc: %w", unmErr)
				}
				v.ServiceSpecificDataNotStoredInEuicc = dec_servicespecificdatanotstoredineuicc
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ServiceSpecificDataNotStoredInEuiccIndef_ = true
					}
				}
				offset += n_servicespecificdatanotstoredineuicc
			}
		}
	}
	// Decode ecallIndication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 123 {
				_, n_ecallindication, rawVal_ecallindication, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ecallIndication: %w", err)
				}
				decVal_ecallindication, boolErr := ber.DecodeBooleanValue(rawVal_ecallindication)
				if boolErr != nil {
					return fmt.Errorf("decoding ecallIndication: %w", boolErr)
				}
				if len(rawVal_ecallindication) == 1 {
					v.EcallIndicationRaw_ = rawVal_ecallindication[0]
				}
				v.EcallIndication = &decVal_ecallindication
				offset += n_ecallindication
			}
		}
	}
	// Decode fallbackAllowed
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 103 {
				_, n_fallbackallowed, rawVal_fallbackallowed, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding fallbackAllowed: %w", err)
				}
				decVal_fallbackallowed, boolErr := ber.DecodeBooleanValue(rawVal_fallbackallowed)
				if boolErr != nil {
					return fmt.Errorf("decoding fallbackAllowed: %w", boolErr)
				}
				if len(rawVal_fallbackallowed) == 1 {
					v.FallbackAllowedRaw_ = rawVal_fallbackallowed[0]
				}
				v.FallbackAllowed = &decVal_fallbackallowed
				offset += n_fallbackallowed
			}
		}
	}
	// Decode iotSpecificMetadata
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 100 {
				_, n_iotspecificmetadata, rawVal_iotspecificmetadata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iotSpecificMetadata: %w", err)
				}
				reconstructed_iotspecificmetadata := ber.EncodeSequence(rawVal_iotspecificmetadata)
				var dec_iotspecificmetadata StoreMetadataRequestIotSpecificMetadata
				if unmErr := dec_iotspecificmetadata.UnmarshalBER(reconstructed_iotspecificmetadata); unmErr != nil {
					return fmt.Errorf("decoding iotSpecificMetadata: %w", unmErr)
				}
				v.IotSpecificMetadata = &dec_iotspecificmetadata
				offset += n_iotspecificmetadata
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "StoreMetadataRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AuthenticateClientRequest to BER format.
func (v *AuthenticateClientRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_authenticateserverresponse, err := v.AuthenticateServerResponse.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding authenticateServerResponse: %w", err)
	}
	children = append(children, enc_authenticateserverresponse...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 59, Constructed: true}, children), nil
}

// MarshalDER encodes AuthenticateClientRequest to DER format.
func (v *AuthenticateClientRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateClientRequest from BER/DER format.
func (v *AuthenticateClientRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateClientRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 59 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AuthenticateClientRequest: %w: expected tag [CONTEXT 59], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = sgp22.TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode authenticateServerResponse
	if offset >= len(content) {
		return fmt.Errorf("missing required field authenticateServerResponse")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 56 {
			return fmt.Errorf("expected tag [%s %d] for authenticateServerResponse, got %s", "CONTEXT", 56, reqTag_)
		}
	}
	// Decode nested CHOICE (AuthenticateServerResponse)
	_, n_authenticateserverresponse, _, tlvErr_authenticateserverresponse := ber.DecodeTLV(content[offset:])
	if tlvErr_authenticateserverresponse != nil {
		return fmt.Errorf("decoding authenticateServerResponse: %w", tlvErr_authenticateserverresponse)
	}
	if unmErr := v.AuthenticateServerResponse.UnmarshalBER(content[offset : offset+n_authenticateserverresponse]); unmErr != nil {
		return fmt.Errorf("decoding authenticateServerResponse: %w", unmErr)
	}
	offset += n_authenticateserverresponse
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateClientRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EUICCInfo2 to BER format.
func (v *EUICCInfo2) MarshalBER() ([]byte, error) {
	var children []byte
	enc_profileversion := ber.EncodeOctetString([]byte(v.ProfileVersion))
	enc_profileversion = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_profileversion)
	children = append(children, enc_profileversion...)
	enc_svn := ber.EncodeOctetString([]byte(v.Svn))
	enc_svn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_svn)
	children = append(children, enc_svn...)
	enc_euiccfirmwarever := ber.EncodeOctetString([]byte(v.EuiccFirmwareVer))
	enc_euiccfirmwarever = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_euiccfirmwarever)
	children = append(children, enc_euiccfirmwarever...)
	enc_extcardresource := ber.EncodeOctetString(v.ExtCardResource)
	enc_extcardresource = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_extcardresource)
	children = append(children, enc_extcardresource...)
	enc_uicccapability := ber.EncodeBitString(v.UiccCapability.Bytes, (8-(v.UiccCapability.BitLength%8))%8)
	enc_uicccapability = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_uicccapability)
	children = append(children, enc_uicccapability...)
	if v.Ts102241Version != nil {
		enc_ts102241version := ber.EncodeOctetString([]byte(*v.Ts102241Version))
		enc_ts102241version = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_ts102241version)
		children = append(children, enc_ts102241version...)
	}
	if v.GlobalplatformVersion != nil {
		enc_globalplatformversion := ber.EncodeOctetString([]byte(*v.GlobalplatformVersion))
		enc_globalplatformversion = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_globalplatformversion)
		children = append(children, enc_globalplatformversion...)
	}
	enc_rspcapability := ber.EncodeBitString(v.RspCapability.Bytes, (8-(v.RspCapability.BitLength%8))%8)
	enc_rspcapability = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_rspcapability)
	children = append(children, enc_rspcapability...)
	enc_euicccipkidlistforverification, err := MarshalBEREUICCInfo2EuiccCiPKIdListForVerification(v.EuiccCiPKIdListForVerification)
	if err != nil {
		return nil, fmt.Errorf("encoding euiccCiPKIdListForVerification: %w", err)
	}
	if v.EuiccCiPKIdListForVerificationIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_euicccipkidlistforverification)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_euicccipkidlistforverification = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 9}, seqContent_)
	} else {
		enc_euicccipkidlistforverification = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_euicccipkidlistforverification)
	}
	children = append(children, enc_euicccipkidlistforverification...)
	enc_euicccipkidlistforsigning, err := MarshalBEREUICCInfo2EuiccCiPKIdListForSigning(v.EuiccCiPKIdListForSigning)
	if err != nil {
		return nil, fmt.Errorf("encoding euiccCiPKIdListForSigning: %w", err)
	}
	if v.EuiccCiPKIdListForSigningIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_euicccipkidlistforsigning)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_euicccipkidlistforsigning = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 10}, seqContent_)
	} else {
		enc_euicccipkidlistforsigning = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_euicccipkidlistforsigning)
	}
	children = append(children, enc_euicccipkidlistforsigning...)
	if v.EuiccCategory != nil {
		enc_euicccategory := ber.EncodeInteger(int64(*v.EuiccCategory))
		enc_euicccategory = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_euicccategory)
		children = append(children, enc_euicccategory...)
	}
	if v.ForbiddenProfilePolicyRules != nil {
		enc_forbiddenprofilepolicyrules := ber.EncodeBitString(v.ForbiddenProfilePolicyRules.Bytes, (8-(v.ForbiddenProfilePolicyRules.BitLength%8))%8)
		enc_forbiddenprofilepolicyrules = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, false, enc_forbiddenprofilepolicyrules)
		children = append(children, enc_forbiddenprofilepolicyrules...)
	}
	enc_ppversion := ber.EncodeOctetString([]byte(v.PpVersion))
	children = append(children, enc_ppversion...)
	enc_sasacreditationnumber := ber.EncodeStringTag(12, v.SasAcreditationNumber)
	children = append(children, enc_sasacreditationnumber...)
	if v.CertificationDataObject != nil {
		enc_certificationdataobject, err := v.CertificationDataObject.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding certificationDataObject: %w", err)
		}
		enc_certificationdataobject = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, true, enc_certificationdataobject)
		children = append(children, enc_certificationdataobject...)
	}
	if v.TreProperties != nil {
		enc_treproperties := ber.EncodeBitString(v.TreProperties.Bytes, (8-(v.TreProperties.BitLength%8))%8)
		enc_treproperties = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, false, enc_treproperties)
		children = append(children, enc_treproperties...)
	}
	if v.TreProductReference != nil {
		enc_treproductreference := ber.EncodeStringTag(12, *v.TreProductReference)
		enc_treproductreference = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, false, enc_treproductreference)
		children = append(children, enc_treproductreference...)
	}
	if v.AdditionalEuiccProfilePackageVersions != nil {
		enc_additionaleuiccprofilepackageversions, err := MarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions(v.AdditionalEuiccProfilePackageVersions)
		if err != nil {
			return nil, fmt.Errorf("encoding additionalEuiccProfilePackageVersions: %w", err)
		}
		if v.AdditionalEuiccProfilePackageVersionsIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_additionaleuiccprofilepackageversions)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_additionaleuiccprofilepackageversions = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 15}, seqContent_)
		} else {
			enc_additionaleuiccprofilepackageversions = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, true, enc_additionaleuiccprofilepackageversions)
		}
		children = append(children, enc_additionaleuiccprofilepackageversions...)
	}
	if v.IpaMode != nil {
		enc_ipamode := ber.EncodeInteger(int64(*v.IpaMode))
		enc_ipamode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_ipamode)
		children = append(children, enc_ipamode...)
	}
	if v.EuiccCiPKIdListForSigningV3 != nil {
		enc_euicccipkidlistforsigningv3, err := MarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3(v.EuiccCiPKIdListForSigningV3)
		if err != nil {
			return nil, fmt.Errorf("encoding euiccCiPKIdListForSigningV3: %w", err)
		}
		if v.EuiccCiPKIdListForSigningV3Indef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_euicccipkidlistforsigningv3)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_euicccipkidlistforsigningv3 = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 17}, seqContent_)
		} else {
			enc_euicccipkidlistforsigningv3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, true, enc_euicccipkidlistforsigningv3)
		}
		children = append(children, enc_euicccipkidlistforsigningv3...)
	}
	if v.AdditionalEuiccInfo != nil {
		enc_additionaleuiccinfo := ber.EncodeOctetString(v.AdditionalEuiccInfo)
		enc_additionaleuiccinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_additionaleuiccinfo)
		children = append(children, enc_additionaleuiccinfo...)
	}
	if v.HighestSvn != nil {
		enc_highestsvn := ber.EncodeOctetString([]byte(*v.HighestSvn))
		enc_highestsvn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_highestsvn)
		children = append(children, enc_highestsvn...)
	}
	if v.IotSpecificInfo != nil {
		enc_iotspecificinfo, err := v.IotSpecificInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding iotSpecificInfo: %w", err)
		}
		enc_iotspecificinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, true, enc_iotspecificinfo)
		children = append(children, enc_iotspecificinfo...)
	}
	if v.EuiccMinimumSecurityLevel != nil {
		enc_euiccminimumsecuritylevel := ber.EncodeOctetString(v.EuiccMinimumSecurityLevel)
		enc_euiccminimumsecuritylevel = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, false, enc_euiccminimumsecuritylevel)
		children = append(children, enc_euiccminimumsecuritylevel...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 34, Constructed: true}, children), nil
}

// MarshalDER encodes EUICCInfo2 to DER format.
func (v *EUICCInfo2) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.EuiccCiPKIdListForVerificationIndef_ = false
	derValue.EuiccCiPKIdListForSigningIndef_ = false
	derValue.AdditionalEuiccProfilePackageVersionsIndef_ = false
	derValue.EuiccCiPKIdListForSigningV3Indef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes EUICCInfo2 from BER/DER format.
func (v *EUICCInfo2) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EUICCInfo2: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 34 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EUICCInfo2: %w: expected tag [CONTEXT 34], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EUICCInfo2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode profileVersion
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileVersion")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for profileVersion, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_profileversion, rawVal_profileversion, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding profileVersion: %w", err)
	}
	v.ProfileVersion = sgp22.VersionType(rawVal_profileversion)
	offset += n_profileversion
	// Decode svn
	if offset >= len(content) {
		return fmt.Errorf("missing required field svn")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for svn, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_svn, rawVal_svn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding svn: %w", err)
	}
	v.Svn = sgp22.VersionType(rawVal_svn)
	offset += n_svn
	// Decode euiccFirmwareVer
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccFirmwareVer")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for euiccFirmwareVer, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_euiccfirmwarever, rawVal_euiccfirmwarever, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccFirmwareVer: %w", err)
	}
	v.EuiccFirmwareVer = sgp22.VersionType(rawVal_euiccfirmwarever)
	offset += n_euiccfirmwarever
	// Decode extCardResource
	if offset >= len(content) {
		return fmt.Errorf("missing required field extCardResource")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for extCardResource, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	_, n_extcardresource, rawVal_extcardresource, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding extCardResource: %w", err)
	}
	v.ExtCardResource = rawVal_extcardresource
	offset += n_extcardresource
	// Decode uiccCapability
	if offset >= len(content) {
		return fmt.Errorf("missing required field uiccCapability")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 5 {
			return fmt.Errorf("expected tag [%s %d] for uiccCapability, got %s", "CONTEXT", 5, reqTag_)
		}
	}
	_, n_uicccapability, rawVal_uicccapability, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uiccCapability: %w", err)
	}
	bsBytes_uicccapability, bsUnused_uicccapability, bsErr := ber.DecodeBitStringValue(rawVal_uicccapability)
	if bsErr != nil {
		return fmt.Errorf("decoding uiccCapability: %w", bsErr)
	}
	v.UiccCapability = runtime.BitString{Bytes: bsBytes_uicccapability, BitLength: len(bsBytes_uicccapability)*8 - bsUnused_uicccapability}
	offset += n_uicccapability
	// Decode ts102241Version
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_ts102241version, rawVal_ts102241version, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ts102241Version: %w", err)
				}
				tmp_ts102241version := sgp22.VersionType(rawVal_ts102241version)
				v.Ts102241Version = &tmp_ts102241version
				offset += n_ts102241version
			}
		}
	}
	// Decode globalplatformVersion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_globalplatformversion, rawVal_globalplatformversion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding globalplatformVersion: %w", err)
				}
				tmp_globalplatformversion := sgp22.VersionType(rawVal_globalplatformversion)
				v.GlobalplatformVersion = &tmp_globalplatformversion
				offset += n_globalplatformversion
			}
		}
	}
	// Decode rspCapability
	if offset >= len(content) {
		return fmt.Errorf("missing required field rspCapability")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 8 {
			return fmt.Errorf("expected tag [%s %d] for rspCapability, got %s", "CONTEXT", 8, reqTag_)
		}
	}
	_, n_rspcapability, rawVal_rspcapability, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding rspCapability: %w", err)
	}
	bsBytes_rspcapability, bsUnused_rspcapability, bsErr := ber.DecodeBitStringValue(rawVal_rspcapability)
	if bsErr != nil {
		return fmt.Errorf("decoding rspCapability: %w", bsErr)
	}
	v.RspCapability = runtime.BitString{Bytes: bsBytes_rspcapability, BitLength: len(bsBytes_rspcapability)*8 - bsUnused_rspcapability}
	offset += n_rspcapability
	// Decode euiccCiPKIdListForVerification
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCiPKIdListForVerification")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 9 {
			return fmt.Errorf("expected tag [%s %d] for euiccCiPKIdListForVerification, got %s", "CONTEXT", 9, reqTag_)
		}
	}
	v.EuiccCiPKIdListForVerificationIndef_ = false
	_, n_euicccipkidlistforverification, rawVal_euicccipkidlistforverification, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForVerification: %w", err)
	}
	reconstructed_euicccipkidlistforverification := ber.EncodeSequence(rawVal_euicccipkidlistforverification)
	dec_euicccipkidlistforverification, unmErr := UnmarshalBEREUICCInfo2EuiccCiPKIdListForVerification(reconstructed_euicccipkidlistforverification)
	if unmErr != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForVerification: %w", unmErr)
	}
	v.EuiccCiPKIdListForVerification = dec_euicccipkidlistforverification
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.EuiccCiPKIdListForVerificationIndef_ = true
		}
	}
	offset += n_euicccipkidlistforverification
	// Decode euiccCiPKIdListForSigning
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCiPKIdListForSigning")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 10 {
			return fmt.Errorf("expected tag [%s %d] for euiccCiPKIdListForSigning, got %s", "CONTEXT", 10, reqTag_)
		}
	}
	v.EuiccCiPKIdListForSigningIndef_ = false
	_, n_euicccipkidlistforsigning, rawVal_euicccipkidlistforsigning, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForSigning: %w", err)
	}
	reconstructed_euicccipkidlistforsigning := ber.EncodeSequence(rawVal_euicccipkidlistforsigning)
	dec_euicccipkidlistforsigning, unmErr := UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigning(reconstructed_euicccipkidlistforsigning)
	if unmErr != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForSigning: %w", unmErr)
	}
	v.EuiccCiPKIdListForSigning = dec_euicccipkidlistforsigning
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.EuiccCiPKIdListForSigningIndef_ = true
		}
	}
	offset += n_euicccipkidlistforsigning
	// Decode euiccCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				_, n_euicccategory, rawVal_euicccategory, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccCategory: %w", err)
				}
				decVal_euicccategory, intErr := ber.DecodeIntegerValue(rawVal_euicccategory)
				if intErr != nil {
					return fmt.Errorf("decoding euiccCategory: %w", intErr)
				}
				v.EuiccCategory = &decVal_euicccategory
				offset += n_euicccategory
			}
		}
	}
	// Decode forbiddenProfilePolicyRules
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				_, n_forbiddenprofilepolicyrules, rawVal_forbiddenprofilepolicyrules, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forbiddenProfilePolicyRules: %w", err)
				}
				bsBytes_forbiddenprofilepolicyrules, bsUnused_forbiddenprofilepolicyrules, bsErr := ber.DecodeBitStringValue(rawVal_forbiddenprofilepolicyrules)
				if bsErr != nil {
					return fmt.Errorf("decoding forbiddenProfilePolicyRules: %w", bsErr)
				}
				tmp_forbiddenprofilepolicyrules := runtime.BitString{Bytes: bsBytes_forbiddenprofilepolicyrules, BitLength: len(bsBytes_forbiddenprofilepolicyrules)*8 - bsUnused_forbiddenprofilepolicyrules}
				v.ForbiddenProfilePolicyRules = &tmp_forbiddenprofilepolicyrules
				offset += n_forbiddenprofilepolicyrules
			}
		}
	}
	// Decode ppVersion
	if offset >= len(content) {
		return fmt.Errorf("missing required field ppVersion")
	}
	val_ppversion, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ppVersion: %w", err)
	}
	v.PpVersion = sgp22.VersionType(val_ppversion)
	offset += n
	// Decode sasAcreditationNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field sasAcreditationNumber")
	}
	val_sasacreditationnumber, n, err := ber.DecodeString(content[offset:], 12)
	if err != nil {
		return fmt.Errorf("decoding sasAcreditationNumber: %w", err)
	}
	v.SasAcreditationNumber = val_sasacreditationnumber
	offset += n
	// Decode certificationDataObject
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				_, n_certificationdataobject, rawVal_certificationdataobject, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding certificationDataObject: %w", err)
				}
				reconstructed_certificationdataobject := ber.EncodeSequence(rawVal_certificationdataobject)
				var dec_certificationdataobject sgp22.CertificationDataObject
				if unmErr := dec_certificationdataobject.UnmarshalBER(reconstructed_certificationdataobject); unmErr != nil {
					return fmt.Errorf("decoding certificationDataObject: %w", unmErr)
				}
				v.CertificationDataObject = &dec_certificationdataobject
				offset += n_certificationdataobject
			}
		}
	}
	// Decode treProperties
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				_, n_treproperties, rawVal_treproperties, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding treProperties: %w", err)
				}
				bsBytes_treproperties, bsUnused_treproperties, bsErr := ber.DecodeBitStringValue(rawVal_treproperties)
				if bsErr != nil {
					return fmt.Errorf("decoding treProperties: %w", bsErr)
				}
				tmp_treproperties := runtime.BitString{Bytes: bsBytes_treproperties, BitLength: len(bsBytes_treproperties)*8 - bsUnused_treproperties}
				v.TreProperties = &tmp_treproperties
				offset += n_treproperties
			}
		}
	}
	// Decode treProductReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				_, n_treproductreference, rawVal_treproductreference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding treProductReference: %w", err)
				}
				decVal_treproductreference := ber.DecodeStringValue(rawVal_treproductreference)
				v.TreProductReference = &decVal_treproductreference
				offset += n_treproductreference
			}
		}
	}
	// Decode additionalEuiccProfilePackageVersions
	v.AdditionalEuiccProfilePackageVersionsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				_, n_additionaleuiccprofilepackageversions, rawVal_additionaleuiccprofilepackageversions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalEuiccProfilePackageVersions: %w", err)
				}
				reconstructed_additionaleuiccprofilepackageversions := ber.EncodeSequence(rawVal_additionaleuiccprofilepackageversions)
				dec_additionaleuiccprofilepackageversions, unmErr := UnmarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions(reconstructed_additionaleuiccprofilepackageversions)
				if unmErr != nil {
					return fmt.Errorf("decoding additionalEuiccProfilePackageVersions: %w", unmErr)
				}
				v.AdditionalEuiccProfilePackageVersions = dec_additionaleuiccprofilepackageversions
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.AdditionalEuiccProfilePackageVersionsIndef_ = true
					}
				}
				offset += n_additionaleuiccprofilepackageversions
			}
		}
	}
	// Decode ipaMode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				_, n_ipamode, rawVal_ipamode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ipaMode: %w", err)
				}
				decVal_ipamode, intErr := ber.DecodeIntegerValue(rawVal_ipamode)
				if intErr != nil {
					return fmt.Errorf("decoding ipaMode: %w", intErr)
				}
				tmp_ipamode := IpaMode(decVal_ipamode)
				v.IpaMode = &tmp_ipamode
				offset += n_ipamode
			}
		}
	}
	// Decode euiccCiPKIdListForSigningV3
	v.EuiccCiPKIdListForSigningV3Indef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				_, n_euicccipkidlistforsigningv3, rawVal_euicccipkidlistforsigningv3, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccCiPKIdListForSigningV3: %w", err)
				}
				reconstructed_euicccipkidlistforsigningv3 := ber.EncodeSequence(rawVal_euicccipkidlistforsigningv3)
				dec_euicccipkidlistforsigningv3, unmErr := UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3(reconstructed_euicccipkidlistforsigningv3)
				if unmErr != nil {
					return fmt.Errorf("decoding euiccCiPKIdListForSigningV3: %w", unmErr)
				}
				v.EuiccCiPKIdListForSigningV3 = dec_euicccipkidlistforsigningv3
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.EuiccCiPKIdListForSigningV3Indef_ = true
					}
				}
				offset += n_euicccipkidlistforsigningv3
			}
		}
	}
	// Decode additionalEuiccInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				_, n_additionaleuiccinfo, rawVal_additionaleuiccinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalEuiccInfo: %w", err)
				}
				tmp_additionaleuiccinfo := rawVal_additionaleuiccinfo
				v.AdditionalEuiccInfo = tmp_additionaleuiccinfo
				offset += n_additionaleuiccinfo
			}
		}
	}
	// Decode highestSvn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_highestsvn, rawVal_highestsvn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding highestSvn: %w", err)
				}
				tmp_highestsvn := sgp22.VersionType(rawVal_highestsvn)
				v.HighestSvn = &tmp_highestsvn
				offset += n_highestsvn
			}
		}
	}
	// Decode iotSpecificInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				_, n_iotspecificinfo, rawVal_iotspecificinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iotSpecificInfo: %w", err)
				}
				reconstructed_iotspecificinfo := ber.EncodeSequence(rawVal_iotspecificinfo)
				var dec_iotspecificinfo IoTSpecificInfo
				if unmErr := dec_iotspecificinfo.UnmarshalBER(reconstructed_iotspecificinfo); unmErr != nil {
					return fmt.Errorf("decoding iotSpecificInfo: %w", unmErr)
				}
				v.IotSpecificInfo = &dec_iotspecificinfo
				offset += n_iotspecificinfo
			}
		}
	}
	// Decode euiccMinimumSecurityLevel
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				_, n_euiccminimumsecuritylevel, rawVal_euiccminimumsecuritylevel, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccMinimumSecurityLevel: %w", err)
				}
				tmp_euiccminimumsecuritylevel := rawVal_euiccminimumsecuritylevel
				v.EuiccMinimumSecurityLevel = tmp_euiccminimumsecuritylevel
				offset += n_euiccminimumsecuritylevel
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EUICCInfo2", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes IoTSpecificInfo to BER format.
func (v *IoTSpecificInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_iotversion, err := MarshalBERIoTSpecificInfoIotVersion(v.IotVersion)
	if err != nil {
		return nil, fmt.Errorf("encoding iotVersion: %w", err)
	}
	if v.IotVersionIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_iotversion)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_iotversion = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
	} else {
		enc_iotversion = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_iotversion)
	}
	children = append(children, enc_iotversion...)
	if v.EcallSupported != nil {
		enc_ecallsupported := ber.EncodeNull()
		enc_ecallsupported = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_ecallsupported)
		children = append(children, enc_ecallsupported...)
	}
	if v.FallbackSupported != nil {
		enc_fallbacksupported := ber.EncodeNull()
		enc_fallbacksupported = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_fallbacksupported)
		children = append(children, enc_fallbacksupported...)
	}
	if v.FallbackAllowedUpdateSupported != nil {
		enc_fallbackallowedupdatesupported := ber.EncodeNull()
		enc_fallbackallowedupdatesupported = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_fallbackallowedupdatesupported)
		children = append(children, enc_fallbackallowedupdatesupported...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes IoTSpecificInfo to DER format.
func (v *IoTSpecificInfo) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.IotVersionIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes IoTSpecificInfo from BER/DER format.
func (v *IoTSpecificInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IoTSpecificInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IoTSpecificInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode iotVersion
	if offset >= len(content) {
		return fmt.Errorf("missing required field iotVersion")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for iotVersion, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	v.IotVersionIndef_ = false
	_, n_iotversion, rawVal_iotversion, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding iotVersion: %w", err)
	}
	reconstructed_iotversion := ber.EncodeSequence(rawVal_iotversion)
	dec_iotversion, unmErr := UnmarshalBERIoTSpecificInfoIotVersion(reconstructed_iotversion)
	if unmErr != nil {
		return fmt.Errorf("decoding iotVersion: %w", unmErr)
	}
	v.IotVersion = dec_iotversion
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.IotVersionIndef_ = true
		}
	}
	offset += n_iotversion
	// Decode ecallSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_ecallsupported, rawVal_ecallsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ecallSupported: %w", err)
				}
				_ = rawVal_ecallsupported
				v.EcallSupported = &struct{}{}
				offset += n_ecallsupported
			}
		}
	}
	// Decode fallbackSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_fallbacksupported, rawVal_fallbacksupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding fallbackSupported: %w", err)
				}
				_ = rawVal_fallbacksupported
				v.FallbackSupported = &struct{}{}
				offset += n_fallbacksupported
			}
		}
	}
	// Decode fallbackAllowedUpdateSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_fallbackallowedupdatesupported, rawVal_fallbackallowedupdatesupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding fallbackAllowedUpdateSupported: %w", err)
				}
				_ = rawVal_fallbackallowedupdatesupported
				v.FallbackAllowedUpdateSupported = &struct{}{}
				offset += n_fallbackallowedupdatesupported
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "IoTSpecificInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AddInitialEimRequest to BER format.
func (v *AddInitialEimRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eimconfigurationdatalist, err := MarshalBERAddInitialEimRequestEimConfigurationDataList(v.EimConfigurationDataList)
	if err != nil {
		return nil, fmt.Errorf("encoding eimConfigurationDataList: %w", err)
	}
	if v.EimConfigurationDataListIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_eimconfigurationdatalist)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_eimconfigurationdatalist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
	} else {
		enc_eimconfigurationdatalist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_eimconfigurationdatalist)
	}
	children = append(children, enc_eimconfigurationdatalist...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 87, Constructed: true}, children), nil
}

// MarshalDER encodes AddInitialEimRequest to DER format.
func (v *AddInitialEimRequest) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.EimConfigurationDataListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes AddInitialEimRequest from BER/DER format.
func (v *AddInitialEimRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AddInitialEimRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 87 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AddInitialEimRequest: %w: expected tag [CONTEXT 87], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AddInitialEimRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimConfigurationDataList
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimConfigurationDataList")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for eimConfigurationDataList, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	v.EimConfigurationDataListIndef_ = false
	_, n_eimconfigurationdatalist, rawVal_eimconfigurationdatalist, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimConfigurationDataList: %w", err)
	}
	reconstructed_eimconfigurationdatalist := ber.EncodeSequence(rawVal_eimconfigurationdatalist)
	dec_eimconfigurationdatalist, unmErr := UnmarshalBERAddInitialEimRequestEimConfigurationDataList(reconstructed_eimconfigurationdatalist)
	if unmErr != nil {
		return fmt.Errorf("decoding eimConfigurationDataList: %w", unmErr)
	}
	v.EimConfigurationDataList = dec_eimconfigurationdatalist
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.EimConfigurationDataListIndef_ = true
		}
	}
	offset += n_eimconfigurationdatalist
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AddInitialEimRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AddInitialEimResponse to BER format.
func (v *AddInitialEimResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AddInitialEimResponseChoiceAddInitialEimOk:
		if v.AddInitialEimOk == nil {
			return nil, fmt.Errorf("choice AddInitialEimResponse: addInitialEimOk is nil")
		}
		enc_0, err := MarshalBERAddInitialEimResponseAddInitialEimOk(v.AddInitialEimOk)
		if err != nil {
			return nil, fmt.Errorf("encoding addInitialEimOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 87, enc_0)
		return enc_0, nil
	case AddInitialEimResponseChoiceAddInitialEimError:
		if v.AddInitialEimError == nil {
			return nil, fmt.Errorf("choice AddInitialEimResponse: addInitialEimError is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.AddInitialEimError))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 87, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AddInitialEimResponse", v.Choice)
	}
}

// MarshalDER encodes AddInitialEimResponse to DER format.
func (v *AddInitialEimResponse) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes AddInitialEimResponse from BER/DER format.
func (v *AddInitialEimResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AddInitialEimResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AddInitialEimResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 87 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AddInitialEimResponse CHOICE: %w: expected tag [CONTEXT 87], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AddInitialEimResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for AddInitialEimResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AddInitialEimResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AddInitialEimResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AddInitialEimResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = AddInitialEimResponseChoiceAddInitialEimOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding addInitialEimOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERAddInitialEimResponseAddInitialEimOk(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding addInitialEimOk: %w", unmErr)
		}
		v.AddInitialEimOk = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = AddInitialEimResponseChoiceAddInitialEimError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding addInitialEimError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding addInitialEimError: %w", intErr)
		}
		v.AddInitialEimError = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for AddInitialEimResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EuiccMemoryResetRequest to BER format.
func (v *EuiccMemoryResetRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_resetoptions := ber.EncodeBitString(v.ResetOptions.Bytes, (8-(v.ResetOptions.BitLength%8))%8)
	enc_resetoptions = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_resetoptions)
	children = append(children, enc_resetoptions...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 100, Constructed: true}, children), nil
}

// MarshalDER encodes EuiccMemoryResetRequest to DER format.
func (v *EuiccMemoryResetRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccMemoryResetRequest from BER/DER format.
func (v *EuiccMemoryResetRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccMemoryResetRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 100 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EuiccMemoryResetRequest: %w: expected tag [CONTEXT 100], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccMemoryResetRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode resetOptions
	if offset >= len(content) {
		return fmt.Errorf("missing required field resetOptions")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for resetOptions, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_resetoptions, rawVal_resetoptions, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding resetOptions: %w", err)
	}
	bsBytes_resetoptions, bsUnused_resetoptions, bsErr := ber.DecodeBitStringValue(rawVal_resetoptions)
	if bsErr != nil {
		return fmt.Errorf("decoding resetOptions: %w", bsErr)
	}
	v.ResetOptions = runtime.BitString{Bytes: bsBytes_resetoptions, BitLength: len(bsBytes_resetoptions)*8 - bsUnused_resetoptions}
	offset += n_resetoptions
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EuiccMemoryResetRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EuiccMemoryResetResponse to BER format.
func (v *EuiccMemoryResetResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_resetresult := ber.EncodeInteger(int64(v.ResetResult))
	enc_resetresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_resetresult)
	children = append(children, enc_resetresult...)
	if v.ResetEimResult != nil {
		enc_reseteimresult := ber.EncodeInteger(int64(*v.ResetEimResult))
		enc_reseteimresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_reseteimresult)
		children = append(children, enc_reseteimresult...)
	}
	if v.ResetImmediateEnableConfigResult != nil {
		enc_resetimmediateenableconfigresult := ber.EncodeInteger(int64(*v.ResetImmediateEnableConfigResult))
		enc_resetimmediateenableconfigresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_resetimmediateenableconfigresult)
		children = append(children, enc_resetimmediateenableconfigresult...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 100, Constructed: true}, children), nil
}

// MarshalDER encodes EuiccMemoryResetResponse to DER format.
func (v *EuiccMemoryResetResponse) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccMemoryResetResponse from BER/DER format.
func (v *EuiccMemoryResetResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccMemoryResetResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 100 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EuiccMemoryResetResponse: %w: expected tag [CONTEXT 100], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccMemoryResetResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode resetResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field resetResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for resetResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_resetresult, rawVal_resetresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding resetResult: %w", err)
	}
	decVal_resetresult, intErr := ber.DecodeIntegerValue(rawVal_resetresult)
	if intErr != nil {
		return fmt.Errorf("decoding resetResult: %w", intErr)
	}
	v.ResetResult = decVal_resetresult
	offset += n_resetresult
	// Decode resetEimResult
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_reseteimresult, rawVal_reseteimresult, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding resetEimResult: %w", err)
				}
				decVal_reseteimresult, intErr := ber.DecodeIntegerValue(rawVal_reseteimresult)
				if intErr != nil {
					return fmt.Errorf("decoding resetEimResult: %w", intErr)
				}
				v.ResetEimResult = &decVal_reseteimresult
				offset += n_reseteimresult
			}
		}
	}
	// Decode resetImmediateEnableConfigResult
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_resetimmediateenableconfigresult, rawVal_resetimmediateenableconfigresult, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding resetImmediateEnableConfigResult: %w", err)
				}
				decVal_resetimmediateenableconfigresult, intErr := ber.DecodeIntegerValue(rawVal_resetimmediateenableconfigresult)
				if intErr != nil {
					return fmt.Errorf("decoding resetImmediateEnableConfigResult: %w", intErr)
				}
				v.ResetImmediateEnableConfigResult = &decVal_resetimmediateenableconfigresult
				offset += n_resetimmediateenableconfigresult
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EuiccMemoryResetResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes GetCertsRequest to BER format.
func (v *GetCertsRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.EuiccCiPKId != nil {
		enc_euicccipkid := ber.EncodeOctetString([]byte(*v.EuiccCiPKId))
		enc_euicccipkid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_euicccipkid)
		children = append(children, enc_euicccipkid...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 86, Constructed: true}, children), nil
}

// MarshalDER encodes GetCertsRequest to DER format.
func (v *GetCertsRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetCertsRequest from BER/DER format.
func (v *GetCertsRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetCertsRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 86 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetCertsRequest: %w: expected tag [CONTEXT 86], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetCertsRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccCiPKId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_euicccipkid, rawVal_euicccipkid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccCiPKId: %w", err)
				}
				tmp_euicccipkid := sgp22.SubjectKeyIdentifier(rawVal_euicccipkid)
				v.EuiccCiPKId = &tmp_euicccipkid
				offset += n_euicccipkid
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "GetCertsRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes GetCertsResponse to BER format.
func (v *GetCertsResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case GetCertsResponseChoiceCerts:
		if v.Certs == nil {
			return nil, fmt.Errorf("choice GetCertsResponse: certs is nil")
		}
		enc_0, err := v.Certs.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding certs: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 86, enc_0)
		return enc_0, nil
	case GetCertsResponseChoiceGetCertsError:
		if v.GetCertsError == nil {
			return nil, fmt.Errorf("choice GetCertsResponse: getCertsError is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.GetCertsError))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 86, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for GetCertsResponse", v.Choice)
	}
}

// MarshalDER encodes GetCertsResponse to DER format.
func (v *GetCertsResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case GetCertsResponseChoiceCerts:
		if v.Certs == nil {
			return nil, fmt.Errorf("choice GetCertsResponse: certs is nil")
		}
		enc_der_0, err := v.Certs.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding certs: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 86, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes GetCertsResponse from BER/DER format.
func (v *GetCertsResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for GetCertsResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetCertsResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 86 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetCertsResponse CHOICE: %w: expected tag [CONTEXT 86], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetCertsResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for GetCertsResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for GetCertsResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding GetCertsResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "GetCertsResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = GetCertsResponseChoiceCerts
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding certs: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec GetCertsResponseCerts
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding certs: %w", unmErr)
		}
		v.Certs = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = GetCertsResponseChoiceGetCertsError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding getCertsError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding getCertsError: %w", intErr)
		}
		v.GetCertsError = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for GetCertsResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes RetrieveNotificationsListRequest to BER format.
func (v *RetrieveNotificationsListRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SearchCriteria != nil {
		enc_searchcriteria, err := v.SearchCriteria.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding searchCriteria: %w", err)
		}
		enc_searchcriteria = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_searchcriteria)
		children = append(children, enc_searchcriteria...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 43, Constructed: true}, children), nil
}

// MarshalDER encodes RetrieveNotificationsListRequest to DER format.
func (v *RetrieveNotificationsListRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RetrieveNotificationsListRequest from BER/DER format.
func (v *RetrieveNotificationsListRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding RetrieveNotificationsListRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 43 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RetrieveNotificationsListRequest: %w: expected tag [CONTEXT 43], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RetrieveNotificationsListRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode searchCriteria
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_searchcriteria, innerData_searchcriteria, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding searchCriteria: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_searchcriteria RetrieveNotificationsListRequestSearchCriteria
				if unmErr := dec_searchcriteria.UnmarshalBER(innerData_searchcriteria); unmErr != nil {
					return fmt.Errorf("decoding searchCriteria: %w", unmErr)
				}
				v.SearchCriteria = &dec_searchcriteria
				offset += n_searchcriteria
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "RetrieveNotificationsListRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RetrieveNotificationsListResponse to BER format.
func (v *RetrieveNotificationsListResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case RetrieveNotificationsListResponseChoiceNotificationList:
		if v.NotificationList == nil {
			return nil, fmt.Errorf("choice RetrieveNotificationsListResponse: notificationList is nil")
		}
		enc_0, err := MarshalBERPendingNotificationList(v.NotificationList)
		if err != nil {
			return nil, fmt.Errorf("encoding notificationList: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 43, enc_0)
		return enc_0, nil
	case RetrieveNotificationsListResponseChoiceNotificationsListResultError:
		if v.NotificationsListResultError == nil {
			return nil, fmt.Errorf("choice RetrieveNotificationsListResponse: notificationsListResultError is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.NotificationsListResultError))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 43, enc_1)
		return enc_1, nil
	case RetrieveNotificationsListResponseChoiceEuiccPackageResultList:
		if v.EuiccPackageResultList == nil {
			return nil, fmt.Errorf("choice RetrieveNotificationsListResponse: euiccPackageResultList is nil")
		}
		enc_2, err := MarshalBEREuiccPackageResultList(v.EuiccPackageResultList)
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageResultList: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_2)
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 43, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RetrieveNotificationsListResponse", v.Choice)
	}
}

// MarshalDER encodes RetrieveNotificationsListResponse to DER format.
func (v *RetrieveNotificationsListResponse) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes RetrieveNotificationsListResponse from BER/DER format.
func (v *RetrieveNotificationsListResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for RetrieveNotificationsListResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding RetrieveNotificationsListResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 43 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RetrieveNotificationsListResponse CHOICE: %w: expected tag [CONTEXT 43], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RetrieveNotificationsListResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for RetrieveNotificationsListResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RetrieveNotificationsListResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding RetrieveNotificationsListResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RetrieveNotificationsListResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = RetrieveNotificationsListResponseChoiceNotificationList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding notificationList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERPendingNotificationList(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding notificationList: %w", unmErr)
		}
		v.NotificationList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = RetrieveNotificationsListResponseChoiceNotificationsListResultError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding notificationsListResultError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding notificationsListResultError: %w", intErr)
		}
		v.NotificationsListResultError = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = RetrieveNotificationsListResponseChoiceEuiccPackageResultList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding euiccPackageResultList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBEREuiccPackageResultList(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding euiccPackageResultList: %w", unmErr)
		}
		v.EuiccPackageResultList = dec
	} else {
		return fmt.Errorf("unknown tag %s for RetrieveNotificationsListResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ImmediateEnableRequest to BER format.
func (v *ImmediateEnableRequest) MarshalBER() ([]byte, error) {
	var children []byte
	var enc_refreshflag []byte
	if v.RefreshFlagRaw_ != 0 {
		enc_refreshflag = ber.EncodeBooleanRaw(v.RefreshFlagRaw_)
	} else {
		enc_refreshflag = ber.EncodeBoolean(v.RefreshFlag)
	}
	enc_refreshflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_refreshflag)
	children = append(children, enc_refreshflag...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 90, Constructed: true}, children), nil
}

// MarshalDER encodes ImmediateEnableRequest to DER format.
func (v *ImmediateEnableRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ImmediateEnableRequest from BER/DER format.
func (v *ImmediateEnableRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ImmediateEnableRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 90 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ImmediateEnableRequest: %w: expected tag [CONTEXT 90], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ImmediateEnableRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode refreshFlag
	if offset >= len(content) {
		return fmt.Errorf("missing required field refreshFlag")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for refreshFlag, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_refreshflag, rawVal_refreshflag, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding refreshFlag: %w", err)
	}
	decVal_refreshflag, boolErr := ber.DecodeBooleanValue(rawVal_refreshflag)
	if boolErr != nil {
		return fmt.Errorf("decoding refreshFlag: %w", boolErr)
	}
	if len(rawVal_refreshflag) == 1 {
		v.RefreshFlagRaw_ = rawVal_refreshflag[0]
	}
	v.RefreshFlag = decVal_refreshflag
	offset += n_refreshflag
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ImmediateEnableRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ImmediateEnableResponse to BER format.
func (v *ImmediateEnableResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_immediateenableresult := ber.EncodeInteger(int64(v.ImmediateEnableResult))
	enc_immediateenableresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_immediateenableresult)
	children = append(children, enc_immediateenableresult...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 90, Constructed: true}, children), nil
}

// MarshalDER encodes ImmediateEnableResponse to DER format.
func (v *ImmediateEnableResponse) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ImmediateEnableResponse from BER/DER format.
func (v *ImmediateEnableResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ImmediateEnableResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 90 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ImmediateEnableResponse: %w: expected tag [CONTEXT 90], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ImmediateEnableResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode immediateEnableResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field immediateEnableResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for immediateEnableResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_immediateenableresult, rawVal_immediateenableresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding immediateEnableResult: %w", err)
	}
	decVal_immediateenableresult, intErr := ber.DecodeIntegerValue(rawVal_immediateenableresult)
	if intErr != nil {
		return fmt.Errorf("decoding immediateEnableResult: %w", intErr)
	}
	v.ImmediateEnableResult = decVal_immediateenableresult
	offset += n_immediateenableresult
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ImmediateEnableResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ProfileRollbackRequest to BER format.
func (v *ProfileRollbackRequest) MarshalBER() ([]byte, error) {
	var children []byte
	var enc_refreshflag []byte
	if v.RefreshFlagRaw_ != 0 {
		enc_refreshflag = ber.EncodeBooleanRaw(v.RefreshFlagRaw_)
	} else {
		enc_refreshflag = ber.EncodeBoolean(v.RefreshFlag)
	}
	enc_refreshflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_refreshflag)
	children = append(children, enc_refreshflag...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 88, Constructed: true}, children), nil
}

// MarshalDER encodes ProfileRollbackRequest to DER format.
func (v *ProfileRollbackRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileRollbackRequest from BER/DER format.
func (v *ProfileRollbackRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileRollbackRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 88 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileRollbackRequest: %w: expected tag [CONTEXT 88], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileRollbackRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode refreshFlag
	if offset >= len(content) {
		return fmt.Errorf("missing required field refreshFlag")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for refreshFlag, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_refreshflag, rawVal_refreshflag, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding refreshFlag: %w", err)
	}
	decVal_refreshflag, boolErr := ber.DecodeBooleanValue(rawVal_refreshflag)
	if boolErr != nil {
		return fmt.Errorf("decoding refreshFlag: %w", boolErr)
	}
	if len(rawVal_refreshflag) == 1 {
		v.RefreshFlagRaw_ = rawVal_refreshflag[0]
	}
	v.RefreshFlag = decVal_refreshflag
	offset += n_refreshflag
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProfileRollbackRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ProfileRollbackResponse to BER format.
func (v *ProfileRollbackResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_cmdresult := ber.EncodeInteger(int64(v.CmdResult))
	children = append(children, enc_cmdresult...)
	if v.EUICCPackageResult != nil {
		enc_euiccpackageresult, err := v.EUICCPackageResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding eUICCPackageResult: %w", err)
		}
		children = append(children, enc_euiccpackageresult...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 88, Constructed: true}, children), nil
}

// MarshalDER encodes ProfileRollbackResponse to DER format.
func (v *ProfileRollbackResponse) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileRollbackResponse from BER/DER format.
func (v *ProfileRollbackResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileRollbackResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 88 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileRollbackResponse: %w: expected tag [CONTEXT 88], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileRollbackResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cmdResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field cmdResult")
	}
	val_cmdresult, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding cmdResult: %w", err)
	}
	v.CmdResult = val_cmdresult
	offset += n
	// Decode eUICCPackageResult
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 81 {
				// Decode nested CHOICE (EuiccPackageResult)
				_, n_euiccpackageresult, _, tlvErr_euiccpackageresult := ber.DecodeTLV(content[offset:])
				if tlvErr_euiccpackageresult != nil {
					return fmt.Errorf("decoding eUICCPackageResult: %w", tlvErr_euiccpackageresult)
				}
				var dec_euiccpackageresult EuiccPackageResult
				if unmErr := dec_euiccpackageresult.UnmarshalBER(content[offset : offset+n_euiccpackageresult]); unmErr != nil {
					return fmt.Errorf("decoding eUICCPackageResult: %w", unmErr)
				}
				v.EUICCPackageResult = &dec_euiccpackageresult
				offset += n_euiccpackageresult
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProfileRollbackResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ConfigureImmediateProfileEnablingRequest to BER format.
func (v *ConfigureImmediateProfileEnablingRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ImmediateEnableFlag != nil {
		enc_immediateenableflag := ber.EncodeNull()
		enc_immediateenableflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_immediateenableflag)
		children = append(children, enc_immediateenableflag...)
	}
	if v.DefaultSmdpOid != nil {
		enc_defaultsmdpoid := ber.EncodeObjectIdentifier([]uint64(v.DefaultSmdpOid))
		enc_defaultsmdpoid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_defaultsmdpoid)
		children = append(children, enc_defaultsmdpoid...)
	}
	if v.DefaultSmdpAddress != nil {
		enc_defaultsmdpaddress := ber.EncodeStringTag(12, *v.DefaultSmdpAddress)
		enc_defaultsmdpaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_defaultsmdpaddress)
		children = append(children, enc_defaultsmdpaddress...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 89, Constructed: true}, children), nil
}

// MarshalDER encodes ConfigureImmediateProfileEnablingRequest to DER format.
func (v *ConfigureImmediateProfileEnablingRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ConfigureImmediateProfileEnablingRequest from BER/DER format.
func (v *ConfigureImmediateProfileEnablingRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ConfigureImmediateProfileEnablingRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 89 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ConfigureImmediateProfileEnablingRequest: %w: expected tag [CONTEXT 89], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ConfigureImmediateProfileEnablingRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode immediateEnableFlag
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_immediateenableflag, rawVal_immediateenableflag, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding immediateEnableFlag: %w", err)
				}
				_ = rawVal_immediateenableflag
				v.ImmediateEnableFlag = &struct{}{}
				offset += n_immediateenableflag
			}
		}
	}
	// Decode defaultSmdpOid
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_defaultsmdpoid, rawVal_defaultsmdpoid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding defaultSmdpOid: %w", err)
				}
				decVal_defaultsmdpoid, oidErr := ber.DecodeOIDValue(rawVal_defaultsmdpoid)
				if oidErr != nil {
					return fmt.Errorf("decoding defaultSmdpOid: %w", oidErr)
				}
				tmp_defaultsmdpoid := runtime.ObjectIdentifier(decVal_defaultsmdpoid)
				v.DefaultSmdpOid = tmp_defaultsmdpoid
				offset += n_defaultsmdpoid
			}
		}
	}
	// Decode defaultSmdpAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_defaultsmdpaddress, rawVal_defaultsmdpaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding defaultSmdpAddress: %w", err)
				}
				decVal_defaultsmdpaddress := ber.DecodeStringValue(rawVal_defaultsmdpaddress)
				v.DefaultSmdpAddress = &decVal_defaultsmdpaddress
				offset += n_defaultsmdpaddress
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ConfigureImmediateProfileEnablingRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ConfigureImmediateProfileEnablingResponse to BER format.
func (v *ConfigureImmediateProfileEnablingResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_configimmediateenableresult := ber.EncodeInteger(int64(v.ConfigImmediateEnableResult))
	enc_configimmediateenableresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_configimmediateenableresult)
	children = append(children, enc_configimmediateenableresult...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 89, Constructed: true}, children), nil
}

// MarshalDER encodes ConfigureImmediateProfileEnablingResponse to DER format.
func (v *ConfigureImmediateProfileEnablingResponse) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ConfigureImmediateProfileEnablingResponse from BER/DER format.
func (v *ConfigureImmediateProfileEnablingResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ConfigureImmediateProfileEnablingResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 89 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ConfigureImmediateProfileEnablingResponse: %w: expected tag [CONTEXT 89], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ConfigureImmediateProfileEnablingResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode configImmediateEnableResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field configImmediateEnableResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for configImmediateEnableResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_configimmediateenableresult, rawVal_configimmediateenableresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding configImmediateEnableResult: %w", err)
	}
	decVal_configimmediateenableresult, intErr := ber.DecodeIntegerValue(rawVal_configimmediateenableresult)
	if intErr != nil {
		return fmt.Errorf("decoding configImmediateEnableResult: %w", intErr)
	}
	v.ConfigImmediateEnableResult = decVal_configimmediateenableresult
	offset += n_configimmediateenableresult
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ConfigureImmediateProfileEnablingResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes GetEimConfigurationDataRequest to BER format.
func (v *GetEimConfigurationDataRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SearchCriteria != nil {
		enc_searchcriteria, err := v.SearchCriteria.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding searchCriteria: %w", err)
		}
		enc_searchcriteria = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_searchcriteria)
		children = append(children, enc_searchcriteria...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 85, Constructed: true}, children), nil
}

// MarshalDER encodes GetEimConfigurationDataRequest to DER format.
func (v *GetEimConfigurationDataRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetEimConfigurationDataRequest from BER/DER format.
func (v *GetEimConfigurationDataRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetEimConfigurationDataRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 85 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetEimConfigurationDataRequest: %w: expected tag [CONTEXT 85], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEimConfigurationDataRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode searchCriteria
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_searchcriteria, innerData_searchcriteria, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding searchCriteria: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_searchcriteria GetEimConfigurationDataRequestSearchCriteria
				if unmErr := dec_searchcriteria.UnmarshalBER(innerData_searchcriteria); unmErr != nil {
					return fmt.Errorf("decoding searchCriteria: %w", unmErr)
				}
				v.SearchCriteria = &dec_searchcriteria
				offset += n_searchcriteria
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "GetEimConfigurationDataRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes GetEimConfigurationDataResponse to BER format.
func (v *GetEimConfigurationDataResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eimconfigurationdatalist, err := MarshalBERGetEimConfigurationDataResponseEimConfigurationDataList(v.EimConfigurationDataList)
	if err != nil {
		return nil, fmt.Errorf("encoding eimConfigurationDataList: %w", err)
	}
	if v.EimConfigurationDataListIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_eimconfigurationdatalist)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_eimconfigurationdatalist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
	} else {
		enc_eimconfigurationdatalist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_eimconfigurationdatalist)
	}
	children = append(children, enc_eimconfigurationdatalist...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 85, Constructed: true}, children), nil
}

// MarshalDER encodes GetEimConfigurationDataResponse to DER format.
func (v *GetEimConfigurationDataResponse) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.EimConfigurationDataListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes GetEimConfigurationDataResponse from BER/DER format.
func (v *GetEimConfigurationDataResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetEimConfigurationDataResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 85 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetEimConfigurationDataResponse: %w: expected tag [CONTEXT 85], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEimConfigurationDataResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimConfigurationDataList
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimConfigurationDataList")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for eimConfigurationDataList, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	v.EimConfigurationDataListIndef_ = false
	_, n_eimconfigurationdatalist, rawVal_eimconfigurationdatalist, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimConfigurationDataList: %w", err)
	}
	reconstructed_eimconfigurationdatalist := ber.EncodeSequence(rawVal_eimconfigurationdatalist)
	dec_eimconfigurationdatalist, unmErr := UnmarshalBERGetEimConfigurationDataResponseEimConfigurationDataList(reconstructed_eimconfigurationdatalist)
	if unmErr != nil {
		return fmt.Errorf("decoding eimConfigurationDataList: %w", unmErr)
	}
	v.EimConfigurationDataList = dec_eimconfigurationdatalist
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.EimConfigurationDataListIndef_ = true
		}
	}
	offset += n_eimconfigurationdatalist
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "GetEimConfigurationDataResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ExecuteFallbackMechanismRequest to BER format.
func (v *ExecuteFallbackMechanismRequest) MarshalBER() ([]byte, error) {
	var children []byte
	var enc_refreshflag []byte
	if v.RefreshFlagRaw_ != 0 {
		enc_refreshflag = ber.EncodeBooleanRaw(v.RefreshFlagRaw_)
	} else {
		enc_refreshflag = ber.EncodeBoolean(v.RefreshFlag)
	}
	enc_refreshflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_refreshflag)
	children = append(children, enc_refreshflag...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 93, Constructed: true}, children), nil
}

// MarshalDER encodes ExecuteFallbackMechanismRequest to DER format.
func (v *ExecuteFallbackMechanismRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ExecuteFallbackMechanismRequest from BER/DER format.
func (v *ExecuteFallbackMechanismRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExecuteFallbackMechanismRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 93 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ExecuteFallbackMechanismRequest: %w: expected tag [CONTEXT 93], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExecuteFallbackMechanismRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode refreshFlag
	if offset >= len(content) {
		return fmt.Errorf("missing required field refreshFlag")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for refreshFlag, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_refreshflag, rawVal_refreshflag, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding refreshFlag: %w", err)
	}
	decVal_refreshflag, boolErr := ber.DecodeBooleanValue(rawVal_refreshflag)
	if boolErr != nil {
		return fmt.Errorf("decoding refreshFlag: %w", boolErr)
	}
	if len(rawVal_refreshflag) == 1 {
		v.RefreshFlagRaw_ = rawVal_refreshflag[0]
	}
	v.RefreshFlag = decVal_refreshflag
	offset += n_refreshflag
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExecuteFallbackMechanismRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ExecuteFallbackMechanismResponse to BER format.
func (v *ExecuteFallbackMechanismResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_executefallbackmechanismresult := ber.EncodeInteger(int64(v.ExecuteFallbackMechanismResult))
	enc_executefallbackmechanismresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_executefallbackmechanismresult)
	children = append(children, enc_executefallbackmechanismresult...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 93, Constructed: true}, children), nil
}

// MarshalDER encodes ExecuteFallbackMechanismResponse to DER format.
func (v *ExecuteFallbackMechanismResponse) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ExecuteFallbackMechanismResponse from BER/DER format.
func (v *ExecuteFallbackMechanismResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExecuteFallbackMechanismResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 93 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ExecuteFallbackMechanismResponse: %w: expected tag [CONTEXT 93], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExecuteFallbackMechanismResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode executeFallbackMechanismResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field executeFallbackMechanismResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for executeFallbackMechanismResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_executefallbackmechanismresult, rawVal_executefallbackmechanismresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding executeFallbackMechanismResult: %w", err)
	}
	decVal_executefallbackmechanismresult, intErr := ber.DecodeIntegerValue(rawVal_executefallbackmechanismresult)
	if intErr != nil {
		return fmt.Errorf("decoding executeFallbackMechanismResult: %w", intErr)
	}
	v.ExecuteFallbackMechanismResult = decVal_executefallbackmechanismresult
	offset += n_executefallbackmechanismresult
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExecuteFallbackMechanismResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ReturnFromFallbackRequest to BER format.
func (v *ReturnFromFallbackRequest) MarshalBER() ([]byte, error) {
	var children []byte
	var enc_refreshflag []byte
	if v.RefreshFlagRaw_ != 0 {
		enc_refreshflag = ber.EncodeBooleanRaw(v.RefreshFlagRaw_)
	} else {
		enc_refreshflag = ber.EncodeBoolean(v.RefreshFlag)
	}
	enc_refreshflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_refreshflag)
	children = append(children, enc_refreshflag...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 94, Constructed: true}, children), nil
}

// MarshalDER encodes ReturnFromFallbackRequest to DER format.
func (v *ReturnFromFallbackRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ReturnFromFallbackRequest from BER/DER format.
func (v *ReturnFromFallbackRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReturnFromFallbackRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 94 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ReturnFromFallbackRequest: %w: expected tag [CONTEXT 94], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnFromFallbackRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode refreshFlag
	if offset >= len(content) {
		return fmt.Errorf("missing required field refreshFlag")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for refreshFlag, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_refreshflag, rawVal_refreshflag, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding refreshFlag: %w", err)
	}
	decVal_refreshflag, boolErr := ber.DecodeBooleanValue(rawVal_refreshflag)
	if boolErr != nil {
		return fmt.Errorf("decoding refreshFlag: %w", boolErr)
	}
	if len(rawVal_refreshflag) == 1 {
		v.RefreshFlagRaw_ = rawVal_refreshflag[0]
	}
	v.RefreshFlag = decVal_refreshflag
	offset += n_refreshflag
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnFromFallbackRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ReturnFromFallbackResponse to BER format.
func (v *ReturnFromFallbackResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_returnfromfallbackresult := ber.EncodeInteger(int64(v.ReturnFromFallbackResult))
	enc_returnfromfallbackresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_returnfromfallbackresult)
	children = append(children, enc_returnfromfallbackresult...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 94, Constructed: true}, children), nil
}

// MarshalDER encodes ReturnFromFallbackResponse to DER format.
func (v *ReturnFromFallbackResponse) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ReturnFromFallbackResponse from BER/DER format.
func (v *ReturnFromFallbackResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReturnFromFallbackResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 94 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ReturnFromFallbackResponse: %w: expected tag [CONTEXT 94], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnFromFallbackResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode returnFromFallbackResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field returnFromFallbackResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for returnFromFallbackResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_returnfromfallbackresult, rawVal_returnfromfallbackresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding returnFromFallbackResult: %w", err)
	}
	decVal_returnfromfallbackresult, intErr := ber.DecodeIntegerValue(rawVal_returnfromfallbackresult)
	if intErr != nil {
		return fmt.Errorf("decoding returnFromFallbackResult: %w", intErr)
	}
	v.ReturnFromFallbackResult = decVal_returnfromfallbackresult
	offset += n_returnfromfallbackresult
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnFromFallbackResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EnableEmergencyProfileRequest to BER format.
func (v *EnableEmergencyProfileRequest) MarshalBER() ([]byte, error) {
	var children []byte
	var enc_refreshflag []byte
	if v.RefreshFlagRaw_ != 0 {
		enc_refreshflag = ber.EncodeBooleanRaw(v.RefreshFlagRaw_)
	} else {
		enc_refreshflag = ber.EncodeBoolean(v.RefreshFlag)
	}
	enc_refreshflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_refreshflag)
	children = append(children, enc_refreshflag...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 91, Constructed: true}, children), nil
}

// MarshalDER encodes EnableEmergencyProfileRequest to DER format.
func (v *EnableEmergencyProfileRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EnableEmergencyProfileRequest from BER/DER format.
func (v *EnableEmergencyProfileRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EnableEmergencyProfileRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 91 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EnableEmergencyProfileRequest: %w: expected tag [CONTEXT 91], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EnableEmergencyProfileRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode refreshFlag
	if offset >= len(content) {
		return fmt.Errorf("missing required field refreshFlag")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for refreshFlag, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_refreshflag, rawVal_refreshflag, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding refreshFlag: %w", err)
	}
	decVal_refreshflag, boolErr := ber.DecodeBooleanValue(rawVal_refreshflag)
	if boolErr != nil {
		return fmt.Errorf("decoding refreshFlag: %w", boolErr)
	}
	if len(rawVal_refreshflag) == 1 {
		v.RefreshFlagRaw_ = rawVal_refreshflag[0]
	}
	v.RefreshFlag = decVal_refreshflag
	offset += n_refreshflag
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EnableEmergencyProfileRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EnableEmergencyProfileResponse to BER format.
func (v *EnableEmergencyProfileResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_enableemergencyprofileresult := ber.EncodeInteger(int64(v.EnableEmergencyProfileResult))
	enc_enableemergencyprofileresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_enableemergencyprofileresult)
	children = append(children, enc_enableemergencyprofileresult...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 91, Constructed: true}, children), nil
}

// MarshalDER encodes EnableEmergencyProfileResponse to DER format.
func (v *EnableEmergencyProfileResponse) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EnableEmergencyProfileResponse from BER/DER format.
func (v *EnableEmergencyProfileResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EnableEmergencyProfileResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 91 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EnableEmergencyProfileResponse: %w: expected tag [CONTEXT 91], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EnableEmergencyProfileResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode enableEmergencyProfileResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field enableEmergencyProfileResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for enableEmergencyProfileResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_enableemergencyprofileresult, rawVal_enableemergencyprofileresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding enableEmergencyProfileResult: %w", err)
	}
	decVal_enableemergencyprofileresult, intErr := ber.DecodeIntegerValue(rawVal_enableemergencyprofileresult)
	if intErr != nil {
		return fmt.Errorf("decoding enableEmergencyProfileResult: %w", intErr)
	}
	v.EnableEmergencyProfileResult = decVal_enableemergencyprofileresult
	offset += n_enableemergencyprofileresult
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EnableEmergencyProfileResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes DisableEmergencyProfileRequest to BER format.
func (v *DisableEmergencyProfileRequest) MarshalBER() ([]byte, error) {
	var children []byte
	var enc_refreshflag []byte
	if v.RefreshFlagRaw_ != 0 {
		enc_refreshflag = ber.EncodeBooleanRaw(v.RefreshFlagRaw_)
	} else {
		enc_refreshflag = ber.EncodeBoolean(v.RefreshFlag)
	}
	enc_refreshflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_refreshflag)
	children = append(children, enc_refreshflag...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 92, Constructed: true}, children), nil
}

// MarshalDER encodes DisableEmergencyProfileRequest to DER format.
func (v *DisableEmergencyProfileRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DisableEmergencyProfileRequest from BER/DER format.
func (v *DisableEmergencyProfileRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding DisableEmergencyProfileRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 92 || !decodedTag.Constructed {
		return fmt.Errorf("decoding DisableEmergencyProfileRequest: %w: expected tag [CONTEXT 92], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DisableEmergencyProfileRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode refreshFlag
	if offset >= len(content) {
		return fmt.Errorf("missing required field refreshFlag")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for refreshFlag, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_refreshflag, rawVal_refreshflag, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding refreshFlag: %w", err)
	}
	decVal_refreshflag, boolErr := ber.DecodeBooleanValue(rawVal_refreshflag)
	if boolErr != nil {
		return fmt.Errorf("decoding refreshFlag: %w", boolErr)
	}
	if len(rawVal_refreshflag) == 1 {
		v.RefreshFlagRaw_ = rawVal_refreshflag[0]
	}
	v.RefreshFlag = decVal_refreshflag
	offset += n_refreshflag
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DisableEmergencyProfileRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes DisableEmergencyProfileResponse to BER format.
func (v *DisableEmergencyProfileResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_disableemergencyprofileresult := ber.EncodeInteger(int64(v.DisableEmergencyProfileResult))
	enc_disableemergencyprofileresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_disableemergencyprofileresult)
	children = append(children, enc_disableemergencyprofileresult...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 92, Constructed: true}, children), nil
}

// MarshalDER encodes DisableEmergencyProfileResponse to DER format.
func (v *DisableEmergencyProfileResponse) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DisableEmergencyProfileResponse from BER/DER format.
func (v *DisableEmergencyProfileResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding DisableEmergencyProfileResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 92 || !decodedTag.Constructed {
		return fmt.Errorf("decoding DisableEmergencyProfileResponse: %w: expected tag [CONTEXT 92], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DisableEmergencyProfileResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode disableEmergencyProfileResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field disableEmergencyProfileResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for disableEmergencyProfileResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_disableemergencyprofileresult, rawVal_disableemergencyprofileresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding disableEmergencyProfileResult: %w", err)
	}
	decVal_disableemergencyprofileresult, intErr := ber.DecodeIntegerValue(rawVal_disableemergencyprofileresult)
	if intErr != nil {
		return fmt.Errorf("decoding disableEmergencyProfileResult: %w", intErr)
	}
	v.DisableEmergencyProfileResult = decVal_disableemergencyprofileresult
	offset += n_disableemergencyprofileresult
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DisableEmergencyProfileResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes GetConnectivityParametersRequest to BER format.
func (v *GetConnectivityParametersRequest) MarshalBER() ([]byte, error) {
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 95, Constructed: true}, nil), nil
}

// MarshalDER encodes GetConnectivityParametersRequest to DER format.
func (v *GetConnectivityParametersRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetConnectivityParametersRequest from BER/DER format.
func (v *GetConnectivityParametersRequest) UnmarshalBER(data []byte) error {
	decodedTag, _, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetConnectivityParametersRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 95 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetConnectivityParametersRequest: %w: expected tag [CONTEXT 95], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetConnectivityParametersRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes GetConnectivityParametersResponse to BER format.
func (v *GetConnectivityParametersResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case GetConnectivityParametersResponseChoiceConnectivityParameters:
		if v.ConnectivityParameters == nil {
			return nil, fmt.Errorf("choice GetConnectivityParametersResponse: connectivityParameters is nil")
		}
		enc_0, err := v.ConnectivityParameters.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding connectivityParameters: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 95, enc_0)
		return enc_0, nil
	case GetConnectivityParametersResponseChoiceConnectivityParametersError:
		if v.ConnectivityParametersError == nil {
			return nil, fmt.Errorf("choice GetConnectivityParametersResponse: connectivityParametersError is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.ConnectivityParametersError))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 95, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for GetConnectivityParametersResponse", v.Choice)
	}
}

// MarshalDER encodes GetConnectivityParametersResponse to DER format.
func (v *GetConnectivityParametersResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case GetConnectivityParametersResponseChoiceConnectivityParameters:
		if v.ConnectivityParameters == nil {
			return nil, fmt.Errorf("choice GetConnectivityParametersResponse: connectivityParameters is nil")
		}
		enc_der_0, err := v.ConnectivityParameters.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding connectivityParameters: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 95, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes GetConnectivityParametersResponse from BER/DER format.
func (v *GetConnectivityParametersResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for GetConnectivityParametersResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetConnectivityParametersResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 95 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetConnectivityParametersResponse CHOICE: %w: expected tag [CONTEXT 95], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetConnectivityParametersResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for GetConnectivityParametersResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for GetConnectivityParametersResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding GetConnectivityParametersResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "GetConnectivityParametersResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = GetConnectivityParametersResponseChoiceConnectivityParameters
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding connectivityParameters: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ConnectivityParameters
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding connectivityParameters: %w", unmErr)
		}
		v.ConnectivityParameters = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = GetConnectivityParametersResponseChoiceConnectivityParametersError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding connectivityParametersError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding connectivityParametersError: %w", intErr)
		}
		tmp := ConnectivityParametersError(decVal)
		v.ConnectivityParametersError = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for GetConnectivityParametersResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ConnectivityParameters to BER format.
func (v *ConnectivityParameters) MarshalBER() ([]byte, error) {
	var children []byte
	if v.HttpParams != nil {
		enc_httpparams := ber.EncodeOctetString(v.HttpParams)
		enc_httpparams = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_httpparams)
		children = append(children, enc_httpparams...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ConnectivityParameters to DER format.
func (v *ConnectivityParameters) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ConnectivityParameters from BER/DER format.
func (v *ConnectivityParameters) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ConnectivityParameters SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ConnectivityParameters", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode httpParams
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_httpparams, rawVal_httpparams, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding httpParams: %w", err)
				}
				tmp_httpparams := rawVal_httpparams
				v.HttpParams = tmp_httpparams
				offset += n_httpparams
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ConnectivityParameters", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SetDefaultDpAddressRequest to BER format.
func (v *SetDefaultDpAddressRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_defaultdpaddress := ber.EncodeStringTag(12, v.DefaultDpAddress)
	enc_defaultdpaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_defaultdpaddress)
	children = append(children, enc_defaultdpaddress...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 101, Constructed: true}, children), nil
}

// MarshalDER encodes SetDefaultDpAddressRequest to DER format.
func (v *SetDefaultDpAddressRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SetDefaultDpAddressRequest from BER/DER format.
func (v *SetDefaultDpAddressRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding SetDefaultDpAddressRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 101 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SetDefaultDpAddressRequest: %w: expected tag [CONTEXT 101], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SetDefaultDpAddressRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode defaultDpAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field defaultDpAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for defaultDpAddress, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_defaultdpaddress, rawVal_defaultdpaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding defaultDpAddress: %w", err)
	}
	decVal_defaultdpaddress := ber.DecodeStringValue(rawVal_defaultdpaddress)
	v.DefaultDpAddress = decVal_defaultdpaddress
	offset += n_defaultdpaddress
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SetDefaultDpAddressRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SetDefaultDpAddressResponse to BER format.
func (v *SetDefaultDpAddressResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_setdefaultdpaddressresult := ber.EncodeInteger(int64(v.SetDefaultDpAddressResult))
	enc_setdefaultdpaddressresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_setdefaultdpaddressresult)
	children = append(children, enc_setdefaultdpaddressresult...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 101, Constructed: true}, children), nil
}

// MarshalDER encodes SetDefaultDpAddressResponse to DER format.
func (v *SetDefaultDpAddressResponse) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SetDefaultDpAddressResponse from BER/DER format.
func (v *SetDefaultDpAddressResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding SetDefaultDpAddressResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 101 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SetDefaultDpAddressResponse: %w: expected tag [CONTEXT 101], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SetDefaultDpAddressResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode setDefaultDpAddressResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field setDefaultDpAddressResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for setDefaultDpAddressResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_setdefaultdpaddressresult, rawVal_setdefaultdpaddressresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding setDefaultDpAddressResult: %w", err)
	}
	decVal_setdefaultdpaddressresult, intErr := ber.DecodeIntegerValue(rawVal_setdefaultdpaddressresult)
	if intErr != nil {
		return fmt.Errorf("decoding setDefaultDpAddressResult: %w", intErr)
	}
	v.SetDefaultDpAddressResult = decVal_setdefaultdpaddressresult
	offset += n_setdefaultdpaddressresult
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SetDefaultDpAddressResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PrepareDownloadResponse to BER format.
func (v *PrepareDownloadResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case PrepareDownloadResponseChoiceDownloadResponseOk:
		if v.DownloadResponseOk == nil {
			return nil, fmt.Errorf("choice PrepareDownloadResponse: downloadResponseOk is nil")
		}
		enc_0, err := v.DownloadResponseOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding downloadResponseOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 33, enc_0)
		return enc_0, nil
	case PrepareDownloadResponseChoiceDownloadResponseError:
		if v.DownloadResponseError == nil {
			return nil, fmt.Errorf("choice PrepareDownloadResponse: downloadResponseError is nil")
		}
		enc_1, err := v.DownloadResponseError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding downloadResponseError: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 33, enc_1)
		return enc_1, nil
	case PrepareDownloadResponseChoiceCompactDownloadResponseOk:
		if v.CompactDownloadResponseOk == nil {
			return nil, fmt.Errorf("choice PrepareDownloadResponse: compactDownloadResponseOk is nil")
		}
		enc_2, err := v.CompactDownloadResponseOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactDownloadResponseOk: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_2)
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 33, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PrepareDownloadResponse", v.Choice)
	}
}

// MarshalDER encodes PrepareDownloadResponse to DER format.
func (v *PrepareDownloadResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case PrepareDownloadResponseChoiceDownloadResponseOk:
		if v.DownloadResponseOk == nil {
			return nil, fmt.Errorf("choice PrepareDownloadResponse: downloadResponseOk is nil")
		}
		enc_der_0, err := v.DownloadResponseOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding downloadResponseOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 33, enc_der_0)
		return enc_der_0, nil
	case PrepareDownloadResponseChoiceDownloadResponseError:
		if v.DownloadResponseError == nil {
			return nil, fmt.Errorf("choice PrepareDownloadResponse: downloadResponseError is nil")
		}
		enc_der_1, err := v.DownloadResponseError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding downloadResponseError: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 33, enc_der_1)
		return enc_der_1, nil
	case PrepareDownloadResponseChoiceCompactDownloadResponseOk:
		if v.CompactDownloadResponseOk == nil {
			return nil, fmt.Errorf("choice PrepareDownloadResponse: compactDownloadResponseOk is nil")
		}
		enc_der_2, err := v.CompactDownloadResponseOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactDownloadResponseOk: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_der_2)
		enc_der_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 33, enc_der_2)
		return enc_der_2, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes PrepareDownloadResponse from BER/DER format.
func (v *PrepareDownloadResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for PrepareDownloadResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding PrepareDownloadResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 33 || !decodedTag.Constructed {
		return fmt.Errorf("decoding PrepareDownloadResponse CHOICE: %w: expected tag [CONTEXT 33], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareDownloadResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for PrepareDownloadResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PrepareDownloadResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding PrepareDownloadResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareDownloadResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = PrepareDownloadResponseChoiceDownloadResponseOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding downloadResponseOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec sgp22.PrepareDownloadResponseOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding downloadResponseOk: %w", unmErr)
		}
		v.DownloadResponseOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = PrepareDownloadResponseChoiceDownloadResponseError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding downloadResponseError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec sgp22.PrepareDownloadResponseError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding downloadResponseError: %w", unmErr)
		}
		v.DownloadResponseError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = PrepareDownloadResponseChoiceCompactDownloadResponseOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding compactDownloadResponseOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CompactPrepareDownloadResponseOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding compactDownloadResponseOk: %w", unmErr)
		}
		v.CompactDownloadResponseOk = &dec
	} else {
		return fmt.Errorf("unknown tag %s for PrepareDownloadResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CompactPrepareDownloadResponseOk to BER format.
func (v *CompactPrepareDownloadResponseOk) MarshalBER() ([]byte, error) {
	var children []byte
	enc_compacteuiccsigned2, err := v.CompactEuiccSigned2.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding compactEuiccSigned2: %w", err)
	}
	children = append(children, enc_compacteuiccsigned2...)
	enc_euiccsignature2 := ber.EncodeOctetString(v.EuiccSignature2)
	enc_euiccsignature2 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccsignature2)
	children = append(children, enc_euiccsignature2...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CompactPrepareDownloadResponseOk to DER format.
func (v *CompactPrepareDownloadResponseOk) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactPrepareDownloadResponseOk from BER/DER format.
func (v *CompactPrepareDownloadResponseOk) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CompactPrepareDownloadResponseOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactPrepareDownloadResponseOk", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode compactEuiccSigned2
	if offset >= len(content) {
		return fmt.Errorf("missing required field compactEuiccSigned2")
	}
	// Decode nested SEQUENCE (CompactEuiccSigned2)
	_, n_compacteuiccsigned2, _, tlvErr_compacteuiccsigned2 := ber.DecodeTLV(content[offset:])
	if tlvErr_compacteuiccsigned2 != nil {
		return fmt.Errorf("decoding compactEuiccSigned2: %w", tlvErr_compacteuiccsigned2)
	}
	if unmErr := v.CompactEuiccSigned2.UnmarshalBER(content[offset : offset+n_compacteuiccsigned2]); unmErr != nil {
		return fmt.Errorf("decoding compactEuiccSigned2: %w", unmErr)
	}
	offset += n_compacteuiccsigned2
	// Decode euiccSignature2
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSignature2")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccSignature2, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccsignature2, rawVal_euiccsignature2, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccSignature2: %w", err)
	}
	v.EuiccSignature2 = rawVal_euiccsignature2
	offset += n_euiccsignature2
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CompactPrepareDownloadResponseOk", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CompactEuiccSigned2 to BER format.
func (v *CompactEuiccSigned2) MarshalBER() ([]byte, error) {
	var children []byte
	if v.EuiccOtpk != nil {
		enc_euiccotpk := ber.EncodeOctetString(v.EuiccOtpk)
		enc_euiccotpk = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 73, false, enc_euiccotpk)
		children = append(children, enc_euiccotpk...)
	}
	if v.HashCc != nil {
		enc_hashcc := ber.EncodeOctetString([]byte(*v.HashCc))
		children = append(children, enc_hashcc...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CompactEuiccSigned2 to DER format.
func (v *CompactEuiccSigned2) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactEuiccSigned2 from BER/DER format.
func (v *CompactEuiccSigned2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CompactEuiccSigned2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactEuiccSigned2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccOtpk
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 73 {
				_, n_euiccotpk, rawVal_euiccotpk, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccOtpk: %w", err)
				}
				tmp_euiccotpk := rawVal_euiccotpk
				v.EuiccOtpk = tmp_euiccotpk
				offset += n_euiccotpk
			}
		}
	}
	// Decode hashCc
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_hashcc, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding hashCc: %w", err)
				}
				tmp_hashcc := sgp22.Octet32(val_hashcc)
				v.HashCc = &tmp_hashcc
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CompactEuiccSigned2", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EuiccSigned1 to BER format.
func (v *EuiccSigned1) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_serveraddress := ber.EncodeStringTag(12, v.ServerAddress)
	enc_serveraddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_serveraddress)
	children = append(children, enc_serveraddress...)
	enc_serverchallenge := ber.EncodeOctetString([]byte(v.ServerChallenge))
	enc_serverchallenge = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_serverchallenge)
	children = append(children, enc_serverchallenge...)
	enc_euiccinfo2, err := v.EuiccInfo2.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccInfo2: %w", err)
	}
	children = append(children, enc_euiccinfo2...)
	enc_ctxparams1, err := v.CtxParams1.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding ctxParams1: %w", err)
	}
	children = append(children, enc_ctxparams1...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EuiccSigned1 to DER format.
func (v *EuiccSigned1) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccSigned1 from BER/DER format.
func (v *EuiccSigned1) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccSigned1 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccSigned1", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = sgp22.TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode serverAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for serverAddress, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_serveraddress, rawVal_serveraddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serverAddress: %w", err)
	}
	decVal_serveraddress := ber.DecodeStringValue(rawVal_serveraddress)
	v.ServerAddress = decVal_serveraddress
	offset += n_serveraddress
	// Decode serverChallenge
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverChallenge")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for serverChallenge, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	_, n_serverchallenge, rawVal_serverchallenge, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serverChallenge: %w", err)
	}
	v.ServerChallenge = sgp22.Octet16(rawVal_serverchallenge)
	offset += n_serverchallenge
	// Decode euiccInfo2
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccInfo2")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 34 {
			return fmt.Errorf("expected tag [%s %d] for euiccInfo2, got %s", "CONTEXT", 34, reqTag_)
		}
	}
	// Decode nested SEQUENCE (EUICCInfo2)
	_, n_euiccinfo2, _, tlvErr_euiccinfo2 := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccinfo2 != nil {
		return fmt.Errorf("decoding euiccInfo2: %w", tlvErr_euiccinfo2)
	}
	if unmErr := v.EuiccInfo2.UnmarshalBER(content[offset : offset+n_euiccinfo2]); unmErr != nil {
		return fmt.Errorf("decoding euiccInfo2: %w", unmErr)
	}
	offset += n_euiccinfo2
	// Decode ctxParams1
	if offset >= len(content) {
		return fmt.Errorf("missing required field ctxParams1")
	}
	// Decode nested CHOICE (sgp22.CtxParams1)
	_, n_ctxparams1, _, tlvErr_ctxparams1 := ber.DecodeTLV(content[offset:])
	if tlvErr_ctxparams1 != nil {
		return fmt.Errorf("decoding ctxParams1: %w", tlvErr_ctxparams1)
	}
	if unmErr := v.CtxParams1.UnmarshalBER(content[offset : offset+n_ctxparams1]); unmErr != nil {
		return fmt.Errorf("decoding ctxParams1: %w", unmErr)
	}
	offset += n_ctxparams1
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EuiccSigned1", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AuthenticateResponseOk to BER format.
func (v *AuthenticateResponseOk) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccsigned1, err := v.EuiccSigned1.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccSigned1: %w", err)
	}
	children = append(children, enc_euiccsigned1...)
	enc_euiccsignature1 := ber.EncodeOctetString(v.EuiccSignature1)
	enc_euiccsignature1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccsignature1)
	children = append(children, enc_euiccsignature1...)
	enc_euicccertificate, err := v.EuiccCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccCertificate: %w", err)
	}
	children = append(children, enc_euicccertificate...)
	enc_eumcertificate, err := v.EumCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding eumCertificate: %w", err)
	}
	children = append(children, enc_eumcertificate...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AuthenticateResponseOk to DER format.
func (v *AuthenticateResponseOk) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateResponseOk from BER/DER format.
func (v *AuthenticateResponseOk) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateResponseOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateResponseOk", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccSigned1
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSigned1")
	}
	// Decode nested SEQUENCE (EuiccSigned1)
	_, n_euiccsigned1, _, tlvErr_euiccsigned1 := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccsigned1 != nil {
		return fmt.Errorf("decoding euiccSigned1: %w", tlvErr_euiccsigned1)
	}
	if unmErr := v.EuiccSigned1.UnmarshalBER(content[offset : offset+n_euiccsigned1]); unmErr != nil {
		return fmt.Errorf("decoding euiccSigned1: %w", unmErr)
	}
	offset += n_euiccsigned1
	// Decode euiccSignature1
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSignature1")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccSignature1, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccsignature1, rawVal_euiccsignature1, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccSignature1: %w", err)
	}
	v.EuiccSignature1 = rawVal_euiccsignature1
	offset += n_euiccsignature1
	// Decode euiccCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCertificate")
	}
	// Decode nested SEQUENCE (sgp22.Certificate)
	_, n_euicccertificate, _, tlvErr_euicccertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_euicccertificate != nil {
		return fmt.Errorf("decoding euiccCertificate: %w", tlvErr_euicccertificate)
	}
	if unmErr := v.EuiccCertificate.UnmarshalBER(content[offset : offset+n_euicccertificate]); unmErr != nil {
		return fmt.Errorf("decoding euiccCertificate: %w", unmErr)
	}
	offset += n_euicccertificate
	// Decode eumCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field eumCertificate")
	}
	// Decode nested SEQUENCE (sgp22.Certificate)
	_, n_eumcertificate, _, tlvErr_eumcertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_eumcertificate != nil {
		return fmt.Errorf("decoding eumCertificate: %w", tlvErr_eumcertificate)
	}
	if unmErr := v.EumCertificate.UnmarshalBER(content[offset : offset+n_eumcertificate]); unmErr != nil {
		return fmt.Errorf("decoding eumCertificate: %w", unmErr)
	}
	offset += n_eumcertificate
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateResponseOk", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AuthenticateServerResponse to BER format.
func (v *AuthenticateServerResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AuthenticateServerResponseChoiceAuthenticateResponseOk:
		if v.AuthenticateResponseOk == nil {
			return nil, fmt.Errorf("choice AuthenticateServerResponse: authenticateResponseOk is nil")
		}
		enc_0, err := v.AuthenticateResponseOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateResponseOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 56, enc_0)
		return enc_0, nil
	case AuthenticateServerResponseChoiceAuthenticateResponseError:
		if v.AuthenticateResponseError == nil {
			return nil, fmt.Errorf("choice AuthenticateServerResponse: authenticateResponseError is nil")
		}
		enc_1, err := v.AuthenticateResponseError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateResponseError: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 56, enc_1)
		return enc_1, nil
	case AuthenticateServerResponseChoiceCompactAuthenticateResponseOk:
		if v.CompactAuthenticateResponseOk == nil {
			return nil, fmt.Errorf("choice AuthenticateServerResponse: compactAuthenticateResponseOk is nil")
		}
		enc_2, err := v.CompactAuthenticateResponseOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactAuthenticateResponseOk: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_2)
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 56, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AuthenticateServerResponse", v.Choice)
	}
}

// MarshalDER encodes AuthenticateServerResponse to DER format.
func (v *AuthenticateServerResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case AuthenticateServerResponseChoiceAuthenticateResponseOk:
		if v.AuthenticateResponseOk == nil {
			return nil, fmt.Errorf("choice AuthenticateServerResponse: authenticateResponseOk is nil")
		}
		enc_der_0, err := v.AuthenticateResponseOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateResponseOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 56, enc_der_0)
		return enc_der_0, nil
	case AuthenticateServerResponseChoiceAuthenticateResponseError:
		if v.AuthenticateResponseError == nil {
			return nil, fmt.Errorf("choice AuthenticateServerResponse: authenticateResponseError is nil")
		}
		enc_der_1, err := v.AuthenticateResponseError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateResponseError: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 56, enc_der_1)
		return enc_der_1, nil
	case AuthenticateServerResponseChoiceCompactAuthenticateResponseOk:
		if v.CompactAuthenticateResponseOk == nil {
			return nil, fmt.Errorf("choice AuthenticateServerResponse: compactAuthenticateResponseOk is nil")
		}
		enc_der_2, err := v.CompactAuthenticateResponseOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactAuthenticateResponseOk: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_der_2)
		enc_der_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 56, enc_der_2)
		return enc_der_2, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateServerResponse from BER/DER format.
func (v *AuthenticateServerResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AuthenticateServerResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateServerResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 56 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AuthenticateServerResponse CHOICE: %w: expected tag [CONTEXT 56], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateServerResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for AuthenticateServerResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AuthenticateServerResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AuthenticateServerResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateServerResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = AuthenticateServerResponseChoiceAuthenticateResponseOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateResponseOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AuthenticateResponseOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding authenticateResponseOk: %w", unmErr)
		}
		v.AuthenticateResponseOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = AuthenticateServerResponseChoiceAuthenticateResponseError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateResponseError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec sgp22.AuthenticateResponseError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding authenticateResponseError: %w", unmErr)
		}
		v.AuthenticateResponseError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = AuthenticateServerResponseChoiceCompactAuthenticateResponseOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding compactAuthenticateResponseOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CompactAuthenticateResponseOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding compactAuthenticateResponseOk: %w", unmErr)
		}
		v.CompactAuthenticateResponseOk = &dec
	} else {
		return fmt.Errorf("unknown tag %s for AuthenticateServerResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CompactAuthenticateResponseOk to BER format.
func (v *CompactAuthenticateResponseOk) MarshalBER() ([]byte, error) {
	var children []byte
	enc_signeddata, err := v.SignedData.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding signedData: %w", err)
	}
	children = append(children, enc_signeddata...)
	enc_euiccsignature1 := ber.EncodeOctetString(v.EuiccSignature1)
	enc_euiccsignature1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccsignature1)
	children = append(children, enc_euiccsignature1...)
	if v.EuiccCertificate != nil {
		enc_euicccertificate, err := v.EuiccCertificate.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccCertificate: %w", err)
		}
		enc_euicccertificate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_euicccertificate)
		children = append(children, enc_euicccertificate...)
	}
	if v.EumCertificate != nil {
		enc_eumcertificate, err := v.EumCertificate.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding eumCertificate: %w", err)
		}
		enc_eumcertificate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_eumcertificate)
		children = append(children, enc_eumcertificate...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CompactAuthenticateResponseOk to DER format.
func (v *CompactAuthenticateResponseOk) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactAuthenticateResponseOk from BER/DER format.
func (v *CompactAuthenticateResponseOk) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CompactAuthenticateResponseOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactAuthenticateResponseOk", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode signedData
	if offset >= len(content) {
		return fmt.Errorf("missing required field signedData")
	}
	// Decode nested CHOICE (CompactAuthenticateResponseOkSignedData)
	_, n_signeddata, _, tlvErr_signeddata := ber.DecodeTLV(content[offset:])
	if tlvErr_signeddata != nil {
		return fmt.Errorf("decoding signedData: %w", tlvErr_signeddata)
	}
	if unmErr := v.SignedData.UnmarshalBER(content[offset : offset+n_signeddata]); unmErr != nil {
		return fmt.Errorf("decoding signedData: %w", unmErr)
	}
	offset += n_signeddata
	// Decode euiccSignature1
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSignature1")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccSignature1, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccsignature1, rawVal_euiccsignature1, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccSignature1: %w", err)
	}
	v.EuiccSignature1 = rawVal_euiccsignature1
	offset += n_euiccsignature1
	// Decode euiccCertificate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_euicccertificate, rawVal_euicccertificate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccCertificate: %w", err)
				}
				reconstructed_euicccertificate := ber.EncodeSequence(rawVal_euicccertificate)
				var dec_euicccertificate sgp22.Certificate
				if unmErr := dec_euicccertificate.UnmarshalBER(reconstructed_euicccertificate); unmErr != nil {
					return fmt.Errorf("decoding euiccCertificate: %w", unmErr)
				}
				v.EuiccCertificate = &dec_euicccertificate
				offset += n_euicccertificate
			}
		}
	}
	// Decode eumCertificate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eumcertificate, rawVal_eumcertificate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eumCertificate: %w", err)
				}
				reconstructed_eumcertificate := ber.EncodeSequence(rawVal_eumcertificate)
				var dec_eumcertificate sgp22.Certificate
				if unmErr := dec_eumcertificate.UnmarshalBER(reconstructed_eumcertificate); unmErr != nil {
					return fmt.Errorf("decoding eumCertificate: %w", unmErr)
				}
				v.EumCertificate = &dec_eumcertificate
				offset += n_eumcertificate
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CompactAuthenticateResponseOk", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CompactEuiccSigned1 to BER format.
func (v *CompactEuiccSigned1) MarshalBER() ([]byte, error) {
	var children []byte
	enc_extcardresource := ber.EncodeOctetString(v.ExtCardResource)
	enc_extcardresource = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_extcardresource)
	children = append(children, enc_extcardresource...)
	if v.CtxParams1 != nil {
		enc_ctxparams1, err := v.CtxParams1.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ctxParams1: %w", err)
		}
		enc_ctxparams1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ctxparams1)
		children = append(children, enc_ctxparams1...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CompactEuiccSigned1 to DER format.
func (v *CompactEuiccSigned1) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactEuiccSigned1 from BER/DER format.
func (v *CompactEuiccSigned1) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CompactEuiccSigned1 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactEuiccSigned1", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extCardResource
	if offset >= len(content) {
		return fmt.Errorf("missing required field extCardResource")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for extCardResource, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	_, n_extcardresource, rawVal_extcardresource, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding extCardResource: %w", err)
	}
	v.ExtCardResource = rawVal_extcardresource
	offset += n_extcardresource
	// Decode ctxParams1
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_ctxparams1, innerData_ctxparams1, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ctxParams1: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_ctxparams1 sgp22.CtxParams1
				if unmErr := dec_ctxparams1.UnmarshalBER(innerData_ctxparams1); unmErr != nil {
					return fmt.Errorf("decoding ctxParams1: %w", unmErr)
				}
				v.CtxParams1 = &dec_ctxparams1
				offset += n_ctxparams1
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CompactEuiccSigned1", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PendingNotification to BER format.
func (v *PendingNotification) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case PendingNotificationChoiceProfileInstallationResult:
		if v.ProfileInstallationResult == nil {
			return nil, fmt.Errorf("choice PendingNotification: profileInstallationResult is nil")
		}
		enc_0, err := v.ProfileInstallationResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileInstallationResult: %w", err)
		}
		return enc_0, nil
	case PendingNotificationChoiceOtherSignedNotification:
		if v.OtherSignedNotification == nil {
			return nil, fmt.Errorf("choice PendingNotification: otherSignedNotification is nil")
		}
		enc_1, err := v.OtherSignedNotification.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding otherSignedNotification: %w", err)
		}
		return enc_1, nil
	case PendingNotificationChoiceCompactProfileInstallationResult:
		if v.CompactProfileInstallationResult == nil {
			return nil, fmt.Errorf("choice PendingNotification: compactProfileInstallationResult is nil")
		}
		enc_2, err := v.CompactProfileInstallationResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactProfileInstallationResult: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_2)
		return enc_2, nil
	case PendingNotificationChoiceCompactOtherSignedNotification:
		if v.CompactOtherSignedNotification == nil {
			return nil, fmt.Errorf("choice PendingNotification: compactOtherSignedNotification is nil")
		}
		enc_3, err := v.CompactOtherSignedNotification.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactOtherSignedNotification: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PendingNotification", v.Choice)
	}
}

// MarshalDER encodes PendingNotification to DER format.
func (v *PendingNotification) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case PendingNotificationChoiceProfileInstallationResult:
		if v.ProfileInstallationResult == nil {
			return nil, fmt.Errorf("choice PendingNotification: profileInstallationResult is nil")
		}
		enc_der_0, err := v.ProfileInstallationResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileInstallationResult: %w", err)
		}
		return enc_der_0, nil
	case PendingNotificationChoiceOtherSignedNotification:
		if v.OtherSignedNotification == nil {
			return nil, fmt.Errorf("choice PendingNotification: otherSignedNotification is nil")
		}
		enc_der_1, err := v.OtherSignedNotification.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding otherSignedNotification: %w", err)
		}
		return enc_der_1, nil
	case PendingNotificationChoiceCompactProfileInstallationResult:
		if v.CompactProfileInstallationResult == nil {
			return nil, fmt.Errorf("choice PendingNotification: compactProfileInstallationResult is nil")
		}
		enc_der_2, err := v.CompactProfileInstallationResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactProfileInstallationResult: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_2)
		return enc_der_2, nil
	case PendingNotificationChoiceCompactOtherSignedNotification:
		if v.CompactOtherSignedNotification == nil {
			return nil, fmt.Errorf("choice PendingNotification: compactOtherSignedNotification is nil")
		}
		enc_der_3, err := v.CompactOtherSignedNotification.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactOtherSignedNotification: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_3)
		return enc_der_3, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes PendingNotification from BER/DER format.
func (v *PendingNotification) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for PendingNotification CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PendingNotification: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding PendingNotification CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PendingNotification", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 55 {
		v.Choice = PendingNotificationChoiceProfileInstallationResult
		var dec ProfileInstallationResult
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding profileInstallationResult: %w", unmErr)
		}
		v.ProfileInstallationResult = &dec
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = PendingNotificationChoiceOtherSignedNotification
		var dec sgp22.OtherSignedNotification
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding otherSignedNotification: %w", unmErr)
		}
		v.OtherSignedNotification = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = PendingNotificationChoiceCompactProfileInstallationResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding compactProfileInstallationResult: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CompactProfileInstallationResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding compactProfileInstallationResult: %w", unmErr)
		}
		v.CompactProfileInstallationResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = PendingNotificationChoiceCompactOtherSignedNotification
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding compactOtherSignedNotification: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CompactOtherSignedNotification
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding compactOtherSignedNotification: %w", unmErr)
		}
		v.CompactOtherSignedNotification = &dec
	} else {
		return fmt.Errorf("unknown tag %s for PendingNotification CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ProfileInstallationResult to BER format.
func (v *ProfileInstallationResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_profileinstallationresultdata, err := v.ProfileInstallationResultData.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding profileInstallationResultData: %w", err)
	}
	children = append(children, enc_profileinstallationresultdata...)
	enc_euiccsignpir := ber.EncodeOctetString([]byte(v.EuiccSignPIR))
	enc_euiccsignpir = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccsignpir)
	children = append(children, enc_euiccsignpir...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 55, Constructed: true}, children), nil
}

// MarshalDER encodes ProfileInstallationResult to DER format.
func (v *ProfileInstallationResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInstallationResult from BER/DER format.
func (v *ProfileInstallationResult) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileInstallationResult: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 55 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileInstallationResult: %w: expected tag [CONTEXT 55], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInstallationResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode profileInstallationResultData
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileInstallationResultData")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 39 {
			return fmt.Errorf("expected tag [%s %d] for profileInstallationResultData, got %s", "CONTEXT", 39, reqTag_)
		}
	}
	// Decode nested SEQUENCE (sgp22.ProfileInstallationResultData)
	_, n_profileinstallationresultdata, _, tlvErr_profileinstallationresultdata := ber.DecodeTLV(content[offset:])
	if tlvErr_profileinstallationresultdata != nil {
		return fmt.Errorf("decoding profileInstallationResultData: %w", tlvErr_profileinstallationresultdata)
	}
	if unmErr := v.ProfileInstallationResultData.UnmarshalBER(content[offset : offset+n_profileinstallationresultdata]); unmErr != nil {
		return fmt.Errorf("decoding profileInstallationResultData: %w", unmErr)
	}
	offset += n_profileinstallationresultdata
	// Decode euiccSignPIR
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSignPIR")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccSignPIR, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccsignpir, rawVal_euiccsignpir, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccSignPIR: %w", err)
	}
	v.EuiccSignPIR = sgp22.EuiccSignPIR(rawVal_euiccsignpir)
	offset += n_euiccsignpir
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProfileInstallationResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CompactProfileInstallationResult to BER format.
func (v *CompactProfileInstallationResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_compactprofileinstallationresultdata, err := v.CompactProfileInstallationResultData.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding compactProfileInstallationResultData: %w", err)
	}
	enc_compactprofileinstallationresultdata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_compactprofileinstallationresultdata)
	children = append(children, enc_compactprofileinstallationresultdata...)
	enc_euiccsignpir := ber.EncodeOctetString([]byte(v.EuiccSignPIR))
	enc_euiccsignpir = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccsignpir)
	children = append(children, enc_euiccsignpir...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CompactProfileInstallationResult to DER format.
func (v *CompactProfileInstallationResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactProfileInstallationResult from BER/DER format.
func (v *CompactProfileInstallationResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CompactProfileInstallationResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactProfileInstallationResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode compactProfileInstallationResultData
	if offset >= len(content) {
		return fmt.Errorf("missing required field compactProfileInstallationResultData")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for compactProfileInstallationResultData, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_compactprofileinstallationresultdata, rawVal_compactprofileinstallationresultdata, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding compactProfileInstallationResultData: %w", err)
	}
	reconstructed_compactprofileinstallationresultdata := ber.EncodeSequence(rawVal_compactprofileinstallationresultdata)
	if unmErr := v.CompactProfileInstallationResultData.UnmarshalBER(reconstructed_compactprofileinstallationresultdata); unmErr != nil {
		return fmt.Errorf("decoding compactProfileInstallationResultData: %w", unmErr)
	}
	offset += n_compactprofileinstallationresultdata
	// Decode euiccSignPIR
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSignPIR")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccSignPIR, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccsignpir, rawVal_euiccsignpir, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccSignPIR: %w", err)
	}
	v.EuiccSignPIR = sgp22.EuiccSignPIR(rawVal_euiccsignpir)
	offset += n_euiccsignpir
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CompactProfileInstallationResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CompactProfileInstallationResultData to BER format.
func (v *CompactProfileInstallationResultData) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	if v.SeqNumber == nil {
		return nil, fmt.Errorf("encoding seqNumber: required INTEGER is nil")
	}
	enc_seqnumber := ber.EncodeBigInt(v.SeqNumber)
	children = append(children, enc_seqnumber...)
	if v.IccidPresent != nil {
		var enc_iccidpresent []byte
		if v.IccidPresentRaw_ != 0 {
			enc_iccidpresent = ber.EncodeBooleanRaw(v.IccidPresentRaw_)
		} else {
			enc_iccidpresent = ber.EncodeBoolean(*v.IccidPresent)
		}
		children = append(children, enc_iccidpresent...)
	}
	enc_compactfinalresult, err := v.CompactFinalResult.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding compactFinalResult: %w", err)
	}
	enc_compactfinalresult = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_compactfinalresult)
	children = append(children, enc_compactfinalresult...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CompactProfileInstallationResultData to DER format.
func (v *CompactProfileInstallationResultData) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactProfileInstallationResultData from BER/DER format.
func (v *CompactProfileInstallationResultData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CompactProfileInstallationResultData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactProfileInstallationResultData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = sgp22.TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode seqNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field seqNumber")
	}
	val_seqnumber, n, err := ber.DecodeBigInt(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding seqNumber: %w", err)
	}
	v.SeqNumber = val_seqnumber
	offset += n
	// Decode iccidPresent
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 1 {
				val_iccidpresent, raw_iccidpresent, n, err := ber.DecodeBoolean(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iccidPresent: %w", err)
				}
				v.IccidPresent = &val_iccidpresent
				v.IccidPresentRaw_ = raw_iccidpresent
				offset += n
			}
		}
	}
	// Decode compactFinalResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field compactFinalResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for compactFinalResult, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_compactfinalresult, innerData_compactfinalresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding compactFinalResult: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.CompactFinalResult.UnmarshalBER(innerData_compactfinalresult); unmErr != nil {
		return fmt.Errorf("decoding compactFinalResult: %w", unmErr)
	}
	offset += n_compactfinalresult
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CompactProfileInstallationResultData", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CompactSuccessResult to BER format.
func (v *CompactSuccessResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_compactaid := ber.EncodeOctetString(v.CompactAid)
	enc_compactaid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 15, false, enc_compactaid)
	children = append(children, enc_compactaid...)
	if v.SimaResponse != nil {
		enc_simaresponse := ber.EncodeOctetString(v.SimaResponse)
		children = append(children, enc_simaresponse...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CompactSuccessResult to DER format.
func (v *CompactSuccessResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactSuccessResult from BER/DER format.
func (v *CompactSuccessResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CompactSuccessResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactSuccessResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode compactAid
	if offset >= len(content) {
		return fmt.Errorf("missing required field compactAid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 15 {
			return fmt.Errorf("expected tag [%s %d] for compactAid, got %s", "APPLICATION", 15, reqTag_)
		}
	}
	_, n_compactaid, rawVal_compactaid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding compactAid: %w", err)
	}
	v.CompactAid = rawVal_compactaid
	offset += n_compactaid
	// Decode simaResponse
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_simaresponse, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding simaResponse: %w", err)
				}
				tmp_simaresponse := val_simaresponse
				v.SimaResponse = tmp_simaresponse
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CompactSuccessResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CompactOtherSignedNotification to BER format.
func (v *CompactOtherSignedNotification) MarshalBER() ([]byte, error) {
	var children []byte
	if v.EidValue != nil {
		enc_eidvalue := ber.EncodeOctetString([]byte(*v.EidValue))
		enc_eidvalue = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_eidvalue)
		children = append(children, enc_eidvalue...)
	}
	enc_tbsothernotification, err := v.TbsOtherNotification.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding tbsOtherNotification: %w", err)
	}
	children = append(children, enc_tbsothernotification...)
	enc_euiccnotificationsignature := ber.EncodeOctetString(v.EuiccNotificationSignature)
	enc_euiccnotificationsignature = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccnotificationsignature)
	children = append(children, enc_euiccnotificationsignature...)
	if v.EuiccCiPKIdentifierToBeUsed != nil {
		enc_euicccipkidentifiertobeused := ber.EncodeOctetString(v.EuiccCiPKIdentifierToBeUsed)
		children = append(children, enc_euicccipkidentifiertobeused...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CompactOtherSignedNotification to DER format.
func (v *CompactOtherSignedNotification) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactOtherSignedNotification from BER/DER format.
func (v *CompactOtherSignedNotification) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CompactOtherSignedNotification SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactOtherSignedNotification", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eidValue
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 26 {
				_, n_eidvalue, rawVal_eidvalue, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eidValue: %w", err)
				}
				tmp_eidvalue := sgp22.Octet16(rawVal_eidvalue)
				v.EidValue = &tmp_eidvalue
				offset += n_eidvalue
			}
		}
	}
	// Decode tbsOtherNotification
	if offset >= len(content) {
		return fmt.Errorf("missing required field tbsOtherNotification")
	}
	// Decode nested SEQUENCE (sgp22.NotificationMetadata)
	_, n_tbsothernotification, _, tlvErr_tbsothernotification := ber.DecodeTLV(content[offset:])
	if tlvErr_tbsothernotification != nil {
		return fmt.Errorf("decoding tbsOtherNotification: %w", tlvErr_tbsothernotification)
	}
	if unmErr := v.TbsOtherNotification.UnmarshalBER(content[offset : offset+n_tbsothernotification]); unmErr != nil {
		return fmt.Errorf("decoding tbsOtherNotification: %w", unmErr)
	}
	offset += n_tbsothernotification
	// Decode euiccNotificationSignature
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccNotificationSignature")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccNotificationSignature, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccnotificationsignature, rawVal_euiccnotificationsignature, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccNotificationSignature: %w", err)
	}
	v.EuiccNotificationSignature = rawVal_euiccnotificationsignature
	offset += n_euiccnotificationsignature
	// Decode euiccCiPKIdentifierToBeUsed
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_euicccipkidentifiertobeused, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccCiPKIdentifierToBeUsed: %w", err)
				}
				tmp_euicccipkidentifiertobeused := val_euicccipkidentifiertobeused
				v.EuiccCiPKIdentifierToBeUsed = tmp_euicccipkidentifiertobeused
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CompactOtherSignedNotification", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CancelSessionResponse to BER format.
func (v *CancelSessionResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CancelSessionResponseChoiceCancelSessionResponseOk:
		if v.CancelSessionResponseOk == nil {
			return nil, fmt.Errorf("choice CancelSessionResponse: cancelSessionResponseOk is nil")
		}
		enc_0, err := v.CancelSessionResponseOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionResponseOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_0)
		return enc_0, nil
	case CancelSessionResponseChoiceCancelSessionResponseError:
		if v.CancelSessionResponseError == nil {
			return nil, fmt.Errorf("choice CancelSessionResponse: cancelSessionResponseError is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.CancelSessionResponseError))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_1)
		return enc_1, nil
	case CancelSessionResponseChoiceCompactCancelSessionResponseOk:
		if v.CompactCancelSessionResponseOk == nil {
			return nil, fmt.Errorf("choice CancelSessionResponse: compactCancelSessionResponseOk is nil")
		}
		enc_2, err := v.CompactCancelSessionResponseOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactCancelSessionResponseOk: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_2)
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CancelSessionResponse", v.Choice)
	}
}

// MarshalDER encodes CancelSessionResponse to DER format.
func (v *CancelSessionResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CancelSessionResponseChoiceCancelSessionResponseOk:
		if v.CancelSessionResponseOk == nil {
			return nil, fmt.Errorf("choice CancelSessionResponse: cancelSessionResponseOk is nil")
		}
		enc_der_0, err := v.CancelSessionResponseOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionResponseOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_der_0)
		return enc_der_0, nil
	case CancelSessionResponseChoiceCompactCancelSessionResponseOk:
		if v.CompactCancelSessionResponseOk == nil {
			return nil, fmt.Errorf("choice CancelSessionResponse: compactCancelSessionResponseOk is nil")
		}
		enc_der_2, err := v.CompactCancelSessionResponseOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactCancelSessionResponseOk: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_der_2)
		enc_der_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_der_2)
		return enc_der_2, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes CancelSessionResponse from BER/DER format.
func (v *CancelSessionResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CancelSessionResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding CancelSessionResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 65 || !decodedTag.Constructed {
		return fmt.Errorf("decoding CancelSessionResponse CHOICE: %w: expected tag [CONTEXT 65], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for CancelSessionResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CancelSessionResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CancelSessionResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CancelSessionResponseChoiceCancelSessionResponseOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cancelSessionResponseOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec sgp22.CancelSessionResponseOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding cancelSessionResponseOk: %w", unmErr)
		}
		v.CancelSessionResponseOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CancelSessionResponseChoiceCancelSessionResponseError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cancelSessionResponseError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding cancelSessionResponseError: %w", intErr)
		}
		v.CancelSessionResponseError = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = CancelSessionResponseChoiceCompactCancelSessionResponseOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding compactCancelSessionResponseOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CompactCancelSessionResponseOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding compactCancelSessionResponseOk: %w", unmErr)
		}
		v.CompactCancelSessionResponseOk = &dec
	} else {
		return fmt.Errorf("unknown tag %s for CancelSessionResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CompactCancelSessionResponseOk to BER format.
func (v *CompactCancelSessionResponseOk) MarshalBER() ([]byte, error) {
	var children []byte
	enc_compacteuicccancelsessionsigned, err := v.CompactEuiccCancelSessionSigned.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding compactEuiccCancelSessionSigned: %w", err)
	}
	children = append(children, enc_compacteuicccancelsessionsigned...)
	enc_euicccancelsessionsignature := ber.EncodeOctetString(v.EuiccCancelSessionSignature)
	enc_euicccancelsessionsignature = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euicccancelsessionsignature)
	children = append(children, enc_euicccancelsessionsignature...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CompactCancelSessionResponseOk to DER format.
func (v *CompactCancelSessionResponseOk) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactCancelSessionResponseOk from BER/DER format.
func (v *CompactCancelSessionResponseOk) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CompactCancelSessionResponseOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactCancelSessionResponseOk", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode compactEuiccCancelSessionSigned
	if offset >= len(content) {
		return fmt.Errorf("missing required field compactEuiccCancelSessionSigned")
	}
	// Decode nested SEQUENCE (CompactEuiccCancelSessionSigned)
	_, n_compacteuicccancelsessionsigned, _, tlvErr_compacteuicccancelsessionsigned := ber.DecodeTLV(content[offset:])
	if tlvErr_compacteuicccancelsessionsigned != nil {
		return fmt.Errorf("decoding compactEuiccCancelSessionSigned: %w", tlvErr_compacteuicccancelsessionsigned)
	}
	if unmErr := v.CompactEuiccCancelSessionSigned.UnmarshalBER(content[offset : offset+n_compacteuicccancelsessionsigned]); unmErr != nil {
		return fmt.Errorf("decoding compactEuiccCancelSessionSigned: %w", unmErr)
	}
	offset += n_compacteuicccancelsessionsigned
	// Decode euiccCancelSessionSignature
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCancelSessionSignature")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccCancelSessionSignature, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euicccancelsessionsignature, rawVal_euicccancelsessionsignature, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCancelSessionSignature: %w", err)
	}
	v.EuiccCancelSessionSignature = rawVal_euicccancelsessionsignature
	offset += n_euicccancelsessionsignature
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CompactCancelSessionResponseOk", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CompactEuiccCancelSessionSigned to BER format.
func (v *CompactEuiccCancelSessionSigned) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Reason != nil {
		enc_reason := ber.EncodeInteger(int64(*v.Reason))
		enc_reason = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_reason)
		children = append(children, enc_reason...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CompactEuiccCancelSessionSigned to DER format.
func (v *CompactEuiccCancelSessionSigned) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactEuiccCancelSessionSigned from BER/DER format.
func (v *CompactEuiccCancelSessionSigned) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CompactEuiccCancelSessionSigned SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactEuiccCancelSessionSigned", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_reason, rawVal_reason, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reason: %w", err)
				}
				decVal_reason, intErr := ber.DecodeIntegerValue(rawVal_reason)
				if intErr != nil {
					return fmt.Errorf("decoding reason: %w", intErr)
				}
				tmp_reason := sgp22.CancelSessionReason(decVal_reason)
				v.Reason = &tmp_reason
				offset += n_reason
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CompactEuiccCancelSessionSigned", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EsipaMessageFromIpaToEim to BER format.
func (v *EsipaMessageFromIpaToEim) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EsipaMessageFromIpaToEimChoiceInitiateAuthenticationRequestEsipa:
		if v.InitiateAuthenticationRequestEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: initiateAuthenticationRequestEsipa is nil")
		}
		enc_0, err := v.InitiateAuthenticationRequestEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationRequestEsipa: %w", err)
		}
		return enc_0, nil
	case EsipaMessageFromIpaToEimChoiceAuthenticateClientRequestEsipa:
		if v.AuthenticateClientRequestEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: authenticateClientRequestEsipa is nil")
		}
		enc_1, err := v.AuthenticateClientRequestEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientRequestEsipa: %w", err)
		}
		return enc_1, nil
	case EsipaMessageFromIpaToEimChoiceGetBoundProfilePackageRequestEsipa:
		if v.GetBoundProfilePackageRequestEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: getBoundProfilePackageRequestEsipa is nil")
		}
		enc_2, err := v.GetBoundProfilePackageRequestEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageRequestEsipa: %w", err)
		}
		return enc_2, nil
	case EsipaMessageFromIpaToEimChoiceCancelSessionRequestEsipa:
		if v.CancelSessionRequestEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: cancelSessionRequestEsipa is nil")
		}
		enc_3, err := v.CancelSessionRequestEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionRequestEsipa: %w", err)
		}
		return enc_3, nil
	case EsipaMessageFromIpaToEimChoiceHandleNotificationEsipa:
		if v.HandleNotificationEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: handleNotificationEsipa is nil")
		}
		enc_4, err := v.HandleNotificationEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding handleNotificationEsipa: %w", err)
		}
		return enc_4, nil
	case EsipaMessageFromIpaToEimChoiceTransferEimPackageResponse:
		if v.TransferEimPackageResponse == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: transferEimPackageResponse is nil")
		}
		enc_5, err := v.TransferEimPackageResponse.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding transferEimPackageResponse: %w", err)
		}
		return enc_5, nil
	case EsipaMessageFromIpaToEimChoiceGetEimPackageRequest:
		if v.GetEimPackageRequest == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: getEimPackageRequest is nil")
		}
		enc_6, err := v.GetEimPackageRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding getEimPackageRequest: %w", err)
		}
		return enc_6, nil
	case EsipaMessageFromIpaToEimChoiceProvideEimPackageResult:
		if v.ProvideEimPackageResult == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: provideEimPackageResult is nil")
		}
		enc_7, err := v.ProvideEimPackageResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding provideEimPackageResult: %w", err)
		}
		return enc_7, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EsipaMessageFromIpaToEim", v.Choice)
	}
}

// MarshalDER encodes EsipaMessageFromIpaToEim to DER format.
func (v *EsipaMessageFromIpaToEim) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case EsipaMessageFromIpaToEimChoiceInitiateAuthenticationRequestEsipa:
		if v.InitiateAuthenticationRequestEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: initiateAuthenticationRequestEsipa is nil")
		}
		enc_der_0, err := v.InitiateAuthenticationRequestEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationRequestEsipa: %w", err)
		}
		return enc_der_0, nil
	case EsipaMessageFromIpaToEimChoiceAuthenticateClientRequestEsipa:
		if v.AuthenticateClientRequestEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: authenticateClientRequestEsipa is nil")
		}
		enc_der_1, err := v.AuthenticateClientRequestEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientRequestEsipa: %w", err)
		}
		return enc_der_1, nil
	case EsipaMessageFromIpaToEimChoiceGetBoundProfilePackageRequestEsipa:
		if v.GetBoundProfilePackageRequestEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: getBoundProfilePackageRequestEsipa is nil")
		}
		enc_der_2, err := v.GetBoundProfilePackageRequestEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageRequestEsipa: %w", err)
		}
		return enc_der_2, nil
	case EsipaMessageFromIpaToEimChoiceCancelSessionRequestEsipa:
		if v.CancelSessionRequestEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: cancelSessionRequestEsipa is nil")
		}
		enc_der_3, err := v.CancelSessionRequestEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionRequestEsipa: %w", err)
		}
		return enc_der_3, nil
	case EsipaMessageFromIpaToEimChoiceHandleNotificationEsipa:
		if v.HandleNotificationEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: handleNotificationEsipa is nil")
		}
		enc_der_4, err := v.HandleNotificationEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding handleNotificationEsipa: %w", err)
		}
		return enc_der_4, nil
	case EsipaMessageFromIpaToEimChoiceTransferEimPackageResponse:
		if v.TransferEimPackageResponse == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: transferEimPackageResponse is nil")
		}
		enc_der_5, err := v.TransferEimPackageResponse.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding transferEimPackageResponse: %w", err)
		}
		return enc_der_5, nil
	case EsipaMessageFromIpaToEimChoiceGetEimPackageRequest:
		if v.GetEimPackageRequest == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: getEimPackageRequest is nil")
		}
		enc_der_6, err := v.GetEimPackageRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding getEimPackageRequest: %w", err)
		}
		return enc_der_6, nil
	case EsipaMessageFromIpaToEimChoiceProvideEimPackageResult:
		if v.ProvideEimPackageResult == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromIpaToEim: provideEimPackageResult is nil")
		}
		enc_der_7, err := v.ProvideEimPackageResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding provideEimPackageResult: %w", err)
		}
		return enc_der_7, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes EsipaMessageFromIpaToEim from BER/DER format.
func (v *EsipaMessageFromIpaToEim) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for EsipaMessageFromIpaToEim CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EsipaMessageFromIpaToEim: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding EsipaMessageFromIpaToEim CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EsipaMessageFromIpaToEim", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 57 {
		v.Choice = EsipaMessageFromIpaToEimChoiceInitiateAuthenticationRequestEsipa
		var dec InitiateAuthenticationRequestEsipa
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationRequestEsipa: %w", unmErr)
		}
		v.InitiateAuthenticationRequestEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 59 {
		v.Choice = EsipaMessageFromIpaToEimChoiceAuthenticateClientRequestEsipa
		var dec AuthenticateClientRequestEsipa
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding authenticateClientRequestEsipa: %w", unmErr)
		}
		v.AuthenticateClientRequestEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 58 {
		v.Choice = EsipaMessageFromIpaToEimChoiceGetBoundProfilePackageRequestEsipa
		var dec GetBoundProfilePackageRequestEsipa
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageRequestEsipa: %w", unmErr)
		}
		v.GetBoundProfilePackageRequestEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 65 {
		v.Choice = EsipaMessageFromIpaToEimChoiceCancelSessionRequestEsipa
		var dec CancelSessionRequestEsipa
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding cancelSessionRequestEsipa: %w", unmErr)
		}
		v.CancelSessionRequestEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 61 {
		v.Choice = EsipaMessageFromIpaToEimChoiceHandleNotificationEsipa
		var dec HandleNotificationEsipa
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding handleNotificationEsipa: %w", unmErr)
		}
		v.HandleNotificationEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 78 {
		v.Choice = EsipaMessageFromIpaToEimChoiceTransferEimPackageResponse
		var dec TransferEimPackageResponse
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding transferEimPackageResponse: %w", unmErr)
		}
		v.TransferEimPackageResponse = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 79 {
		v.Choice = EsipaMessageFromIpaToEimChoiceGetEimPackageRequest
		var dec GetEimPackageRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding getEimPackageRequest: %w", unmErr)
		}
		v.GetEimPackageRequest = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 80 {
		v.Choice = EsipaMessageFromIpaToEimChoiceProvideEimPackageResult
		var dec ProvideEimPackageResult
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding provideEimPackageResult: %w", unmErr)
		}
		v.ProvideEimPackageResult = &dec
	} else {
		return fmt.Errorf("unknown tag %s for EsipaMessageFromIpaToEim CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EsipaMessageFromEimToIpa to BER format.
func (v *EsipaMessageFromEimToIpa) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EsipaMessageFromEimToIpaChoiceInitiateAuthenticationResponseEsipa:
		if v.InitiateAuthenticationResponseEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: initiateAuthenticationResponseEsipa is nil")
		}
		enc_0, err := v.InitiateAuthenticationResponseEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationResponseEsipa: %w", err)
		}
		return enc_0, nil
	case EsipaMessageFromEimToIpaChoiceAuthenticateClientResponseEsipa:
		if v.AuthenticateClientResponseEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: authenticateClientResponseEsipa is nil")
		}
		enc_1, err := v.AuthenticateClientResponseEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientResponseEsipa: %w", err)
		}
		return enc_1, nil
	case EsipaMessageFromEimToIpaChoiceGetBoundProfilePackageResponseEsipa:
		if v.GetBoundProfilePackageResponseEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: getBoundProfilePackageResponseEsipa is nil")
		}
		enc_2, err := v.GetBoundProfilePackageResponseEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageResponseEsipa: %w", err)
		}
		return enc_2, nil
	case EsipaMessageFromEimToIpaChoiceCancelSessionResponseEsipa:
		if v.CancelSessionResponseEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: cancelSessionResponseEsipa is nil")
		}
		enc_3, err := v.CancelSessionResponseEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionResponseEsipa: %w", err)
		}
		return enc_3, nil
	case EsipaMessageFromEimToIpaChoiceTransferEimPackageRequest:
		if v.TransferEimPackageRequest == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: transferEimPackageRequest is nil")
		}
		enc_4, err := v.TransferEimPackageRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding transferEimPackageRequest: %w", err)
		}
		return enc_4, nil
	case EsipaMessageFromEimToIpaChoiceGetEimPackageResponse:
		if v.GetEimPackageResponse == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: getEimPackageResponse is nil")
		}
		enc_5, err := v.GetEimPackageResponse.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding getEimPackageResponse: %w", err)
		}
		return enc_5, nil
	case EsipaMessageFromEimToIpaChoiceProvideEimPackageResultResponse:
		if v.ProvideEimPackageResultResponse == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: provideEimPackageResultResponse is nil")
		}
		enc_6, err := v.ProvideEimPackageResultResponse.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding provideEimPackageResultResponse: %w", err)
		}
		return enc_6, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EsipaMessageFromEimToIpa", v.Choice)
	}
}

// MarshalDER encodes EsipaMessageFromEimToIpa to DER format.
func (v *EsipaMessageFromEimToIpa) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case EsipaMessageFromEimToIpaChoiceInitiateAuthenticationResponseEsipa:
		if v.InitiateAuthenticationResponseEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: initiateAuthenticationResponseEsipa is nil")
		}
		enc_der_0, err := v.InitiateAuthenticationResponseEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationResponseEsipa: %w", err)
		}
		return enc_der_0, nil
	case EsipaMessageFromEimToIpaChoiceAuthenticateClientResponseEsipa:
		if v.AuthenticateClientResponseEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: authenticateClientResponseEsipa is nil")
		}
		enc_der_1, err := v.AuthenticateClientResponseEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientResponseEsipa: %w", err)
		}
		return enc_der_1, nil
	case EsipaMessageFromEimToIpaChoiceGetBoundProfilePackageResponseEsipa:
		if v.GetBoundProfilePackageResponseEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: getBoundProfilePackageResponseEsipa is nil")
		}
		enc_der_2, err := v.GetBoundProfilePackageResponseEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageResponseEsipa: %w", err)
		}
		return enc_der_2, nil
	case EsipaMessageFromEimToIpaChoiceCancelSessionResponseEsipa:
		if v.CancelSessionResponseEsipa == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: cancelSessionResponseEsipa is nil")
		}
		enc_der_3, err := v.CancelSessionResponseEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionResponseEsipa: %w", err)
		}
		return enc_der_3, nil
	case EsipaMessageFromEimToIpaChoiceTransferEimPackageRequest:
		if v.TransferEimPackageRequest == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: transferEimPackageRequest is nil")
		}
		enc_der_4, err := v.TransferEimPackageRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding transferEimPackageRequest: %w", err)
		}
		return enc_der_4, nil
	case EsipaMessageFromEimToIpaChoiceGetEimPackageResponse:
		if v.GetEimPackageResponse == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: getEimPackageResponse is nil")
		}
		enc_der_5, err := v.GetEimPackageResponse.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding getEimPackageResponse: %w", err)
		}
		return enc_der_5, nil
	case EsipaMessageFromEimToIpaChoiceProvideEimPackageResultResponse:
		if v.ProvideEimPackageResultResponse == nil {
			return nil, fmt.Errorf("choice EsipaMessageFromEimToIpa: provideEimPackageResultResponse is nil")
		}
		enc_der_6, err := v.ProvideEimPackageResultResponse.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding provideEimPackageResultResponse: %w", err)
		}
		return enc_der_6, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes EsipaMessageFromEimToIpa from BER/DER format.
func (v *EsipaMessageFromEimToIpa) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for EsipaMessageFromEimToIpa CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EsipaMessageFromEimToIpa: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding EsipaMessageFromEimToIpa CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EsipaMessageFromEimToIpa", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 57 {
		v.Choice = EsipaMessageFromEimToIpaChoiceInitiateAuthenticationResponseEsipa
		var dec InitiateAuthenticationResponseEsipa
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationResponseEsipa: %w", unmErr)
		}
		v.InitiateAuthenticationResponseEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 59 {
		v.Choice = EsipaMessageFromEimToIpaChoiceAuthenticateClientResponseEsipa
		var dec AuthenticateClientResponseEsipa
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding authenticateClientResponseEsipa: %w", unmErr)
		}
		v.AuthenticateClientResponseEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 58 {
		v.Choice = EsipaMessageFromEimToIpaChoiceGetBoundProfilePackageResponseEsipa
		var dec GetBoundProfilePackageResponseEsipa
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageResponseEsipa: %w", unmErr)
		}
		v.GetBoundProfilePackageResponseEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 65 {
		v.Choice = EsipaMessageFromEimToIpaChoiceCancelSessionResponseEsipa
		var dec CancelSessionResponseEsipa
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding cancelSessionResponseEsipa: %w", unmErr)
		}
		v.CancelSessionResponseEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 78 {
		v.Choice = EsipaMessageFromEimToIpaChoiceTransferEimPackageRequest
		var dec TransferEimPackageRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding transferEimPackageRequest: %w", unmErr)
		}
		v.TransferEimPackageRequest = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 79 {
		v.Choice = EsipaMessageFromEimToIpaChoiceGetEimPackageResponse
		var dec GetEimPackageResponse
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding getEimPackageResponse: %w", unmErr)
		}
		v.GetEimPackageResponse = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 80 {
		v.Choice = EsipaMessageFromEimToIpaChoiceProvideEimPackageResultResponse
		var dec ProvideEimPackageResultResponse
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding provideEimPackageResultResponse: %w", unmErr)
		}
		v.ProvideEimPackageResultResponse = &dec
	} else {
		return fmt.Errorf("unknown tag %s for EsipaMessageFromEimToIpa CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes InitiateAuthenticationRequestEsipa to BER format.
func (v *InitiateAuthenticationRequestEsipa) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccchallenge := ber.EncodeOctetString([]byte(v.EuiccChallenge))
	enc_euiccchallenge = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_euiccchallenge)
	children = append(children, enc_euiccchallenge...)
	if v.SmdpAddress != nil {
		enc_smdpaddress := ber.EncodeStringTag(12, *v.SmdpAddress)
		enc_smdpaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_smdpaddress)
		children = append(children, enc_smdpaddress...)
	}
	if v.EuiccInfo1 != nil {
		enc_euiccinfo1, err := v.EuiccInfo1.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccInfo1: %w", err)
		}
		children = append(children, enc_euiccinfo1...)
	}
	if v.EimTransactionId != nil {
		enc_eimtransactionid := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_eimtransactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_eimtransactionid)
		children = append(children, enc_eimtransactionid...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 57, Constructed: true}, children), nil
}

// MarshalDER encodes InitiateAuthenticationRequestEsipa to DER format.
func (v *InitiateAuthenticationRequestEsipa) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes InitiateAuthenticationRequestEsipa from BER/DER format.
func (v *InitiateAuthenticationRequestEsipa) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding InitiateAuthenticationRequestEsipa: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 57 || !decodedTag.Constructed {
		return fmt.Errorf("decoding InitiateAuthenticationRequestEsipa: %w: expected tag [CONTEXT 57], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InitiateAuthenticationRequestEsipa", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccChallenge
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccChallenge")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for euiccChallenge, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_euiccchallenge, rawVal_euiccchallenge, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccChallenge: %w", err)
	}
	v.EuiccChallenge = sgp22.Octet16(rawVal_euiccchallenge)
	offset += n_euiccchallenge
	// Decode smdpAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_smdpaddress, rawVal_smdpaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smdpAddress: %w", err)
				}
				decVal_smdpaddress := ber.DecodeStringValue(rawVal_smdpaddress)
				v.SmdpAddress = &decVal_smdpaddress
				offset += n_smdpaddress
			}
		}
	}
	// Decode euiccInfo1
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (sgp22.EUICCInfo1)
				_, n_euiccinfo1, _, tlvErr_euiccinfo1 := ber.DecodeTLV(content[offset:])
				if tlvErr_euiccinfo1 != nil {
					return fmt.Errorf("decoding euiccInfo1: %w", tlvErr_euiccinfo1)
				}
				var dec_euiccinfo1 sgp22.EUICCInfo1
				if unmErr := dec_euiccinfo1.UnmarshalBER(content[offset : offset+n_euiccinfo1]); unmErr != nil {
					return fmt.Errorf("decoding euiccInfo1: %w", unmErr)
				}
				v.EuiccInfo1 = &dec_euiccinfo1
				offset += n_euiccinfo1
			}
		}
	}
	// Decode eimTransactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eimtransactionid, rawVal_eimtransactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimTransactionId: %w", err)
				}
				tmp_eimtransactionid := sgp22.TransactionId(rawVal_eimtransactionid)
				v.EimTransactionId = &tmp_eimtransactionid
				offset += n_eimtransactionid
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "InitiateAuthenticationRequestEsipa", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes InitiateAuthenticationResponseEsipa to BER format.
func (v *InitiateAuthenticationResponseEsipa) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case InitiateAuthenticationResponseEsipaChoiceInitiateAuthenticationOkEsipa:
		if v.InitiateAuthenticationOkEsipa == nil {
			return nil, fmt.Errorf("choice InitiateAuthenticationResponseEsipa: initiateAuthenticationOkEsipa is nil")
		}
		enc_0, err := v.InitiateAuthenticationOkEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationOkEsipa: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 57, enc_0)
		return enc_0, nil
	case InitiateAuthenticationResponseEsipaChoiceInitiateAuthenticationErrorEsipa:
		if v.InitiateAuthenticationErrorEsipa == nil {
			return nil, fmt.Errorf("choice InitiateAuthenticationResponseEsipa: initiateAuthenticationErrorEsipa is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.InitiateAuthenticationErrorEsipa))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 57, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for InitiateAuthenticationResponseEsipa", v.Choice)
	}
}

// MarshalDER encodes InitiateAuthenticationResponseEsipa to DER format.
func (v *InitiateAuthenticationResponseEsipa) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case InitiateAuthenticationResponseEsipaChoiceInitiateAuthenticationOkEsipa:
		if v.InitiateAuthenticationOkEsipa == nil {
			return nil, fmt.Errorf("choice InitiateAuthenticationResponseEsipa: initiateAuthenticationOkEsipa is nil")
		}
		enc_der_0, err := v.InitiateAuthenticationOkEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationOkEsipa: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 57, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes InitiateAuthenticationResponseEsipa from BER/DER format.
func (v *InitiateAuthenticationResponseEsipa) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for InitiateAuthenticationResponseEsipa CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding InitiateAuthenticationResponseEsipa CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 57 || !decodedTag.Constructed {
		return fmt.Errorf("decoding InitiateAuthenticationResponseEsipa CHOICE: %w: expected tag [CONTEXT 57], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InitiateAuthenticationResponseEsipa", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for InitiateAuthenticationResponseEsipa CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InitiateAuthenticationResponseEsipa: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding InitiateAuthenticationResponseEsipa CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InitiateAuthenticationResponseEsipa", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = InitiateAuthenticationResponseEsipaChoiceInitiateAuthenticationOkEsipa
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationOkEsipa: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec InitiateAuthenticationOkEsipa
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationOkEsipa: %w", unmErr)
		}
		v.InitiateAuthenticationOkEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = InitiateAuthenticationResponseEsipaChoiceInitiateAuthenticationErrorEsipa
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationErrorEsipa: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationErrorEsipa: %w", intErr)
		}
		v.InitiateAuthenticationErrorEsipa = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for InitiateAuthenticationResponseEsipa CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes InitiateAuthenticationOkEsipa to BER format.
func (v *InitiateAuthenticationOkEsipa) MarshalBER() ([]byte, error) {
	var children []byte
	if v.TransactionId != nil {
		enc_transactionid := ber.EncodeOctetString([]byte(*v.TransactionId))
		enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
		children = append(children, enc_transactionid...)
	}
	enc_serversigned1, err := v.ServerSigned1.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding serverSigned1: %w", err)
	}
	children = append(children, enc_serversigned1...)
	enc_serversignature1 := ber.EncodeOctetString(v.ServerSignature1)
	enc_serversignature1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_serversignature1)
	children = append(children, enc_serversignature1...)
	enc_euicccipkidentifiertobeused := ber.EncodeOctetString(v.EuiccCiPKIdentifierToBeUsed)
	children = append(children, enc_euicccipkidentifiertobeused...)
	enc_servercertificate, err := v.ServerCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding serverCertificate: %w", err)
	}
	children = append(children, enc_servercertificate...)
	if v.MatchingId != nil {
		enc_matchingid := ber.EncodeStringTag(12, *v.MatchingId)
		children = append(children, enc_matchingid...)
	}
	if v.CtxParams1 != nil {
		enc_ctxparams1, err := v.CtxParams1.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ctxParams1: %w", err)
		}
		enc_ctxparams1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ctxparams1)
		children = append(children, enc_ctxparams1...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes InitiateAuthenticationOkEsipa to DER format.
func (v *InitiateAuthenticationOkEsipa) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes InitiateAuthenticationOkEsipa from BER/DER format.
func (v *InitiateAuthenticationOkEsipa) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding InitiateAuthenticationOkEsipa SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InitiateAuthenticationOkEsipa", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding transactionId: %w", err)
				}
				tmp_transactionid := sgp22.TransactionId(rawVal_transactionid)
				v.TransactionId = &tmp_transactionid
				offset += n_transactionid
			}
		}
	}
	// Decode serverSigned1
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverSigned1")
	}
	// Decode nested SEQUENCE (sgp22.ServerSigned1)
	_, n_serversigned1, _, tlvErr_serversigned1 := ber.DecodeTLV(content[offset:])
	if tlvErr_serversigned1 != nil {
		return fmt.Errorf("decoding serverSigned1: %w", tlvErr_serversigned1)
	}
	if unmErr := v.ServerSigned1.UnmarshalBER(content[offset : offset+n_serversigned1]); unmErr != nil {
		return fmt.Errorf("decoding serverSigned1: %w", unmErr)
	}
	offset += n_serversigned1
	// Decode serverSignature1
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverSignature1")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for serverSignature1, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_serversignature1, rawVal_serversignature1, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serverSignature1: %w", err)
	}
	v.ServerSignature1 = rawVal_serversignature1
	offset += n_serversignature1
	// Decode euiccCiPKIdentifierToBeUsed
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCiPKIdentifierToBeUsed")
	}
	val_euicccipkidentifiertobeused, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCiPKIdentifierToBeUsed: %w", err)
	}
	v.EuiccCiPKIdentifierToBeUsed = val_euicccipkidentifiertobeused
	offset += n
	// Decode serverCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverCertificate")
	}
	// Decode nested SEQUENCE (sgp22.Certificate)
	_, n_servercertificate, _, tlvErr_servercertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_servercertificate != nil {
		return fmt.Errorf("decoding serverCertificate: %w", tlvErr_servercertificate)
	}
	if unmErr := v.ServerCertificate.UnmarshalBER(content[offset : offset+n_servercertificate]); unmErr != nil {
		return fmt.Errorf("decoding serverCertificate: %w", unmErr)
	}
	offset += n_servercertificate
	// Decode matchingId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
				val_matchingid, n, err := ber.DecodeString(content[offset:], 12)
				if err != nil {
					return fmt.Errorf("decoding matchingId: %w", err)
				}
				v.MatchingId = &val_matchingid
				offset += n
			}
		}
	}
	// Decode ctxParams1
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_ctxparams1, innerData_ctxparams1, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ctxParams1: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_ctxparams1 sgp22.CtxParams1
				if unmErr := dec_ctxparams1.UnmarshalBER(innerData_ctxparams1); unmErr != nil {
					return fmt.Errorf("decoding ctxParams1: %w", unmErr)
				}
				v.CtxParams1 = &dec_ctxparams1
				offset += n_ctxparams1
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "InitiateAuthenticationOkEsipa", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AuthenticateClientRequestEsipa to BER format.
func (v *AuthenticateClientRequestEsipa) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_authenticateserverresponse, err := v.AuthenticateServerResponse.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding authenticateServerResponse: %w", err)
	}
	children = append(children, enc_authenticateserverresponse...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 59, Constructed: true}, children), nil
}

// MarshalDER encodes AuthenticateClientRequestEsipa to DER format.
func (v *AuthenticateClientRequestEsipa) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateClientRequestEsipa from BER/DER format.
func (v *AuthenticateClientRequestEsipa) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateClientRequestEsipa: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 59 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AuthenticateClientRequestEsipa: %w: expected tag [CONTEXT 59], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientRequestEsipa", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = sgp22.TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode authenticateServerResponse
	if offset >= len(content) {
		return fmt.Errorf("missing required field authenticateServerResponse")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 56 {
			return fmt.Errorf("expected tag [%s %d] for authenticateServerResponse, got %s", "CONTEXT", 56, reqTag_)
		}
	}
	// Decode nested CHOICE (AuthenticateServerResponse)
	_, n_authenticateserverresponse, _, tlvErr_authenticateserverresponse := ber.DecodeTLV(content[offset:])
	if tlvErr_authenticateserverresponse != nil {
		return fmt.Errorf("decoding authenticateServerResponse: %w", tlvErr_authenticateserverresponse)
	}
	if unmErr := v.AuthenticateServerResponse.UnmarshalBER(content[offset : offset+n_authenticateserverresponse]); unmErr != nil {
		return fmt.Errorf("decoding authenticateServerResponse: %w", unmErr)
	}
	offset += n_authenticateserverresponse
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateClientRequestEsipa", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AuthenticateClientResponseEsipa to BER format.
func (v *AuthenticateClientResponseEsipa) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AuthenticateClientResponseEsipaChoiceAuthenticateClientOkDPEsipa:
		if v.AuthenticateClientOkDPEsipa == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEsipa: authenticateClientOkDPEsipa is nil")
		}
		enc_0, err := v.AuthenticateClientOkDPEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientOkDPEsipa: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 59, enc_0)
		return enc_0, nil
	case AuthenticateClientResponseEsipaChoiceAuthenticateClientOkDSEsipa:
		if v.AuthenticateClientOkDSEsipa == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEsipa: authenticateClientOkDSEsipa is nil")
		}
		enc_1, err := v.AuthenticateClientOkDSEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientOkDSEsipa: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 59, enc_1)
		return enc_1, nil
	case AuthenticateClientResponseEsipaChoiceAuthenticateClientErrorEsipa:
		if v.AuthenticateClientErrorEsipa == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEsipa: authenticateClientErrorEsipa is nil")
		}
		enc_2 := ber.EncodeInteger(int64(*v.AuthenticateClientErrorEsipa))
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_2)
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 59, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AuthenticateClientResponseEsipa", v.Choice)
	}
}

// MarshalDER encodes AuthenticateClientResponseEsipa to DER format.
func (v *AuthenticateClientResponseEsipa) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case AuthenticateClientResponseEsipaChoiceAuthenticateClientOkDPEsipa:
		if v.AuthenticateClientOkDPEsipa == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEsipa: authenticateClientOkDPEsipa is nil")
		}
		enc_der_0, err := v.AuthenticateClientOkDPEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientOkDPEsipa: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 59, enc_der_0)
		return enc_der_0, nil
	case AuthenticateClientResponseEsipaChoiceAuthenticateClientOkDSEsipa:
		if v.AuthenticateClientOkDSEsipa == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEsipa: authenticateClientOkDSEsipa is nil")
		}
		enc_der_1, err := v.AuthenticateClientOkDSEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientOkDSEsipa: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 59, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateClientResponseEsipa from BER/DER format.
func (v *AuthenticateClientResponseEsipa) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AuthenticateClientResponseEsipa CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateClientResponseEsipa CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 59 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AuthenticateClientResponseEsipa CHOICE: %w: expected tag [CONTEXT 59], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientResponseEsipa", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for AuthenticateClientResponseEsipa CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AuthenticateClientResponseEsipa: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AuthenticateClientResponseEsipa CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientResponseEsipa", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = AuthenticateClientResponseEsipaChoiceAuthenticateClientOkDPEsipa
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateClientOkDPEsipa: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AuthenticateClientOkDPEsipa
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding authenticateClientOkDPEsipa: %w", unmErr)
		}
		v.AuthenticateClientOkDPEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = AuthenticateClientResponseEsipaChoiceAuthenticateClientOkDSEsipa
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateClientOkDSEsipa: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AuthenticateClientOkDSEsipa
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding authenticateClientOkDSEsipa: %w", unmErr)
		}
		v.AuthenticateClientOkDSEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = AuthenticateClientResponseEsipaChoiceAuthenticateClientErrorEsipa
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateClientErrorEsipa: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding authenticateClientErrorEsipa: %w", intErr)
		}
		v.AuthenticateClientErrorEsipa = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for AuthenticateClientResponseEsipa CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AuthenticateClientOkDPEsipa to BER format.
func (v *AuthenticateClientOkDPEsipa) MarshalBER() ([]byte, error) {
	var children []byte
	if v.TransactionId != nil {
		enc_transactionid := ber.EncodeOctetString([]byte(*v.TransactionId))
		enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
		children = append(children, enc_transactionid...)
	}
	if v.ProfileMetaData != nil {
		enc_profilemetadata, err := v.ProfileMetaData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileMetaData: %w", err)
		}
		children = append(children, enc_profilemetadata...)
	}
	enc_smdpsigned2, err := v.SmdpSigned2.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding smdpSigned2: %w", err)
	}
	children = append(children, enc_smdpsigned2...)
	enc_smdpsignature2 := ber.EncodeOctetString(v.SmdpSignature2)
	enc_smdpsignature2 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_smdpsignature2)
	children = append(children, enc_smdpsignature2...)
	enc_smdpcertificate, err := v.SmdpCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding smdpCertificate: %w", err)
	}
	children = append(children, enc_smdpcertificate...)
	if v.HashCc != nil {
		enc_hashcc := ber.EncodeOctetString([]byte(*v.HashCc))
		children = append(children, enc_hashcc...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AuthenticateClientOkDPEsipa to DER format.
func (v *AuthenticateClientOkDPEsipa) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateClientOkDPEsipa from BER/DER format.
func (v *AuthenticateClientOkDPEsipa) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateClientOkDPEsipa SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientOkDPEsipa", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding transactionId: %w", err)
				}
				tmp_transactionid := sgp22.TransactionId(rawVal_transactionid)
				v.TransactionId = &tmp_transactionid
				offset += n_transactionid
			}
		}
	}
	// Decode profileMetaData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 37 {
				// Decode nested SEQUENCE (StoreMetadataRequest)
				_, n_profilemetadata, _, tlvErr_profilemetadata := ber.DecodeTLV(content[offset:])
				if tlvErr_profilemetadata != nil {
					return fmt.Errorf("decoding profileMetaData: %w", tlvErr_profilemetadata)
				}
				var dec_profilemetadata StoreMetadataRequest
				if unmErr := dec_profilemetadata.UnmarshalBER(content[offset : offset+n_profilemetadata]); unmErr != nil {
					return fmt.Errorf("decoding profileMetaData: %w", unmErr)
				}
				v.ProfileMetaData = &dec_profilemetadata
				offset += n_profilemetadata
			}
		}
	}
	// Decode smdpSigned2
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpSigned2")
	}
	// Decode nested SEQUENCE (sgp22.SmdpSigned2)
	_, n_smdpsigned2, _, tlvErr_smdpsigned2 := ber.DecodeTLV(content[offset:])
	if tlvErr_smdpsigned2 != nil {
		return fmt.Errorf("decoding smdpSigned2: %w", tlvErr_smdpsigned2)
	}
	if unmErr := v.SmdpSigned2.UnmarshalBER(content[offset : offset+n_smdpsigned2]); unmErr != nil {
		return fmt.Errorf("decoding smdpSigned2: %w", unmErr)
	}
	offset += n_smdpsigned2
	// Decode smdpSignature2
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpSignature2")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for smdpSignature2, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_smdpsignature2, rawVal_smdpsignature2, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding smdpSignature2: %w", err)
	}
	v.SmdpSignature2 = rawVal_smdpsignature2
	offset += n_smdpsignature2
	// Decode smdpCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpCertificate")
	}
	// Decode nested SEQUENCE (sgp22.Certificate)
	_, n_smdpcertificate, _, tlvErr_smdpcertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_smdpcertificate != nil {
		return fmt.Errorf("decoding smdpCertificate: %w", tlvErr_smdpcertificate)
	}
	if unmErr := v.SmdpCertificate.UnmarshalBER(content[offset : offset+n_smdpcertificate]); unmErr != nil {
		return fmt.Errorf("decoding smdpCertificate: %w", unmErr)
	}
	offset += n_smdpcertificate
	// Decode hashCc
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_hashcc, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding hashCc: %w", err)
				}
				tmp_hashcc := sgp22.Octet32(val_hashcc)
				v.HashCc = &tmp_hashcc
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateClientOkDPEsipa", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AuthenticateClientOkDSEsipa to BER format.
func (v *AuthenticateClientOkDSEsipa) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	if v.ProfileDownloadTrigger != nil {
		enc_profiledownloadtrigger, err := v.ProfileDownloadTrigger.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileDownloadTrigger: %w", err)
		}
		children = append(children, enc_profiledownloadtrigger...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AuthenticateClientOkDSEsipa to DER format.
func (v *AuthenticateClientOkDSEsipa) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateClientOkDSEsipa from BER/DER format.
func (v *AuthenticateClientOkDSEsipa) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateClientOkDSEsipa SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientOkDSEsipa", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = sgp22.TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode profileDownloadTrigger
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 84 {
				// Decode nested SEQUENCE (ProfileDownloadTriggerRequest)
				_, n_profiledownloadtrigger, _, tlvErr_profiledownloadtrigger := ber.DecodeTLV(content[offset:])
				if tlvErr_profiledownloadtrigger != nil {
					return fmt.Errorf("decoding profileDownloadTrigger: %w", tlvErr_profiledownloadtrigger)
				}
				var dec_profiledownloadtrigger ProfileDownloadTriggerRequest
				if unmErr := dec_profiledownloadtrigger.UnmarshalBER(content[offset : offset+n_profiledownloadtrigger]); unmErr != nil {
					return fmt.Errorf("decoding profileDownloadTrigger: %w", unmErr)
				}
				v.ProfileDownloadTrigger = &dec_profiledownloadtrigger
				offset += n_profiledownloadtrigger
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateClientOkDSEsipa", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes GetBoundProfilePackageRequestEsipa to BER format.
func (v *GetBoundProfilePackageRequestEsipa) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_preparedownloadresponse, err := v.PrepareDownloadResponse.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding prepareDownloadResponse: %w", err)
	}
	children = append(children, enc_preparedownloadresponse...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 58, Constructed: true}, children), nil
}

// MarshalDER encodes GetBoundProfilePackageRequestEsipa to DER format.
func (v *GetBoundProfilePackageRequestEsipa) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetBoundProfilePackageRequestEsipa from BER/DER format.
func (v *GetBoundProfilePackageRequestEsipa) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetBoundProfilePackageRequestEsipa: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 58 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetBoundProfilePackageRequestEsipa: %w: expected tag [CONTEXT 58], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetBoundProfilePackageRequestEsipa", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = sgp22.TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode prepareDownloadResponse
	if offset >= len(content) {
		return fmt.Errorf("missing required field prepareDownloadResponse")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 33 {
			return fmt.Errorf("expected tag [%s %d] for prepareDownloadResponse, got %s", "CONTEXT", 33, reqTag_)
		}
	}
	// Decode nested CHOICE (PrepareDownloadResponse)
	_, n_preparedownloadresponse, _, tlvErr_preparedownloadresponse := ber.DecodeTLV(content[offset:])
	if tlvErr_preparedownloadresponse != nil {
		return fmt.Errorf("decoding prepareDownloadResponse: %w", tlvErr_preparedownloadresponse)
	}
	if unmErr := v.PrepareDownloadResponse.UnmarshalBER(content[offset : offset+n_preparedownloadresponse]); unmErr != nil {
		return fmt.Errorf("decoding prepareDownloadResponse: %w", unmErr)
	}
	offset += n_preparedownloadresponse
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "GetBoundProfilePackageRequestEsipa", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes GetBoundProfilePackageResponseEsipa to BER format.
func (v *GetBoundProfilePackageResponseEsipa) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case GetBoundProfilePackageResponseEsipaChoiceGetBoundProfilePackageOkEsipa:
		if v.GetBoundProfilePackageOkEsipa == nil {
			return nil, fmt.Errorf("choice GetBoundProfilePackageResponseEsipa: getBoundProfilePackageOkEsipa is nil")
		}
		enc_0, err := v.GetBoundProfilePackageOkEsipa.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageOkEsipa: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 58, enc_0)
		return enc_0, nil
	case GetBoundProfilePackageResponseEsipaChoiceGetBoundProfilePackageErrorEsipa:
		if v.GetBoundProfilePackageErrorEsipa == nil {
			return nil, fmt.Errorf("choice GetBoundProfilePackageResponseEsipa: getBoundProfilePackageErrorEsipa is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.GetBoundProfilePackageErrorEsipa))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 58, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for GetBoundProfilePackageResponseEsipa", v.Choice)
	}
}

// MarshalDER encodes GetBoundProfilePackageResponseEsipa to DER format.
func (v *GetBoundProfilePackageResponseEsipa) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case GetBoundProfilePackageResponseEsipaChoiceGetBoundProfilePackageOkEsipa:
		if v.GetBoundProfilePackageOkEsipa == nil {
			return nil, fmt.Errorf("choice GetBoundProfilePackageResponseEsipa: getBoundProfilePackageOkEsipa is nil")
		}
		enc_der_0, err := v.GetBoundProfilePackageOkEsipa.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageOkEsipa: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 58, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes GetBoundProfilePackageResponseEsipa from BER/DER format.
func (v *GetBoundProfilePackageResponseEsipa) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for GetBoundProfilePackageResponseEsipa CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetBoundProfilePackageResponseEsipa CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 58 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetBoundProfilePackageResponseEsipa CHOICE: %w: expected tag [CONTEXT 58], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetBoundProfilePackageResponseEsipa", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for GetBoundProfilePackageResponseEsipa CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for GetBoundProfilePackageResponseEsipa: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding GetBoundProfilePackageResponseEsipa CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "GetBoundProfilePackageResponseEsipa", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = GetBoundProfilePackageResponseEsipaChoiceGetBoundProfilePackageOkEsipa
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageOkEsipa: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec GetBoundProfilePackageOkEsipa
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageOkEsipa: %w", unmErr)
		}
		v.GetBoundProfilePackageOkEsipa = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = GetBoundProfilePackageResponseEsipaChoiceGetBoundProfilePackageErrorEsipa
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageErrorEsipa: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageErrorEsipa: %w", intErr)
		}
		v.GetBoundProfilePackageErrorEsipa = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for GetBoundProfilePackageResponseEsipa CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes GetBoundProfilePackageOkEsipa to BER format.
func (v *GetBoundProfilePackageOkEsipa) MarshalBER() ([]byte, error) {
	var children []byte
	if v.TransactionId != nil {
		enc_transactionid := ber.EncodeOctetString([]byte(*v.TransactionId))
		enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
		children = append(children, enc_transactionid...)
	}
	enc_boundprofilepackage, err := v.BoundProfilePackage.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding boundProfilePackage: %w", err)
	}
	children = append(children, enc_boundprofilepackage...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes GetBoundProfilePackageOkEsipa to DER format.
func (v *GetBoundProfilePackageOkEsipa) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetBoundProfilePackageOkEsipa from BER/DER format.
func (v *GetBoundProfilePackageOkEsipa) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetBoundProfilePackageOkEsipa SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetBoundProfilePackageOkEsipa", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding transactionId: %w", err)
				}
				tmp_transactionid := sgp22.TransactionId(rawVal_transactionid)
				v.TransactionId = &tmp_transactionid
				offset += n_transactionid
			}
		}
	}
	// Decode boundProfilePackage
	if offset >= len(content) {
		return fmt.Errorf("missing required field boundProfilePackage")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 54 {
			return fmt.Errorf("expected tag [%s %d] for boundProfilePackage, got %s", "CONTEXT", 54, reqTag_)
		}
	}
	// Decode nested SEQUENCE (sgp22.BoundProfilePackage)
	_, n_boundprofilepackage, _, tlvErr_boundprofilepackage := ber.DecodeTLV(content[offset:])
	if tlvErr_boundprofilepackage != nil {
		return fmt.Errorf("decoding boundProfilePackage: %w", tlvErr_boundprofilepackage)
	}
	if unmErr := v.BoundProfilePackage.UnmarshalBER(content[offset : offset+n_boundprofilepackage]); unmErr != nil {
		return fmt.Errorf("decoding boundProfilePackage: %w", unmErr)
	}
	offset += n_boundprofilepackage
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "GetBoundProfilePackageOkEsipa", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes HandleNotificationEsipa to BER format.
func (v *HandleNotificationEsipa) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case HandleNotificationEsipaChoicePendingNotification:
		if v.PendingNotification == nil {
			return nil, fmt.Errorf("choice HandleNotificationEsipa: pendingNotification is nil")
		}
		enc_0, err := v.PendingNotification.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding pendingNotification: %w", err)
		}
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 61, enc_0)
		return enc_0, nil
	case HandleNotificationEsipaChoiceProvideEimPackageResult:
		if v.ProvideEimPackageResult == nil {
			return nil, fmt.Errorf("choice HandleNotificationEsipa: provideEimPackageResult is nil")
		}
		enc_1, err := v.ProvideEimPackageResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding provideEimPackageResult: %w", err)
		}
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 61, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for HandleNotificationEsipa", v.Choice)
	}
}

// MarshalDER encodes HandleNotificationEsipa to DER format.
func (v *HandleNotificationEsipa) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case HandleNotificationEsipaChoicePendingNotification:
		if v.PendingNotification == nil {
			return nil, fmt.Errorf("choice HandleNotificationEsipa: pendingNotification is nil")
		}
		enc_der_0, err := v.PendingNotification.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding pendingNotification: %w", err)
		}
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 61, enc_der_0)
		return enc_der_0, nil
	case HandleNotificationEsipaChoiceProvideEimPackageResult:
		if v.ProvideEimPackageResult == nil {
			return nil, fmt.Errorf("choice HandleNotificationEsipa: provideEimPackageResult is nil")
		}
		enc_der_1, err := v.ProvideEimPackageResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding provideEimPackageResult: %w", err)
		}
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 61, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes HandleNotificationEsipa from BER/DER format.
func (v *HandleNotificationEsipa) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for HandleNotificationEsipa CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding HandleNotificationEsipa CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 61 || !decodedTag.Constructed {
		return fmt.Errorf("decoding HandleNotificationEsipa CHOICE: %w: expected tag [CONTEXT 61], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "HandleNotificationEsipa", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for HandleNotificationEsipa CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for HandleNotificationEsipa: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding HandleNotificationEsipa CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "HandleNotificationEsipa", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = HandleNotificationEsipaChoicePendingNotification
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding pendingNotification: %w", tlvErr)
		}
		var dec PendingNotification
		if unmErr := dec.UnmarshalBER(innerData); unmErr != nil {
			return fmt.Errorf("decoding pendingNotification: %w", unmErr)
		}
		v.PendingNotification = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 80 {
		v.Choice = HandleNotificationEsipaChoiceProvideEimPackageResult
		var dec ProvideEimPackageResult
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding provideEimPackageResult: %w", unmErr)
		}
		v.ProvideEimPackageResult = &dec
	} else {
		return fmt.Errorf("unknown tag %s for HandleNotificationEsipa CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CancelSessionRequestEsipa to BER format.
func (v *CancelSessionRequestEsipa) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_cancelsessionresponse, err := v.CancelSessionResponse.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding cancelSessionResponse: %w", err)
	}
	enc_cancelsessionresponse = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cancelsessionresponse)
	children = append(children, enc_cancelsessionresponse...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 65, Constructed: true}, children), nil
}

// MarshalDER encodes CancelSessionRequestEsipa to DER format.
func (v *CancelSessionRequestEsipa) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CancelSessionRequestEsipa from BER/DER format.
func (v *CancelSessionRequestEsipa) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding CancelSessionRequestEsipa: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 65 || !decodedTag.Constructed {
		return fmt.Errorf("decoding CancelSessionRequestEsipa: %w: expected tag [CONTEXT 65], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionRequestEsipa", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = sgp22.TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode cancelSessionResponse
	if offset >= len(content) {
		return fmt.Errorf("missing required field cancelSessionResponse")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for cancelSessionResponse, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_cancelsessionresponse, innerData_cancelsessionresponse, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding cancelSessionResponse: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.CancelSessionResponse.UnmarshalBER(innerData_cancelsessionresponse); unmErr != nil {
		return fmt.Errorf("decoding cancelSessionResponse: %w", unmErr)
	}
	offset += n_cancelsessionresponse
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CancelSessionRequestEsipa", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CancelSessionResponseEsipa to BER format.
func (v *CancelSessionResponseEsipa) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CancelSessionResponseEsipaChoiceCancelSessionOk:
		if v.CancelSessionOk == nil {
			return nil, fmt.Errorf("choice CancelSessionResponseEsipa: cancelSessionOk is nil")
		}
		enc_0, err := v.CancelSessionOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_0)
		return enc_0, nil
	case CancelSessionResponseEsipaChoiceCancelSessionError:
		if v.CancelSessionError == nil {
			return nil, fmt.Errorf("choice CancelSessionResponseEsipa: cancelSessionError is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.CancelSessionError))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CancelSessionResponseEsipa", v.Choice)
	}
}

// MarshalDER encodes CancelSessionResponseEsipa to DER format.
func (v *CancelSessionResponseEsipa) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CancelSessionResponseEsipaChoiceCancelSessionOk:
		if v.CancelSessionOk == nil {
			return nil, fmt.Errorf("choice CancelSessionResponseEsipa: cancelSessionOk is nil")
		}
		enc_der_0, err := v.CancelSessionOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes CancelSessionResponseEsipa from BER/DER format.
func (v *CancelSessionResponseEsipa) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CancelSessionResponseEsipa CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding CancelSessionResponseEsipa CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 65 || !decodedTag.Constructed {
		return fmt.Errorf("decoding CancelSessionResponseEsipa CHOICE: %w: expected tag [CONTEXT 65], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionResponseEsipa", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for CancelSessionResponseEsipa CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CancelSessionResponseEsipa: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CancelSessionResponseEsipa CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionResponseEsipa", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CancelSessionResponseEsipaChoiceCancelSessionOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cancelSessionOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CancelSessionOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding cancelSessionOk: %w", unmErr)
		}
		v.CancelSessionOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CancelSessionResponseEsipaChoiceCancelSessionError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cancelSessionError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding cancelSessionError: %w", intErr)
		}
		v.CancelSessionError = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for CancelSessionResponseEsipa CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CancelSessionOk to BER format.
func (v *CancelSessionOk) MarshalBER() ([]byte, error) {
	return ber.EncodeSequence(nil), nil
}

// MarshalDER encodes CancelSessionOk to DER format.
func (v *CancelSessionOk) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CancelSessionOk from BER/DER format.
func (v *CancelSessionOk) UnmarshalBER(data []byte) error {
	_, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CancelSessionOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionOk", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes GetEimPackageRequest to BER format.
func (v *GetEimPackageRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eidvalue := ber.EncodeOctetString([]byte(v.EidValue))
	enc_eidvalue = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_eidvalue)
	children = append(children, enc_eidvalue...)
	if v.NotifyStateChange != nil {
		enc_notifystatechange := ber.EncodeNull()
		enc_notifystatechange = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_notifystatechange)
		children = append(children, enc_notifystatechange...)
	}
	if v.StateChangeCause != nil {
		enc_statechangecause := ber.EncodeInteger(int64(*v.StateChangeCause))
		enc_statechangecause = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_statechangecause)
		children = append(children, enc_statechangecause...)
	}
	if v.RPLMN != nil {
		enc_rplmn := ber.EncodeOctetString(v.RPLMN)
		enc_rplmn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_rplmn)
		children = append(children, enc_rplmn...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 79, Constructed: true}, children), nil
}

// MarshalDER encodes GetEimPackageRequest to DER format.
func (v *GetEimPackageRequest) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetEimPackageRequest from BER/DER format.
func (v *GetEimPackageRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetEimPackageRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 79 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetEimPackageRequest: %w: expected tag [CONTEXT 79], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEimPackageRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eidValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field eidValue")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 26 {
			return fmt.Errorf("expected tag [%s %d] for eidValue, got %s", "APPLICATION", 26, reqTag_)
		}
	}
	_, n_eidvalue, rawVal_eidvalue, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eidValue: %w", err)
	}
	v.EidValue = sgp22.Octet16(rawVal_eidvalue)
	offset += n_eidvalue
	// Decode notifyStateChange
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_notifystatechange, rawVal_notifystatechange, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding notifyStateChange: %w", err)
				}
				_ = rawVal_notifystatechange
				v.NotifyStateChange = &struct{}{}
				offset += n_notifystatechange
			}
		}
	}
	// Decode stateChangeCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_statechangecause, rawVal_statechangecause, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding stateChangeCause: %w", err)
				}
				decVal_statechangecause, intErr := ber.DecodeIntegerValue(rawVal_statechangecause)
				if intErr != nil {
					return fmt.Errorf("decoding stateChangeCause: %w", intErr)
				}
				tmp_statechangecause := StateChangeCause(decVal_statechangecause)
				v.StateChangeCause = &tmp_statechangecause
				offset += n_statechangecause
			}
		}
	}
	// Decode rPLMN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_rplmn, rawVal_rplmn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rPLMN: %w", err)
				}
				tmp_rplmn := rawVal_rplmn
				v.RPLMN = tmp_rplmn
				offset += n_rplmn
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "GetEimPackageRequest", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes GetEimPackageResponse to BER format.
func (v *GetEimPackageResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case GetEimPackageResponseChoiceEuiccPackageRequest:
		if v.EuiccPackageRequest == nil {
			return nil, fmt.Errorf("choice GetEimPackageResponse: euiccPackageRequest is nil")
		}
		enc_0, err := v.EuiccPackageRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageRequest: %w", err)
		}
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 79, enc_0)
		return enc_0, nil
	case GetEimPackageResponseChoiceIpaEuiccDataRequest:
		if v.IpaEuiccDataRequest == nil {
			return nil, fmt.Errorf("choice GetEimPackageResponse: ipaEuiccDataRequest is nil")
		}
		enc_1, err := v.IpaEuiccDataRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccDataRequest: %w", err)
		}
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 79, enc_1)
		return enc_1, nil
	case GetEimPackageResponseChoiceProfileDownloadTriggerRequest:
		if v.ProfileDownloadTriggerRequest == nil {
			return nil, fmt.Errorf("choice GetEimPackageResponse: profileDownloadTriggerRequest is nil")
		}
		enc_2, err := v.ProfileDownloadTriggerRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileDownloadTriggerRequest: %w", err)
		}
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 79, enc_2)
		return enc_2, nil
	case GetEimPackageResponseChoiceEimPackageError:
		if v.EimPackageError == nil {
			return nil, fmt.Errorf("choice GetEimPackageResponse: eimPackageError is nil")
		}
		enc_3 := ber.EncodeInteger(int64(*v.EimPackageError))
		enc_3 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 79, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for GetEimPackageResponse", v.Choice)
	}
}

// MarshalDER encodes GetEimPackageResponse to DER format.
func (v *GetEimPackageResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case GetEimPackageResponseChoiceEuiccPackageRequest:
		if v.EuiccPackageRequest == nil {
			return nil, fmt.Errorf("choice GetEimPackageResponse: euiccPackageRequest is nil")
		}
		enc_der_0, err := v.EuiccPackageRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageRequest: %w", err)
		}
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 79, enc_der_0)
		return enc_der_0, nil
	case GetEimPackageResponseChoiceIpaEuiccDataRequest:
		if v.IpaEuiccDataRequest == nil {
			return nil, fmt.Errorf("choice GetEimPackageResponse: ipaEuiccDataRequest is nil")
		}
		enc_der_1, err := v.IpaEuiccDataRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccDataRequest: %w", err)
		}
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 79, enc_der_1)
		return enc_der_1, nil
	case GetEimPackageResponseChoiceProfileDownloadTriggerRequest:
		if v.ProfileDownloadTriggerRequest == nil {
			return nil, fmt.Errorf("choice GetEimPackageResponse: profileDownloadTriggerRequest is nil")
		}
		enc_der_2, err := v.ProfileDownloadTriggerRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileDownloadTriggerRequest: %w", err)
		}
		enc_der_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 79, enc_der_2)
		return enc_der_2, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes GetEimPackageResponse from BER/DER format.
func (v *GetEimPackageResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for GetEimPackageResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetEimPackageResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 79 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetEimPackageResponse CHOICE: %w: expected tag [CONTEXT 79], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEimPackageResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for GetEimPackageResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for GetEimPackageResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding GetEimPackageResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEimPackageResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 81 {
		v.Choice = GetEimPackageResponseChoiceEuiccPackageRequest
		var dec EuiccPackageRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding euiccPackageRequest: %w", unmErr)
		}
		v.EuiccPackageRequest = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 82 {
		v.Choice = GetEimPackageResponseChoiceIpaEuiccDataRequest
		var dec IpaEuiccDataRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding ipaEuiccDataRequest: %w", unmErr)
		}
		v.IpaEuiccDataRequest = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 84 {
		v.Choice = GetEimPackageResponseChoiceProfileDownloadTriggerRequest
		var dec ProfileDownloadTriggerRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding profileDownloadTriggerRequest: %w", unmErr)
		}
		v.ProfileDownloadTriggerRequest = &dec
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = GetEimPackageResponseChoiceEimPackageError
		decVal, _, intErr := ber.DecodeInteger(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding eimPackageError: %w", intErr)
		}
		v.EimPackageError = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for GetEimPackageResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EimPackageResultResponseError to BER format.
func (v *EimPackageResultResponseError) MarshalBER() ([]byte, error) {
	var children []byte
	if v.EimTransactionId != nil {
		enc_eimtransactionid := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_eimtransactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_eimtransactionid)
		children = append(children, enc_eimtransactionid...)
	}
	enc_eimpackageresulterrorcode := ber.EncodeInteger(int64(v.EimPackageResultErrorCode))
	children = append(children, enc_eimpackageresulterrorcode...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EimPackageResultResponseError to DER format.
func (v *EimPackageResultResponseError) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EimPackageResultResponseError from BER/DER format.
func (v *EimPackageResultResponseError) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EimPackageResultResponseError SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EimPackageResultResponseError", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimTransactionId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_eimtransactionid, rawVal_eimtransactionid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eimTransactionId: %w", err)
				}
				tmp_eimtransactionid := sgp22.TransactionId(rawVal_eimtransactionid)
				v.EimTransactionId = &tmp_eimtransactionid
				offset += n_eimtransactionid
			}
		}
	}
	// Decode eimPackageResultErrorCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimPackageResultErrorCode")
	}
	val_eimpackageresulterrorcode, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimPackageResultErrorCode: %w", err)
	}
	v.EimPackageResultErrorCode = EimPackageResultErrorCode(val_eimpackageresulterrorcode)
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EimPackageResultResponseError", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EimPackageResult to BER format.
func (v *EimPackageResult) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EimPackageResultChoiceEuiccPackageResult:
		if v.EuiccPackageResult == nil {
			return nil, fmt.Errorf("choice EimPackageResult: euiccPackageResult is nil")
		}
		enc_0, err := v.EuiccPackageResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageResult: %w", err)
		}
		return enc_0, nil
	case EimPackageResultChoiceEPRAndNotifications:
		if v.EPRAndNotifications == nil {
			return nil, fmt.Errorf("choice EimPackageResult: ePRAndNotifications is nil")
		}
		enc_1, err := v.EPRAndNotifications.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ePRAndNotifications: %w", err)
		}
		return enc_1, nil
	case EimPackageResultChoiceIpaEuiccDataResponse:
		if v.IpaEuiccDataResponse == nil {
			return nil, fmt.Errorf("choice EimPackageResult: ipaEuiccDataResponse is nil")
		}
		enc_2, err := v.IpaEuiccDataResponse.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccDataResponse: %w", err)
		}
		return enc_2, nil
	case EimPackageResultChoiceProfileDownloadTriggerResult:
		if v.ProfileDownloadTriggerResult == nil {
			return nil, fmt.Errorf("choice EimPackageResult: profileDownloadTriggerResult is nil")
		}
		enc_3, err := v.ProfileDownloadTriggerResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileDownloadTriggerResult: %w", err)
		}
		return enc_3, nil
	case EimPackageResultChoiceEimPackageResultResponseError:
		if v.EimPackageResultResponseError == nil {
			return nil, fmt.Errorf("choice EimPackageResult: eimPackageResultResponseError is nil")
		}
		enc_4, err := v.EimPackageResultResponseError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding eimPackageResultResponseError: %w", err)
		}
		enc_4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_4)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EimPackageResult", v.Choice)
	}
}

// MarshalDER encodes EimPackageResult to DER format.
func (v *EimPackageResult) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case EimPackageResultChoiceEuiccPackageResult:
		if v.EuiccPackageResult == nil {
			return nil, fmt.Errorf("choice EimPackageResult: euiccPackageResult is nil")
		}
		enc_der_0, err := v.EuiccPackageResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageResult: %w", err)
		}
		return enc_der_0, nil
	case EimPackageResultChoiceEPRAndNotifications:
		if v.EPRAndNotifications == nil {
			return nil, fmt.Errorf("choice EimPackageResult: ePRAndNotifications is nil")
		}
		enc_der_1, err := v.EPRAndNotifications.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ePRAndNotifications: %w", err)
		}
		return enc_der_1, nil
	case EimPackageResultChoiceIpaEuiccDataResponse:
		if v.IpaEuiccDataResponse == nil {
			return nil, fmt.Errorf("choice EimPackageResult: ipaEuiccDataResponse is nil")
		}
		enc_der_2, err := v.IpaEuiccDataResponse.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccDataResponse: %w", err)
		}
		return enc_der_2, nil
	case EimPackageResultChoiceProfileDownloadTriggerResult:
		if v.ProfileDownloadTriggerResult == nil {
			return nil, fmt.Errorf("choice EimPackageResult: profileDownloadTriggerResult is nil")
		}
		enc_der_3, err := v.ProfileDownloadTriggerResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileDownloadTriggerResult: %w", err)
		}
		return enc_der_3, nil
	case EimPackageResultChoiceEimPackageResultResponseError:
		if v.EimPackageResultResponseError == nil {
			return nil, fmt.Errorf("choice EimPackageResult: eimPackageResultResponseError is nil")
		}
		enc_der_4, err := v.EimPackageResultResponseError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding eimPackageResultResponseError: %w", err)
		}
		enc_der_4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_4)
		return enc_der_4, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes EimPackageResult from BER/DER format.
func (v *EimPackageResult) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for EimPackageResult CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EimPackageResult: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding EimPackageResult CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EimPackageResult", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 81 {
		v.Choice = EimPackageResultChoiceEuiccPackageResult
		var dec EuiccPackageResult
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding euiccPackageResult: %w", unmErr)
		}
		v.EuiccPackageResult = &dec
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = EimPackageResultChoiceEPRAndNotifications
		var dec EimPackageResultEPRAndNotifications
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding ePRAndNotifications: %w", unmErr)
		}
		v.EPRAndNotifications = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 82 {
		v.Choice = EimPackageResultChoiceIpaEuiccDataResponse
		var dec IpaEuiccDataResponse
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding ipaEuiccDataResponse: %w", unmErr)
		}
		v.IpaEuiccDataResponse = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 84 {
		v.Choice = EimPackageResultChoiceProfileDownloadTriggerResult
		var dec ProfileDownloadTriggerResult
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding profileDownloadTriggerResult: %w", unmErr)
		}
		v.ProfileDownloadTriggerResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = EimPackageResultChoiceEimPackageResultResponseError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding eimPackageResultResponseError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec EimPackageResultResponseError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding eimPackageResultResponseError: %w", unmErr)
		}
		v.EimPackageResultResponseError = &dec
	} else {
		return fmt.Errorf("unknown tag %s for EimPackageResult CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ProvideEimPackageResult to BER format.
func (v *ProvideEimPackageResult) MarshalBER() ([]byte, error) {
	var children []byte
	if v.EidValue != nil {
		enc_eidvalue := ber.EncodeOctetString([]byte(*v.EidValue))
		enc_eidvalue = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_eidvalue)
		children = append(children, enc_eidvalue...)
	}
	enc_eimpackageresult, err := v.EimPackageResult.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding eimPackageResult: %w", err)
	}
	children = append(children, enc_eimpackageresult...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 80, Constructed: true}, children), nil
}

// MarshalDER encodes ProvideEimPackageResult to DER format.
func (v *ProvideEimPackageResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProvideEimPackageResult from BER/DER format.
func (v *ProvideEimPackageResult) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProvideEimPackageResult: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 80 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProvideEimPackageResult: %w: expected tag [CONTEXT 80], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideEimPackageResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eidValue
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 26 {
				_, n_eidvalue, rawVal_eidvalue, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eidValue: %w", err)
				}
				tmp_eidvalue := sgp22.Octet16(rawVal_eidvalue)
				v.EidValue = &tmp_eidvalue
				offset += n_eidvalue
			}
		}
	}
	// Decode eimPackageResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimPackageResult")
	}
	// Decode nested CHOICE (EimPackageResult)
	_, n_eimpackageresult, _, tlvErr_eimpackageresult := ber.DecodeTLV(content[offset:])
	if tlvErr_eimpackageresult != nil {
		return fmt.Errorf("decoding eimPackageResult: %w", tlvErr_eimpackageresult)
	}
	if unmErr := v.EimPackageResult.UnmarshalBER(content[offset : offset+n_eimpackageresult]); unmErr != nil {
		return fmt.Errorf("decoding eimPackageResult: %w", unmErr)
	}
	offset += n_eimpackageresult
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProvideEimPackageResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ProvideEimPackageResultResponse to BER format.
func (v *ProvideEimPackageResultResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ProvideEimPackageResultResponseChoiceEimAcknowledgements:
		if v.EimAcknowledgements == nil {
			return nil, fmt.Errorf("choice ProvideEimPackageResultResponse: eimAcknowledgements is nil")
		}
		enc_0, err := MarshalBEREimAcknowledgements(v.EimAcknowledgements)
		if err != nil {
			return nil, fmt.Errorf("encoding eimAcknowledgements: %w", err)
		}
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 80, enc_0)
		return enc_0, nil
	case ProvideEimPackageResultResponseChoiceEmptyResponse:
		if v.EmptyResponse == nil {
			return nil, fmt.Errorf("choice ProvideEimPackageResultResponse: emptyResponse is nil")
		}
		enc_1, err := v.EmptyResponse.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding emptyResponse: %w", err)
		}
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 80, enc_1)
		return enc_1, nil
	case ProvideEimPackageResultResponseChoiceProvideEimPackageResultError:
		if v.ProvideEimPackageResultError == nil {
			return nil, fmt.Errorf("choice ProvideEimPackageResultResponse: provideEimPackageResultError is nil")
		}
		enc_2 := ber.EncodeInteger(int64(*v.ProvideEimPackageResultError))
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 80, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ProvideEimPackageResultResponse", v.Choice)
	}
}

// MarshalDER encodes ProvideEimPackageResultResponse to DER format.
func (v *ProvideEimPackageResultResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ProvideEimPackageResultResponseChoiceEmptyResponse:
		if v.EmptyResponse == nil {
			return nil, fmt.Errorf("choice ProvideEimPackageResultResponse: emptyResponse is nil")
		}
		enc_der_1, err := v.EmptyResponse.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding emptyResponse: %w", err)
		}
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 80, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes ProvideEimPackageResultResponse from BER/DER format.
func (v *ProvideEimPackageResultResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ProvideEimPackageResultResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProvideEimPackageResultResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 80 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProvideEimPackageResultResponse CHOICE: %w: expected tag [CONTEXT 80], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideEimPackageResultResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for ProvideEimPackageResultResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ProvideEimPackageResultResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ProvideEimPackageResultResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideEimPackageResultResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 83 {
		v.Choice = ProvideEimPackageResultResponseChoiceEimAcknowledgements
		dec, unmErr := UnmarshalBEREimAcknowledgements(choiceData)
		if unmErr != nil {
			return fmt.Errorf("decoding eimAcknowledgements: %w", unmErr)
		}
		v.EimAcknowledgements = dec
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = ProvideEimPackageResultResponseChoiceEmptyResponse
		var dec ProvideEimPackageResultResponseEmptyResponse
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding emptyResponse: %w", unmErr)
		}
		v.EmptyResponse = &dec
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = ProvideEimPackageResultResponseChoiceProvideEimPackageResultError
		decVal, _, intErr := ber.DecodeInteger(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding provideEimPackageResultError: %w", intErr)
		}
		v.ProvideEimPackageResultError = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for ProvideEimPackageResultResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes TransferEimPackageRequest to BER format.
func (v *TransferEimPackageRequest) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case TransferEimPackageRequestChoiceEuiccPackageRequest:
		if v.EuiccPackageRequest == nil {
			return nil, fmt.Errorf("choice TransferEimPackageRequest: euiccPackageRequest is nil")
		}
		enc_0, err := v.EuiccPackageRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageRequest: %w", err)
		}
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_0)
		return enc_0, nil
	case TransferEimPackageRequestChoiceIpaEuiccDataRequest:
		if v.IpaEuiccDataRequest == nil {
			return nil, fmt.Errorf("choice TransferEimPackageRequest: ipaEuiccDataRequest is nil")
		}
		enc_1, err := v.IpaEuiccDataRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccDataRequest: %w", err)
		}
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_1)
		return enc_1, nil
	case TransferEimPackageRequestChoiceEimAcknowledgements:
		if v.EimAcknowledgements == nil {
			return nil, fmt.Errorf("choice TransferEimPackageRequest: eimAcknowledgements is nil")
		}
		enc_2, err := MarshalBEREimAcknowledgements(v.EimAcknowledgements)
		if err != nil {
			return nil, fmt.Errorf("encoding eimAcknowledgements: %w", err)
		}
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_2)
		return enc_2, nil
	case TransferEimPackageRequestChoiceProfileDownloadTriggerRequest:
		if v.ProfileDownloadTriggerRequest == nil {
			return nil, fmt.Errorf("choice TransferEimPackageRequest: profileDownloadTriggerRequest is nil")
		}
		enc_3, err := v.ProfileDownloadTriggerRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileDownloadTriggerRequest: %w", err)
		}
		enc_3 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TransferEimPackageRequest", v.Choice)
	}
}

// MarshalDER encodes TransferEimPackageRequest to DER format.
func (v *TransferEimPackageRequest) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case TransferEimPackageRequestChoiceEuiccPackageRequest:
		if v.EuiccPackageRequest == nil {
			return nil, fmt.Errorf("choice TransferEimPackageRequest: euiccPackageRequest is nil")
		}
		enc_der_0, err := v.EuiccPackageRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageRequest: %w", err)
		}
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_der_0)
		return enc_der_0, nil
	case TransferEimPackageRequestChoiceIpaEuiccDataRequest:
		if v.IpaEuiccDataRequest == nil {
			return nil, fmt.Errorf("choice TransferEimPackageRequest: ipaEuiccDataRequest is nil")
		}
		enc_der_1, err := v.IpaEuiccDataRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccDataRequest: %w", err)
		}
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_der_1)
		return enc_der_1, nil
	case TransferEimPackageRequestChoiceProfileDownloadTriggerRequest:
		if v.ProfileDownloadTriggerRequest == nil {
			return nil, fmt.Errorf("choice TransferEimPackageRequest: profileDownloadTriggerRequest is nil")
		}
		enc_der_3, err := v.ProfileDownloadTriggerRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileDownloadTriggerRequest: %w", err)
		}
		enc_der_3 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_der_3)
		return enc_der_3, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes TransferEimPackageRequest from BER/DER format.
func (v *TransferEimPackageRequest) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for TransferEimPackageRequest CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding TransferEimPackageRequest CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 78 || !decodedTag.Constructed {
		return fmt.Errorf("decoding TransferEimPackageRequest CHOICE: %w: expected tag [CONTEXT 78], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TransferEimPackageRequest", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for TransferEimPackageRequest CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TransferEimPackageRequest: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding TransferEimPackageRequest CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TransferEimPackageRequest", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 81 {
		v.Choice = TransferEimPackageRequestChoiceEuiccPackageRequest
		var dec EuiccPackageRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding euiccPackageRequest: %w", unmErr)
		}
		v.EuiccPackageRequest = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 82 {
		v.Choice = TransferEimPackageRequestChoiceIpaEuiccDataRequest
		var dec IpaEuiccDataRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding ipaEuiccDataRequest: %w", unmErr)
		}
		v.IpaEuiccDataRequest = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 83 {
		v.Choice = TransferEimPackageRequestChoiceEimAcknowledgements
		dec, unmErr := UnmarshalBEREimAcknowledgements(choiceData)
		if unmErr != nil {
			return fmt.Errorf("decoding eimAcknowledgements: %w", unmErr)
		}
		v.EimAcknowledgements = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 84 {
		v.Choice = TransferEimPackageRequestChoiceProfileDownloadTriggerRequest
		var dec ProfileDownloadTriggerRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding profileDownloadTriggerRequest: %w", unmErr)
		}
		v.ProfileDownloadTriggerRequest = &dec
	} else {
		return fmt.Errorf("unknown tag %s for TransferEimPackageRequest CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes TransferEimPackageResponse to BER format.
func (v *TransferEimPackageResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case TransferEimPackageResponseChoiceEuiccPackageResult:
		if v.EuiccPackageResult == nil {
			return nil, fmt.Errorf("choice TransferEimPackageResponse: euiccPackageResult is nil")
		}
		enc_0, err := v.EuiccPackageResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageResult: %w", err)
		}
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_0)
		return enc_0, nil
	case TransferEimPackageResponseChoiceEPRAndNotifications:
		if v.EPRAndNotifications == nil {
			return nil, fmt.Errorf("choice TransferEimPackageResponse: ePRAndNotifications is nil")
		}
		enc_1, err := v.EPRAndNotifications.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ePRAndNotifications: %w", err)
		}
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_1)
		return enc_1, nil
	case TransferEimPackageResponseChoiceIpaEuiccDataResponse:
		if v.IpaEuiccDataResponse == nil {
			return nil, fmt.Errorf("choice TransferEimPackageResponse: ipaEuiccDataResponse is nil")
		}
		enc_2, err := v.IpaEuiccDataResponse.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccDataResponse: %w", err)
		}
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_2)
		return enc_2, nil
	case TransferEimPackageResponseChoiceEimPackageReceived:
		enc_3 := ber.EncodeNull()
		enc_3 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_3)
		return enc_3, nil
	case TransferEimPackageResponseChoiceEimPackageReceivedWithCid:
		if v.EimPackageReceivedWithCid == nil {
			return nil, fmt.Errorf("choice TransferEimPackageResponse: eimPackageReceivedWithCid is nil")
		}
		enc_4, err := v.EimPackageReceivedWithCid.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding eimPackageReceivedWithCid: %w", err)
		}
		enc_4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 96, true, enc_4)
		enc_4 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_4)
		return enc_4, nil
	case TransferEimPackageResponseChoiceEimPackageError:
		if v.EimPackageError == nil {
			return nil, fmt.Errorf("choice TransferEimPackageResponse: eimPackageError is nil")
		}
		enc_5 := ber.EncodeInteger(int64(*v.EimPackageError))
		enc_5 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_5)
		return enc_5, nil
	case TransferEimPackageResponseChoiceEimPackageErrorWithCid:
		if v.EimPackageErrorWithCid == nil {
			return nil, fmt.Errorf("choice TransferEimPackageResponse: eimPackageErrorWithCid is nil")
		}
		enc_6, err := v.EimPackageErrorWithCid.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding eimPackageErrorWithCid: %w", err)
		}
		enc_6 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 97, true, enc_6)
		enc_6 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_6)
		return enc_6, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TransferEimPackageResponse", v.Choice)
	}
}

// MarshalDER encodes TransferEimPackageResponse to DER format.
func (v *TransferEimPackageResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case TransferEimPackageResponseChoiceEuiccPackageResult:
		if v.EuiccPackageResult == nil {
			return nil, fmt.Errorf("choice TransferEimPackageResponse: euiccPackageResult is nil")
		}
		enc_der_0, err := v.EuiccPackageResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccPackageResult: %w", err)
		}
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_der_0)
		return enc_der_0, nil
	case TransferEimPackageResponseChoiceEPRAndNotifications:
		if v.EPRAndNotifications == nil {
			return nil, fmt.Errorf("choice TransferEimPackageResponse: ePRAndNotifications is nil")
		}
		enc_der_1, err := v.EPRAndNotifications.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ePRAndNotifications: %w", err)
		}
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_der_1)
		return enc_der_1, nil
	case TransferEimPackageResponseChoiceIpaEuiccDataResponse:
		if v.IpaEuiccDataResponse == nil {
			return nil, fmt.Errorf("choice TransferEimPackageResponse: ipaEuiccDataResponse is nil")
		}
		enc_der_2, err := v.IpaEuiccDataResponse.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ipaEuiccDataResponse: %w", err)
		}
		enc_der_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_der_2)
		return enc_der_2, nil
	case TransferEimPackageResponseChoiceEimPackageReceivedWithCid:
		if v.EimPackageReceivedWithCid == nil {
			return nil, fmt.Errorf("choice TransferEimPackageResponse: eimPackageReceivedWithCid is nil")
		}
		enc_der_4, err := v.EimPackageReceivedWithCid.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding eimPackageReceivedWithCid: %w", err)
		}
		enc_der_4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 96, true, enc_der_4)
		enc_der_4 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_der_4)
		return enc_der_4, nil
	case TransferEimPackageResponseChoiceEimPackageErrorWithCid:
		if v.EimPackageErrorWithCid == nil {
			return nil, fmt.Errorf("choice TransferEimPackageResponse: eimPackageErrorWithCid is nil")
		}
		enc_der_6, err := v.EimPackageErrorWithCid.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding eimPackageErrorWithCid: %w", err)
		}
		enc_der_6 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 97, true, enc_der_6)
		enc_der_6 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, enc_der_6)
		return enc_der_6, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes TransferEimPackageResponse from BER/DER format.
func (v *TransferEimPackageResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for TransferEimPackageResponse CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding TransferEimPackageResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 78 || !decodedTag.Constructed {
		return fmt.Errorf("decoding TransferEimPackageResponse CHOICE: %w: expected tag [CONTEXT 78], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TransferEimPackageResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for TransferEimPackageResponse CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TransferEimPackageResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding TransferEimPackageResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TransferEimPackageResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 81 {
		v.Choice = TransferEimPackageResponseChoiceEuiccPackageResult
		var dec EuiccPackageResult
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding euiccPackageResult: %w", unmErr)
		}
		v.EuiccPackageResult = &dec
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = TransferEimPackageResponseChoiceEPRAndNotifications
		var dec TransferEimPackageResponseEPRAndNotifications
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding ePRAndNotifications: %w", unmErr)
		}
		v.EPRAndNotifications = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 82 {
		v.Choice = TransferEimPackageResponseChoiceIpaEuiccDataResponse
		var dec IpaEuiccDataResponse
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding ipaEuiccDataResponse: %w", unmErr)
		}
		v.IpaEuiccDataResponse = &dec
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
		v.Choice = TransferEimPackageResponseChoiceEimPackageReceived
		_, nullErr := ber.DecodeNull(choiceData)
		if nullErr != nil {
			return fmt.Errorf("decoding eimPackageReceived: %w", nullErr)
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 96 {
		v.Choice = TransferEimPackageResponseChoiceEimPackageReceivedWithCid
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding eimPackageReceivedWithCid: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec EimPackageReceivedWithCid
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding eimPackageReceivedWithCid: %w", unmErr)
		}
		v.EimPackageReceivedWithCid = &dec
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = TransferEimPackageResponseChoiceEimPackageError
		decVal, _, intErr := ber.DecodeInteger(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding eimPackageError: %w", intErr)
		}
		v.EimPackageError = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 97 {
		v.Choice = TransferEimPackageResponseChoiceEimPackageErrorWithCid
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding eimPackageErrorWithCid: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec EimPackageErrorWithCid
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding eimPackageErrorWithCid: %w", unmErr)
		}
		v.EimPackageErrorWithCid = &dec
	} else {
		return fmt.Errorf("unknown tag %s for TransferEimPackageResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EimPackageReceivedWithCid to BER format.
func (v *EimPackageReceivedWithCid) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CorrelationId != nil {
		enc_correlationid, err := v.CorrelationId.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationId: %w", err)
		}
		enc_correlationid = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_correlationid)
		children = append(children, enc_correlationid...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EimPackageReceivedWithCid to DER format.
func (v *EimPackageReceivedWithCid) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EimPackageReceivedWithCid from BER/DER format.
func (v *EimPackageReceivedWithCid) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EimPackageReceivedWithCid SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EimPackageReceivedWithCid", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode correlationId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_correlationid, innerData_correlationid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding correlationId: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_correlationid EimPackageReceivedWithCidCorrelationId
				if unmErr := dec_correlationid.UnmarshalBER(innerData_correlationid); unmErr != nil {
					return fmt.Errorf("decoding correlationId: %w", unmErr)
				}
				v.CorrelationId = &dec_correlationid
				offset += n_correlationid
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EimPackageReceivedWithCid", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EimPackageErrorWithCid to BER format.
func (v *EimPackageErrorWithCid) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CorrelationId != nil {
		enc_correlationid, err := v.CorrelationId.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationId: %w", err)
		}
		enc_correlationid = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_correlationid)
		children = append(children, enc_correlationid...)
	}
	enc_eimpackageerror := ber.EncodeInteger(int64(v.EimPackageError))
	enc_eimpackageerror = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_eimpackageerror)
	children = append(children, enc_eimpackageerror...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EimPackageErrorWithCid to DER format.
func (v *EimPackageErrorWithCid) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EimPackageErrorWithCid from BER/DER format.
func (v *EimPackageErrorWithCid) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EimPackageErrorWithCid SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EimPackageErrorWithCid", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode correlationId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_correlationid, innerData_correlationid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding correlationId: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_correlationid EimPackageErrorWithCidCorrelationId
				if unmErr := dec_correlationid.UnmarshalBER(innerData_correlationid); unmErr != nil {
					return fmt.Errorf("decoding correlationId: %w", unmErr)
				}
				v.CorrelationId = &dec_correlationid
				offset += n_correlationid
			}
		}
	}
	// Decode eimPackageError
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimPackageError")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for eimPackageError, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_eimpackageerror, rawVal_eimpackageerror, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimPackageError: %w", err)
	}
	decVal_eimpackageerror, intErr := ber.DecodeIntegerValue(rawVal_eimpackageerror)
	if intErr != nil {
		return fmt.Errorf("decoding eimPackageError: %w", intErr)
	}
	v.EimPackageError = EimPackageResultErrorCode(decVal_eimpackageerror)
	offset += n_eimpackageerror
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EimPackageErrorWithCid", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBEREuiccPackagePsmoList encodes a EuiccPackagePsmoList list to BER.
func MarshalBEREuiccPackagePsmoList(list EuiccPackagePsmoList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREuiccPackagePsmoList decodes a EuiccPackagePsmoList list from BER.
func UnmarshalBEREuiccPackagePsmoList(data []byte) (EuiccPackagePsmoList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EuiccPackagePsmoList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EuiccPackagePsmoList", Cause: ber.ErrExtraData}
	}
	var result EuiccPackagePsmoList
	offset := 0
	for offset < len(content) {
		var elem Psmo
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBEREuiccPackageEcoList encodes a EuiccPackageEcoList list to BER.
func MarshalBEREuiccPackageEcoList(list EuiccPackageEcoList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREuiccPackageEcoList decodes a EuiccPackageEcoList list from BER.
func UnmarshalBEREuiccPackageEcoList(data []byte) (EuiccPackageEcoList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EuiccPackageEcoList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EuiccPackageEcoList", Cause: ber.ErrExtraData}
	}
	var result EuiccPackageEcoList
	offset := 0
	for offset < len(content) {
		var elem Eco
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes EimConfigurationDataEimPublicKeyData to BER format.
func (v *EimConfigurationDataEimPublicKeyData) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EimConfigurationDataEimPublicKeyDataChoiceEimPublicKey:
		if v.EimPublicKey == nil {
			return nil, fmt.Errorf("choice EimConfigurationDataEimPublicKeyData: eimPublicKey is nil")
		}
		enc_0, err := v.EimPublicKey.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding eimPublicKey: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case EimConfigurationDataEimPublicKeyDataChoiceEimCertificate:
		if v.EimCertificate == nil {
			return nil, fmt.Errorf("choice EimConfigurationDataEimPublicKeyData: eimCertificate is nil")
		}
		enc_1, err := v.EimCertificate.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding eimCertificate: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EimConfigurationDataEimPublicKeyData", v.Choice)
	}
}

// MarshalDER encodes EimConfigurationDataEimPublicKeyData to DER format.
func (v *EimConfigurationDataEimPublicKeyData) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case EimConfigurationDataEimPublicKeyDataChoiceEimPublicKey:
		if v.EimPublicKey == nil {
			return nil, fmt.Errorf("choice EimConfigurationDataEimPublicKeyData: eimPublicKey is nil")
		}
		enc_der_0, err := v.EimPublicKey.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding eimPublicKey: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		return enc_der_0, nil
	case EimConfigurationDataEimPublicKeyDataChoiceEimCertificate:
		if v.EimCertificate == nil {
			return nil, fmt.Errorf("choice EimConfigurationDataEimPublicKeyData: eimCertificate is nil")
		}
		enc_der_1, err := v.EimCertificate.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding eimCertificate: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes EimConfigurationDataEimPublicKeyData from BER/DER format.
func (v *EimConfigurationDataEimPublicKeyData) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for EimConfigurationDataEimPublicKeyData CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EimConfigurationDataEimPublicKeyData: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding EimConfigurationDataEimPublicKeyData CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EimConfigurationDataEimPublicKeyData", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = EimConfigurationDataEimPublicKeyDataChoiceEimPublicKey
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding eimPublicKey: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec sgp22.SubjectPublicKeyInfo
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding eimPublicKey: %w", unmErr)
		}
		v.EimPublicKey = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = EimConfigurationDataEimPublicKeyDataChoiceEimCertificate
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding eimCertificate: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec sgp22.Certificate
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding eimCertificate: %w", unmErr)
		}
		v.EimCertificate = &dec
	} else {
		return fmt.Errorf("unknown tag %s for EimConfigurationDataEimPublicKeyData CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EimConfigurationDataTrustedPublicKeyDataTls to BER format.
func (v *EimConfigurationDataTrustedPublicKeyDataTls) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EimConfigurationDataTrustedPublicKeyDataTlsChoiceTrustedEimPkTls:
		if v.TrustedEimPkTls == nil {
			return nil, fmt.Errorf("choice EimConfigurationDataTrustedPublicKeyDataTls: trustedEimPkTls is nil")
		}
		enc_0, err := v.TrustedEimPkTls.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding trustedEimPkTls: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case EimConfigurationDataTrustedPublicKeyDataTlsChoiceTrustedCertificateTls:
		if v.TrustedCertificateTls == nil {
			return nil, fmt.Errorf("choice EimConfigurationDataTrustedPublicKeyDataTls: trustedCertificateTls is nil")
		}
		enc_1, err := v.TrustedCertificateTls.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding trustedCertificateTls: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EimConfigurationDataTrustedPublicKeyDataTls", v.Choice)
	}
}

// MarshalDER encodes EimConfigurationDataTrustedPublicKeyDataTls to DER format.
func (v *EimConfigurationDataTrustedPublicKeyDataTls) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case EimConfigurationDataTrustedPublicKeyDataTlsChoiceTrustedEimPkTls:
		if v.TrustedEimPkTls == nil {
			return nil, fmt.Errorf("choice EimConfigurationDataTrustedPublicKeyDataTls: trustedEimPkTls is nil")
		}
		enc_der_0, err := v.TrustedEimPkTls.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding trustedEimPkTls: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		return enc_der_0, nil
	case EimConfigurationDataTrustedPublicKeyDataTlsChoiceTrustedCertificateTls:
		if v.TrustedCertificateTls == nil {
			return nil, fmt.Errorf("choice EimConfigurationDataTrustedPublicKeyDataTls: trustedCertificateTls is nil")
		}
		enc_der_1, err := v.TrustedCertificateTls.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding trustedCertificateTls: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes EimConfigurationDataTrustedPublicKeyDataTls from BER/DER format.
func (v *EimConfigurationDataTrustedPublicKeyDataTls) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for EimConfigurationDataTrustedPublicKeyDataTls CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EimConfigurationDataTrustedPublicKeyDataTls: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding EimConfigurationDataTrustedPublicKeyDataTls CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EimConfigurationDataTrustedPublicKeyDataTls", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = EimConfigurationDataTrustedPublicKeyDataTlsChoiceTrustedEimPkTls
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding trustedEimPkTls: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec sgp22.SubjectPublicKeyInfo
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding trustedEimPkTls: %w", unmErr)
		}
		v.TrustedEimPkTls = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = EimConfigurationDataTrustedPublicKeyDataTlsChoiceTrustedCertificateTls
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding trustedCertificateTls: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec sgp22.Certificate
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding trustedCertificateTls: %w", unmErr)
		}
		v.TrustedCertificateTls = &dec
	} else {
		return fmt.Errorf("unknown tag %s for EimConfigurationDataTrustedPublicKeyDataTls CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EcoDeleteEim to BER format.
func (v *EcoDeleteEim) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eimid := ber.EncodeStringTag(12, v.EimId)
	enc_eimid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_eimid)
	children = append(children, enc_eimid...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EcoDeleteEim to DER format.
func (v *EcoDeleteEim) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EcoDeleteEim from BER/DER format.
func (v *EcoDeleteEim) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EcoDeleteEim SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EcoDeleteEim", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eimId
	if offset >= len(content) {
		return fmt.Errorf("missing required field eimId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for eimId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_eimid, rawVal_eimid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eimId: %w", err)
	}
	decVal_eimid := ber.DecodeStringValue(rawVal_eimid)
	v.EimId = decVal_eimid
	offset += n_eimid
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EcoDeleteEim", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EcoListEim to BER format.
func (v *EcoListEim) MarshalBER() ([]byte, error) {
	return ber.EncodeSequence(nil), nil
}

// MarshalDER encodes EcoListEim to DER format.
func (v *EcoListEim) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EcoListEim from BER/DER format.
func (v *EcoListEim) UnmarshalBER(data []byte) error {
	_, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EcoListEim SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EcoListEim", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PsmoEnable to BER format.
func (v *PsmoEnable) MarshalBER() ([]byte, error) {
	var children []byte
	enc_iccid := ber.EncodeOctetString([]byte(v.Iccid))
	enc_iccid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_iccid)
	children = append(children, enc_iccid...)
	if v.RollbackFlag != nil {
		enc_rollbackflag := ber.EncodeNull()
		children = append(children, enc_rollbackflag...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PsmoEnable to DER format.
func (v *PsmoEnable) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PsmoEnable from BER/DER format.
func (v *PsmoEnable) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PsmoEnable SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PsmoEnable", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode iccid
	if offset >= len(content) {
		return fmt.Errorf("missing required field iccid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 26 {
			return fmt.Errorf("expected tag [%s %d] for iccid, got %s", "APPLICATION", 26, reqTag_)
		}
	}
	_, n_iccid, rawVal_iccid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding iccid: %w", err)
	}
	v.Iccid = sgp22.Iccid(rawVal_iccid)
	offset += n_iccid
	// Decode rollbackFlag
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rollbackFlag: %w", err)
				}
				v.RollbackFlag = &struct{}{}
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PsmoEnable", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PsmoDisable to BER format.
func (v *PsmoDisable) MarshalBER() ([]byte, error) {
	var children []byte
	enc_iccid := ber.EncodeOctetString([]byte(v.Iccid))
	enc_iccid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_iccid)
	children = append(children, enc_iccid...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PsmoDisable to DER format.
func (v *PsmoDisable) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PsmoDisable from BER/DER format.
func (v *PsmoDisable) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PsmoDisable SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PsmoDisable", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode iccid
	if offset >= len(content) {
		return fmt.Errorf("missing required field iccid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 26 {
			return fmt.Errorf("expected tag [%s %d] for iccid, got %s", "APPLICATION", 26, reqTag_)
		}
	}
	_, n_iccid, rawVal_iccid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding iccid: %w", err)
	}
	v.Iccid = sgp22.Iccid(rawVal_iccid)
	offset += n_iccid
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PsmoDisable", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PsmoDelete to BER format.
func (v *PsmoDelete) MarshalBER() ([]byte, error) {
	var children []byte
	enc_iccid := ber.EncodeOctetString([]byte(v.Iccid))
	enc_iccid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_iccid)
	children = append(children, enc_iccid...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PsmoDelete to DER format.
func (v *PsmoDelete) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PsmoDelete from BER/DER format.
func (v *PsmoDelete) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PsmoDelete SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PsmoDelete", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode iccid
	if offset >= len(content) {
		return fmt.Errorf("missing required field iccid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 26 {
			return fmt.Errorf("expected tag [%s %d] for iccid, got %s", "APPLICATION", 26, reqTag_)
		}
	}
	_, n_iccid, rawVal_iccid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding iccid: %w", err)
	}
	v.Iccid = sgp22.Iccid(rawVal_iccid)
	offset += n_iccid
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PsmoDelete", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PsmoGetRAT to BER format.
func (v *PsmoGetRAT) MarshalBER() ([]byte, error) {
	return ber.EncodeSequence(nil), nil
}

// MarshalDER encodes PsmoGetRAT to DER format.
func (v *PsmoGetRAT) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PsmoGetRAT from BER/DER format.
func (v *PsmoGetRAT) UnmarshalBER(data []byte) error {
	_, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PsmoGetRAT SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PsmoGetRAT", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PsmoConfigureImmediateEnable to BER format.
func (v *PsmoConfigureImmediateEnable) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ImmediateEnableFlag != nil {
		enc_immediateenableflag := ber.EncodeNull()
		enc_immediateenableflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_immediateenableflag)
		children = append(children, enc_immediateenableflag...)
	}
	if v.DefaultSmdpOid != nil {
		enc_defaultsmdpoid := ber.EncodeObjectIdentifier([]uint64(v.DefaultSmdpOid))
		enc_defaultsmdpoid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_defaultsmdpoid)
		children = append(children, enc_defaultsmdpoid...)
	}
	if v.DefaultSmdpAddress != nil {
		enc_defaultsmdpaddress := ber.EncodeStringTag(12, *v.DefaultSmdpAddress)
		enc_defaultsmdpaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_defaultsmdpaddress)
		children = append(children, enc_defaultsmdpaddress...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PsmoConfigureImmediateEnable to DER format.
func (v *PsmoConfigureImmediateEnable) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PsmoConfigureImmediateEnable from BER/DER format.
func (v *PsmoConfigureImmediateEnable) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PsmoConfigureImmediateEnable SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PsmoConfigureImmediateEnable", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode immediateEnableFlag
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_immediateenableflag, rawVal_immediateenableflag, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding immediateEnableFlag: %w", err)
				}
				_ = rawVal_immediateenableflag
				v.ImmediateEnableFlag = &struct{}{}
				offset += n_immediateenableflag
			}
		}
	}
	// Decode defaultSmdpOid
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_defaultsmdpoid, rawVal_defaultsmdpoid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding defaultSmdpOid: %w", err)
				}
				decVal_defaultsmdpoid, oidErr := ber.DecodeOIDValue(rawVal_defaultsmdpoid)
				if oidErr != nil {
					return fmt.Errorf("decoding defaultSmdpOid: %w", oidErr)
				}
				tmp_defaultsmdpoid := runtime.ObjectIdentifier(decVal_defaultsmdpoid)
				v.DefaultSmdpOid = tmp_defaultsmdpoid
				offset += n_defaultsmdpoid
			}
		}
	}
	// Decode defaultSmdpAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_defaultsmdpaddress, rawVal_defaultsmdpaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding defaultSmdpAddress: %w", err)
				}
				decVal_defaultsmdpaddress := ber.DecodeStringValue(rawVal_defaultsmdpaddress)
				v.DefaultSmdpAddress = &decVal_defaultsmdpaddress
				offset += n_defaultsmdpaddress
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PsmoConfigureImmediateEnable", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PsmoSetFallbackAttribute to BER format.
func (v *PsmoSetFallbackAttribute) MarshalBER() ([]byte, error) {
	var children []byte
	enc_iccid := ber.EncodeOctetString([]byte(v.Iccid))
	enc_iccid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_iccid)
	children = append(children, enc_iccid...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PsmoSetFallbackAttribute to DER format.
func (v *PsmoSetFallbackAttribute) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PsmoSetFallbackAttribute from BER/DER format.
func (v *PsmoSetFallbackAttribute) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PsmoSetFallbackAttribute SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PsmoSetFallbackAttribute", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode iccid
	if offset >= len(content) {
		return fmt.Errorf("missing required field iccid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 26 {
			return fmt.Errorf("expected tag [%s %d] for iccid, got %s", "APPLICATION", 26, reqTag_)
		}
	}
	_, n_iccid, rawVal_iccid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding iccid: %w", err)
	}
	v.Iccid = sgp22.Iccid(rawVal_iccid)
	offset += n_iccid
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PsmoSetFallbackAttribute", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PsmoUnsetFallbackAttribute to BER format.
func (v *PsmoUnsetFallbackAttribute) MarshalBER() ([]byte, error) {
	return ber.EncodeSequence(nil), nil
}

// MarshalDER encodes PsmoUnsetFallbackAttribute to DER format.
func (v *PsmoUnsetFallbackAttribute) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PsmoUnsetFallbackAttribute from BER/DER format.
func (v *PsmoUnsetFallbackAttribute) UnmarshalBER(data []byte) error {
	_, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PsmoUnsetFallbackAttribute SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PsmoUnsetFallbackAttribute", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes IpaEuiccDataRequestSearchCriteriaNotification to BER format.
func (v *IpaEuiccDataRequestSearchCriteriaNotification) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case IpaEuiccDataRequestSearchCriteriaNotificationChoiceSeqNumber:
		if v.SeqNumber == nil {
			return nil, fmt.Errorf("choice IpaEuiccDataRequestSearchCriteriaNotification: seqNumber is nil")
		}
		enc_0 := ber.EncodeBigInt(v.SeqNumber)
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case IpaEuiccDataRequestSearchCriteriaNotificationChoiceProfileManagementOperation:
		enc_1 := ber.EncodeBitString(v.ProfileManagementOperation.Bytes, (8-(v.ProfileManagementOperation.BitLength%8))%8)
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for IpaEuiccDataRequestSearchCriteriaNotification", v.Choice)
	}
}

// MarshalDER encodes IpaEuiccDataRequestSearchCriteriaNotification to DER format.
func (v *IpaEuiccDataRequestSearchCriteriaNotification) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes IpaEuiccDataRequestSearchCriteriaNotification from BER/DER format.
func (v *IpaEuiccDataRequestSearchCriteriaNotification) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for IpaEuiccDataRequestSearchCriteriaNotification CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for IpaEuiccDataRequestSearchCriteriaNotification: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding IpaEuiccDataRequestSearchCriteriaNotification CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "IpaEuiccDataRequestSearchCriteriaNotification", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = IpaEuiccDataRequestSearchCriteriaNotificationChoiceSeqNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding seqNumber: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding seqNumber: %w", intErr)
		}
		v.SeqNumber = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = IpaEuiccDataRequestSearchCriteriaNotificationChoiceProfileManagementOperation
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding profileManagementOperation: %w", tlvErr)
		}
		bsBytes, bsUnused, bsErr := ber.DecodeBitStringValue(rawVal)
		if bsErr != nil {
			return fmt.Errorf("decoding profileManagementOperation: %w", bsErr)
		}
		tmp := runtime.BitString{Bytes: bsBytes, BitLength: len(bsBytes)*8 - bsUnused}
		v.ProfileManagementOperation = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for IpaEuiccDataRequestSearchCriteriaNotification CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes IpaEuiccDataRequestSearchCriteriaEuiccPackageResult to BER format.
func (v *IpaEuiccDataRequestSearchCriteriaEuiccPackageResult) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case IpaEuiccDataRequestSearchCriteriaEuiccPackageResultChoiceSeqNumber:
		if v.SeqNumber == nil {
			return nil, fmt.Errorf("choice IpaEuiccDataRequestSearchCriteriaEuiccPackageResult: seqNumber is nil")
		}
		enc_0 := ber.EncodeBigInt(v.SeqNumber)
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for IpaEuiccDataRequestSearchCriteriaEuiccPackageResult", v.Choice)
	}
}

// MarshalDER encodes IpaEuiccDataRequestSearchCriteriaEuiccPackageResult to DER format.
func (v *IpaEuiccDataRequestSearchCriteriaEuiccPackageResult) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes IpaEuiccDataRequestSearchCriteriaEuiccPackageResult from BER/DER format.
func (v *IpaEuiccDataRequestSearchCriteriaEuiccPackageResult) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for IpaEuiccDataRequestSearchCriteriaEuiccPackageResult CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for IpaEuiccDataRequestSearchCriteriaEuiccPackageResult: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding IpaEuiccDataRequestSearchCriteriaEuiccPackageResult CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "IpaEuiccDataRequestSearchCriteriaEuiccPackageResult", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = IpaEuiccDataRequestSearchCriteriaEuiccPackageResultChoiceSeqNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding seqNumber: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding seqNumber: %w", intErr)
		}
		v.SeqNumber = decVal
	} else {
		return fmt.Errorf("unknown tag %s for IpaEuiccDataRequestSearchCriteriaEuiccPackageResult CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ProfileDownloadDataContactSmds to BER format.
func (v *ProfileDownloadDataContactSmds) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SmdsAddress != nil {
		enc_smdsaddress := ber.EncodeStringTag(12, *v.SmdsAddress)
		enc_smdsaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_smdsaddress)
		children = append(children, enc_smdsaddress...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ProfileDownloadDataContactSmds to DER format.
func (v *ProfileDownloadDataContactSmds) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileDownloadDataContactSmds from BER/DER format.
func (v *ProfileDownloadDataContactSmds) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileDownloadDataContactSmds SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileDownloadDataContactSmds", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode smdsAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_smdsaddress, rawVal_smdsaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smdsAddress: %w", err)
				}
				decVal_smdsaddress := ber.DecodeStringValue(rawVal_smdsaddress)
				v.SmdsAddress = &decVal_smdsaddress
				offset += n_smdsaddress
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProfileDownloadDataContactSmds", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBEREuiccPackageResultDataSignedEuiccResult encodes a EuiccPackageResultDataSignedEuiccResult list to BER.
func MarshalBEREuiccPackageResultDataSignedEuiccResult(list EuiccPackageResultDataSignedEuiccResult) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREuiccPackageResultDataSignedEuiccResult decodes a EuiccPackageResultDataSignedEuiccResult list from BER.
func UnmarshalBEREuiccPackageResultDataSignedEuiccResult(data []byte) (EuiccPackageResultDataSignedEuiccResult, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EuiccPackageResultDataSignedEuiccResult: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EuiccPackageResultDataSignedEuiccResult", Cause: ber.ErrExtraData}
	}
	var result EuiccPackageResultDataSignedEuiccResult
	offset := 0
	for offset < len(content) {
		var elem EuiccResultData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBERProfileInfoListResponseProfileInfoListOk encodes a ProfileInfoListResponseProfileInfoListOk list to BER.
func MarshalBERProfileInfoListResponseProfileInfoListOk(list ProfileInfoListResponseProfileInfoListOk) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERProfileInfoListResponseProfileInfoListOk decodes a ProfileInfoListResponseProfileInfoListOk list from BER.
func UnmarshalBERProfileInfoListResponseProfileInfoListOk(data []byte) (ProfileInfoListResponseProfileInfoListOk, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ProfileInfoListResponseProfileInfoListOk: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ProfileInfoListResponseProfileInfoListOk", Cause: ber.ErrExtraData}
	}
	var result ProfileInfoListResponseProfileInfoListOk
	offset := 0
	for offset < len(content) {
		var elem ProfileInfo
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBERListEimResultEimIdList encodes a ListEimResultEimIdList list to BER.
func MarshalBERListEimResultEimIdList(list ListEimResultEimIdList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERListEimResultEimIdList decodes a ListEimResultEimIdList list from BER.
func UnmarshalBERListEimResultEimIdList(data []byte) (ListEimResultEimIdList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ListEimResultEimIdList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ListEimResultEimIdList", Cause: ber.ErrExtraData}
	}
	var result ListEimResultEimIdList
	offset := 0
	for offset < len(content) {
		var elem EimIdInfo
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes ProfileDownloadTriggerResultProfileDownloadTriggerResultData to BER format.
func (v *ProfileDownloadTriggerResultProfileDownloadTriggerResultData) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ProfileDownloadTriggerResultProfileDownloadTriggerResultDataChoiceProfileInstallationResult:
		if v.ProfileInstallationResult == nil {
			return nil, fmt.Errorf("choice ProfileDownloadTriggerResultProfileDownloadTriggerResultData: profileInstallationResult is nil")
		}
		enc_0, err := v.ProfileInstallationResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileInstallationResult: %w", err)
		}
		return enc_0, nil
	case ProfileDownloadTriggerResultProfileDownloadTriggerResultDataChoiceProfileDownloadError:
		if v.ProfileDownloadError == nil {
			return nil, fmt.Errorf("choice ProfileDownloadTriggerResultProfileDownloadTriggerResultData: profileDownloadError is nil")
		}
		enc_1, err := v.ProfileDownloadError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileDownloadError: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ProfileDownloadTriggerResultProfileDownloadTriggerResultData", v.Choice)
	}
}

// MarshalDER encodes ProfileDownloadTriggerResultProfileDownloadTriggerResultData to DER format.
func (v *ProfileDownloadTriggerResultProfileDownloadTriggerResultData) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ProfileDownloadTriggerResultProfileDownloadTriggerResultDataChoiceProfileInstallationResult:
		if v.ProfileInstallationResult == nil {
			return nil, fmt.Errorf("choice ProfileDownloadTriggerResultProfileDownloadTriggerResultData: profileInstallationResult is nil")
		}
		enc_der_0, err := v.ProfileInstallationResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileInstallationResult: %w", err)
		}
		return enc_der_0, nil
	case ProfileDownloadTriggerResultProfileDownloadTriggerResultDataChoiceProfileDownloadError:
		if v.ProfileDownloadError == nil {
			return nil, fmt.Errorf("choice ProfileDownloadTriggerResultProfileDownloadTriggerResultData: profileDownloadError is nil")
		}
		enc_der_1, err := v.ProfileDownloadError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileDownloadError: %w", err)
		}
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileDownloadTriggerResultProfileDownloadTriggerResultData from BER/DER format.
func (v *ProfileDownloadTriggerResultProfileDownloadTriggerResultData) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ProfileDownloadTriggerResultProfileDownloadTriggerResultData CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ProfileDownloadTriggerResultProfileDownloadTriggerResultData: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ProfileDownloadTriggerResultProfileDownloadTriggerResultData CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileDownloadTriggerResultProfileDownloadTriggerResultData", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 55 {
		v.Choice = ProfileDownloadTriggerResultProfileDownloadTriggerResultDataChoiceProfileInstallationResult
		var dec ProfileInstallationResult
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding profileInstallationResult: %w", unmErr)
		}
		v.ProfileInstallationResult = &dec
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = ProfileDownloadTriggerResultProfileDownloadTriggerResultDataChoiceProfileDownloadError
		var dec ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding profileDownloadError: %w", unmErr)
		}
		v.ProfileDownloadError = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ProfileDownloadTriggerResultProfileDownloadTriggerResultData CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError to BER format.
func (v *ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError) MarshalBER() ([]byte, error) {
	var children []byte
	enc_profiledownloaderrorreason := ber.EncodeInteger(int64(v.ProfileDownloadErrorReason))
	enc_profiledownloaderrorreason = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_profiledownloaderrorreason)
	children = append(children, enc_profiledownloaderrorreason...)
	if v.ErrorResponse != nil {
		enc_errorresponse := ber.EncodeOctetString(v.ErrorResponse)
		children = append(children, enc_errorresponse...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError to DER format.
func (v *ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError from BER/DER format.
func (v *ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode profileDownloadErrorReason
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileDownloadErrorReason")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for profileDownloadErrorReason, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_profiledownloaderrorreason, rawVal_profiledownloaderrorreason, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding profileDownloadErrorReason: %w", err)
	}
	decVal_profiledownloaderrorreason, intErr := ber.DecodeIntegerValue(rawVal_profiledownloaderrorreason)
	if intErr != nil {
		return fmt.Errorf("decoding profileDownloadErrorReason: %w", intErr)
	}
	v.ProfileDownloadErrorReason = decVal_profiledownloaderrorreason
	offset += n_profiledownloaderrorreason
	// Decode errorResponse
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_errorresponse, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding errorResponse: %w", err)
				}
				tmp_errorresponse := val_errorresponse
				v.ErrorResponse = tmp_errorresponse
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProfileDownloadTriggerResultProfileDownloadTriggerResultDataProfileDownloadError", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERProfileInfoNotificationConfigurationInfo encodes a ProfileInfoNotificationConfigurationInfo list to BER.
func MarshalBERProfileInfoNotificationConfigurationInfo(list ProfileInfoNotificationConfigurationInfo) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERProfileInfoNotificationConfigurationInfo decodes a ProfileInfoNotificationConfigurationInfo list from BER.
func UnmarshalBERProfileInfoNotificationConfigurationInfo(data []byte) (ProfileInfoNotificationConfigurationInfo, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ProfileInfoNotificationConfigurationInfo: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ProfileInfoNotificationConfigurationInfo", Cause: ber.ErrExtraData}
	}
	var result ProfileInfoNotificationConfigurationInfo
	offset := 0
	for offset < len(content) {
		var elem sgp22.NotificationConfigurationInformation
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes ProfileInfoIotSpecificProfileInfo to BER format.
func (v *ProfileInfoIotSpecificProfileInfo) MarshalBER() ([]byte, error) {
	return ber.EncodeSequence(nil), nil
}

// MarshalDER encodes ProfileInfoIotSpecificProfileInfo to DER format.
func (v *ProfileInfoIotSpecificProfileInfo) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInfoIotSpecificProfileInfo from BER/DER format.
func (v *ProfileInfoIotSpecificProfileInfo) UnmarshalBER(data []byte) error {
	_, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileInfoIotSpecificProfileInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInfoIotSpecificProfileInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERStoreMetadataRequestNotificationConfigurationInfo encodes a StoreMetadataRequestNotificationConfigurationInfo list to BER.
func MarshalBERStoreMetadataRequestNotificationConfigurationInfo(list StoreMetadataRequestNotificationConfigurationInfo) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERStoreMetadataRequestNotificationConfigurationInfo decodes a StoreMetadataRequestNotificationConfigurationInfo list from BER.
func UnmarshalBERStoreMetadataRequestNotificationConfigurationInfo(data []byte) (StoreMetadataRequestNotificationConfigurationInfo, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding StoreMetadataRequestNotificationConfigurationInfo: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "StoreMetadataRequestNotificationConfigurationInfo", Cause: ber.ErrExtraData}
	}
	var result StoreMetadataRequestNotificationConfigurationInfo
	offset := 0
	for offset < len(content) {
		var elem sgp22.NotificationConfigurationInformation
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes StoreMetadataRequestIotSpecificMetadata to BER format.
func (v *StoreMetadataRequestIotSpecificMetadata) MarshalBER() ([]byte, error) {
	return ber.EncodeSequence(nil), nil
}

// MarshalDER encodes StoreMetadataRequestIotSpecificMetadata to DER format.
func (v *StoreMetadataRequestIotSpecificMetadata) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes StoreMetadataRequestIotSpecificMetadata from BER/DER format.
func (v *StoreMetadataRequestIotSpecificMetadata) UnmarshalBER(data []byte) error {
	_, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding StoreMetadataRequestIotSpecificMetadata SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "StoreMetadataRequestIotSpecificMetadata", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBEREUICCInfo2EuiccCiPKIdListForVerification encodes a EUICCInfo2EuiccCiPKIdListForVerification list to BER.
func MarshalBEREUICCInfo2EuiccCiPKIdListForVerification(list EUICCInfo2EuiccCiPKIdListForVerification) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREUICCInfo2EuiccCiPKIdListForVerification decodes a EUICCInfo2EuiccCiPKIdListForVerification list from BER.
func UnmarshalBEREUICCInfo2EuiccCiPKIdListForVerification(data []byte) (EUICCInfo2EuiccCiPKIdListForVerification, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EUICCInfo2EuiccCiPKIdListForVerification: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUICCInfo2EuiccCiPKIdListForVerification", Cause: ber.ErrExtraData}
	}
	var result EUICCInfo2EuiccCiPKIdListForVerification
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, sgp22.SubjectKeyIdentifier(val))
		offset += n
	}
	return result, nil
}

// MarshalBEREUICCInfo2EuiccCiPKIdListForSigning encodes a EUICCInfo2EuiccCiPKIdListForSigning list to BER.
func MarshalBEREUICCInfo2EuiccCiPKIdListForSigning(list EUICCInfo2EuiccCiPKIdListForSigning) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigning decodes a EUICCInfo2EuiccCiPKIdListForSigning list from BER.
func UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigning(data []byte) (EUICCInfo2EuiccCiPKIdListForSigning, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EUICCInfo2EuiccCiPKIdListForSigning: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUICCInfo2EuiccCiPKIdListForSigning", Cause: ber.ErrExtraData}
	}
	var result EUICCInfo2EuiccCiPKIdListForSigning
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, sgp22.SubjectKeyIdentifier(val))
		offset += n
	}
	return result, nil
}

// MarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions encodes a EUICCInfo2AdditionalEuiccProfilePackageVersions list to BER.
func MarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions(list EUICCInfo2AdditionalEuiccProfilePackageVersions) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions decodes a EUICCInfo2AdditionalEuiccProfilePackageVersions list from BER.
func UnmarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions(data []byte) (EUICCInfo2AdditionalEuiccProfilePackageVersions, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EUICCInfo2AdditionalEuiccProfilePackageVersions: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUICCInfo2AdditionalEuiccProfilePackageVersions", Cause: ber.ErrExtraData}
	}
	var result EUICCInfo2AdditionalEuiccProfilePackageVersions
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, sgp22.VersionType(val))
		offset += n
	}
	return result, nil
}

// MarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3 encodes a EUICCInfo2EuiccCiPKIdListForSigningV3 list to BER.
func MarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3(list EUICCInfo2EuiccCiPKIdListForSigningV3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3 decodes a EUICCInfo2EuiccCiPKIdListForSigningV3 list from BER.
func UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3(data []byte) (EUICCInfo2EuiccCiPKIdListForSigningV3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EUICCInfo2EuiccCiPKIdListForSigningV3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUICCInfo2EuiccCiPKIdListForSigningV3", Cause: ber.ErrExtraData}
	}
	var result EUICCInfo2EuiccCiPKIdListForSigningV3
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, sgp22.SubjectKeyIdentifier(val))
		offset += n
	}
	return result, nil
}

// MarshalBERIoTSpecificInfoIotVersion encodes a IoTSpecificInfoIotVersion list to BER.
func MarshalBERIoTSpecificInfoIotVersion(list IoTSpecificInfoIotVersion) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERIoTSpecificInfoIotVersion decodes a IoTSpecificInfoIotVersion list from BER.
func UnmarshalBERIoTSpecificInfoIotVersion(data []byte) (IoTSpecificInfoIotVersion, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding IoTSpecificInfoIotVersion: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "IoTSpecificInfoIotVersion", Cause: ber.ErrExtraData}
	}
	var result IoTSpecificInfoIotVersion
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, sgp22.VersionType(val))
		offset += n
	}
	return result, nil
}

// MarshalBERAddInitialEimRequestEimConfigurationDataList encodes a AddInitialEimRequestEimConfigurationDataList list to BER.
func MarshalBERAddInitialEimRequestEimConfigurationDataList(list AddInitialEimRequestEimConfigurationDataList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERAddInitialEimRequestEimConfigurationDataList decodes a AddInitialEimRequestEimConfigurationDataList list from BER.
func UnmarshalBERAddInitialEimRequestEimConfigurationDataList(data []byte) (AddInitialEimRequestEimConfigurationDataList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AddInitialEimRequestEimConfigurationDataList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AddInitialEimRequestEimConfigurationDataList", Cause: ber.ErrExtraData}
	}
	var result AddInitialEimRequestEimConfigurationDataList
	offset := 0
	for offset < len(content) {
		var elem EimConfigurationData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes AddInitialEimResponseAddInitialEimOkElem to BER format.
func (v *AddInitialEimResponseAddInitialEimOkElem) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AddInitialEimResponseAddInitialEimOkElemChoiceAssociationToken:
		if v.AssociationToken == nil {
			return nil, fmt.Errorf("choice AddInitialEimResponseAddInitialEimOkElem: associationToken is nil")
		}
		enc_0 := ber.EncodeBigInt(v.AssociationToken)
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_0)
		return enc_0, nil
	case AddInitialEimResponseAddInitialEimOkElemChoiceAddOk:
		enc_1 := ber.EncodeNull()
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AddInitialEimResponseAddInitialEimOkElem", v.Choice)
	}
}

// MarshalDER encodes AddInitialEimResponseAddInitialEimOkElem to DER format.
func (v *AddInitialEimResponseAddInitialEimOkElem) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes AddInitialEimResponseAddInitialEimOkElem from BER/DER format.
func (v *AddInitialEimResponseAddInitialEimOkElem) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AddInitialEimResponseAddInitialEimOkElem CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AddInitialEimResponseAddInitialEimOkElem: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AddInitialEimResponseAddInitialEimOkElem CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AddInitialEimResponseAddInitialEimOkElem", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = AddInitialEimResponseAddInitialEimOkElemChoiceAssociationToken
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding associationToken: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding associationToken: %w", intErr)
		}
		v.AssociationToken = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
		v.Choice = AddInitialEimResponseAddInitialEimOkElemChoiceAddOk
		_, nullErr := ber.DecodeNull(choiceData)
		if nullErr != nil {
			return fmt.Errorf("decoding addOk: %w", nullErr)
		}
	} else {
		return fmt.Errorf("unknown tag %s for AddInitialEimResponseAddInitialEimOkElem CHOICE", peekTag)
	}
	return nil
}

// MarshalBERAddInitialEimResponseAddInitialEimOk encodes a AddInitialEimResponseAddInitialEimOk list to BER.
func MarshalBERAddInitialEimResponseAddInitialEimOk(list AddInitialEimResponseAddInitialEimOk) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERAddInitialEimResponseAddInitialEimOk decodes a AddInitialEimResponseAddInitialEimOk list from BER.
func UnmarshalBERAddInitialEimResponseAddInitialEimOk(data []byte) (AddInitialEimResponseAddInitialEimOk, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AddInitialEimResponseAddInitialEimOk: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AddInitialEimResponseAddInitialEimOk", Cause: ber.ErrExtraData}
	}
	var result AddInitialEimResponseAddInitialEimOk
	offset := 0
	for offset < len(content) {
		var elem AddInitialEimResponseAddInitialEimOkElem
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes GetCertsResponseCerts to BER format.
func (v *GetCertsResponseCerts) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eumcertificate, err := v.EumCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding eumCertificate: %w", err)
	}
	enc_eumcertificate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_eumcertificate)
	children = append(children, enc_eumcertificate...)
	enc_euicccertificate, err := v.EuiccCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccCertificate: %w", err)
	}
	enc_euicccertificate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_euicccertificate)
	children = append(children, enc_euicccertificate...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes GetCertsResponseCerts to DER format.
func (v *GetCertsResponseCerts) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetCertsResponseCerts from BER/DER format.
func (v *GetCertsResponseCerts) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetCertsResponseCerts SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetCertsResponseCerts", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eumCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field eumCertificate")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 5 {
			return fmt.Errorf("expected tag [%s %d] for eumCertificate, got %s", "CONTEXT", 5, reqTag_)
		}
	}
	_, n_eumcertificate, rawVal_eumcertificate, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eumCertificate: %w", err)
	}
	reconstructed_eumcertificate := ber.EncodeSequence(rawVal_eumcertificate)
	if unmErr := v.EumCertificate.UnmarshalBER(reconstructed_eumcertificate); unmErr != nil {
		return fmt.Errorf("decoding eumCertificate: %w", unmErr)
	}
	offset += n_eumcertificate
	// Decode euiccCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCertificate")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 6 {
			return fmt.Errorf("expected tag [%s %d] for euiccCertificate, got %s", "CONTEXT", 6, reqTag_)
		}
	}
	_, n_euicccertificate, rawVal_euicccertificate, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCertificate: %w", err)
	}
	reconstructed_euicccertificate := ber.EncodeSequence(rawVal_euicccertificate)
	if unmErr := v.EuiccCertificate.UnmarshalBER(reconstructed_euicccertificate); unmErr != nil {
		return fmt.Errorf("decoding euiccCertificate: %w", unmErr)
	}
	offset += n_euicccertificate
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "GetCertsResponseCerts", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RetrieveNotificationsListRequestSearchCriteria to BER format.
func (v *RetrieveNotificationsListRequestSearchCriteria) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case RetrieveNotificationsListRequestSearchCriteriaChoiceSeqNumber:
		if v.SeqNumber == nil {
			return nil, fmt.Errorf("choice RetrieveNotificationsListRequestSearchCriteria: seqNumber is nil")
		}
		enc_0 := ber.EncodeBigInt(v.SeqNumber)
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case RetrieveNotificationsListRequestSearchCriteriaChoiceProfileManagementOperation:
		enc_1 := ber.EncodeBitString(v.ProfileManagementOperation.Bytes, (8-(v.ProfileManagementOperation.BitLength%8))%8)
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	case RetrieveNotificationsListRequestSearchCriteriaChoiceEuiccPackageResults:
		enc_2 := ber.EncodeNull()
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RetrieveNotificationsListRequestSearchCriteria", v.Choice)
	}
}

// MarshalDER encodes RetrieveNotificationsListRequestSearchCriteria to DER format.
func (v *RetrieveNotificationsListRequestSearchCriteria) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes RetrieveNotificationsListRequestSearchCriteria from BER/DER format.
func (v *RetrieveNotificationsListRequestSearchCriteria) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for RetrieveNotificationsListRequestSearchCriteria CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RetrieveNotificationsListRequestSearchCriteria: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding RetrieveNotificationsListRequestSearchCriteria CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RetrieveNotificationsListRequestSearchCriteria", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = RetrieveNotificationsListRequestSearchCriteriaChoiceSeqNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding seqNumber: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding seqNumber: %w", intErr)
		}
		v.SeqNumber = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = RetrieveNotificationsListRequestSearchCriteriaChoiceProfileManagementOperation
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding profileManagementOperation: %w", tlvErr)
		}
		bsBytes, bsUnused, bsErr := ber.DecodeBitStringValue(rawVal)
		if bsErr != nil {
			return fmt.Errorf("decoding profileManagementOperation: %w", bsErr)
		}
		tmp := runtime.BitString{Bytes: bsBytes, BitLength: len(bsBytes)*8 - bsUnused}
		v.ProfileManagementOperation = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = RetrieveNotificationsListRequestSearchCriteriaChoiceEuiccPackageResults
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding euiccPackageResults: %w", tlvErr)
		}
		_ = rawVal // NULL has no content
		v.EuiccPackageResults = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for RetrieveNotificationsListRequestSearchCriteria CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes GetEimConfigurationDataRequestSearchCriteria to BER format.
func (v *GetEimConfigurationDataRequestSearchCriteria) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case GetEimConfigurationDataRequestSearchCriteriaChoiceEimId:
		if v.EimId == nil {
			return nil, fmt.Errorf("choice GetEimConfigurationDataRequestSearchCriteria: eimId is nil")
		}
		enc_0 := ber.EncodeStringTag(12, *v.EimId)
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for GetEimConfigurationDataRequestSearchCriteria", v.Choice)
	}
}

// MarshalDER encodes GetEimConfigurationDataRequestSearchCriteria to DER format.
func (v *GetEimConfigurationDataRequestSearchCriteria) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes GetEimConfigurationDataRequestSearchCriteria from BER/DER format.
func (v *GetEimConfigurationDataRequestSearchCriteria) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for GetEimConfigurationDataRequestSearchCriteria CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for GetEimConfigurationDataRequestSearchCriteria: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding GetEimConfigurationDataRequestSearchCriteria CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEimConfigurationDataRequestSearchCriteria", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = GetEimConfigurationDataRequestSearchCriteriaChoiceEimId
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding eimId: %w", tlvErr)
		}
		decVal := ber.DecodeStringValue(rawVal)
		v.EimId = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for GetEimConfigurationDataRequestSearchCriteria CHOICE", peekTag)
	}
	return nil
}

// MarshalBERGetEimConfigurationDataResponseEimConfigurationDataList encodes a GetEimConfigurationDataResponseEimConfigurationDataList list to BER.
func MarshalBERGetEimConfigurationDataResponseEimConfigurationDataList(list GetEimConfigurationDataResponseEimConfigurationDataList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERGetEimConfigurationDataResponseEimConfigurationDataList decodes a GetEimConfigurationDataResponseEimConfigurationDataList list from BER.
func UnmarshalBERGetEimConfigurationDataResponseEimConfigurationDataList(data []byte) (GetEimConfigurationDataResponseEimConfigurationDataList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding GetEimConfigurationDataResponseEimConfigurationDataList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "GetEimConfigurationDataResponseEimConfigurationDataList", Cause: ber.ErrExtraData}
	}
	var result GetEimConfigurationDataResponseEimConfigurationDataList
	offset := 0
	for offset < len(content) {
		var elem EimConfigurationData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes CompactAuthenticateResponseOkSignedData to BER format.
func (v *CompactAuthenticateResponseOkSignedData) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CompactAuthenticateResponseOkSignedDataChoiceEuiccSigned1:
		if v.EuiccSigned1 == nil {
			return nil, fmt.Errorf("choice CompactAuthenticateResponseOkSignedData: euiccSigned1 is nil")
		}
		enc_0, err := v.EuiccSigned1.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccSigned1: %w", err)
		}
		return enc_0, nil
	case CompactAuthenticateResponseOkSignedDataChoiceCompactEuiccSigned1:
		if v.CompactEuiccSigned1 == nil {
			return nil, fmt.Errorf("choice CompactAuthenticateResponseOkSignedData: compactEuiccSigned1 is nil")
		}
		enc_1, err := v.CompactEuiccSigned1.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactEuiccSigned1: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CompactAuthenticateResponseOkSignedData", v.Choice)
	}
}

// MarshalDER encodes CompactAuthenticateResponseOkSignedData to DER format.
func (v *CompactAuthenticateResponseOkSignedData) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CompactAuthenticateResponseOkSignedDataChoiceEuiccSigned1:
		if v.EuiccSigned1 == nil {
			return nil, fmt.Errorf("choice CompactAuthenticateResponseOkSignedData: euiccSigned1 is nil")
		}
		enc_der_0, err := v.EuiccSigned1.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding euiccSigned1: %w", err)
		}
		return enc_der_0, nil
	case CompactAuthenticateResponseOkSignedDataChoiceCompactEuiccSigned1:
		if v.CompactEuiccSigned1 == nil {
			return nil, fmt.Errorf("choice CompactAuthenticateResponseOkSignedData: compactEuiccSigned1 is nil")
		}
		enc_der_1, err := v.CompactEuiccSigned1.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactEuiccSigned1: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactAuthenticateResponseOkSignedData from BER/DER format.
func (v *CompactAuthenticateResponseOkSignedData) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CompactAuthenticateResponseOkSignedData CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CompactAuthenticateResponseOkSignedData: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CompactAuthenticateResponseOkSignedData CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactAuthenticateResponseOkSignedData", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = CompactAuthenticateResponseOkSignedDataChoiceEuiccSigned1
		var dec EuiccSigned1
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding euiccSigned1: %w", unmErr)
		}
		v.EuiccSigned1 = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CompactAuthenticateResponseOkSignedDataChoiceCompactEuiccSigned1
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding compactEuiccSigned1: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CompactEuiccSigned1
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding compactEuiccSigned1: %w", unmErr)
		}
		v.CompactEuiccSigned1 = &dec
	} else {
		return fmt.Errorf("unknown tag %s for CompactAuthenticateResponseOkSignedData CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CompactProfileInstallationResultDataCompactFinalResult to BER format.
func (v *CompactProfileInstallationResultDataCompactFinalResult) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CompactProfileInstallationResultDataCompactFinalResultChoiceCompactSuccessResult:
		if v.CompactSuccessResult == nil {
			return nil, fmt.Errorf("choice CompactProfileInstallationResultDataCompactFinalResult: compactSuccessResult is nil")
		}
		enc_0, err := v.CompactSuccessResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactSuccessResult: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case CompactProfileInstallationResultDataCompactFinalResultChoiceErrorResult:
		if v.ErrorResult == nil {
			return nil, fmt.Errorf("choice CompactProfileInstallationResultDataCompactFinalResult: errorResult is nil")
		}
		enc_1, err := v.ErrorResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding errorResult: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CompactProfileInstallationResultDataCompactFinalResult", v.Choice)
	}
}

// MarshalDER encodes CompactProfileInstallationResultDataCompactFinalResult to DER format.
func (v *CompactProfileInstallationResultDataCompactFinalResult) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CompactProfileInstallationResultDataCompactFinalResultChoiceCompactSuccessResult:
		if v.CompactSuccessResult == nil {
			return nil, fmt.Errorf("choice CompactProfileInstallationResultDataCompactFinalResult: compactSuccessResult is nil")
		}
		enc_der_0, err := v.CompactSuccessResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding compactSuccessResult: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		return enc_der_0, nil
	case CompactProfileInstallationResultDataCompactFinalResultChoiceErrorResult:
		if v.ErrorResult == nil {
			return nil, fmt.Errorf("choice CompactProfileInstallationResultDataCompactFinalResult: errorResult is nil")
		}
		enc_der_1, err := v.ErrorResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding errorResult: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes CompactProfileInstallationResultDataCompactFinalResult from BER/DER format.
func (v *CompactProfileInstallationResultDataCompactFinalResult) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CompactProfileInstallationResultDataCompactFinalResult CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CompactProfileInstallationResultDataCompactFinalResult: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CompactProfileInstallationResultDataCompactFinalResult CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CompactProfileInstallationResultDataCompactFinalResult", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CompactProfileInstallationResultDataCompactFinalResultChoiceCompactSuccessResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding compactSuccessResult: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CompactSuccessResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding compactSuccessResult: %w", unmErr)
		}
		v.CompactSuccessResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CompactProfileInstallationResultDataCompactFinalResultChoiceErrorResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding errorResult: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec sgp22.ErrorResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding errorResult: %w", unmErr)
		}
		v.ErrorResult = &dec
	} else {
		return fmt.Errorf("unknown tag %s for CompactProfileInstallationResultDataCompactFinalResult CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EimPackageResultEPRAndNotifications to BER format.
func (v *EimPackageResultEPRAndNotifications) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccpackageresult, err := v.EuiccPackageResult.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccPackageResult: %w", err)
	}
	children = append(children, enc_euiccpackageresult...)
	enc_notificationlist, err := MarshalBERPendingNotificationList(v.NotificationList)
	if err != nil {
		return nil, fmt.Errorf("encoding notificationList: %w", err)
	}
	if v.NotificationListIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_notificationlist)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_notificationlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
	} else {
		enc_notificationlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_notificationlist)
	}
	children = append(children, enc_notificationlist...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EimPackageResultEPRAndNotifications to DER format.
func (v *EimPackageResultEPRAndNotifications) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.NotificationListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes EimPackageResultEPRAndNotifications from BER/DER format.
func (v *EimPackageResultEPRAndNotifications) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EimPackageResultEPRAndNotifications SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EimPackageResultEPRAndNotifications", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccPackageResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccPackageResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 81 {
			return fmt.Errorf("expected tag [%s %d] for euiccPackageResult, got %s", "CONTEXT", 81, reqTag_)
		}
	}
	// Decode nested CHOICE (EuiccPackageResult)
	_, n_euiccpackageresult, _, tlvErr_euiccpackageresult := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccpackageresult != nil {
		return fmt.Errorf("decoding euiccPackageResult: %w", tlvErr_euiccpackageresult)
	}
	if unmErr := v.EuiccPackageResult.UnmarshalBER(content[offset : offset+n_euiccpackageresult]); unmErr != nil {
		return fmt.Errorf("decoding euiccPackageResult: %w", unmErr)
	}
	offset += n_euiccpackageresult
	// Decode notificationList
	if offset >= len(content) {
		return fmt.Errorf("missing required field notificationList")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for notificationList, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	v.NotificationListIndef_ = false
	_, n_notificationlist, rawVal_notificationlist, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding notificationList: %w", err)
	}
	reconstructed_notificationlist := ber.EncodeSequence(rawVal_notificationlist)
	dec_notificationlist, unmErr := UnmarshalBERPendingNotificationList(reconstructed_notificationlist)
	if unmErr != nil {
		return fmt.Errorf("decoding notificationList: %w", unmErr)
	}
	v.NotificationList = dec_notificationlist
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.NotificationListIndef_ = true
		}
	}
	offset += n_notificationlist
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EimPackageResultEPRAndNotifications", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ProvideEimPackageResultResponseEmptyResponse to BER format.
func (v *ProvideEimPackageResultResponseEmptyResponse) MarshalBER() ([]byte, error) {
	return ber.EncodeSequence(nil), nil
}

// MarshalDER encodes ProvideEimPackageResultResponseEmptyResponse to DER format.
func (v *ProvideEimPackageResultResponseEmptyResponse) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProvideEimPackageResultResponseEmptyResponse from BER/DER format.
func (v *ProvideEimPackageResultResponseEmptyResponse) UnmarshalBER(data []byte) error {
	_, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProvideEimPackageResultResponseEmptyResponse SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideEimPackageResultResponseEmptyResponse", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TransferEimPackageResponseEPRAndNotifications to BER format.
func (v *TransferEimPackageResponseEPRAndNotifications) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccpackageresult, err := v.EuiccPackageResult.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccPackageResult: %w", err)
	}
	children = append(children, enc_euiccpackageresult...)
	enc_notificationlist, err := MarshalBERPendingNotificationList(v.NotificationList)
	if err != nil {
		return nil, fmt.Errorf("encoding notificationList: %w", err)
	}
	if v.NotificationListIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_notificationlist)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_notificationlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
	} else {
		enc_notificationlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_notificationlist)
	}
	children = append(children, enc_notificationlist...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes TransferEimPackageResponseEPRAndNotifications to DER format.
func (v *TransferEimPackageResponseEPRAndNotifications) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.NotificationListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes TransferEimPackageResponseEPRAndNotifications from BER/DER format.
func (v *TransferEimPackageResponseEPRAndNotifications) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TransferEimPackageResponseEPRAndNotifications SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TransferEimPackageResponseEPRAndNotifications", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccPackageResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccPackageResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 81 {
			return fmt.Errorf("expected tag [%s %d] for euiccPackageResult, got %s", "CONTEXT", 81, reqTag_)
		}
	}
	// Decode nested CHOICE (EuiccPackageResult)
	_, n_euiccpackageresult, _, tlvErr_euiccpackageresult := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccpackageresult != nil {
		return fmt.Errorf("decoding euiccPackageResult: %w", tlvErr_euiccpackageresult)
	}
	if unmErr := v.EuiccPackageResult.UnmarshalBER(content[offset : offset+n_euiccpackageresult]); unmErr != nil {
		return fmt.Errorf("decoding euiccPackageResult: %w", unmErr)
	}
	offset += n_euiccpackageresult
	// Decode notificationList
	if offset >= len(content) {
		return fmt.Errorf("missing required field notificationList")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for notificationList, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	v.NotificationListIndef_ = false
	_, n_notificationlist, rawVal_notificationlist, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding notificationList: %w", err)
	}
	reconstructed_notificationlist := ber.EncodeSequence(rawVal_notificationlist)
	dec_notificationlist, unmErr := UnmarshalBERPendingNotificationList(reconstructed_notificationlist)
	if unmErr != nil {
		return fmt.Errorf("decoding notificationList: %w", unmErr)
	}
	v.NotificationList = dec_notificationlist
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.NotificationListIndef_ = true
		}
	}
	offset += n_notificationlist
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TransferEimPackageResponseEPRAndNotifications", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EimPackageReceivedWithCidCorrelationId to BER format.
func (v *EimPackageReceivedWithCidCorrelationId) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EimPackageReceivedWithCidCorrelationIdChoiceEimTransactionId:
		enc_0 := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case EimPackageReceivedWithCidCorrelationIdChoiceEidValue:
		enc_1 := ber.EncodeOctetString([]byte(*v.EidValue))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EimPackageReceivedWithCidCorrelationId", v.Choice)
	}
}

// MarshalDER encodes EimPackageReceivedWithCidCorrelationId to DER format.
func (v *EimPackageReceivedWithCidCorrelationId) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes EimPackageReceivedWithCidCorrelationId from BER/DER format.
func (v *EimPackageReceivedWithCidCorrelationId) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for EimPackageReceivedWithCidCorrelationId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EimPackageReceivedWithCidCorrelationId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding EimPackageReceivedWithCidCorrelationId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EimPackageReceivedWithCidCorrelationId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = EimPackageReceivedWithCidCorrelationIdChoiceEimTransactionId
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding eimTransactionId: %w", tlvErr)
		}
		tmp := sgp22.TransactionId(rawVal)
		v.EimTransactionId = &tmp
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 26 {
		v.Choice = EimPackageReceivedWithCidCorrelationIdChoiceEidValue
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding eidValue: %w", tlvErr)
		}
		tmp := sgp22.Octet16(rawVal)
		v.EidValue = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for EimPackageReceivedWithCidCorrelationId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EimPackageErrorWithCidCorrelationId to BER format.
func (v *EimPackageErrorWithCidCorrelationId) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EimPackageErrorWithCidCorrelationIdChoiceEimTransactionId:
		enc_0 := ber.EncodeOctetString([]byte(*v.EimTransactionId))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case EimPackageErrorWithCidCorrelationIdChoiceEidValue:
		enc_1 := ber.EncodeOctetString([]byte(*v.EidValue))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EimPackageErrorWithCidCorrelationId", v.Choice)
	}
}

// MarshalDER encodes EimPackageErrorWithCidCorrelationId to DER format.
func (v *EimPackageErrorWithCidCorrelationId) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes EimPackageErrorWithCidCorrelationId from BER/DER format.
func (v *EimPackageErrorWithCidCorrelationId) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for EimPackageErrorWithCidCorrelationId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EimPackageErrorWithCidCorrelationId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding EimPackageErrorWithCidCorrelationId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EimPackageErrorWithCidCorrelationId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = EimPackageErrorWithCidCorrelationIdChoiceEimTransactionId
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding eimTransactionId: %w", tlvErr)
		}
		tmp := sgp22.TransactionId(rawVal)
		v.EimTransactionId = &tmp
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 26 {
		v.Choice = EimPackageErrorWithCidCorrelationIdChoiceEidValue
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding eidValue: %w", tlvErr)
		}
		tmp := sgp22.Octet16(rawVal)
		v.EidValue = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for EimPackageErrorWithCidCorrelationId CHOICE", peekTag)
	}
	return nil
}
