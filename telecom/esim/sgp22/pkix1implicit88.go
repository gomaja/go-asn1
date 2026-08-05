// Code generated from ASN.1 module "PKIX1Implicit88". DO NOT EDIT.

package sgp22

import (
	"fmt"
	"math/big"
	"time"

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

// IdCe returns the OID value for id-ce.
func IdCe() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29} }

// IdCeAuthorityKeyIdentifier returns the OID value for id-ce-authorityKeyIdentifier.
func IdCeAuthorityKeyIdentifier() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 5, 29, 35}
}

// IdCeSubjectKeyIdentifier returns the OID value for id-ce-subjectKeyIdentifier.
func IdCeSubjectKeyIdentifier() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 5, 29, 14}
}

// IdCeKeyUsage returns the OID value for id-ce-keyUsage.
func IdCeKeyUsage() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 15} }

// IdCePrivateKeyUsagePeriod returns the OID value for id-ce-privateKeyUsagePeriod.
func IdCePrivateKeyUsagePeriod() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 5, 29, 16}
}

// IdCeCertificatePolicies returns the OID value for id-ce-certificatePolicies.
func IdCeCertificatePolicies() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 5, 29, 32}
}

// AnyPolicy returns the OID value for anyPolicy.
func AnyPolicy() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 32, 0} }

// IdCePolicyMappings returns the OID value for id-ce-policyMappings.
func IdCePolicyMappings() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 33} }

// IdCeSubjectAltName returns the OID value for id-ce-subjectAltName.
func IdCeSubjectAltName() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 17} }

// IdCeIssuerAltName returns the OID value for id-ce-issuerAltName.
func IdCeIssuerAltName() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 18} }

// IdCeSubjectDirectoryAttributes returns the OID value for id-ce-subjectDirectoryAttributes.
func IdCeSubjectDirectoryAttributes() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 5, 29, 9}
}

// IdCeBasicConstraints returns the OID value for id-ce-basicConstraints.
func IdCeBasicConstraints() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 19} }

// IdCeNameConstraints returns the OID value for id-ce-nameConstraints.
func IdCeNameConstraints() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 30} }

// IdCePolicyConstraints returns the OID value for id-ce-policyConstraints.
func IdCePolicyConstraints() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 36} }

// IdCeCRLDistributionPoints returns the OID value for id-ce-cRLDistributionPoints.
func IdCeCRLDistributionPoints() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 5, 29, 31}
}

// IdCeExtKeyUsage returns the OID value for id-ce-extKeyUsage.
func IdCeExtKeyUsage() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 37} }

// AnyExtendedKeyUsage returns the OID value for anyExtendedKeyUsage.
func AnyExtendedKeyUsage() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 37, 0} }

// IdKpServerAuth returns the OID value for id-kp-serverAuth.
func IdKpServerAuth() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
}

// IdKpClientAuth returns the OID value for id-kp-clientAuth.
func IdKpClientAuth() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
}

// IdKpCodeSigning returns the OID value for id-kp-codeSigning.
func IdKpCodeSigning() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
}

// IdKpEmailProtection returns the OID value for id-kp-emailProtection.
func IdKpEmailProtection() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
}

// IdKpTimeStamping returns the OID value for id-kp-timeStamping.
func IdKpTimeStamping() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
}

// IdKpOCSPSigning returns the OID value for id-kp-OCSPSigning.
func IdKpOCSPSigning() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
}

// IdCeInhibitAnyPolicy returns the OID value for id-ce-inhibitAnyPolicy.
func IdCeInhibitAnyPolicy() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 54} }

// IdCeFreshestCRL returns the OID value for id-ce-freshestCRL.
func IdCeFreshestCRL() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 46} }

// IdPeAuthorityInfoAccess returns the OID value for id-pe-authorityInfoAccess.
func IdPeAuthorityInfoAccess() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
}

// IdPeSubjectInfoAccess returns the OID value for id-pe-subjectInfoAccess.
func IdPeSubjectInfoAccess() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}
}

// IdCeCRLNumber returns the OID value for id-ce-cRLNumber.
func IdCeCRLNumber() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 20} }

// IdCeIssuingDistributionPoint returns the OID value for id-ce-issuingDistributionPoint.
func IdCeIssuingDistributionPoint() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 5, 29, 28}
}

// IdCeDeltaCRLIndicator returns the OID value for id-ce-deltaCRLIndicator.
func IdCeDeltaCRLIndicator() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 27} }

// IdCeCRLReasons returns the OID value for id-ce-cRLReasons.
func IdCeCRLReasons() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 21} }

// IdCeCertificateIssuer returns the OID value for id-ce-certificateIssuer.
func IdCeCertificateIssuer() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 29} }

// IdCeHoldInstructionCode returns the OID value for id-ce-holdInstructionCode.
func IdCeHoldInstructionCode() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 5, 29, 23}
}

// HoldInstruction returns the OID value for holdInstruction.
func HoldInstruction() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 2, 840, 10040, 2} }

// IdHoldinstructionNone returns the OID value for id-holdinstruction-none.
func IdHoldinstructionNone() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 2, 840, 10040, 2, 1}
}

// IdHoldinstructionCallissuer returns the OID value for id-holdinstruction-callissuer.
func IdHoldinstructionCallissuer() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 2, 840, 10040, 2, 2}
}

// IdHoldinstructionReject returns the OID value for id-holdinstruction-reject.
func IdHoldinstructionReject() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 2, 840, 10040, 2, 3}
}

// IdCeInvalidityDate returns the OID value for id-ce-invalidityDate.
func IdCeInvalidityDate() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 29, 24} }

// AuthorityKeyIdentifier represents the ASN.1 type AuthorityKeyIdentifier (SEQUENCE).
type AuthorityKeyIdentifier struct {
	KeyIdentifier             *KeyIdentifier          `asn1:"tag:0,context,implicit,optional" json:"KeyIdentifier,omitempty"`
	AuthorityCertIssuer       GeneralNames            `asn1:"tag:1,context,implicit,optional" json:"AuthorityCertIssuer,omitempty"`
	AuthorityCertIssuerIndef_ bool                    `asn1:"-" json:"-"`
	AuthorityCertSerialNumber CertificateSerialNumber `asn1:"tag:2,context,implicit,optional" json:"AuthorityCertSerialNumber,omitempty"`
}

// KeyIdentifier represents the ASN.1 type KeyIdentifier (OCTET_STRING).
type KeyIdentifier = []byte

// SubjectKeyIdentifier represents the ASN.1 type SubjectKeyIdentifier (OCTET_STRING).
type SubjectKeyIdentifier = KeyIdentifier

// KeyUsage represents the ASN.1 type KeyUsage (BIT_STRING).
type KeyUsage = runtime.BitString

// PrivateKeyUsagePeriod represents the ASN.1 type PrivateKeyUsagePeriod (SEQUENCE).
type PrivateKeyUsagePeriod struct {
	NotBefore *time.Time `asn1:"tag:0,context,implicit,optional" json:"NotBefore,omitempty"`
	NotAfter  *time.Time `asn1:"tag:1,context,implicit,optional" json:"NotAfter,omitempty"`
}

// CertificatePolicies represents the ASN.1 type CertificatePolicies (SEQUENCE_OF).
type CertificatePolicies = []PolicyInformation

// PolicyInformation represents the ASN.1 type PolicyInformation (SEQUENCE).
type PolicyInformation struct {
	PolicyIdentifier       CertPolicyId                      `asn1:""`
	PolicyQualifiers       PolicyInformationPolicyQualifiers `asn1:",optional" json:"PolicyQualifiers,omitempty"`
	PolicyQualifiersIndef_ bool                              `asn1:"-" json:"-"`
}

// CertPolicyId represents the ASN.1 type CertPolicyId (OBJECT_IDENTIFIER).
type CertPolicyId = runtime.ObjectIdentifier

// PolicyQualifierInfo represents the ASN.1 type PolicyQualifierInfo (SEQUENCE).
type PolicyQualifierInfo struct {
	PolicyQualifierId PolicyQualifierId `asn1:""`
	Qualifier         runtime.RawValue  `asn1:""`
}

// PolicyQualifierId represents the ASN.1 type PolicyQualifierId (OBJECT_IDENTIFIER).
type PolicyQualifierId = runtime.ObjectIdentifier

// CPSuri represents the ASN.1 type CPSuri (IA5String).
type CPSuri = string

// UserNotice represents the ASN.1 type UserNotice (SEQUENCE).
type UserNotice struct {
	NoticeRef    *NoticeReference `asn1:",optional" json:"NoticeRef,omitempty"`
	ExplicitText *DisplayText     `asn1:",optional" json:"ExplicitText,omitempty"`
}

// NoticeReference represents the ASN.1 type NoticeReference (SEQUENCE).
type NoticeReference struct {
	Organization        DisplayText                  `asn1:""`
	NoticeNumbers       NoticeReferenceNoticeNumbers `asn1:""`
	NoticeNumbersIndef_ bool                         `asn1:"-" json:"-"`
}

// DisplayText choice constants.
const (
	DisplayTextChoiceIa5String     = 1
	DisplayTextChoiceVisibleString = 2
	DisplayTextChoiceBmpString     = 3
	DisplayTextChoiceUtf8String    = 4
)

// DisplayText represents the ASN.1 CHOICE type DisplayText.
type DisplayText struct {
	Choice        int
	Ia5String     *string `json:"Ia5String,omitempty"`
	VisibleString *string `json:"VisibleString,omitempty"`
	BmpString     *string `json:"BmpString,omitempty"`
	Utf8String    *string `json:"Utf8String,omitempty"`
}

// NewDisplayTextIa5String creates a DisplayText with the ia5String alternative.
func NewDisplayTextIa5String(v string) DisplayText {
	return DisplayText{
		Choice:    DisplayTextChoiceIa5String,
		Ia5String: &v,
	}
}

// NewDisplayTextVisibleString creates a DisplayText with the visibleString alternative.
func NewDisplayTextVisibleString(v string) DisplayText {
	return DisplayText{
		Choice:        DisplayTextChoiceVisibleString,
		VisibleString: &v,
	}
}

// NewDisplayTextBmpString creates a DisplayText with the bmpString alternative.
func NewDisplayTextBmpString(v string) DisplayText {
	return DisplayText{
		Choice:    DisplayTextChoiceBmpString,
		BmpString: &v,
	}
}

// NewDisplayTextUtf8String creates a DisplayText with the utf8String alternative.
func NewDisplayTextUtf8String(v string) DisplayText {
	return DisplayText{
		Choice:     DisplayTextChoiceUtf8String,
		Utf8String: &v,
	}
}

// PolicyMappings represents the ASN.1 type PolicyMappings (SEQUENCE_OF).
type PolicyMappings = []PolicyMappingsElem

// SubjectAltName represents the ASN.1 type SubjectAltName (SEQUENCE_OF).
type SubjectAltName = GeneralNames

// GeneralNames represents the ASN.1 type GeneralNames (SEQUENCE_OF).
type GeneralNames = []GeneralName

// GeneralName choice constants.
const (
	GeneralNameChoiceOtherName                 = 1
	GeneralNameChoiceRfc822Name                = 2
	GeneralNameChoiceDNSName                   = 3
	GeneralNameChoiceX400Address               = 4
	GeneralNameChoiceDirectoryName             = 5
	GeneralNameChoiceEdiPartyName              = 6
	GeneralNameChoiceUniformResourceIdentifier = 7
	GeneralNameChoiceIPAddress                 = 8
	GeneralNameChoiceRegisteredID              = 9
)

// GeneralName represents the ASN.1 CHOICE type GeneralName.
type GeneralName struct {
	Choice                    int
	OtherName                 *AnotherName             `json:"OtherName,omitempty"`
	Rfc822Name                *string                  `json:"Rfc822Name,omitempty"`
	DNSName                   *string                  `json:"DNSName,omitempty"`
	X400Address               *ORAddress               `json:"X400Address,omitempty"`
	DirectoryName             *Name                    `json:"DirectoryName,omitempty"`
	EdiPartyName              *EDIPartyName            `json:"EdiPartyName,omitempty"`
	UniformResourceIdentifier *string                  `json:"UniformResourceIdentifier,omitempty"`
	IPAddress                 []byte                   `json:"IPAddress,omitempty"`
	RegisteredID              runtime.ObjectIdentifier `json:"RegisteredID,omitempty"`
}

// NewGeneralNameOtherName creates a GeneralName with the otherName alternative.
func NewGeneralNameOtherName(v AnotherName) GeneralName {
	return GeneralName{
		Choice:    GeneralNameChoiceOtherName,
		OtherName: &v,
	}
}

// NewGeneralNameRfc822Name creates a GeneralName with the rfc822Name alternative.
func NewGeneralNameRfc822Name(v string) GeneralName {
	return GeneralName{
		Choice:     GeneralNameChoiceRfc822Name,
		Rfc822Name: &v,
	}
}

// NewGeneralNameDNSName creates a GeneralName with the dNSName alternative.
func NewGeneralNameDNSName(v string) GeneralName {
	return GeneralName{
		Choice:  GeneralNameChoiceDNSName,
		DNSName: &v,
	}
}

// NewGeneralNameX400Address creates a GeneralName with the x400Address alternative.
func NewGeneralNameX400Address(v ORAddress) GeneralName {
	return GeneralName{
		Choice:      GeneralNameChoiceX400Address,
		X400Address: &v,
	}
}

// NewGeneralNameDirectoryName creates a GeneralName with the directoryName alternative.
func NewGeneralNameDirectoryName(v Name) GeneralName {
	return GeneralName{
		Choice:        GeneralNameChoiceDirectoryName,
		DirectoryName: &v,
	}
}

// NewGeneralNameEdiPartyName creates a GeneralName with the ediPartyName alternative.
func NewGeneralNameEdiPartyName(v EDIPartyName) GeneralName {
	return GeneralName{
		Choice:       GeneralNameChoiceEdiPartyName,
		EdiPartyName: &v,
	}
}

// NewGeneralNameUniformResourceIdentifier creates a GeneralName with the uniformResourceIdentifier alternative.
func NewGeneralNameUniformResourceIdentifier(v string) GeneralName {
	return GeneralName{
		Choice:                    GeneralNameChoiceUniformResourceIdentifier,
		UniformResourceIdentifier: &v,
	}
}

// NewGeneralNameIPAddress creates a GeneralName with the iPAddress alternative.
func NewGeneralNameIPAddress(v []byte) GeneralName {
	return GeneralName{
		Choice:    GeneralNameChoiceIPAddress,
		IPAddress: v,
	}
}

// NewGeneralNameRegisteredID creates a GeneralName with the registeredID alternative.
func NewGeneralNameRegisteredID(v runtime.ObjectIdentifier) GeneralName {
	return GeneralName{
		Choice:       GeneralNameChoiceRegisteredID,
		RegisteredID: v,
	}
}

// AnotherName represents the ASN.1 type AnotherName (SEQUENCE).
type AnotherName struct {
	TypeId runtime.ObjectIdentifier `asn1:""`
	Value  runtime.RawValue         `asn1:"tag:0,context,explicit"`
}

// EDIPartyName represents the ASN.1 type EDIPartyName (SEQUENCE).
type EDIPartyName struct {
	NameAssigner *DirectoryString `asn1:"tag:0,context,explicit,optional" json:"NameAssigner,omitempty"`
	PartyName    DirectoryString  `asn1:"tag:1,context,explicit"`
}

// IssuerAltName represents the ASN.1 type IssuerAltName (SEQUENCE_OF).
type IssuerAltName = GeneralNames

// SubjectDirectoryAttributes represents the ASN.1 type SubjectDirectoryAttributes (SEQUENCE_OF).
type SubjectDirectoryAttributes = []Attribute

// BasicConstraints represents the ASN.1 type BasicConstraints (SEQUENCE).
type BasicConstraints struct {
	CA                *bool    `asn1:",optional" json:"CA,omitempty"`
	CARaw_            byte     `asn1:"-" json:"-"`
	PathLenConstraint *big.Int `asn1:",optional" json:"PathLenConstraint,omitempty"`
}

// NameConstraints represents the ASN.1 type NameConstraints (SEQUENCE).
type NameConstraints struct {
	PermittedSubtrees       GeneralSubtrees `asn1:"tag:0,context,implicit,optional" json:"PermittedSubtrees,omitempty"`
	PermittedSubtreesIndef_ bool            `asn1:"-" json:"-"`
	ExcludedSubtrees        GeneralSubtrees `asn1:"tag:1,context,implicit,optional" json:"ExcludedSubtrees,omitempty"`
	ExcludedSubtreesIndef_  bool            `asn1:"-" json:"-"`
}

// GeneralSubtrees represents the ASN.1 type GeneralSubtrees (SEQUENCE_OF).
type GeneralSubtrees = []GeneralSubtree

// GeneralSubtree represents the ASN.1 type GeneralSubtree (SEQUENCE).
type GeneralSubtree struct {
	Base    GeneralName  `asn1:""`
	Minimum BaseDistance `asn1:"tag:0,context,implicit,optional" json:"Minimum,omitempty"`
	Maximum BaseDistance `asn1:"tag:1,context,implicit,optional" json:"Maximum,omitempty"`
}

// BaseDistance represents the ASN.1 type BaseDistance (INTEGER).
type BaseDistance = *big.Int

// PolicyConstraints represents the ASN.1 type PolicyConstraints (SEQUENCE).
type PolicyConstraints struct {
	RequireExplicitPolicy SkipCerts `asn1:"tag:0,context,implicit,optional" json:"RequireExplicitPolicy,omitempty"`
	InhibitPolicyMapping  SkipCerts `asn1:"tag:1,context,implicit,optional" json:"InhibitPolicyMapping,omitempty"`
}

// SkipCerts represents the ASN.1 type SkipCerts (INTEGER).
type SkipCerts = *big.Int

// CRLDistributionPoints represents the ASN.1 type CRLDistributionPoints (SEQUENCE_OF).
type CRLDistributionPoints = []DistributionPoint

// DistributionPoint represents the ASN.1 type DistributionPoint (SEQUENCE).
type DistributionPoint struct {
	DistributionPoint *DistributionPointName `asn1:"tag:0,context,explicit,optional" json:"DistributionPoint,omitempty"`
	Reasons           *ReasonFlags           `asn1:"tag:1,context,implicit,optional" json:"Reasons,omitempty"`
	CRLIssuer         GeneralNames           `asn1:"tag:2,context,implicit,optional" json:"CRLIssuer,omitempty"`
	CRLIssuerIndef_   bool                   `asn1:"-" json:"-"`
}

// DistributionPointName choice constants.
const (
	DistributionPointNameChoiceFullName                = 1
	DistributionPointNameChoiceNameRelativeToCRLIssuer = 2
)

// DistributionPointName represents the ASN.1 CHOICE type DistributionPointName.
type DistributionPointName struct {
	Choice                  int
	FullName                GeneralNames              `json:"FullName,omitempty"`
	NameRelativeToCRLIssuer RelativeDistinguishedName `json:"NameRelativeToCRLIssuer,omitempty"`
}

// NewDistributionPointNameFullName creates a DistributionPointName with the fullName alternative.
func NewDistributionPointNameFullName(v GeneralNames) DistributionPointName {
	return DistributionPointName{
		Choice:   DistributionPointNameChoiceFullName,
		FullName: v,
	}
}

// NewDistributionPointNameNameRelativeToCRLIssuer creates a DistributionPointName with the nameRelativeToCRLIssuer alternative.
func NewDistributionPointNameNameRelativeToCRLIssuer(v RelativeDistinguishedName) DistributionPointName {
	return DistributionPointName{
		Choice:                  DistributionPointNameChoiceNameRelativeToCRLIssuer,
		NameRelativeToCRLIssuer: v,
	}
}

// ReasonFlags represents the ASN.1 type ReasonFlags (BIT_STRING).
type ReasonFlags = runtime.BitString

// ExtKeyUsageSyntax represents the ASN.1 type ExtKeyUsageSyntax (SEQUENCE_OF).
type ExtKeyUsageSyntax = []KeyPurposeId

// KeyPurposeId represents the ASN.1 type KeyPurposeId (OBJECT_IDENTIFIER).
type KeyPurposeId = runtime.ObjectIdentifier

// InhibitAnyPolicy represents the ASN.1 type InhibitAnyPolicy (INTEGER).
type InhibitAnyPolicy = SkipCerts

// FreshestCRL represents the ASN.1 type FreshestCRL (SEQUENCE_OF).
type FreshestCRL = CRLDistributionPoints

// AuthorityInfoAccessSyntax represents the ASN.1 type AuthorityInfoAccessSyntax (SEQUENCE_OF).
type AuthorityInfoAccessSyntax = []AccessDescription

// AccessDescription represents the ASN.1 type AccessDescription (SEQUENCE).
type AccessDescription struct {
	AccessMethod   runtime.ObjectIdentifier `asn1:""`
	AccessLocation GeneralName              `asn1:""`
}

// SubjectInfoAccessSyntax represents the ASN.1 type SubjectInfoAccessSyntax (SEQUENCE_OF).
type SubjectInfoAccessSyntax = []AccessDescription

// CRLNumber represents the ASN.1 type CRLNumber (INTEGER).
type CRLNumber = *big.Int

// IssuingDistributionPoint represents the ASN.1 type IssuingDistributionPoint (SEQUENCE).
type IssuingDistributionPoint struct {
	DistributionPoint              *DistributionPointName `asn1:"tag:0,context,explicit,optional" json:"DistributionPoint,omitempty"`
	OnlyContainsUserCerts          *bool                  `asn1:"tag:1,context,implicit,optional" json:"OnlyContainsUserCerts,omitempty"`
	OnlyContainsUserCertsRaw_      byte                   `asn1:"-" json:"-"`
	OnlyContainsCACerts            *bool                  `asn1:"tag:2,context,implicit,optional" json:"OnlyContainsCACerts,omitempty"`
	OnlyContainsCACertsRaw_        byte                   `asn1:"-" json:"-"`
	OnlySomeReasons                *ReasonFlags           `asn1:"tag:3,context,implicit,optional" json:"OnlySomeReasons,omitempty"`
	IndirectCRL                    *bool                  `asn1:"tag:4,context,implicit,optional" json:"IndirectCRL,omitempty"`
	IndirectCRLRaw_                byte                   `asn1:"-" json:"-"`
	OnlyContainsAttributeCerts     *bool                  `asn1:"tag:5,context,implicit,optional" json:"OnlyContainsAttributeCerts,omitempty"`
	OnlyContainsAttributeCertsRaw_ byte                   `asn1:"-" json:"-"`
}

// BaseCRLNumber represents the ASN.1 type BaseCRLNumber (INTEGER).
type BaseCRLNumber = CRLNumber

// CRLReason represents the ASN.1 ENUMERATED type CRLReason.
type CRLReason int64

const (
	CRLReasonUnspecified          CRLReason = 0
	CRLReasonKeyCompromise        CRLReason = 1
	CRLReasonCACompromise         CRLReason = 2
	CRLReasonAffiliationChanged   CRLReason = 3
	CRLReasonSuperseded           CRLReason = 4
	CRLReasonCessationOfOperation CRLReason = 5
	CRLReasonCertificateHold      CRLReason = 6
	CRLReasonRemoveFromCRL        CRLReason = 8
	CRLReasonPrivilegeWithdrawn   CRLReason = 9
	CRLReasonAACompromise         CRLReason = 10
)

func (v CRLReason) String() string {
	switch v {
	case CRLReasonUnspecified:
		return "unspecified"
	case CRLReasonKeyCompromise:
		return "keyCompromise"
	case CRLReasonCACompromise:
		return "cACompromise"
	case CRLReasonAffiliationChanged:
		return "affiliationChanged"
	case CRLReasonSuperseded:
		return "superseded"
	case CRLReasonCessationOfOperation:
		return "cessationOfOperation"
	case CRLReasonCertificateHold:
		return "certificateHold"
	case CRLReasonRemoveFromCRL:
		return "removeFromCRL"
	case CRLReasonPrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case CRLReasonAACompromise:
		return "aACompromise"
	default:
		return "unknown"
	}
}

// CertificateIssuer represents the ASN.1 type CertificateIssuer (SEQUENCE_OF).
type CertificateIssuer = GeneralNames

// HoldInstructionCode represents the ASN.1 type HoldInstructionCode (OBJECT_IDENTIFIER).
type HoldInstructionCode = runtime.ObjectIdentifier

// InvalidityDate represents the ASN.1 type InvalidityDate (GeneralizedTime).
type InvalidityDate = time.Time

// PolicyInformationPolicyQualifiers represents the ASN.1 type PolicyInformation-policyQualifiers (SEQUENCE_OF).
type PolicyInformationPolicyQualifiers = []PolicyQualifierInfo

// NoticeReferenceNoticeNumbers represents the ASN.1 type NoticeReference-noticeNumbers (SEQUENCE_OF).
type NoticeReferenceNoticeNumbers = []*big.Int

// PolicyMappingsElem represents the ASN.1 type PolicyMappings-Elem (SEQUENCE).
type PolicyMappingsElem struct {
	IssuerDomainPolicy  CertPolicyId `asn1:""`
	SubjectDomainPolicy CertPolicyId `asn1:""`
}

// MarshalBER encodes AuthorityKeyIdentifier to BER format.
func (v *AuthorityKeyIdentifier) MarshalBER() ([]byte, error) {
	var children []byte
	if v.KeyIdentifier != nil {
		enc_keyidentifier := ber.EncodeOctetString([]byte(*v.KeyIdentifier))
		enc_keyidentifier = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_keyidentifier)
		children = append(children, enc_keyidentifier...)
	}
	if v.AuthorityCertIssuer != nil {
		enc_authoritycertissuer, err := MarshalBERGeneralNames(v.AuthorityCertIssuer)
		if err != nil {
			return nil, fmt.Errorf("encoding authorityCertIssuer: %w", err)
		}
		if v.AuthorityCertIssuerIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_authoritycertissuer)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_authoritycertissuer = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
		} else {
			enc_authoritycertissuer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_authoritycertissuer)
		}
		children = append(children, enc_authoritycertissuer...)
	}
	if v.AuthorityCertSerialNumber != nil {
		enc_authoritycertserialnumber := ber.EncodeBigInt(v.AuthorityCertSerialNumber)
		enc_authoritycertserialnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_authoritycertserialnumber)
		children = append(children, enc_authoritycertserialnumber...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AuthorityKeyIdentifier to DER format.
func (v *AuthorityKeyIdentifier) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.AuthorityCertIssuerIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthorityKeyIdentifier from BER/DER format.
func (v *AuthorityKeyIdentifier) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthorityKeyIdentifier SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthorityKeyIdentifier", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode keyIdentifier
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_keyidentifier, rawVal_keyidentifier, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding keyIdentifier: %w", err)
				}
				tmp_keyidentifier := KeyIdentifier(rawVal_keyidentifier)
				v.KeyIdentifier = &tmp_keyidentifier
				offset += n_keyidentifier
			}
		}
	}
	// Decode authorityCertIssuer
	v.AuthorityCertIssuerIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_authoritycertissuer, rawVal_authoritycertissuer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding authorityCertIssuer: %w", err)
				}
				reconstructed_authoritycertissuer := ber.EncodeSequence(rawVal_authoritycertissuer)
				dec_authoritycertissuer, unmErr := UnmarshalBERGeneralNames(reconstructed_authoritycertissuer)
				if unmErr != nil {
					return fmt.Errorf("decoding authorityCertIssuer: %w", unmErr)
				}
				v.AuthorityCertIssuer = dec_authoritycertissuer
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.AuthorityCertIssuerIndef_ = true
					}
				}
				offset += n_authoritycertissuer
			}
		}
	}
	// Decode authorityCertSerialNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_authoritycertserialnumber, rawVal_authoritycertserialnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding authorityCertSerialNumber: %w", err)
				}
				decVal_authoritycertserialnumber, intErr := ber.DecodeBigIntValue(rawVal_authoritycertserialnumber)
				if intErr != nil {
					return fmt.Errorf("decoding authorityCertSerialNumber: %w", intErr)
				}
				v.AuthorityCertSerialNumber = decVal_authoritycertserialnumber
				offset += n_authoritycertserialnumber
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AuthorityKeyIdentifier", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PrivateKeyUsagePeriod to BER format.
func (v *PrivateKeyUsagePeriod) MarshalBER() ([]byte, error) {
	var children []byte
	if v.NotBefore != nil {
		enc_notbefore := ber.EncodeGeneralizedTime(*v.NotBefore)
		enc_notbefore = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_notbefore)
		children = append(children, enc_notbefore...)
	}
	if v.NotAfter != nil {
		enc_notafter := ber.EncodeGeneralizedTime(*v.NotAfter)
		enc_notafter = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_notafter)
		children = append(children, enc_notafter...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PrivateKeyUsagePeriod to DER format.
func (v *PrivateKeyUsagePeriod) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PrivateKeyUsagePeriod from BER/DER format.
func (v *PrivateKeyUsagePeriod) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PrivateKeyUsagePeriod SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrivateKeyUsagePeriod", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode notBefore
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_notbefore, rawVal_notbefore, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding notBefore: %w", err)
				}
				decVal_notbefore, timeErr := ber.DecodeGeneralizedTimeValue(rawVal_notbefore)
				if timeErr != nil {
					return fmt.Errorf("decoding notBefore: %w", timeErr)
				}
				v.NotBefore = &decVal_notbefore
				offset += n_notbefore
			}
		}
	}
	// Decode notAfter
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_notafter, rawVal_notafter, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding notAfter: %w", err)
				}
				decVal_notafter, timeErr := ber.DecodeGeneralizedTimeValue(rawVal_notafter)
				if timeErr != nil {
					return fmt.Errorf("decoding notAfter: %w", timeErr)
				}
				v.NotAfter = &decVal_notafter
				offset += n_notafter
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PrivateKeyUsagePeriod", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERCertificatePolicies encodes a CertificatePolicies list to BER.
func MarshalBERCertificatePolicies(list CertificatePolicies) ([]byte, error) {
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

// UnmarshalBERCertificatePolicies decodes a CertificatePolicies list from BER.
func UnmarshalBERCertificatePolicies(data []byte) (CertificatePolicies, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding CertificatePolicies: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CertificatePolicies", Cause: ber.ErrExtraData}
	}
	var result CertificatePolicies
	offset := 0
	for offset < len(content) {
		var elem PolicyInformation
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

// MarshalBER encodes PolicyInformation to BER format.
func (v *PolicyInformation) MarshalBER() ([]byte, error) {
	var children []byte
	enc_policyidentifier := ber.EncodeObjectIdentifier([]uint64(v.PolicyIdentifier))
	children = append(children, enc_policyidentifier...)
	if v.PolicyQualifiers != nil {
		enc_policyqualifiers, err := MarshalBERPolicyInformationPolicyQualifiers(v.PolicyQualifiers)
		if err != nil {
			return nil, fmt.Errorf("encoding policyQualifiers: %w", err)
		}
		children = append(children, enc_policyqualifiers...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PolicyInformation to DER format.
func (v *PolicyInformation) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.PolicyQualifiersIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes PolicyInformation from BER/DER format.
func (v *PolicyInformation) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PolicyInformation SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PolicyInformation", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode policyIdentifier
	if offset >= len(content) {
		return fmt.Errorf("missing required field policyIdentifier")
	}
	val_policyidentifier, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding policyIdentifier: %w", err)
	}
	v.PolicyIdentifier = runtime.ObjectIdentifier(val_policyidentifier)
	offset += n
	// Decode policyQualifiers
	v.PolicyQualifiersIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (PolicyInformationPolicyQualifiers)
				_, n_policyqualifiers, _, tlvErr_policyqualifiers := ber.DecodeTLV(content[offset:])
				if tlvErr_policyqualifiers != nil {
					return fmt.Errorf("decoding policyQualifiers: %w", tlvErr_policyqualifiers)
				}
				tlv_policyqualifiers := content[offset : offset+n_policyqualifiers]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_policyqualifiers)
					if tagSz_ < len(tlv_policyqualifiers) && tlv_policyqualifiers[tagSz_] == 0x80 {
						v.PolicyQualifiersIndef_ = true
					}
				}
				dec_policyqualifiers, unmErr := UnmarshalBERPolicyInformationPolicyQualifiers(tlv_policyqualifiers)
				if unmErr != nil {
					return fmt.Errorf("decoding policyQualifiers: %w", unmErr)
				}
				v.PolicyQualifiers = dec_policyqualifiers
				offset += n_policyqualifiers
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PolicyInformation", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PolicyQualifierInfo to BER format.
func (v *PolicyQualifierInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_policyqualifierid := ber.EncodeObjectIdentifier([]uint64(v.PolicyQualifierId))
	children = append(children, enc_policyqualifierid...)
	enc_qualifier := v.Qualifier.Bytes
	children = append(children, enc_qualifier...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PolicyQualifierInfo to DER format.
func (v *PolicyQualifierInfo) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PolicyQualifierInfo from BER/DER format.
func (v *PolicyQualifierInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PolicyQualifierInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PolicyQualifierInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode policyQualifierId
	if offset >= len(content) {
		return fmt.Errorf("missing required field policyQualifierId")
	}
	val_policyqualifierid, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding policyQualifierId: %w", err)
	}
	v.PolicyQualifierId = runtime.ObjectIdentifier(val_policyqualifierid)
	offset += n
	// Decode qualifier
	if offset >= len(content) {
		return fmt.Errorf("missing required field qualifier")
	}
	_, n_qualifier, _, tlvErr_qualifier := ber.DecodeTLV(content[offset:])
	if tlvErr_qualifier != nil {
		return fmt.Errorf("decoding qualifier: %w", tlvErr_qualifier)
	}
	v.Qualifier = runtime.RawValue{Bytes: content[offset : offset+n_qualifier]}
	offset += n_qualifier
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PolicyQualifierInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes UserNotice to BER format.
func (v *UserNotice) MarshalBER() ([]byte, error) {
	var children []byte
	if v.NoticeRef != nil {
		enc_noticeref, err := v.NoticeRef.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding noticeRef: %w", err)
		}
		children = append(children, enc_noticeref...)
	}
	if v.ExplicitText != nil {
		enc_explicittext, err := v.ExplicitText.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding explicitText: %w", err)
		}
		children = append(children, enc_explicittext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes UserNotice to DER format.
func (v *UserNotice) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes UserNotice from BER/DER format.
func (v *UserNotice) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UserNotice SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UserNotice", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode noticeRef
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (NoticeReference)
				_, n_noticeref, _, tlvErr_noticeref := ber.DecodeTLV(content[offset:])
				if tlvErr_noticeref != nil {
					return fmt.Errorf("decoding noticeRef: %w", tlvErr_noticeref)
				}
				var dec_noticeref NoticeReference
				if unmErr := dec_noticeref.UnmarshalBER(content[offset : offset+n_noticeref]); unmErr != nil {
					return fmt.Errorf("decoding noticeRef: %w", unmErr)
				}
				v.NoticeRef = &dec_noticeref
				offset += n_noticeref
			}
		}
	}
	// Decode explicitText
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 22) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 26) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 30) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 12) {
				// Decode nested CHOICE (DisplayText)
				_, n_explicittext, _, tlvErr_explicittext := ber.DecodeTLV(content[offset:])
				if tlvErr_explicittext != nil {
					return fmt.Errorf("decoding explicitText: %w", tlvErr_explicittext)
				}
				var dec_explicittext DisplayText
				if unmErr := dec_explicittext.UnmarshalBER(content[offset : offset+n_explicittext]); unmErr != nil {
					return fmt.Errorf("decoding explicitText: %w", unmErr)
				}
				v.ExplicitText = &dec_explicittext
				offset += n_explicittext
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "UserNotice", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes NoticeReference to BER format.
func (v *NoticeReference) MarshalBER() ([]byte, error) {
	var children []byte
	enc_organization, err := v.Organization.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding organization: %w", err)
	}
	children = append(children, enc_organization...)
	enc_noticenumbers, err := MarshalBERNoticeReferenceNoticeNumbers(v.NoticeNumbers)
	if err != nil {
		return nil, fmt.Errorf("encoding noticeNumbers: %w", err)
	}
	children = append(children, enc_noticenumbers...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes NoticeReference to DER format.
func (v *NoticeReference) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.NoticeNumbersIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes NoticeReference from BER/DER format.
func (v *NoticeReference) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NoticeReference SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoticeReference", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode organization
	if offset >= len(content) {
		return fmt.Errorf("missing required field organization")
	}
	// Decode nested CHOICE (DisplayText)
	_, n_organization, _, tlvErr_organization := ber.DecodeTLV(content[offset:])
	if tlvErr_organization != nil {
		return fmt.Errorf("decoding organization: %w", tlvErr_organization)
	}
	if unmErr := v.Organization.UnmarshalBER(content[offset : offset+n_organization]); unmErr != nil {
		return fmt.Errorf("decoding organization: %w", unmErr)
	}
	offset += n_organization
	// Decode noticeNumbers
	if offset >= len(content) {
		return fmt.Errorf("missing required field noticeNumbers")
	}
	v.NoticeNumbersIndef_ = false
	// Decode nested SEQUENCE_OF (NoticeReferenceNoticeNumbers)
	_, n_noticenumbers, _, tlvErr_noticenumbers := ber.DecodeTLV(content[offset:])
	if tlvErr_noticenumbers != nil {
		return fmt.Errorf("decoding noticeNumbers: %w", tlvErr_noticenumbers)
	}
	tlv_noticenumbers := content[offset : offset+n_noticenumbers]
	{
		_, tagSz_, _ := ber.DecodeTag(tlv_noticenumbers)
		if tagSz_ < len(tlv_noticenumbers) && tlv_noticenumbers[tagSz_] == 0x80 {
			v.NoticeNumbersIndef_ = true
		}
	}
	dec_noticenumbers, unmErr := UnmarshalBERNoticeReferenceNoticeNumbers(tlv_noticenumbers)
	if unmErr != nil {
		return fmt.Errorf("decoding noticeNumbers: %w", unmErr)
	}
	v.NoticeNumbers = dec_noticenumbers
	offset += n_noticenumbers
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "NoticeReference", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes DisplayText to BER format.
func (v *DisplayText) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case DisplayTextChoiceIa5String:
		if v.Ia5String == nil {
			return nil, fmt.Errorf("choice DisplayText: ia5String is nil")
		}
		enc_0 := ber.EncodeStringTag(22, *v.Ia5String)
		return enc_0, nil
	case DisplayTextChoiceVisibleString:
		if v.VisibleString == nil {
			return nil, fmt.Errorf("choice DisplayText: visibleString is nil")
		}
		enc_1 := ber.EncodeStringTag(26, *v.VisibleString)
		return enc_1, nil
	case DisplayTextChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("choice DisplayText: bmpString is nil")
		}
		enc_2 := ber.EncodeStringTag(30, *v.BmpString)
		return enc_2, nil
	case DisplayTextChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("choice DisplayText: utf8String is nil")
		}
		enc_3 := ber.EncodeStringTag(12, *v.Utf8String)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DisplayText", v.Choice)
	}
}

// MarshalDER encodes DisplayText to DER format.
func (v *DisplayText) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes DisplayText from BER/DER format.
func (v *DisplayText) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for DisplayText CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DisplayText: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding DisplayText CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DisplayText", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 22 {
		v.Choice = DisplayTextChoiceIa5String
		decVal, _, strErr := ber.DecodeString(choiceData, 22)
		if strErr != nil {
			return fmt.Errorf("decoding ia5String: %w", strErr)
		}
		v.Ia5String = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 26 {
		v.Choice = DisplayTextChoiceVisibleString
		decVal, _, strErr := ber.DecodeString(choiceData, 26)
		if strErr != nil {
			return fmt.Errorf("decoding visibleString: %w", strErr)
		}
		v.VisibleString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = DisplayTextChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = DisplayTextChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for DisplayText CHOICE", peekTag)
	}
	return nil
}

// MarshalBERPolicyMappings encodes a PolicyMappings list to BER.
func MarshalBERPolicyMappings(list PolicyMappings) ([]byte, error) {
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

// UnmarshalBERPolicyMappings decodes a PolicyMappings list from BER.
func UnmarshalBERPolicyMappings(data []byte) (PolicyMappings, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding PolicyMappings: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PolicyMappings", Cause: ber.ErrExtraData}
	}
	var result PolicyMappings
	offset := 0
	for offset < len(content) {
		var elem PolicyMappingsElem
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

// MarshalBERGeneralNames encodes a GeneralNames list to BER.
func MarshalBERGeneralNames(list GeneralNames) ([]byte, error) {
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

// UnmarshalBERGeneralNames decodes a GeneralNames list from BER.
func UnmarshalBERGeneralNames(data []byte) (GeneralNames, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding GeneralNames: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "GeneralNames", Cause: ber.ErrExtraData}
	}
	var result GeneralNames
	offset := 0
	for offset < len(content) {
		var elem GeneralName
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

// MarshalBER encodes GeneralName to BER format.
func (v *GeneralName) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case GeneralNameChoiceOtherName:
		if v.OtherName == nil {
			return nil, fmt.Errorf("choice GeneralName: otherName is nil")
		}
		enc_0, err := v.OtherName.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding otherName: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case GeneralNameChoiceRfc822Name:
		if v.Rfc822Name == nil {
			return nil, fmt.Errorf("choice GeneralName: rfc822Name is nil")
		}
		enc_1 := ber.EncodeStringTag(22, *v.Rfc822Name)
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	case GeneralNameChoiceDNSName:
		if v.DNSName == nil {
			return nil, fmt.Errorf("choice GeneralName: dNSName is nil")
		}
		enc_2 := ber.EncodeStringTag(22, *v.DNSName)
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_2)
		return enc_2, nil
	case GeneralNameChoiceX400Address:
		if v.X400Address == nil {
			return nil, fmt.Errorf("choice GeneralName: x400Address is nil")
		}
		enc_3, err := v.X400Address.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding x400Address: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_3)
		return enc_3, nil
	case GeneralNameChoiceDirectoryName:
		if v.DirectoryName == nil {
			return nil, fmt.Errorf("choice GeneralName: directoryName is nil")
		}
		enc_4, err := v.DirectoryName.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding directoryName: %w", err)
		}
		enc_4 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 4, enc_4)
		return enc_4, nil
	case GeneralNameChoiceEdiPartyName:
		if v.EdiPartyName == nil {
			return nil, fmt.Errorf("choice GeneralName: ediPartyName is nil")
		}
		enc_5, err := v.EdiPartyName.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ediPartyName: %w", err)
		}
		enc_5 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_5)
		return enc_5, nil
	case GeneralNameChoiceUniformResourceIdentifier:
		if v.UniformResourceIdentifier == nil {
			return nil, fmt.Errorf("choice GeneralName: uniformResourceIdentifier is nil")
		}
		enc_6 := ber.EncodeStringTag(22, *v.UniformResourceIdentifier)
		enc_6 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_6)
		return enc_6, nil
	case GeneralNameChoiceIPAddress:
		enc_7 := ber.EncodeOctetString(v.IPAddress)
		enc_7 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_7)
		return enc_7, nil
	case GeneralNameChoiceRegisteredID:
		enc_8 := ber.EncodeObjectIdentifier([]uint64(v.RegisteredID))
		enc_8 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_8)
		return enc_8, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for GeneralName", v.Choice)
	}
}

// MarshalDER encodes GeneralName to DER format.
func (v *GeneralName) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case GeneralNameChoiceOtherName:
		if v.OtherName == nil {
			return nil, fmt.Errorf("choice GeneralName: otherName is nil")
		}
		enc_der_0, err := v.OtherName.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding otherName: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		return enc_der_0, nil
	case GeneralNameChoiceX400Address:
		if v.X400Address == nil {
			return nil, fmt.Errorf("choice GeneralName: x400Address is nil")
		}
		enc_der_3, err := v.X400Address.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding x400Address: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_der_3)
		return enc_der_3, nil
	case GeneralNameChoiceDirectoryName:
		if v.DirectoryName == nil {
			return nil, fmt.Errorf("choice GeneralName: directoryName is nil")
		}
		enc_der_4, err := v.DirectoryName.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding directoryName: %w", err)
		}
		enc_der_4 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_4)
		return enc_der_4, nil
	case GeneralNameChoiceEdiPartyName:
		if v.EdiPartyName == nil {
			return nil, fmt.Errorf("choice GeneralName: ediPartyName is nil")
		}
		enc_der_5, err := v.EdiPartyName.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ediPartyName: %w", err)
		}
		enc_der_5 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_der_5)
		return enc_der_5, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes GeneralName from BER/DER format.
func (v *GeneralName) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for GeneralName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for GeneralName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding GeneralName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "GeneralName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = GeneralNameChoiceOtherName
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding otherName: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AnotherName
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding otherName: %w", unmErr)
		}
		v.OtherName = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = GeneralNameChoiceRfc822Name
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding rfc822Name: %w", tlvErr)
		}
		decVal := ber.DecodeStringValue(rawVal)
		v.Rfc822Name = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = GeneralNameChoiceDNSName
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dNSName: %w", tlvErr)
		}
		decVal := ber.DecodeStringValue(rawVal)
		v.DNSName = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = GeneralNameChoiceX400Address
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding x400Address: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ORAddress
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding x400Address: %w", unmErr)
		}
		v.X400Address = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = GeneralNameChoiceDirectoryName
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding directoryName: %w", tlvErr)
		}
		var dec Name
		if unmErr := dec.UnmarshalBER(innerData); unmErr != nil {
			return fmt.Errorf("decoding directoryName: %w", unmErr)
		}
		v.DirectoryName = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
		v.Choice = GeneralNameChoiceEdiPartyName
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ediPartyName: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec EDIPartyName
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding ediPartyName: %w", unmErr)
		}
		v.EdiPartyName = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
		v.Choice = GeneralNameChoiceUniformResourceIdentifier
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding uniformResourceIdentifier: %w", tlvErr)
		}
		decVal := ber.DecodeStringValue(rawVal)
		v.UniformResourceIdentifier = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
		v.Choice = GeneralNameChoiceIPAddress
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding iPAddress: %w", tlvErr)
		}
		v.IPAddress = rawVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
		v.Choice = GeneralNameChoiceRegisteredID
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding registeredID: %w", tlvErr)
		}
		decVal, oidErr := ber.DecodeOIDValue(rawVal)
		if oidErr != nil {
			return fmt.Errorf("decoding registeredID: %w", oidErr)
		}
		v.RegisteredID = runtime.ObjectIdentifier(decVal)
	} else {
		return fmt.Errorf("unknown tag %s for GeneralName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AnotherName to BER format.
func (v *AnotherName) MarshalBER() ([]byte, error) {
	var children []byte
	enc_typeid := ber.EncodeObjectIdentifier([]uint64(v.TypeId))
	children = append(children, enc_typeid...)
	enc_value := v.Value.Bytes
	enc_value = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_value)
	children = append(children, enc_value...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AnotherName to DER format.
func (v *AnotherName) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AnotherName from BER/DER format.
func (v *AnotherName) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AnotherName SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AnotherName", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode type-id
	if offset >= len(content) {
		return fmt.Errorf("missing required field type-id")
	}
	val_typeid, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding type-id: %w", err)
	}
	v.TypeId = runtime.ObjectIdentifier(val_typeid)
	offset += n
	// Decode value
	if offset >= len(content) {
		return fmt.Errorf("missing required field value")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for value, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_value, innerData_value, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding value: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	v.Value = runtime.RawValue{Bytes: innerData_value}
	offset += n_value
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AnotherName", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EDIPartyName to BER format.
func (v *EDIPartyName) MarshalBER() ([]byte, error) {
	var children []byte
	if v.NameAssigner != nil {
		enc_nameassigner, err := v.NameAssigner.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding nameAssigner: %w", err)
		}
		enc_nameassigner = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_nameassigner)
		children = append(children, enc_nameassigner...)
	}
	enc_partyname, err := v.PartyName.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding partyName: %w", err)
	}
	enc_partyname = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_partyname)
	children = append(children, enc_partyname...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EDIPartyName to DER format.
func (v *EDIPartyName) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EDIPartyName from BER/DER format.
func (v *EDIPartyName) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EDIPartyName SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EDIPartyName", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode nameAssigner
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_nameassigner, innerData_nameassigner, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nameAssigner: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_nameassigner DirectoryString
				if unmErr := dec_nameassigner.UnmarshalBER(innerData_nameassigner); unmErr != nil {
					return fmt.Errorf("decoding nameAssigner: %w", unmErr)
				}
				v.NameAssigner = &dec_nameassigner
				offset += n_nameassigner
			}
		}
	}
	// Decode partyName
	if offset >= len(content) {
		return fmt.Errorf("missing required field partyName")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for partyName, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_partyname, innerData_partyname, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding partyName: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.PartyName.UnmarshalBER(innerData_partyname); unmErr != nil {
		return fmt.Errorf("decoding partyName: %w", unmErr)
	}
	offset += n_partyname
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EDIPartyName", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERSubjectDirectoryAttributes encodes a SubjectDirectoryAttributes list to BER.
func MarshalBERSubjectDirectoryAttributes(list SubjectDirectoryAttributes) ([]byte, error) {
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

// UnmarshalBERSubjectDirectoryAttributes decodes a SubjectDirectoryAttributes list from BER.
func UnmarshalBERSubjectDirectoryAttributes(data []byte) (SubjectDirectoryAttributes, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SubjectDirectoryAttributes: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SubjectDirectoryAttributes", Cause: ber.ErrExtraData}
	}
	var result SubjectDirectoryAttributes
	offset := 0
	for offset < len(content) {
		var elem Attribute
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

// MarshalBER encodes BasicConstraints to BER format.
func (v *BasicConstraints) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CA != nil {
		var enc_ca []byte
		if v.CARaw_ != 0 {
			enc_ca = ber.EncodeBooleanRaw(v.CARaw_)
		} else {
			enc_ca = ber.EncodeBoolean(*v.CA)
		}
		children = append(children, enc_ca...)
	}
	if v.PathLenConstraint != nil {
		enc_pathlenconstraint := ber.EncodeBigInt(v.PathLenConstraint)
		children = append(children, enc_pathlenconstraint...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes BasicConstraints to DER format.
func (v *BasicConstraints) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes BasicConstraints from BER/DER format.
func (v *BasicConstraints) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding BasicConstraints SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BasicConstraints", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cA
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 1 {
				val_ca, raw_ca, n, err := ber.DecodeBoolean(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cA: %w", err)
				}
				v.CA = &val_ca
				v.CARaw_ = raw_ca
				offset += n
			}
		}
	}
	// Decode pathLenConstraint
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				val_pathlenconstraint, n, err := ber.DecodeBigInt(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pathLenConstraint: %w", err)
				}
				v.PathLenConstraint = val_pathlenconstraint
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "BasicConstraints", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes NameConstraints to BER format.
func (v *NameConstraints) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PermittedSubtrees != nil {
		enc_permittedsubtrees, err := MarshalBERGeneralSubtrees(v.PermittedSubtrees)
		if err != nil {
			return nil, fmt.Errorf("encoding permittedSubtrees: %w", err)
		}
		if v.PermittedSubtreesIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_permittedsubtrees)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_permittedsubtrees = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
		} else {
			enc_permittedsubtrees = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_permittedsubtrees)
		}
		children = append(children, enc_permittedsubtrees...)
	}
	if v.ExcludedSubtrees != nil {
		enc_excludedsubtrees, err := MarshalBERGeneralSubtrees(v.ExcludedSubtrees)
		if err != nil {
			return nil, fmt.Errorf("encoding excludedSubtrees: %w", err)
		}
		if v.ExcludedSubtreesIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_excludedsubtrees)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_excludedsubtrees = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
		} else {
			enc_excludedsubtrees = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_excludedsubtrees)
		}
		children = append(children, enc_excludedsubtrees...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes NameConstraints to DER format.
func (v *NameConstraints) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.PermittedSubtreesIndef_ = false
	derValue.ExcludedSubtreesIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes NameConstraints from BER/DER format.
func (v *NameConstraints) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NameConstraints SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NameConstraints", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode permittedSubtrees
	v.PermittedSubtreesIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_permittedsubtrees, rawVal_permittedsubtrees, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding permittedSubtrees: %w", err)
				}
				reconstructed_permittedsubtrees := ber.EncodeSequence(rawVal_permittedsubtrees)
				dec_permittedsubtrees, unmErr := UnmarshalBERGeneralSubtrees(reconstructed_permittedsubtrees)
				if unmErr != nil {
					return fmt.Errorf("decoding permittedSubtrees: %w", unmErr)
				}
				v.PermittedSubtrees = dec_permittedsubtrees
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.PermittedSubtreesIndef_ = true
					}
				}
				offset += n_permittedsubtrees
			}
		}
	}
	// Decode excludedSubtrees
	v.ExcludedSubtreesIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_excludedsubtrees, rawVal_excludedsubtrees, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding excludedSubtrees: %w", err)
				}
				reconstructed_excludedsubtrees := ber.EncodeSequence(rawVal_excludedsubtrees)
				dec_excludedsubtrees, unmErr := UnmarshalBERGeneralSubtrees(reconstructed_excludedsubtrees)
				if unmErr != nil {
					return fmt.Errorf("decoding excludedSubtrees: %w", unmErr)
				}
				v.ExcludedSubtrees = dec_excludedsubtrees
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ExcludedSubtreesIndef_ = true
					}
				}
				offset += n_excludedsubtrees
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "NameConstraints", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERGeneralSubtrees encodes a GeneralSubtrees list to BER.
func MarshalBERGeneralSubtrees(list GeneralSubtrees) ([]byte, error) {
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

// UnmarshalBERGeneralSubtrees decodes a GeneralSubtrees list from BER.
func UnmarshalBERGeneralSubtrees(data []byte) (GeneralSubtrees, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding GeneralSubtrees: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "GeneralSubtrees", Cause: ber.ErrExtraData}
	}
	var result GeneralSubtrees
	offset := 0
	for offset < len(content) {
		var elem GeneralSubtree
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

// MarshalBER encodes GeneralSubtree to BER format.
func (v *GeneralSubtree) MarshalBER() ([]byte, error) {
	var children []byte
	enc_base, err := v.Base.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding base: %w", err)
	}
	children = append(children, enc_base...)
	if v.Minimum != nil {
		enc_minimum := ber.EncodeBigInt(v.Minimum)
		enc_minimum = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_minimum)
		children = append(children, enc_minimum...)
	}
	if v.Maximum != nil {
		enc_maximum := ber.EncodeBigInt(v.Maximum)
		enc_maximum = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_maximum)
		children = append(children, enc_maximum...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes GeneralSubtree to DER format.
func (v *GeneralSubtree) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GeneralSubtree from BER/DER format.
func (v *GeneralSubtree) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding GeneralSubtree SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GeneralSubtree", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode base
	if offset >= len(content) {
		return fmt.Errorf("missing required field base")
	}
	// Decode nested CHOICE (GeneralName)
	_, n_base, _, tlvErr_base := ber.DecodeTLV(content[offset:])
	if tlvErr_base != nil {
		return fmt.Errorf("decoding base: %w", tlvErr_base)
	}
	if unmErr := v.Base.UnmarshalBER(content[offset : offset+n_base]); unmErr != nil {
		return fmt.Errorf("decoding base: %w", unmErr)
	}
	offset += n_base
	// Decode minimum
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_minimum, rawVal_minimum, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding minimum: %w", err)
				}
				decVal_minimum, intErr := ber.DecodeBigIntValue(rawVal_minimum)
				if intErr != nil {
					return fmt.Errorf("decoding minimum: %w", intErr)
				}
				v.Minimum = decVal_minimum
				offset += n_minimum
			}
		}
	}
	// Decode maximum
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_maximum, rawVal_maximum, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding maximum: %w", err)
				}
				decVal_maximum, intErr := ber.DecodeBigIntValue(rawVal_maximum)
				if intErr != nil {
					return fmt.Errorf("decoding maximum: %w", intErr)
				}
				v.Maximum = decVal_maximum
				offset += n_maximum
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "GeneralSubtree", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PolicyConstraints to BER format.
func (v *PolicyConstraints) MarshalBER() ([]byte, error) {
	var children []byte
	if v.RequireExplicitPolicy != nil {
		enc_requireexplicitpolicy := ber.EncodeBigInt(v.RequireExplicitPolicy)
		enc_requireexplicitpolicy = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_requireexplicitpolicy)
		children = append(children, enc_requireexplicitpolicy...)
	}
	if v.InhibitPolicyMapping != nil {
		enc_inhibitpolicymapping := ber.EncodeBigInt(v.InhibitPolicyMapping)
		enc_inhibitpolicymapping = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_inhibitpolicymapping)
		children = append(children, enc_inhibitpolicymapping...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PolicyConstraints to DER format.
func (v *PolicyConstraints) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PolicyConstraints from BER/DER format.
func (v *PolicyConstraints) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PolicyConstraints SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PolicyConstraints", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode requireExplicitPolicy
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_requireexplicitpolicy, rawVal_requireexplicitpolicy, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding requireExplicitPolicy: %w", err)
				}
				decVal_requireexplicitpolicy, intErr := ber.DecodeBigIntValue(rawVal_requireexplicitpolicy)
				if intErr != nil {
					return fmt.Errorf("decoding requireExplicitPolicy: %w", intErr)
				}
				v.RequireExplicitPolicy = decVal_requireexplicitpolicy
				offset += n_requireexplicitpolicy
			}
		}
	}
	// Decode inhibitPolicyMapping
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_inhibitpolicymapping, rawVal_inhibitpolicymapping, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding inhibitPolicyMapping: %w", err)
				}
				decVal_inhibitpolicymapping, intErr := ber.DecodeBigIntValue(rawVal_inhibitpolicymapping)
				if intErr != nil {
					return fmt.Errorf("decoding inhibitPolicyMapping: %w", intErr)
				}
				v.InhibitPolicyMapping = decVal_inhibitpolicymapping
				offset += n_inhibitpolicymapping
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PolicyConstraints", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERCRLDistributionPoints encodes a CRLDistributionPoints list to BER.
func MarshalBERCRLDistributionPoints(list CRLDistributionPoints) ([]byte, error) {
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

// UnmarshalBERCRLDistributionPoints decodes a CRLDistributionPoints list from BER.
func UnmarshalBERCRLDistributionPoints(data []byte) (CRLDistributionPoints, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding CRLDistributionPoints: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CRLDistributionPoints", Cause: ber.ErrExtraData}
	}
	var result CRLDistributionPoints
	offset := 0
	for offset < len(content) {
		var elem DistributionPoint
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

// MarshalBER encodes DistributionPoint to BER format.
func (v *DistributionPoint) MarshalBER() ([]byte, error) {
	var children []byte
	if v.DistributionPoint != nil {
		enc_distributionpoint, err := v.DistributionPoint.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding distributionPoint: %w", err)
		}
		enc_distributionpoint = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_distributionpoint)
		children = append(children, enc_distributionpoint...)
	}
	if v.Reasons != nil {
		enc_reasons := ber.EncodeBitString(v.Reasons.Bytes, (8-(v.Reasons.BitLength%8))%8)
		enc_reasons = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_reasons)
		children = append(children, enc_reasons...)
	}
	if v.CRLIssuer != nil {
		enc_crlissuer, err := MarshalBERGeneralNames(v.CRLIssuer)
		if err != nil {
			return nil, fmt.Errorf("encoding cRLIssuer: %w", err)
		}
		if v.CRLIssuerIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_crlissuer)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_crlissuer = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
		} else {
			enc_crlissuer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_crlissuer)
		}
		children = append(children, enc_crlissuer...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DistributionPoint to DER format.
func (v *DistributionPoint) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.CRLIssuerIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes DistributionPoint from BER/DER format.
func (v *DistributionPoint) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DistributionPoint SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DistributionPoint", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode distributionPoint
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_distributionpoint, innerData_distributionpoint, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding distributionPoint: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_distributionpoint DistributionPointName
				if unmErr := dec_distributionpoint.UnmarshalBER(innerData_distributionpoint); unmErr != nil {
					return fmt.Errorf("decoding distributionPoint: %w", unmErr)
				}
				v.DistributionPoint = &dec_distributionpoint
				offset += n_distributionpoint
			}
		}
	}
	// Decode reasons
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_reasons, rawVal_reasons, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reasons: %w", err)
				}
				bsBytes_reasons, bsUnused_reasons, bsErr := ber.DecodeBitStringValue(rawVal_reasons)
				if bsErr != nil {
					return fmt.Errorf("decoding reasons: %w", bsErr)
				}
				tmp_reasons := runtime.BitString{Bytes: bsBytes_reasons, BitLength: len(bsBytes_reasons)*8 - bsUnused_reasons}
				v.Reasons = &tmp_reasons
				offset += n_reasons
			}
		}
	}
	// Decode cRLIssuer
	v.CRLIssuerIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_crlissuer, rawVal_crlissuer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cRLIssuer: %w", err)
				}
				reconstructed_crlissuer := ber.EncodeSequence(rawVal_crlissuer)
				dec_crlissuer, unmErr := UnmarshalBERGeneralNames(reconstructed_crlissuer)
				if unmErr != nil {
					return fmt.Errorf("decoding cRLIssuer: %w", unmErr)
				}
				v.CRLIssuer = dec_crlissuer
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.CRLIssuerIndef_ = true
					}
				}
				offset += n_crlissuer
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DistributionPoint", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes DistributionPointName to BER format.
func (v *DistributionPointName) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case DistributionPointNameChoiceFullName:
		if v.FullName == nil {
			return nil, fmt.Errorf("choice DistributionPointName: fullName is nil")
		}
		enc_0, err := MarshalBERGeneralNames(v.FullName)
		if err != nil {
			return nil, fmt.Errorf("encoding fullName: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case DistributionPointNameChoiceNameRelativeToCRLIssuer:
		if v.NameRelativeToCRLIssuer == nil {
			return nil, fmt.Errorf("choice DistributionPointName: nameRelativeToCRLIssuer is nil")
		}
		enc_1, err := MarshalBERRelativeDistinguishedName(v.NameRelativeToCRLIssuer)
		if err != nil {
			return nil, fmt.Errorf("encoding nameRelativeToCRLIssuer: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DistributionPointName", v.Choice)
	}
}

// MarshalDER encodes DistributionPointName to DER format.
func (v *DistributionPointName) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes DistributionPointName from BER/DER format.
func (v *DistributionPointName) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for DistributionPointName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DistributionPointName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding DistributionPointName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DistributionPointName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = DistributionPointNameChoiceFullName
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding fullName: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERGeneralNames(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding fullName: %w", unmErr)
		}
		v.FullName = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = DistributionPointNameChoiceNameRelativeToCRLIssuer
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding nameRelativeToCRLIssuer: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERRelativeDistinguishedName(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding nameRelativeToCRLIssuer: %w", unmErr)
		}
		v.NameRelativeToCRLIssuer = dec
	} else {
		return fmt.Errorf("unknown tag %s for DistributionPointName CHOICE", peekTag)
	}
	return nil
}

// MarshalBERExtKeyUsageSyntax encodes a ExtKeyUsageSyntax list to BER.
func MarshalBERExtKeyUsageSyntax(list ExtKeyUsageSyntax) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeObjectIdentifier([]uint64(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERExtKeyUsageSyntax decodes a ExtKeyUsageSyntax list from BER.
func UnmarshalBERExtKeyUsageSyntax(data []byte) (ExtKeyUsageSyntax, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ExtKeyUsageSyntax: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ExtKeyUsageSyntax", Cause: ber.ErrExtraData}
	}
	var result ExtKeyUsageSyntax
	offset := 0
	for offset < len(content) {
		val, n, oidErr := ber.DecodeObjectIdentifier(content[offset:])
		if oidErr != nil {
			return nil, fmt.Errorf("decoding element: %w", oidErr)
		}
		result = append(result, KeyPurposeId(val))
		offset += n
	}
	return result, nil
}

// MarshalBERAuthorityInfoAccessSyntax encodes a AuthorityInfoAccessSyntax list to BER.
func MarshalBERAuthorityInfoAccessSyntax(list AuthorityInfoAccessSyntax) ([]byte, error) {
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

// UnmarshalBERAuthorityInfoAccessSyntax decodes a AuthorityInfoAccessSyntax list from BER.
func UnmarshalBERAuthorityInfoAccessSyntax(data []byte) (AuthorityInfoAccessSyntax, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AuthorityInfoAccessSyntax: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AuthorityInfoAccessSyntax", Cause: ber.ErrExtraData}
	}
	var result AuthorityInfoAccessSyntax
	offset := 0
	for offset < len(content) {
		var elem AccessDescription
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

// MarshalBER encodes AccessDescription to BER format.
func (v *AccessDescription) MarshalBER() ([]byte, error) {
	var children []byte
	enc_accessmethod := ber.EncodeObjectIdentifier([]uint64(v.AccessMethod))
	children = append(children, enc_accessmethod...)
	enc_accesslocation, err := v.AccessLocation.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding accessLocation: %w", err)
	}
	children = append(children, enc_accesslocation...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AccessDescription to DER format.
func (v *AccessDescription) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AccessDescription from BER/DER format.
func (v *AccessDescription) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AccessDescription SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AccessDescription", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode accessMethod
	if offset >= len(content) {
		return fmt.Errorf("missing required field accessMethod")
	}
	val_accessmethod, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding accessMethod: %w", err)
	}
	v.AccessMethod = runtime.ObjectIdentifier(val_accessmethod)
	offset += n
	// Decode accessLocation
	if offset >= len(content) {
		return fmt.Errorf("missing required field accessLocation")
	}
	// Decode nested CHOICE (GeneralName)
	_, n_accesslocation, _, tlvErr_accesslocation := ber.DecodeTLV(content[offset:])
	if tlvErr_accesslocation != nil {
		return fmt.Errorf("decoding accessLocation: %w", tlvErr_accesslocation)
	}
	if unmErr := v.AccessLocation.UnmarshalBER(content[offset : offset+n_accesslocation]); unmErr != nil {
		return fmt.Errorf("decoding accessLocation: %w", unmErr)
	}
	offset += n_accesslocation
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AccessDescription", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERSubjectInfoAccessSyntax encodes a SubjectInfoAccessSyntax list to BER.
func MarshalBERSubjectInfoAccessSyntax(list SubjectInfoAccessSyntax) ([]byte, error) {
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

// UnmarshalBERSubjectInfoAccessSyntax decodes a SubjectInfoAccessSyntax list from BER.
func UnmarshalBERSubjectInfoAccessSyntax(data []byte) (SubjectInfoAccessSyntax, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SubjectInfoAccessSyntax: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SubjectInfoAccessSyntax", Cause: ber.ErrExtraData}
	}
	var result SubjectInfoAccessSyntax
	offset := 0
	for offset < len(content) {
		var elem AccessDescription
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

// MarshalBER encodes IssuingDistributionPoint to BER format.
func (v *IssuingDistributionPoint) MarshalBER() ([]byte, error) {
	var children []byte
	if v.DistributionPoint != nil {
		enc_distributionpoint, err := v.DistributionPoint.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding distributionPoint: %w", err)
		}
		enc_distributionpoint = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_distributionpoint)
		children = append(children, enc_distributionpoint...)
	}
	if v.OnlyContainsUserCerts != nil {
		var enc_onlycontainsusercerts []byte
		if v.OnlyContainsUserCertsRaw_ != 0 {
			enc_onlycontainsusercerts = ber.EncodeBooleanRaw(v.OnlyContainsUserCertsRaw_)
		} else {
			enc_onlycontainsusercerts = ber.EncodeBoolean(*v.OnlyContainsUserCerts)
		}
		enc_onlycontainsusercerts = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_onlycontainsusercerts)
		children = append(children, enc_onlycontainsusercerts...)
	}
	if v.OnlyContainsCACerts != nil {
		var enc_onlycontainscacerts []byte
		if v.OnlyContainsCACertsRaw_ != 0 {
			enc_onlycontainscacerts = ber.EncodeBooleanRaw(v.OnlyContainsCACertsRaw_)
		} else {
			enc_onlycontainscacerts = ber.EncodeBoolean(*v.OnlyContainsCACerts)
		}
		enc_onlycontainscacerts = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_onlycontainscacerts)
		children = append(children, enc_onlycontainscacerts...)
	}
	if v.OnlySomeReasons != nil {
		enc_onlysomereasons := ber.EncodeBitString(v.OnlySomeReasons.Bytes, (8-(v.OnlySomeReasons.BitLength%8))%8)
		enc_onlysomereasons = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_onlysomereasons)
		children = append(children, enc_onlysomereasons...)
	}
	if v.IndirectCRL != nil {
		var enc_indirectcrl []byte
		if v.IndirectCRLRaw_ != 0 {
			enc_indirectcrl = ber.EncodeBooleanRaw(v.IndirectCRLRaw_)
		} else {
			enc_indirectcrl = ber.EncodeBoolean(*v.IndirectCRL)
		}
		enc_indirectcrl = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_indirectcrl)
		children = append(children, enc_indirectcrl...)
	}
	if v.OnlyContainsAttributeCerts != nil {
		var enc_onlycontainsattributecerts []byte
		if v.OnlyContainsAttributeCertsRaw_ != 0 {
			enc_onlycontainsattributecerts = ber.EncodeBooleanRaw(v.OnlyContainsAttributeCertsRaw_)
		} else {
			enc_onlycontainsattributecerts = ber.EncodeBoolean(*v.OnlyContainsAttributeCerts)
		}
		enc_onlycontainsattributecerts = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_onlycontainsattributecerts)
		children = append(children, enc_onlycontainsattributecerts...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes IssuingDistributionPoint to DER format.
func (v *IssuingDistributionPoint) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IssuingDistributionPoint from BER/DER format.
func (v *IssuingDistributionPoint) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IssuingDistributionPoint SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IssuingDistributionPoint", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode distributionPoint
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_distributionpoint, innerData_distributionpoint, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding distributionPoint: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_distributionpoint DistributionPointName
				if unmErr := dec_distributionpoint.UnmarshalBER(innerData_distributionpoint); unmErr != nil {
					return fmt.Errorf("decoding distributionPoint: %w", unmErr)
				}
				v.DistributionPoint = &dec_distributionpoint
				offset += n_distributionpoint
			}
		}
	}
	// Decode onlyContainsUserCerts
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_onlycontainsusercerts, rawVal_onlycontainsusercerts, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding onlyContainsUserCerts: %w", err)
				}
				decVal_onlycontainsusercerts, boolErr := ber.DecodeBooleanValue(rawVal_onlycontainsusercerts)
				if boolErr != nil {
					return fmt.Errorf("decoding onlyContainsUserCerts: %w", boolErr)
				}
				if len(rawVal_onlycontainsusercerts) == 1 {
					v.OnlyContainsUserCertsRaw_ = rawVal_onlycontainsusercerts[0]
				}
				v.OnlyContainsUserCerts = &decVal_onlycontainsusercerts
				offset += n_onlycontainsusercerts
			}
		}
	}
	// Decode onlyContainsCACerts
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_onlycontainscacerts, rawVal_onlycontainscacerts, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding onlyContainsCACerts: %w", err)
				}
				decVal_onlycontainscacerts, boolErr := ber.DecodeBooleanValue(rawVal_onlycontainscacerts)
				if boolErr != nil {
					return fmt.Errorf("decoding onlyContainsCACerts: %w", boolErr)
				}
				if len(rawVal_onlycontainscacerts) == 1 {
					v.OnlyContainsCACertsRaw_ = rawVal_onlycontainscacerts[0]
				}
				v.OnlyContainsCACerts = &decVal_onlycontainscacerts
				offset += n_onlycontainscacerts
			}
		}
	}
	// Decode onlySomeReasons
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_onlysomereasons, rawVal_onlysomereasons, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding onlySomeReasons: %w", err)
				}
				bsBytes_onlysomereasons, bsUnused_onlysomereasons, bsErr := ber.DecodeBitStringValue(rawVal_onlysomereasons)
				if bsErr != nil {
					return fmt.Errorf("decoding onlySomeReasons: %w", bsErr)
				}
				tmp_onlysomereasons := runtime.BitString{Bytes: bsBytes_onlysomereasons, BitLength: len(bsBytes_onlysomereasons)*8 - bsUnused_onlysomereasons}
				v.OnlySomeReasons = &tmp_onlysomereasons
				offset += n_onlysomereasons
			}
		}
	}
	// Decode indirectCRL
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_indirectcrl, rawVal_indirectcrl, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding indirectCRL: %w", err)
				}
				decVal_indirectcrl, boolErr := ber.DecodeBooleanValue(rawVal_indirectcrl)
				if boolErr != nil {
					return fmt.Errorf("decoding indirectCRL: %w", boolErr)
				}
				if len(rawVal_indirectcrl) == 1 {
					v.IndirectCRLRaw_ = rawVal_indirectcrl[0]
				}
				v.IndirectCRL = &decVal_indirectcrl
				offset += n_indirectcrl
			}
		}
	}
	// Decode onlyContainsAttributeCerts
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_onlycontainsattributecerts, rawVal_onlycontainsattributecerts, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding onlyContainsAttributeCerts: %w", err)
				}
				decVal_onlycontainsattributecerts, boolErr := ber.DecodeBooleanValue(rawVal_onlycontainsattributecerts)
				if boolErr != nil {
					return fmt.Errorf("decoding onlyContainsAttributeCerts: %w", boolErr)
				}
				if len(rawVal_onlycontainsattributecerts) == 1 {
					v.OnlyContainsAttributeCertsRaw_ = rawVal_onlycontainsattributecerts[0]
				}
				v.OnlyContainsAttributeCerts = &decVal_onlycontainsattributecerts
				offset += n_onlycontainsattributecerts
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "IssuingDistributionPoint", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERPolicyInformationPolicyQualifiers encodes a PolicyInformationPolicyQualifiers list to BER.
func MarshalBERPolicyInformationPolicyQualifiers(list PolicyInformationPolicyQualifiers) ([]byte, error) {
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

// UnmarshalBERPolicyInformationPolicyQualifiers decodes a PolicyInformationPolicyQualifiers list from BER.
func UnmarshalBERPolicyInformationPolicyQualifiers(data []byte) (PolicyInformationPolicyQualifiers, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding PolicyInformationPolicyQualifiers: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PolicyInformationPolicyQualifiers", Cause: ber.ErrExtraData}
	}
	var result PolicyInformationPolicyQualifiers
	offset := 0
	for offset < len(content) {
		var elem PolicyQualifierInfo
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

// MarshalBERNoticeReferenceNoticeNumbers encodes a NoticeReferenceNoticeNumbers list to BER.
func MarshalBERNoticeReferenceNoticeNumbers(list NoticeReferenceNoticeNumbers) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeBigInt(elem)...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERNoticeReferenceNoticeNumbers decodes a NoticeReferenceNoticeNumbers list from BER.
func UnmarshalBERNoticeReferenceNoticeNumbers(data []byte) (NoticeReferenceNoticeNumbers, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding NoticeReferenceNoticeNumbers: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "NoticeReferenceNoticeNumbers", Cause: ber.ErrExtraData}
	}
	var result NoticeReferenceNoticeNumbers
	offset := 0
	for offset < len(content) {
		val, n, intErr := ber.DecodeBigInt(content[offset:])
		if intErr != nil {
			return nil, fmt.Errorf("decoding element: %w", intErr)
		}
		result = append(result, val)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes PolicyMappingsElem to BER format.
func (v *PolicyMappingsElem) MarshalBER() ([]byte, error) {
	var children []byte
	enc_issuerdomainpolicy := ber.EncodeObjectIdentifier([]uint64(v.IssuerDomainPolicy))
	children = append(children, enc_issuerdomainpolicy...)
	enc_subjectdomainpolicy := ber.EncodeObjectIdentifier([]uint64(v.SubjectDomainPolicy))
	children = append(children, enc_subjectdomainpolicy...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PolicyMappingsElem to DER format.
func (v *PolicyMappingsElem) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PolicyMappingsElem from BER/DER format.
func (v *PolicyMappingsElem) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PolicyMappingsElem SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PolicyMappingsElem", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode issuerDomainPolicy
	if offset >= len(content) {
		return fmt.Errorf("missing required field issuerDomainPolicy")
	}
	val_issuerdomainpolicy, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding issuerDomainPolicy: %w", err)
	}
	v.IssuerDomainPolicy = runtime.ObjectIdentifier(val_issuerdomainpolicy)
	offset += n
	// Decode subjectDomainPolicy
	if offset >= len(content) {
		return fmt.Errorf("missing required field subjectDomainPolicy")
	}
	val_subjectdomainpolicy, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding subjectDomainPolicy: %w", err)
	}
	v.SubjectDomainPolicy = runtime.ObjectIdentifier(val_subjectdomainpolicy)
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PolicyMappingsElem", Cause: ber.ErrExtraData}
	}
	return nil
}
