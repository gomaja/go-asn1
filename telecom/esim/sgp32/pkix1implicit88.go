// Code generated from ASN.1 module "PKIX1Implicit88". DO NOT EDIT.

package sgp32

import (
	"fmt"
	"math/big"

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
func IdCe() runtime.ObjectIdentifier { return runtime.MustObjectIdentifierFromEncoded("\x55\x1d") }

// IdCeAuthorityKeyIdentifier returns the OID value for id-ce-authorityKeyIdentifier.
func IdCeAuthorityKeyIdentifier() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x23")
}

// IdCeSubjectKeyIdentifier returns the OID value for id-ce-subjectKeyIdentifier.
func IdCeSubjectKeyIdentifier() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x0e")
}

// IdCeKeyUsage returns the OID value for id-ce-keyUsage.
func IdCeKeyUsage() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x0f")
}

// IdCePrivateKeyUsagePeriod returns the OID value for id-ce-privateKeyUsagePeriod.
func IdCePrivateKeyUsagePeriod() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x10")
}

// IdCeCertificatePolicies returns the OID value for id-ce-certificatePolicies.
func IdCeCertificatePolicies() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x20")
}

// AnyPolicy returns the OID value for anyPolicy.
func AnyPolicy() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x20\x00")
}

// IdCePolicyMappings returns the OID value for id-ce-policyMappings.
func IdCePolicyMappings() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x21")
}

// IdCeSubjectAltName returns the OID value for id-ce-subjectAltName.
func IdCeSubjectAltName() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x11")
}

// IdCeIssuerAltName returns the OID value for id-ce-issuerAltName.
func IdCeIssuerAltName() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x12")
}

// IdCeSubjectDirectoryAttributes returns the OID value for id-ce-subjectDirectoryAttributes.
func IdCeSubjectDirectoryAttributes() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x09")
}

// IdCeBasicConstraints returns the OID value for id-ce-basicConstraints.
func IdCeBasicConstraints() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x13")
}

// IdCeNameConstraints returns the OID value for id-ce-nameConstraints.
func IdCeNameConstraints() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x1e")
}

// IdCePolicyConstraints returns the OID value for id-ce-policyConstraints.
func IdCePolicyConstraints() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x24")
}

// IdCeCRLDistributionPoints returns the OID value for id-ce-cRLDistributionPoints.
func IdCeCRLDistributionPoints() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x1f")
}

// IdCeExtKeyUsage returns the OID value for id-ce-extKeyUsage.
func IdCeExtKeyUsage() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x25")
}

// AnyExtendedKeyUsage returns the OID value for anyExtendedKeyUsage.
func AnyExtendedKeyUsage() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x25\x00")
}

// IdKpServerAuth returns the OID value for id-kp-serverAuth.
func IdKpServerAuth() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x2b\x06\x01\x05\x05\x07\x03\x01")
}

// IdKpClientAuth returns the OID value for id-kp-clientAuth.
func IdKpClientAuth() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x2b\x06\x01\x05\x05\x07\x03\x02")
}

// IdKpCodeSigning returns the OID value for id-kp-codeSigning.
func IdKpCodeSigning() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x2b\x06\x01\x05\x05\x07\x03\x03")
}

// IdKpEmailProtection returns the OID value for id-kp-emailProtection.
func IdKpEmailProtection() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x2b\x06\x01\x05\x05\x07\x03\x04")
}

// IdKpTimeStamping returns the OID value for id-kp-timeStamping.
func IdKpTimeStamping() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x2b\x06\x01\x05\x05\x07\x03\x08")
}

// IdKpOCSPSigning returns the OID value for id-kp-OCSPSigning.
func IdKpOCSPSigning() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x2b\x06\x01\x05\x05\x07\x03\x09")
}

// IdCeInhibitAnyPolicy returns the OID value for id-ce-inhibitAnyPolicy.
func IdCeInhibitAnyPolicy() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x36")
}

// IdCeFreshestCRL returns the OID value for id-ce-freshestCRL.
func IdCeFreshestCRL() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x2e")
}

// IdPeAuthorityInfoAccess returns the OID value for id-pe-authorityInfoAccess.
func IdPeAuthorityInfoAccess() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x2b\x06\x01\x05\x05\x07\x01\x01")
}

// IdPeSubjectInfoAccess returns the OID value for id-pe-subjectInfoAccess.
func IdPeSubjectInfoAccess() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x2b\x06\x01\x05\x05\x07\x01\x0b")
}

// IdCeCRLNumber returns the OID value for id-ce-cRLNumber.
func IdCeCRLNumber() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x14")
}

// IdCeIssuingDistributionPoint returns the OID value for id-ce-issuingDistributionPoint.
func IdCeIssuingDistributionPoint() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x1c")
}

// IdCeDeltaCRLIndicator returns the OID value for id-ce-deltaCRLIndicator.
func IdCeDeltaCRLIndicator() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x1b")
}

// IdCeCRLReasons returns the OID value for id-ce-cRLReasons.
func IdCeCRLReasons() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x15")
}

// IdCeCertificateIssuer returns the OID value for id-ce-certificateIssuer.
func IdCeCertificateIssuer() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x1d")
}

// IdCeHoldInstructionCode returns the OID value for id-ce-holdInstructionCode.
func IdCeHoldInstructionCode() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x17")
}

// HoldInstruction returns the OID value for holdInstruction.
func HoldInstruction() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x52\x86\x48\xce\x38\x02")
}

// IdHoldinstructionNone returns the OID value for id-holdinstruction-none.
func IdHoldinstructionNone() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x52\x86\x48\xce\x38\x02\x01")
}

// IdHoldinstructionCallissuer returns the OID value for id-holdinstruction-callissuer.
func IdHoldinstructionCallissuer() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x52\x86\x48\xce\x38\x02\x02")
}

// IdHoldinstructionReject returns the OID value for id-holdinstruction-reject.
func IdHoldinstructionReject() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x52\x86\x48\xce\x38\x02\x03")
}

// IdCeInvalidityDate returns the OID value for id-ce-invalidityDate.
func IdCeInvalidityDate() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x55\x1d\x18")
}

// AuthorityKeyIdentifier represents the ASN.1 type AuthorityKeyIdentifier (SEQUENCE).
type AuthorityKeyIdentifier struct {
	KeyIdentifier             *KeyIdentifier          `asn1:"tag:0,context,implicit,optional" json:"KeyIdentifier,omitempty"`
	AuthorityCertIssuer       *GeneralNames           `asn1:"tag:1,context,implicit,optional" json:"AuthorityCertIssuer,omitempty"`
	AuthorityCertIssuerIndef_ bool                    `asn1:"-" json:"-"`
	AuthorityCertSerialNumber CertificateSerialNumber `asn1:"tag:2,context,implicit,optional" json:"AuthorityCertSerialNumber,omitzero"`
	berOriginal_              []byte                  `asn1:"-" json:"-"`
	berSnapshot_              []byte                  `asn1:"-" json:"-"`
}

// KeyIdentifier represents the ASN.1 type KeyIdentifier (OCTET_STRING).
type KeyIdentifier = []byte

// SubjectKeyIdentifier represents the ASN.1 type SubjectKeyIdentifier (OCTET_STRING).
type SubjectKeyIdentifier = KeyIdentifier

// KeyUsage represents the ASN.1 type KeyUsage (BIT_STRING).
type KeyUsage = runtime.BitString

// PrivateKeyUsagePeriod represents the ASN.1 type PrivateKeyUsagePeriod (SEQUENCE).
type PrivateKeyUsagePeriod struct {
	NotBefore    *runtime.GeneralizedTime `asn1:"tag:0,context,implicit,optional" json:"NotBefore,omitempty"`
	NotAfter     *runtime.GeneralizedTime `asn1:"tag:1,context,implicit,optional" json:"NotAfter,omitempty"`
	berOriginal_ []byte                   `asn1:"-" json:"-"`
	berSnapshot_ []byte                   `asn1:"-" json:"-"`
}

// CertificatePolicies represents the ASN.1 type CertificatePolicies (SEQUENCE_OF).
type CertificatePolicies struct {
	Values       []PolicyInformation `json:"Values"`
	berOriginal_ []byte              `json:"-"`
	berSnapshot_ []byte              `json:"-"`
}

// PolicyInformation represents the ASN.1 type PolicyInformation (SEQUENCE).
type PolicyInformation struct {
	PolicyIdentifier       CertPolicyId                       `asn1:""`
	PolicyQualifiers       *PolicyInformationPolicyQualifiers `asn1:",optional" json:"PolicyQualifiers,omitempty"`
	PolicyQualifiersIndef_ bool                               `asn1:"-" json:"-"`
	berOriginal_           []byte                             `asn1:"-" json:"-"`
	berSnapshot_           []byte                             `asn1:"-" json:"-"`
}

// CertPolicyId represents the ASN.1 type CertPolicyId (OBJECT_IDENTIFIER).
type CertPolicyId = runtime.ObjectIdentifier

// PolicyQualifierInfo represents the ASN.1 type PolicyQualifierInfo (SEQUENCE).
type PolicyQualifierInfo struct {
	PolicyQualifierId PolicyQualifierId `asn1:""`
	Qualifier         runtime.RawValue  `asn1:"" asn1c:"raw-preserve"`
	berOriginal_      []byte            `asn1:"-" json:"-"`
	berSnapshot_      []byte            `asn1:"-" json:"-"`
}

// PolicyQualifierId represents the ASN.1 type PolicyQualifierId (OBJECT_IDENTIFIER).
type PolicyQualifierId = runtime.ObjectIdentifier

// CPSuri represents the ASN.1 type CPSuri (IA5String).
type CPSuri = string

// UserNotice represents the ASN.1 type UserNotice (SEQUENCE).
type UserNotice struct {
	NoticeRef    *NoticeReference `asn1:",optional" json:"NoticeRef,omitempty"`
	ExplicitText *DisplayText     `asn1:",optional" json:"ExplicitText,omitempty"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// NoticeReference represents the ASN.1 type NoticeReference (SEQUENCE).
type NoticeReference struct {
	Organization        DisplayText                   `asn1:""`
	NoticeNumbers       *NoticeReferenceNoticeNumbers `asn1:""`
	NoticeNumbersIndef_ bool                          `asn1:"-" json:"-"`
	berOriginal_        []byte                        `asn1:"-" json:"-"`
	berSnapshot_        []byte                        `asn1:"-" json:"-"`
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
	berOriginal_  []byte  `json:"-"`
	berSnapshot_  []byte  `json:"-"`
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
type PolicyMappings struct {
	Values       []PolicyMappingsElem `json:"Values"`
	berOriginal_ []byte               `json:"-"`
	berSnapshot_ []byte               `json:"-"`
}

// SubjectAltName represents the ASN.1 type SubjectAltName (SEQUENCE_OF).
type SubjectAltName = GeneralNames

// GeneralNames represents the ASN.1 type GeneralNames (SEQUENCE_OF).
type GeneralNames struct {
	Values       []GeneralName `json:"Values"`
	berOriginal_ []byte        `json:"-"`
	berSnapshot_ []byte        `json:"-"`
}

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
	berOriginal_              []byte                    `json:"-"`
	berSnapshot_              []byte                    `json:"-"`
	OtherName                 *AnotherName              `json:"OtherName,omitempty"`
	Rfc822Name                *string                   `json:"Rfc822Name,omitempty"`
	DNSName                   *string                   `json:"DNSName,omitempty"`
	X400Address               *ORAddress                `json:"X400Address,omitempty"`
	DirectoryName             *Name                     `json:"DirectoryName,omitempty"`
	EdiPartyName              *EDIPartyName             `json:"EdiPartyName,omitempty"`
	UniformResourceIdentifier *string                   `json:"UniformResourceIdentifier,omitempty"`
	IPAddress                 []byte                    `json:"IPAddress,omitzero"`
	RegisteredID              *runtime.ObjectIdentifier `json:"RegisteredID,omitempty"`
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
		RegisteredID: &v,
	}
}

// AnotherName represents the ASN.1 type AnotherName (SEQUENCE).
type AnotherName struct {
	TypeId       runtime.ObjectIdentifier `asn1:""`
	Value        runtime.RawValue         `asn1:"tag:0,context,explicit" asn1c:"raw-preserve"`
	berOriginal_ []byte                   `asn1:"-" json:"-"`
	berSnapshot_ []byte                   `asn1:"-" json:"-"`
}

// EDIPartyName represents the ASN.1 type EDIPartyName (SEQUENCE).
type EDIPartyName struct {
	NameAssigner *DirectoryString `asn1:"tag:0,context,explicit,optional" json:"NameAssigner,omitempty"`
	PartyName    DirectoryString  `asn1:"tag:1,context,explicit"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// IssuerAltName represents the ASN.1 type IssuerAltName (SEQUENCE_OF).
type IssuerAltName = GeneralNames

// SubjectDirectoryAttributes represents the ASN.1 type SubjectDirectoryAttributes (SEQUENCE_OF).
type SubjectDirectoryAttributes struct {
	Values       []Attribute `json:"Values"`
	berOriginal_ []byte      `json:"-"`
	berSnapshot_ []byte      `json:"-"`
}

// BasicConstraints represents the ASN.1 type BasicConstraints (SEQUENCE).
type BasicConstraints struct {
	CA                *bool    `asn1:",optional" json:"CA,omitempty"`
	CARaw_            byte     `asn1:"-" json:"-"`
	PathLenConstraint *big.Int `asn1:",optional" json:"PathLenConstraint,omitempty"`
	berOriginal_      []byte   `asn1:"-" json:"-"`
	berSnapshot_      []byte   `asn1:"-" json:"-"`
}

// NameConstraints represents the ASN.1 type NameConstraints (SEQUENCE).
type NameConstraints struct {
	PermittedSubtrees       *GeneralSubtrees `asn1:"tag:0,context,implicit,optional" json:"PermittedSubtrees,omitempty"`
	PermittedSubtreesIndef_ bool             `asn1:"-" json:"-"`
	ExcludedSubtrees        *GeneralSubtrees `asn1:"tag:1,context,implicit,optional" json:"ExcludedSubtrees,omitempty"`
	ExcludedSubtreesIndef_  bool             `asn1:"-" json:"-"`
	berOriginal_            []byte           `asn1:"-" json:"-"`
	berSnapshot_            []byte           `asn1:"-" json:"-"`
}

// GeneralSubtrees represents the ASN.1 type GeneralSubtrees (SEQUENCE_OF).
type GeneralSubtrees struct {
	Values       []GeneralSubtree `json:"Values"`
	berOriginal_ []byte           `json:"-"`
	berSnapshot_ []byte           `json:"-"`
}

// GeneralSubtree represents the ASN.1 type GeneralSubtree (SEQUENCE).
type GeneralSubtree struct {
	Base         GeneralName  `asn1:""`
	Minimum      BaseDistance `asn1:"tag:0,context,implicit,optional" json:"Minimum,omitzero"`
	Maximum      BaseDistance `asn1:"tag:1,context,implicit,optional" json:"Maximum,omitzero"`
	berOriginal_ []byte       `asn1:"-" json:"-"`
	berSnapshot_ []byte       `asn1:"-" json:"-"`
}

// BaseDistance represents the ASN.1 type BaseDistance (INTEGER).
type BaseDistance = *big.Int

// PolicyConstraints represents the ASN.1 type PolicyConstraints (SEQUENCE).
type PolicyConstraints struct {
	RequireExplicitPolicy SkipCerts `asn1:"tag:0,context,implicit,optional" json:"RequireExplicitPolicy,omitzero"`
	InhibitPolicyMapping  SkipCerts `asn1:"tag:1,context,implicit,optional" json:"InhibitPolicyMapping,omitzero"`
	berOriginal_          []byte    `asn1:"-" json:"-"`
	berSnapshot_          []byte    `asn1:"-" json:"-"`
}

// SkipCerts represents the ASN.1 type SkipCerts (INTEGER).
type SkipCerts = *big.Int

// CRLDistributionPoints represents the ASN.1 type CRLDistributionPoints (SEQUENCE_OF).
type CRLDistributionPoints struct {
	Values       []DistributionPoint `json:"Values"`
	berOriginal_ []byte              `json:"-"`
	berSnapshot_ []byte              `json:"-"`
}

// DistributionPoint represents the ASN.1 type DistributionPoint (SEQUENCE).
type DistributionPoint struct {
	DistributionPoint *DistributionPointName `asn1:"tag:0,context,explicit,optional" json:"DistributionPoint,omitempty"`
	Reasons           *ReasonFlags           `asn1:"tag:1,context,implicit,optional" json:"Reasons,omitempty"`
	CRLIssuer         *GeneralNames          `asn1:"tag:2,context,implicit,optional" json:"CRLIssuer,omitempty"`
	CRLIssuerIndef_   bool                   `asn1:"-" json:"-"`
	berOriginal_      []byte                 `asn1:"-" json:"-"`
	berSnapshot_      []byte                 `asn1:"-" json:"-"`
}

// DistributionPointName choice constants.
const (
	DistributionPointNameChoiceFullName                = 1
	DistributionPointNameChoiceNameRelativeToCRLIssuer = 2
)

// DistributionPointName represents the ASN.1 CHOICE type DistributionPointName.
type DistributionPointName struct {
	Choice                  int
	berOriginal_            []byte                     `json:"-"`
	berSnapshot_            []byte                     `json:"-"`
	FullName                *GeneralNames              `json:"FullName,omitempty"`
	NameRelativeToCRLIssuer *RelativeDistinguishedName `json:"NameRelativeToCRLIssuer,omitempty"`
}

// NewDistributionPointNameFullName creates a DistributionPointName with the fullName alternative.
func NewDistributionPointNameFullName(v *GeneralNames) DistributionPointName {
	return DistributionPointName{
		Choice:   DistributionPointNameChoiceFullName,
		FullName: v,
	}
}

// NewDistributionPointNameNameRelativeToCRLIssuer creates a DistributionPointName with the nameRelativeToCRLIssuer alternative.
func NewDistributionPointNameNameRelativeToCRLIssuer(v *RelativeDistinguishedName) DistributionPointName {
	return DistributionPointName{
		Choice:                  DistributionPointNameChoiceNameRelativeToCRLIssuer,
		NameRelativeToCRLIssuer: v,
	}
}

// ReasonFlags represents the ASN.1 type ReasonFlags (BIT_STRING).
type ReasonFlags = runtime.BitString

// ExtKeyUsageSyntax represents the ASN.1 type ExtKeyUsageSyntax (SEQUENCE_OF).
type ExtKeyUsageSyntax struct {
	Values       []KeyPurposeId `json:"Values"`
	berOriginal_ []byte         `json:"-"`
	berSnapshot_ []byte         `json:"-"`
}

// KeyPurposeId represents the ASN.1 type KeyPurposeId (OBJECT_IDENTIFIER).
type KeyPurposeId = runtime.ObjectIdentifier

// InhibitAnyPolicy represents the ASN.1 type InhibitAnyPolicy (INTEGER).
type InhibitAnyPolicy = SkipCerts

// FreshestCRL represents the ASN.1 type FreshestCRL (SEQUENCE_OF).
type FreshestCRL = CRLDistributionPoints

// AuthorityInfoAccessSyntax represents the ASN.1 type AuthorityInfoAccessSyntax (SEQUENCE_OF).
type AuthorityInfoAccessSyntax struct {
	Values       []AccessDescription `json:"Values"`
	berOriginal_ []byte              `json:"-"`
	berSnapshot_ []byte              `json:"-"`
}

// AccessDescription represents the ASN.1 type AccessDescription (SEQUENCE).
type AccessDescription struct {
	AccessMethod   runtime.ObjectIdentifier `asn1:""`
	AccessLocation GeneralName              `asn1:""`
	berOriginal_   []byte                   `asn1:"-" json:"-"`
	berSnapshot_   []byte                   `asn1:"-" json:"-"`
}

// SubjectInfoAccessSyntax represents the ASN.1 type SubjectInfoAccessSyntax (SEQUENCE_OF).
type SubjectInfoAccessSyntax struct {
	Values       []AccessDescription `json:"Values"`
	berOriginal_ []byte              `json:"-"`
	berSnapshot_ []byte              `json:"-"`
}

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
	berOriginal_                   []byte                 `asn1:"-" json:"-"`
	berSnapshot_                   []byte                 `asn1:"-" json:"-"`
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
type InvalidityDate = runtime.GeneralizedTime

// PolicyInformationPolicyQualifiers represents the ASN.1 type PolicyInformation-policyQualifiers (SEQUENCE_OF).
type PolicyInformationPolicyQualifiers struct {
	Values       []PolicyQualifierInfo `json:"Values"`
	berOriginal_ []byte                `json:"-"`
	berSnapshot_ []byte                `json:"-"`
}

// NoticeReferenceNoticeNumbers represents the ASN.1 type NoticeReference-noticeNumbers (SEQUENCE_OF).
type NoticeReferenceNoticeNumbers struct {
	Values       []*big.Int `json:"Values"`
	berOriginal_ []byte     `json:"-"`
	berSnapshot_ []byte     `json:"-"`
}

// PolicyMappingsElem represents the ASN.1 type PolicyMappings-Elem (SEQUENCE).
type PolicyMappingsElem struct {
	IssuerDomainPolicy  CertPolicyId `asn1:""`
	SubjectDomainPolicy CertPolicyId `asn1:""`
	berOriginal_        []byte       `asn1:"-" json:"-"`
	berSnapshot_        []byte       `asn1:"-" json:"-"`
}

// MarshalBER encodes AuthorityKeyIdentifier to BER format.
func (v *AuthorityKeyIdentifier) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AuthorityKeyIdentifier receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AuthorityKeyIdentifier) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.KeyIdentifier != nil {
		enc_keyidentifier, encodeErr_enc_keyidentifier := ber.EncodeOctetString([]byte(*v.KeyIdentifier))
		if encodeErr_enc_keyidentifier != nil {
			return nil, qualifyBERError(encodeErr_enc_keyidentifier, "keyIdentifier", "encoding", false)
		}
		retagged_enc_keyidentifier, tagErr_enc_keyidentifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_keyidentifier)
		if tagErr_enc_keyidentifier != nil {
			return nil, qualifyBERError(tagErr_enc_keyidentifier, "keyIdentifier", "encoding", false)
		}
		enc_keyidentifier = retagged_enc_keyidentifier
		children = append(children, enc_keyidentifier...)
	}
	if v.AuthorityCertIssuer != nil {
		if len((v.AuthorityCertIssuer).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "authorityCertIssuer", "SIZE (1..MAX)", len((v.AuthorityCertIssuer).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_authoritycertissuer, err := MarshalBERGeneralNames(v.AuthorityCertIssuer, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "authorityCertIssuer"))...)
		if err != nil {
			return nil, qualifyBERError(err, "authorityCertIssuer", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.AuthorityCertIssuerIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_authoritycertissuer)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_authoritycertissuer, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "authorityCertIssuer", "encoding", false)
				}
			}
		} else {
			retagged_enc_authoritycertissuer, tagErr_enc_authoritycertissuer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_authoritycertissuer)
			if tagErr_enc_authoritycertissuer != nil {
				return nil, qualifyBERError(tagErr_enc_authoritycertissuer, "authorityCertIssuer", "encoding", false)
			}
			enc_authoritycertissuer = retagged_enc_authoritycertissuer
		}
		children = append(children, enc_authoritycertissuer...)
	}
	if v.AuthorityCertSerialNumber != nil {
		enc_authoritycertserialnumber, encodeErr_enc_authoritycertserialnumber := ber.EncodeBigInt(v.AuthorityCertSerialNumber)
		if encodeErr_enc_authoritycertserialnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_authoritycertserialnumber, "authorityCertSerialNumber", "encoding", false)
		}
		retagged_enc_authoritycertserialnumber, tagErr_enc_authoritycertserialnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_authoritycertserialnumber)
		if tagErr_enc_authoritycertserialnumber != nil {
			return nil, qualifyBERError(tagErr_enc_authoritycertserialnumber, "authorityCertSerialNumber", "encoding", false)
		}
		enc_authoritycertserialnumber = retagged_enc_authoritycertserialnumber
		children = append(children, enc_authoritycertserialnumber...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AuthorityKeyIdentifier to DER format.
func (v *AuthorityKeyIdentifier) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AuthorityKeyIdentifier receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.KeyIdentifier != nil {
		enc_keyidentifier, encodeErr_enc_keyidentifier := ber.EncodeOctetString([]byte(*v.KeyIdentifier))
		if encodeErr_enc_keyidentifier != nil {
			return nil, qualifyBERError(encodeErr_enc_keyidentifier, "keyIdentifier", "encoding", true)
		}
		retagged_enc_keyidentifier, tagErr_enc_keyidentifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_keyidentifier)
		if tagErr_enc_keyidentifier != nil {
			return nil, qualifyBERError(tagErr_enc_keyidentifier, "keyIdentifier", "encoding", true)
		}
		enc_keyidentifier = retagged_enc_keyidentifier
		children = append(children, enc_keyidentifier...)
	}
	if v.AuthorityCertIssuer != nil {
		if len((v.AuthorityCertIssuer).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "authorityCertIssuer", "SIZE (1..MAX)", len((v.AuthorityCertIssuer).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_authoritycertissuer, err := MarshalDERGeneralNames(v.AuthorityCertIssuer)
		if err != nil {
			return nil, qualifyBERError(err, "authorityCertIssuer", "encoding", true)
		}
		retagged_enc_authoritycertissuer, tagErr_enc_authoritycertissuer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_authoritycertissuer)
		if tagErr_enc_authoritycertissuer != nil {
			return nil, qualifyBERError(tagErr_enc_authoritycertissuer, "authorityCertIssuer", "encoding", true)
		}
		enc_authoritycertissuer = retagged_enc_authoritycertissuer
		children = append(children, enc_authoritycertissuer...)
	}
	if v.AuthorityCertSerialNumber != nil {
		enc_authoritycertserialnumber, encodeErr_enc_authoritycertserialnumber := ber.EncodeBigInt(v.AuthorityCertSerialNumber)
		if encodeErr_enc_authoritycertserialnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_authoritycertserialnumber, "authorityCertSerialNumber", "encoding", true)
		}
		retagged_enc_authoritycertserialnumber, tagErr_enc_authoritycertserialnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_authoritycertserialnumber)
		if tagErr_enc_authoritycertserialnumber != nil {
			return nil, qualifyBERError(tagErr_enc_authoritycertserialnumber, "authorityCertSerialNumber", "encoding", true)
		}
		enc_authoritycertserialnumber = retagged_enc_authoritycertserialnumber
		children = append(children, enc_authoritycertserialnumber...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AuthorityKeyIdentifier as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes AuthorityKeyIdentifier from BER/DER format.
func (v *AuthorityKeyIdentifier) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AuthorityKeyIdentifier destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AuthorityKeyIdentifier
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = AuthorityKeyIdentifier{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding AuthorityKeyIdentifier SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "keyIdentifier", content[offset:])
				decodedTag_keyidentifier, n_keyidentifier, rawVal_keyidentifier, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "keyIdentifier", "decoding", false)
				}
				if decodedTag_keyidentifier.Class != tag.ClassContextSpecific || decodedTag_keyidentifier.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_keyidentifier), "keyIdentifier", "decoding", false)
				}
				decVal_keyidentifier, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_keyidentifier.Constructed, rawVal_keyidentifier, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "keyIdentifier", "decoding", false)
				}
				tmp_keyidentifier := KeyIdentifier(decVal_keyidentifier)
				v.KeyIdentifier = &tmp_keyidentifier
				if offset > len(content) || n_keyidentifier < 0 || n_keyidentifier > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
				ber.MarkPreflightTarget(opts, "authorityCertIssuer", content[offset:])
				decodedTag_authoritycertissuer, n_authoritycertissuer, rawVal_authoritycertissuer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "authorityCertIssuer", "decoding", false)
				}
				if decodedTag_authoritycertissuer.Class != tag.ClassContextSpecific || decodedTag_authoritycertissuer.Number != 1 || decodedTag_authoritycertissuer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_authoritycertissuer), "authorityCertIssuer", "decoding", false)
				}
				reconstructed_authoritycertissuer, reconstructionErr_authoritycertissuer := ber.EncodeSequence(rawVal_authoritycertissuer)
				if reconstructionErr_authoritycertissuer != nil {
					return qualifyBERError(reconstructionErr_authoritycertissuer, "authorityCertIssuer", "decoding", false)
				}
				dec_authoritycertissuer, unmErr := UnmarshalBERGeneralNames(reconstructed_authoritycertissuer, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "authorityCertIssuer"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "authorityCertIssuer", "decoding", false)
				}
				v.AuthorityCertIssuer = dec_authoritycertissuer
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.AuthorityCertIssuerIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_authoritycertissuer < 0 || n_authoritycertissuer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_authoritycertissuer
				if len((v.AuthorityCertIssuer).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "authorityCertIssuer", "SIZE (1..MAX)", len((v.AuthorityCertIssuer).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode authorityCertSerialNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "authorityCertSerialNumber", content[offset:])
				decodedTag_authoritycertserialnumber, n_authoritycertserialnumber, rawVal_authoritycertserialnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "authorityCertSerialNumber", "decoding", false)
				}
				if decodedTag_authoritycertserialnumber.Class != tag.ClassContextSpecific || decodedTag_authoritycertserialnumber.Number != 2 || decodedTag_authoritycertserialnumber.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_authoritycertserialnumber), "authorityCertSerialNumber", "decoding", false)
				}
				decVal_authoritycertserialnumber, intErr := ber.DecodeBigIntValue(rawVal_authoritycertserialnumber)
				if intErr != nil {
					return qualifyBERError(intErr, "authorityCertSerialNumber", "decoding", false)
				}
				v.AuthorityCertSerialNumber = decVal_authoritycertserialnumber
				if offset < 0 || offset >
					len(content) || n_authoritycertserialnumber < 0 || n_authoritycertserialnumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
func (v *PrivateKeyUsagePeriod) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PrivateKeyUsagePeriod receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PrivateKeyUsagePeriod) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.NotBefore != nil {
		enc_notbefore, encodeErr_enc_notbefore := ber.EncodeGeneralizedTime(*v.NotBefore)
		if encodeErr_enc_notbefore != nil {
			return nil, qualifyBERError(encodeErr_enc_notbefore, "notBefore", "encoding", false)
		}
		retagged_enc_notbefore, tagErr_enc_notbefore := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_notbefore)
		if tagErr_enc_notbefore != nil {
			return nil, qualifyBERError(tagErr_enc_notbefore, "notBefore", "encoding", false)
		}
		enc_notbefore = retagged_enc_notbefore
		children = append(children, enc_notbefore...)
	}
	if v.NotAfter != nil {
		enc_notafter, encodeErr_enc_notafter := ber.EncodeGeneralizedTime(*v.NotAfter)
		if encodeErr_enc_notafter != nil {
			return nil, qualifyBERError(encodeErr_enc_notafter, "notAfter", "encoding", false)
		}
		retagged_enc_notafter, tagErr_enc_notafter := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_notafter)
		if tagErr_enc_notafter != nil {
			return nil, qualifyBERError(tagErr_enc_notafter, "notAfter", "encoding", false)
		}
		enc_notafter = retagged_enc_notafter
		children = append(children, enc_notafter...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PrivateKeyUsagePeriod to DER format.
func (v *PrivateKeyUsagePeriod) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrivateKeyUsagePeriod receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.NotBefore != nil {
		enc_notbefore, encodeErr_enc_notbefore := ber.EncodeGeneralizedTimeDER(*v.NotBefore)
		if encodeErr_enc_notbefore != nil {
			return nil, qualifyBERError(encodeErr_enc_notbefore, "notBefore", "encoding", true)
		}
		retagged_enc_notbefore, tagErr_enc_notbefore := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_notbefore)
		if tagErr_enc_notbefore != nil {
			return nil, qualifyBERError(tagErr_enc_notbefore, "notBefore", "encoding", true)
		}
		enc_notbefore = retagged_enc_notbefore
		children = append(children, enc_notbefore...)
	}
	if v.NotAfter != nil {
		enc_notafter, encodeErr_enc_notafter := ber.EncodeGeneralizedTimeDER(*v.NotAfter)
		if encodeErr_enc_notafter != nil {
			return nil, qualifyBERError(encodeErr_enc_notafter, "notAfter", "encoding", true)
		}
		retagged_enc_notafter, tagErr_enc_notafter := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_notafter)
		if tagErr_enc_notafter != nil {
			return nil, qualifyBERError(tagErr_enc_notafter, "notAfter", "encoding", true)
		}
		enc_notafter = retagged_enc_notafter
		children = append(children, enc_notafter...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PrivateKeyUsagePeriod as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes PrivateKeyUsagePeriod from BER/DER format.
func (v *PrivateKeyUsagePeriod) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PrivateKeyUsagePeriod destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PrivateKeyUsagePeriod
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = PrivateKeyUsagePeriod{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PrivateKeyUsagePeriod SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "notBefore", content[offset:])
				decodedTag_notbefore, n_notbefore, rawVal_notbefore, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "notBefore", "decoding", false)
				}
				if decodedTag_notbefore.Class != tag.ClassContextSpecific || decodedTag_notbefore.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_notbefore), "notBefore", "decoding", false)
				}
				decVal_notbefore, timeErr := ber.DecodeImplicitGeneralizedTimeValue(decodedTag_notbefore.Constructed, rawVal_notbefore, opts...)
				if timeErr != nil {
					return qualifyBERError(timeErr, "notBefore", "decoding", false)
				}
				v.NotBefore = &decVal_notbefore
				if offset > len(content) || n_notbefore < 0 || n_notbefore > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_notbefore
			}
		}
	}
	// Decode notAfter
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "notAfter", content[offset:])
				decodedTag_notafter, n_notafter, rawVal_notafter, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "notAfter", "decoding", false)
				}
				if decodedTag_notafter.Class != tag.ClassContextSpecific || decodedTag_notafter.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_notafter), "notAfter", "decoding", false)
				}
				decVal_notafter, timeErr := ber.DecodeImplicitGeneralizedTimeValue(decodedTag_notafter.Constructed, rawVal_notafter, opts...)
				if timeErr != nil {
					return qualifyBERError(timeErr, "notAfter", "decoding", false)
				}
				v.NotAfter = &decVal_notafter
				if offset < 0 || offset >
					len(content) || n_notafter < 0 || n_notafter > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
func MarshalBERCertificatePolicies(collection *CertificatePolicies, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERCertificatePolicies(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERCertificatePolicies(collection *CertificatePolicies, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "CertificatePolicies", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERCertificatePolicies encodes a CertificatePolicies list to DER.
func MarshalDERCertificatePolicies(collection *CertificatePolicies) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "CertificatePolicies", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
		return nil, fmt.Errorf("%s: %w", "encoding CertificatePolicies as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERCertificatePolicies decodes a CertificatePolicies list from BER.
func UnmarshalBERCertificatePolicies(data []byte, opts ...ber.DecodeOption) (returnValue *CertificatePolicies, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERCertificatePolicies(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding CertificatePolicies", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CertificatePolicies", Cause: ber.ErrExtraData}
	}
	var result []PolicyInformation
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem PolicyInformation
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "CertificatePolicies", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &CertificatePolicies{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERCertificatePolicies(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes PolicyInformation to BER format.
func (v *PolicyInformation) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PolicyInformation receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PolicyInformation) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_policyidentifier, oidErr := ber.EncodeObjectIdentifierChecked(v.PolicyIdentifier)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "policyIdentifier", "encoding", false)
	}
	children = append(children, enc_policyidentifier...)
	if v.PolicyQualifiers != nil {
		if len((v.PolicyQualifiers).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "policyQualifiers", "SIZE (1..MAX)", len((v.PolicyQualifiers).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_policyqualifiers, err := MarshalBERPolicyInformationPolicyQualifiers(v.PolicyQualifiers, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "policyQualifiers"))...)
		if err != nil {
			return nil, qualifyBERError(err, "policyQualifiers", "encoding", false)
		}
		children = append(children, enc_policyqualifiers...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PolicyInformation to DER format.
func (v *PolicyInformation) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PolicyInformation receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_policyidentifier, oidErr := ber.EncodeObjectIdentifierChecked(v.PolicyIdentifier)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "policyIdentifier", "encoding", true)
	}
	children = append(children, enc_policyidentifier...)
	if v.PolicyQualifiers != nil {
		if len((v.PolicyQualifiers).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "policyQualifiers", "SIZE (1..MAX)", len((v.PolicyQualifiers).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_policyqualifiers, err := MarshalDERPolicyInformationPolicyQualifiers(v.PolicyQualifiers)
		if err != nil {
			return nil, qualifyBERError(err, "policyQualifiers", "encoding", true)
		}
		children = append(children, enc_policyqualifiers...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PolicyInformation as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes PolicyInformation from BER/DER format.
func (v *PolicyInformation) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PolicyInformation destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PolicyInformation
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = PolicyInformation{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PolicyInformation SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PolicyInformation", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode policyIdentifier
	if offset >= len(content) {
		return fmt.Errorf("missing required field policyIdentifier")
	}
	{
		ber.MarkPreflightTarget(opts, "policyIdentifier", content[offset:])
		val_policyidentifier, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "policyIdentifier", "decoding", false)
		}
		v.PolicyIdentifier = val_policyidentifier
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	// Decode policyQualifiers
	v.PolicyQualifiersIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "policyQualifiers", content[offset:])
				// Decode nested SEQUENCE_OF (PolicyInformationPolicyQualifiers)
				_, n_policyqualifiers, _, tlvErr_policyqualifiers := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_policyqualifiers != nil {
					return qualifyBERError(tlvErr_policyqualifiers, "policyQualifiers", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_policyqualifiers < 0 || n_policyqualifiers >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_policyqualifiers := content[offset : offset+n_policyqualifiers]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_policyqualifiers)
					if tagSz_ < len(tlv_policyqualifiers) && tlv_policyqualifiers[tagSz_] == 0x80 {
						v.PolicyQualifiersIndef_ = true
					}
				}
				dec_policyqualifiers, unmErr := UnmarshalBERPolicyInformationPolicyQualifiers(tlv_policyqualifiers, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "policyQualifiers"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "policyQualifiers", "decoding", false)
				}
				v.PolicyQualifiers = dec_policyqualifiers
				if offset < 0 || offset >
					len(content) || n_policyqualifiers < 0 || n_policyqualifiers >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_policyqualifiers
				if len((v.PolicyQualifiers).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "policyQualifiers", "SIZE (1..MAX)", len((v.PolicyQualifiers).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PolicyInformation", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PolicyQualifierInfo to BER format.
func (v *PolicyQualifierInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PolicyQualifierInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PolicyQualifierInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_policyqualifierid, oidErr := ber.EncodeObjectIdentifierChecked(v.PolicyQualifierId)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "policyQualifierId", "encoding", false)
	}
	children = append(children, enc_policyqualifierid...)
	enc_qualifier := v.Qualifier.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "qualifier", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_qualifier); rawErr != nil {
		return nil, qualifyBERError(rawErr, "qualifier", "encoding", false)
	}
	children = append(children, enc_qualifier...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PolicyQualifierInfo to DER format.
func (v *PolicyQualifierInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PolicyQualifierInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_policyqualifierid, oidErr := ber.EncodeObjectIdentifierChecked(v.PolicyQualifierId)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "policyQualifierId", "encoding", true)
	}
	children = append(children, enc_policyqualifierid...)
	enc_qualifier := v.Qualifier.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_qualifier); rawErr != nil {
		return nil, qualifyBERError(rawErr, "qualifier", "encoding", true)
	}
	children = append(children, enc_qualifier...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PolicyQualifierInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes PolicyQualifierInfo from BER/DER format.
func (v *PolicyQualifierInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PolicyQualifierInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PolicyQualifierInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = PolicyQualifierInfo{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PolicyQualifierInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PolicyQualifierInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode policyQualifierId
	if offset >= len(content) {
		return fmt.Errorf("missing required field policyQualifierId")
	}
	{
		ber.MarkPreflightTarget(opts, "policyQualifierId", content[offset:])
		val_policyqualifierid, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "policyQualifierId", "decoding", false)
		}
		v.PolicyQualifierId = val_policyqualifierid
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	// Decode qualifier
	if offset >= len(content) {
		return fmt.Errorf("missing required field qualifier")
	}
	{
		ber.MarkPreflightTarget(opts, "qualifier", content[offset:])
		_, n_qualifier, _, tlvErr_qualifier := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_qualifier != nil {
			return qualifyBERError(tlvErr_qualifier, "qualifier", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "qualifier", content[offset:], n_qualifier)
		if offset < 0 || offset >
			len(content) || n_qualifier < 0 || n_qualifier > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Qualifier = runtime.RawValue{Bytes: content[offset : offset+n_qualifier]}
		if offset < 0 || offset >
			len(content) || n_qualifier < 0 || n_qualifier > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_qualifier
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PolicyQualifierInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes UserNotice to BER format.
func (v *UserNotice) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UserNotice receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UserNotice) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.NoticeRef != nil {
		enc_noticeref, err := v.NoticeRef.MarshalBER(ber.ChildEncodeOptions(opts, "noticeRef")...)
		if err != nil {
			return nil, qualifyBERError(err, "noticeRef", "encoding", false)
		}
		children = append(children, enc_noticeref...)
	}
	if v.ExplicitText != nil {
		enc_explicittext, err := v.ExplicitText.MarshalBER(ber.ChildEncodeOptions(opts, "explicitText")...)
		if err != nil {
			return nil, qualifyBERError(err, "explicitText", "encoding", false)
		}
		children = append(children, enc_explicittext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UserNotice to DER format.
func (v *UserNotice) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UserNotice receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.NoticeRef != nil {
		enc_noticeref, err := v.NoticeRef.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "noticeRef", "encoding", true)
		}
		children = append(children, enc_noticeref...)
	}
	if v.ExplicitText != nil {
		enc_explicittext, err := v.ExplicitText.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "explicitText", "encoding", true)
		}
		children = append(children, enc_explicittext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding UserNotice as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes UserNotice from BER/DER format.
func (v *UserNotice) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UserNotice destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe UserNotice
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = UserNotice{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding UserNotice SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "noticeRef", content[offset:])
				// Decode nested SEQUENCE (NoticeReference)
				_, n_noticeref, _, tlvErr_noticeref := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_noticeref != nil {
					return qualifyBERError(tlvErr_noticeref, "noticeRef", "decoding", false)
				}
				var dec_noticeref NoticeReference
				if offset > len(content) || n_noticeref < 0 || n_noticeref > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_noticeref.UnmarshalBER(content[offset:offset+n_noticeref], ber.ChildDecodeOptions(opts, "noticeRef")...); unmErr != nil {
					return qualifyBERError(unmErr, "noticeRef", "decoding", false)
				}
				v.NoticeRef = &dec_noticeref
				if offset > len(content) || n_noticeref < 0 || n_noticeref > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_noticeref
			}
		}
	}
	// Decode explicitText
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 22) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 26) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 30) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 12) {
				ber.MarkPreflightTarget(opts, "explicitText", content[offset:])
				// Decode nested CHOICE (DisplayText)
				_, n_explicittext, _, tlvErr_explicittext := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_explicittext != nil {
					return qualifyBERError(tlvErr_explicittext, "explicitText", "decoding", false)
				}
				var dec_explicittext DisplayText
				if offset < 0 || offset >
					len(content) || n_explicittext < 0 || n_explicittext >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_explicittext.UnmarshalBER(content[offset:offset+n_explicittext], ber.ChildDecodeOptions(opts, "explicitText")...); unmErr != nil {
					return qualifyBERError(unmErr, "explicitText", "decoding", false)
				}
				v.ExplicitText = &dec_explicittext
				if offset < 0 || offset >
					len(content) || n_explicittext < 0 || n_explicittext >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
func (v *NoticeReference) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: NoticeReference receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NoticeReference) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_organization, err := v.Organization.MarshalBER(ber.ChildEncodeOptions(opts, "organization")...)
	if err != nil {
		return nil, qualifyBERError(err, "organization", "encoding", false)
	}
	children = append(children, enc_organization...)
	if v.NoticeNumbers == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "noticeNumbers", "encoding", false)
	}
	enc_noticenumbers, err := MarshalBERNoticeReferenceNoticeNumbers(v.NoticeNumbers, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "noticeNumbers"))...)
	if err != nil {
		return nil, qualifyBERError(err, "noticeNumbers", "encoding", false)
	}
	children = append(children, enc_noticenumbers...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes NoticeReference to DER format.
func (v *NoticeReference) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoticeReference receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_organization, err := v.Organization.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "organization", "encoding", true)
	}
	children = append(children, enc_organization...)
	if v.NoticeNumbers == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "noticeNumbers", "encoding", true)
	}
	enc_noticenumbers, err := MarshalDERNoticeReferenceNoticeNumbers(v.NoticeNumbers)
	if err != nil {
		return nil, qualifyBERError(err, "noticeNumbers", "encoding", true)
	}
	children = append(children, enc_noticenumbers...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding NoticeReference as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes NoticeReference from BER/DER format.
func (v *NoticeReference) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NoticeReference destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe NoticeReference
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = NoticeReference{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding NoticeReference SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoticeReference", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode organization
	if offset >= len(content) {
		return fmt.Errorf("missing required field organization")
	}
	{
		ber.MarkPreflightTarget(opts, "organization", content[offset:])
		// Decode nested CHOICE (DisplayText)
		_, n_organization, _, tlvErr_organization := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_organization != nil {
			return qualifyBERError(tlvErr_organization, "organization", "decoding", false)
		}
		if offset > len(content) || n_organization < 0 || n_organization > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Organization.UnmarshalBER(content[offset:offset+n_organization], ber.ChildDecodeOptions(opts, "organization")...); unmErr != nil {
			return qualifyBERError(unmErr, "organization", "decoding", false)
		}
		if offset > len(content) || n_organization < 0 || n_organization > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_organization
	}
	// Decode noticeNumbers
	if offset >= len(content) {
		return fmt.Errorf("missing required field noticeNumbers")
	}
	{
		v.NoticeNumbersIndef_ = false
		ber.MarkPreflightTarget(opts, "noticeNumbers", content[offset:])
		// Decode nested SEQUENCE_OF (NoticeReferenceNoticeNumbers)
		_, n_noticenumbers, _, tlvErr_noticenumbers := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_noticenumbers != nil {
			return qualifyBERError(tlvErr_noticenumbers, "noticeNumbers", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_noticenumbers < 0 || n_noticenumbers >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tlv_noticenumbers := content[offset : offset+n_noticenumbers]
		{
			_, tagSz_, _ := ber.DecodeTag(tlv_noticenumbers)
			if tagSz_ < len(tlv_noticenumbers) && tlv_noticenumbers[tagSz_] == 0x80 {
				v.NoticeNumbersIndef_ = true
			}
		}
		dec_noticenumbers, unmErr := UnmarshalBERNoticeReferenceNoticeNumbers(tlv_noticenumbers, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "noticeNumbers"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "noticeNumbers", "decoding", false)
		}
		v.NoticeNumbers = dec_noticenumbers
		if offset < 0 || offset >
			len(content) || n_noticenumbers < 0 || n_noticenumbers >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_noticenumbers
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "NoticeReference", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes DisplayText to BER format.
func (v *DisplayText) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DisplayText receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DisplayText) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case DisplayTextChoiceIa5String:
		if v.Ia5String == nil {
			return nil, fmt.Errorf("%w: choice DisplayText: ia5String is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(22, *v.Ia5String)
		if stringErr != nil {
			return nil, qualifyBERError(stringErr, "ia5String", "encoding", false)
		}
		for _, character := range []byte(*v.Ia5String) {
			if !(character >= 0x0 && character <= 0x7f) {
				if constraintErr := ber.CheckEncodedValue(opts, "ia5String", "IA5String character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return nil, constraintErr
				}
				break
			}
		}
		if len(*v.Ia5String) < 1 || len(*v.Ia5String) > 200 {
			if constraintErr := ber.CheckEncodedLength(opts, "ia5String", "SIZE (1..200)", len(*v.Ia5String)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case DisplayTextChoiceVisibleString:
		if v.VisibleString == nil {
			return nil, fmt.Errorf("%w: choice DisplayText: visibleString is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(26, *v.VisibleString)
		if stringErr != nil {
			return nil, qualifyBERError(stringErr, "visibleString", "encoding", false)
		}
		for _, character := range []byte(*v.VisibleString) {
			if !(character >= ' ' && character <= '~') {
				if constraintErr := ber.CheckEncodedValue(opts, "visibleString", "VisibleString character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return nil, constraintErr
				}
				break
			}
		}
		if len(*v.VisibleString) < 1 || len(*v.VisibleString) > 200 {
			if constraintErr := ber.CheckEncodedLength(opts, "visibleString", "SIZE (1..200)", len(*v.VisibleString)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	case DisplayTextChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("%w: choice DisplayText: bmpString is nil", ber.ErrInvalidValue)
		}
		enc_2, stringErr := ber.EncodeStringTagChecked(30, *v.BmpString)
		if stringErr != nil {
			return nil, qualifyBERError(stringErr, "bmpString", "encoding", false)
		}
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 200 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmpString", "SIZE (1..200)", len([]rune(*v.BmpString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_2, nil
	case DisplayTextChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("%w: choice DisplayText: utf8String is nil", ber.ErrInvalidValue)
		}
		enc_3, stringErr := ber.EncodeStringTagChecked(12, *v.Utf8String)
		if stringErr != nil {
			return nil, qualifyBERError(stringErr, "utf8String", "encoding", false)
		}
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 200 {
			if constraintErr := ber.CheckEncodedLength(opts, "utf8String", "SIZE (1..200)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DisplayText", v.Choice)
	}
}

// MarshalDER encodes DisplayText to DER format.
func (v *DisplayText) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DisplayText receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case DisplayTextChoiceIa5String:
			return nil, qualifyBERError(err, "ia5String", "encoding", true)
		case DisplayTextChoiceVisibleString:
			return nil, qualifyBERError(err, "visibleString", "encoding", true)
		case DisplayTextChoiceBmpString:
			return nil, qualifyBERError(err, "bmpString", "encoding", true)
		case DisplayTextChoiceUtf8String:
			return nil, qualifyBERError(err, "utf8String", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding DisplayText as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes DisplayText from BER/DER format.
func (v *DisplayText) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DisplayText destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe DisplayText
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = DisplayText{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for DisplayText CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DisplayText: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding DisplayText CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DisplayText", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 22 {
		v.Choice = DisplayTextChoiceIa5String
		ber.MarkPreflightTarget(opts, "ia5String", choiceData)
		decVal, _, strErr := ber.DecodeString(choiceData, 22, opts...)
		if strErr != nil {
			return qualifyBERError(strErr, "ia5String", "decoding", false)
		}
		v.Ia5String = &decVal
		for _, character := range []byte(*v.Ia5String) {
			if !(character >= 0x0 && character <= 0x7f) {
				if constraintErr := ber.CheckDecodedValue(opts, "ia5String", "IA5String character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return constraintErr
				}
				break
			}
		}
		if len(*v.Ia5String) < 1 || len(*v.Ia5String) > 200 {
			if constraintErr := ber.CheckDecodedLength(opts, "ia5String", "SIZE (1..200)", len(*v.Ia5String)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 26 {
		v.Choice = DisplayTextChoiceVisibleString
		ber.MarkPreflightTarget(opts, "visibleString", choiceData)
		decVal, _, strErr := ber.DecodeString(choiceData, 26, opts...)
		if strErr != nil {
			return qualifyBERError(strErr, "visibleString", "decoding", false)
		}
		v.VisibleString = &decVal
		for _, character := range []byte(*v.VisibleString) {
			if !(character >= ' ' && character <= '~') {
				if constraintErr := ber.CheckDecodedValue(opts, "visibleString", "VisibleString character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return constraintErr
				}
				break
			}
		}
		if len(*v.VisibleString) < 1 || len(*v.VisibleString) > 200 {
			if constraintErr := ber.CheckDecodedLength(opts, "visibleString", "SIZE (1..200)", len(*v.VisibleString)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = DisplayTextChoiceBmpString
		ber.MarkPreflightTarget(opts, "bmpString", choiceData)
		decVal, _, strErr := ber.DecodeString(choiceData, 30, opts...)
		if strErr != nil {
			return qualifyBERError(strErr, "bmpString", "decoding", false)
		}
		v.BmpString = &decVal
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 200 {
			if constraintErr := ber.CheckDecodedLength(opts, "bmpString", "SIZE (1..200)", len([]rune(*v.BmpString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = DisplayTextChoiceUtf8String
		ber.MarkPreflightTarget(opts, "utf8String", choiceData)
		decVal, _, strErr := ber.DecodeString(choiceData, 12, opts...)
		if strErr != nil {
			return qualifyBERError(strErr, "utf8String", "decoding", false)
		}
		v.Utf8String = &decVal
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 200 {
			if constraintErr := ber.CheckDecodedLength(opts, "utf8String", "SIZE (1..200)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for DisplayText CHOICE", peekTag)
	}
	return nil
}

// MarshalBERPolicyMappings encodes a PolicyMappings list to BER.
func MarshalBERPolicyMappings(collection *PolicyMappings, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERPolicyMappings(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERPolicyMappings(collection *PolicyMappings, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "PolicyMappings", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERPolicyMappings encodes a PolicyMappings list to DER.
func MarshalDERPolicyMappings(collection *PolicyMappings) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "PolicyMappings", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
		return nil, fmt.Errorf("%s: %w", "encoding PolicyMappings as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERPolicyMappings decodes a PolicyMappings list from BER.
func UnmarshalBERPolicyMappings(data []byte, opts ...ber.DecodeOption) (returnValue *PolicyMappings, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERPolicyMappings(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding PolicyMappings", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PolicyMappings", Cause: ber.ErrExtraData}
	}
	var result []PolicyMappingsElem
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem PolicyMappingsElem
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "PolicyMappings", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &PolicyMappings{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERPolicyMappings(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERGeneralNames encodes a GeneralNames list to BER.
func MarshalBERGeneralNames(collection *GeneralNames, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERGeneralNames(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERGeneralNames(collection *GeneralNames, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "GeneralNames", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERGeneralNames encodes a GeneralNames list to DER.
func MarshalDERGeneralNames(collection *GeneralNames) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "GeneralNames", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
		return nil, fmt.Errorf("%s: %w", "encoding GeneralNames as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERGeneralNames decodes a GeneralNames list from BER.
func UnmarshalBERGeneralNames(data []byte, opts ...ber.DecodeOption) (returnValue *GeneralNames, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERGeneralNames(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding GeneralNames", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "GeneralNames", Cause: ber.ErrExtraData}
	}
	var result []GeneralName
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem GeneralName
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "GeneralNames", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &GeneralNames{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERGeneralNames(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes GeneralName to BER format.
func (v *GeneralName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: GeneralName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *GeneralName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case GeneralNameChoiceOtherName:
		if v.OtherName == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: otherName is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.OtherName.MarshalBER(ber.ChildEncodeOptions(opts, "otherName")...)
		if err != nil {
			return nil, qualifyBERError(err, "otherName", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "otherName", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case GeneralNameChoiceRfc822Name:
		if v.Rfc822Name == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: rfc822Name is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(22, *v.Rfc822Name)
		if stringErr != nil {
			return nil, qualifyBERError(stringErr, "rfc822Name", "encoding", false)
		}
		for _, character := range []byte(*v.Rfc822Name) {
			if !(character >= 0x0 && character <= 0x7f) {
				if constraintErr := ber.CheckEncodedValue(opts, "rfc822Name", "IA5String character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return nil, constraintErr
				}
				break
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "rfc822Name", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case GeneralNameChoiceDNSName:
		if v.DNSName == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: dNSName is nil", ber.ErrInvalidValue)
		}
		enc_2, stringErr := ber.EncodeStringTagChecked(22, *v.DNSName)
		if stringErr != nil {
			return nil, qualifyBERError(stringErr, "dNSName", "encoding", false)
		}
		for _, character := range []byte(*v.DNSName) {
			if !(character >= 0x0 && character <= 0x7f) {
				if constraintErr := ber.CheckEncodedValue(opts, "dNSName", "IA5String character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return nil, constraintErr
				}
				break
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "dNSName", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case GeneralNameChoiceX400Address:
		if v.X400Address == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: x400Address is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.X400Address.MarshalBER(ber.ChildEncodeOptions(opts, "x400Address")...)
		if err != nil {
			return nil, qualifyBERError(err, "x400Address", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "x400Address", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	case GeneralNameChoiceDirectoryName:
		if v.DirectoryName == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: directoryName is nil", ber.ErrInvalidValue)
		}
		enc_4, err := v.DirectoryName.MarshalBER(ber.ChildEncodeOptions(opts, "directoryName")...)
		if err != nil {
			return nil, qualifyBERError(err, "directoryName", "encoding", false)
		}
		{
			var encodeErr error
			enc_4, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 4, enc_4)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "directoryName", "encoding", false)
			}
		}
		return enc_4, nil
	case GeneralNameChoiceEdiPartyName:
		if v.EdiPartyName == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: ediPartyName is nil", ber.ErrInvalidValue)
		}
		enc_5, err := v.EdiPartyName.MarshalBER(ber.ChildEncodeOptions(opts, "ediPartyName")...)
		if err != nil {
			return nil, qualifyBERError(err, "ediPartyName", "encoding", false)
		}
		retagged_enc_5, tagErr_enc_5 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_5)
		if tagErr_enc_5 != nil {
			return nil, qualifyBERError(tagErr_enc_5, "ediPartyName", "encoding", false)
		}
		enc_5 = retagged_enc_5
		return enc_5, nil
	case GeneralNameChoiceUniformResourceIdentifier:
		if v.UniformResourceIdentifier == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: uniformResourceIdentifier is nil", ber.ErrInvalidValue)
		}
		enc_6, stringErr := ber.EncodeStringTagChecked(22, *v.UniformResourceIdentifier)
		if stringErr != nil {
			return nil, qualifyBERError(stringErr, "uniformResourceIdentifier", "encoding", false)
		}
		for _, character := range []byte(*v.UniformResourceIdentifier) {
			if !(character >= 0x0 && character <= 0x7f) {
				if constraintErr := ber.CheckEncodedValue(opts, "uniformResourceIdentifier", "IA5String character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return nil, constraintErr
				}
				break
			}
		}
		retagged_enc_6, tagErr_enc_6 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_6)
		if tagErr_enc_6 != nil {
			return nil, qualifyBERError(tagErr_enc_6, "uniformResourceIdentifier", "encoding", false)
		}
		enc_6 = retagged_enc_6
		return enc_6, nil
	case GeneralNameChoiceIPAddress:
		enc_7, encodeErr_enc_7 := ber.EncodeOctetString(v.IPAddress)
		if encodeErr_enc_7 != nil {
			return nil, qualifyBERError(encodeErr_enc_7, "iPAddress", "encoding", false)
		}
		retagged_enc_7, tagErr_enc_7 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_7)
		if tagErr_enc_7 != nil {
			return nil, qualifyBERError(tagErr_enc_7, "iPAddress", "encoding", false)
		}
		enc_7 = retagged_enc_7
		return enc_7, nil
	case GeneralNameChoiceRegisteredID:
		if v.RegisteredID == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: registeredID is nil", ber.ErrInvalidValue)
		}
		enc_8, oidErr := ber.EncodeObjectIdentifierChecked(*v.RegisteredID)
		if oidErr != nil {
			return nil, qualifyBERError(oidErr, "registeredID", "encoding", false)
		}
		retagged_enc_8, tagErr_enc_8 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_8)
		if tagErr_enc_8 != nil {
			return nil, qualifyBERError(tagErr_enc_8, "registeredID", "encoding", false)
		}
		enc_8 = retagged_enc_8
		return enc_8, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for GeneralName", v.Choice)
	}
}

// MarshalDER encodes GeneralName to DER format.
func (v *GeneralName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: GeneralName receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case GeneralNameChoiceOtherName:
		if v.OtherName == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: otherName is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.OtherName.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "otherName", "encoding", true)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "otherName", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "otherName", "encoding", true)
		}
		return enc_der_0, nil
	case GeneralNameChoiceX400Address:
		if v.X400Address == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: x400Address is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.X400Address.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "x400Address", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "x400Address", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "x400Address", "encoding", true)
		}
		return enc_der_3, nil
	case GeneralNameChoiceDirectoryName:
		if v.DirectoryName == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: directoryName is nil", ber.ErrInvalidValue)
		}
		enc_der_4, err := v.DirectoryName.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "directoryName", "encoding", true)
		}
		{
			var encodeErr error
			enc_der_4, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_4)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "directoryName", "encoding", true)
			}
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_4); derErr != nil {
			return nil, qualifyBERError(derErr, "directoryName", "encoding", true)
		}
		return enc_der_4, nil
	case GeneralNameChoiceEdiPartyName:
		if v.EdiPartyName == nil {
			return nil, fmt.Errorf("%w: choice GeneralName: ediPartyName is nil", ber.ErrInvalidValue)
		}
		enc_der_5, err := v.EdiPartyName.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "ediPartyName", "encoding", true)
		}
		retagged_enc_der_5, tagErr_enc_der_5 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_der_5)
		if tagErr_enc_der_5 != nil {
			return nil, qualifyBERError(tagErr_enc_der_5, "ediPartyName", "encoding", true)
		}
		enc_der_5 = retagged_enc_der_5
		if derErr := ber.ValidateDEREncodedElement(enc_der_5); derErr != nil {
			return nil, qualifyBERError(derErr, "ediPartyName", "encoding", true)
		}
		return enc_der_5, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case GeneralNameChoiceOtherName:
			return nil, qualifyBERError(err, "otherName", "encoding", true)
		case GeneralNameChoiceRfc822Name:
			return nil, qualifyBERError(err, "rfc822Name", "encoding", true)
		case GeneralNameChoiceDNSName:
			return nil, qualifyBERError(err, "dNSName", "encoding", true)
		case GeneralNameChoiceX400Address:
			return nil, qualifyBERError(err, "x400Address", "encoding", true)
		case GeneralNameChoiceDirectoryName:
			return nil, qualifyBERError(err, "directoryName", "encoding", true)
		case GeneralNameChoiceEdiPartyName:
			return nil, qualifyBERError(err, "ediPartyName", "encoding", true)
		case GeneralNameChoiceUniformResourceIdentifier:
			return nil, qualifyBERError(err, "uniformResourceIdentifier", "encoding", true)
		case GeneralNameChoiceIPAddress:
			return nil, qualifyBERError(err, "iPAddress", "encoding", true)
		case GeneralNameChoiceRegisteredID:
			return nil, qualifyBERError(err, "registeredID", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding GeneralName as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes GeneralName from BER/DER format.
func (v *GeneralName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: GeneralName destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe GeneralName
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = GeneralName{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for GeneralName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for GeneralName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding GeneralName CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "GeneralName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = GeneralNameChoiceOtherName
		ber.MarkPreflightTarget(opts, "otherName", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "otherName", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec AnotherName
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "otherName")...); unmErr != nil {
			return qualifyBERError(unmErr, "otherName", "decoding", false)
		}
		v.OtherName = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = GeneralNameChoiceRfc822Name
		ber.MarkPreflightTarget(opts, "rfc822Name", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "rfc822Name", "decoding", false)
		}
		decVal, stringErr := ber.DecodeImplicitStringValue(22, peekTag.Constructed, rawVal, opts...)
		if stringErr != nil {
			return qualifyBERError(stringErr, "rfc822Name", "decoding", false)
		}
		v.Rfc822Name = &decVal
		for _, character := range []byte(*v.Rfc822Name) {
			if !(character >= 0x0 && character <= 0x7f) {
				if constraintErr := ber.CheckDecodedValue(opts, "rfc822Name", "IA5String character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return constraintErr
				}
				break
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = GeneralNameChoiceDNSName
		ber.MarkPreflightTarget(opts, "dNSName", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "dNSName", "decoding", false)
		}
		decVal, stringErr := ber.DecodeImplicitStringValue(22, peekTag.Constructed, rawVal, opts...)
		if stringErr != nil {
			return qualifyBERError(stringErr, "dNSName", "decoding", false)
		}
		v.DNSName = &decVal
		for _, character := range []byte(*v.DNSName) {
			if !(character >= 0x0 && character <= 0x7f) {
				if constraintErr := ber.CheckDecodedValue(opts, "dNSName", "IA5String character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return constraintErr
				}
				break
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = GeneralNameChoiceX400Address
		ber.MarkPreflightTarget(opts, "x400Address", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "x400Address", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ORAddress
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "x400Address")...); unmErr != nil {
			return qualifyBERError(unmErr, "x400Address", "decoding", false)
		}
		v.X400Address = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = GeneralNameChoiceDirectoryName
		ber.MarkPreflightTarget(opts, "directoryName", choiceData)
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "directoryName", "decoding", false)
		}
		ber.MarkPreflightTarget(opts, "directoryName", innerData)
		_, innerUsed, _, innerErr := ber.DecodeTLV(innerData, opts...)
		if innerErr != nil {
			return qualifyBERError(innerErr, "directoryName", "decoding", false)
		}
		if innerUsed != len(innerData) {
			return qualifyBERError(ber.ErrExtraData, "directoryName", "decoding", false)
		}
		var dec Name
		if unmErr := dec.UnmarshalBER(innerData, ber.ChildDecodeOptions(opts, "directoryName")...); unmErr != nil {
			return qualifyBERError(unmErr, "directoryName", "decoding", false)
		}
		v.DirectoryName = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == true {
		v.Choice = GeneralNameChoiceEdiPartyName
		ber.MarkPreflightTarget(opts, "ediPartyName", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "ediPartyName", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec EDIPartyName
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "ediPartyName")...); unmErr != nil {
			return qualifyBERError(unmErr, "ediPartyName", "decoding", false)
		}
		v.EdiPartyName = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
		v.Choice = GeneralNameChoiceUniformResourceIdentifier
		ber.MarkPreflightTarget(opts, "uniformResourceIdentifier", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "uniformResourceIdentifier", "decoding", false)
		}
		decVal, stringErr := ber.DecodeImplicitStringValue(22, peekTag.Constructed, rawVal, opts...)
		if stringErr != nil {
			return qualifyBERError(stringErr, "uniformResourceIdentifier", "decoding", false)
		}
		v.UniformResourceIdentifier = &decVal
		for _, character := range []byte(*v.UniformResourceIdentifier) {
			if !(character >= 0x0 && character <= 0x7f) {
				if constraintErr := ber.CheckDecodedValue(opts, "uniformResourceIdentifier", "IA5String character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return constraintErr
				}
				break
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
		v.Choice = GeneralNameChoiceIPAddress
		ber.MarkPreflightTarget(opts, "iPAddress", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "iPAddress", "decoding", false)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "iPAddress", "decoding", false)
		}
		v.IPAddress = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 && peekTag.Constructed == false {
		v.Choice = GeneralNameChoiceRegisteredID
		ber.MarkPreflightTarget(opts, "registeredID", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "registeredID", "decoding", false)
		}
		decVal, oidErr := ber.DecodeOIDValue(rawVal)
		if oidErr != nil {
			return qualifyBERError(oidErr, "registeredID", "decoding", false)
		}
		v.RegisteredID = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for GeneralName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AnotherName to BER format.
func (v *AnotherName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AnotherName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AnotherName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_typeid, oidErr := ber.EncodeObjectIdentifierChecked(v.TypeId)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "type-id", "encoding", false)
	}
	children = append(children, enc_typeid...)
	enc_value := v.Value.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "value", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_value); rawErr != nil {
		return nil, qualifyBERError(rawErr, "value", "encoding", false)
	}
	{
		var encodeErr error
		enc_value, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_value)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "value", "encoding", false)
		}
	}
	children = append(children, enc_value...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AnotherName to DER format.
func (v *AnotherName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AnotherName receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_typeid, oidErr := ber.EncodeObjectIdentifierChecked(v.TypeId)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "type-id", "encoding", true)
	}
	children = append(children, enc_typeid...)
	enc_value := v.Value.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_value); rawErr != nil {
		return nil, qualifyBERError(rawErr, "value", "encoding", true)
	}
	{
		var encodeErr error
		enc_value, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_value)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "value", "encoding", true)
		}
	}
	children = append(children, enc_value...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AnotherName as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes AnotherName from BER/DER format.
func (v *AnotherName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AnotherName destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AnotherName
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = AnotherName{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding AnotherName SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AnotherName", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode type-id
	if offset >= len(content) {
		return fmt.Errorf("missing required field type-id")
	}
	{
		ber.MarkPreflightTarget(opts, "type-id", content[offset:])
		val_typeid, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "type-id", "decoding", false)
		}
		v.TypeId = val_typeid
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	// Decode value
	if offset >= len(content) {
		return fmt.Errorf("missing required field value")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for value, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "value", content[offset:])
		decodedTag_value, n_value, innerData_value, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "value", "decoding", false)
		}
		if decodedTag_value.Class != tag.ClassContextSpecific || decodedTag_value.Number != 0 || decodedTag_value.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_value), "value", "decoding", false)
		}
		_, innerUsed_value, _, innerErr_value := ber.DecodeTLV(innerData_value, opts...)
		if innerErr_value != nil {
			return qualifyBERError(innerErr_value, "value", "decoding", false)
		}
		if innerUsed_value != len(innerData_value) {
			return qualifyBERError(ber.ErrExtraData, "value", "decoding", false)
		}
		// Decode inner value from explicit tag wrapper
		ber.MarkPreflightTarget(opts, "value", innerData_value)
		v.Value = runtime.RawValue{Bytes: innerData_value}
		if offset < 0 || offset >
			len(content) || n_value < 0 || n_value > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_value
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AnotherName", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EDIPartyName to BER format.
func (v *EDIPartyName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: EDIPartyName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EDIPartyName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.NameAssigner != nil {
		enc_nameassigner, err := v.NameAssigner.MarshalBER(ber.ChildEncodeOptions(opts, "nameAssigner")...)
		if err != nil {
			return nil, qualifyBERError(err, "nameAssigner", "encoding", false)
		}
		{
			var encodeErr error
			enc_nameassigner, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_nameassigner)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "nameAssigner", "encoding", false)
			}
		}
		children = append(children, enc_nameassigner...)
	}
	enc_partyname, err := v.PartyName.MarshalBER(ber.ChildEncodeOptions(opts, "partyName")...)
	if err != nil {
		return nil, qualifyBERError(err, "partyName", "encoding", false)
	}
	{
		var encodeErr error
		enc_partyname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_partyname)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "partyName", "encoding", false)
		}
	}
	children = append(children, enc_partyname...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes EDIPartyName to DER format.
func (v *EDIPartyName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EDIPartyName receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.NameAssigner != nil {
		enc_nameassigner, err := v.NameAssigner.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "nameAssigner", "encoding", true)
		}
		{
			var encodeErr error
			enc_nameassigner, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_nameassigner)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "nameAssigner", "encoding", true)
			}
		}
		children = append(children, enc_nameassigner...)
	}
	enc_partyname, err := v.PartyName.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "partyName", "encoding", true)
	}
	{
		var encodeErr error
		enc_partyname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_partyname)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "partyName", "encoding", true)
		}
	}
	children = append(children, enc_partyname...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding EDIPartyName as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes EDIPartyName from BER/DER format.
func (v *EDIPartyName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EDIPartyName destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe EDIPartyName
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = EDIPartyName{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding EDIPartyName SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "nameAssigner", content[offset:])
				decodedTag_nameassigner, n_nameassigner, innerData_nameassigner, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "nameAssigner", "decoding", false)
				}
				if decodedTag_nameassigner.Class != tag.ClassContextSpecific || decodedTag_nameassigner.Number != 0 || decodedTag_nameassigner.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nameassigner), "nameAssigner", "decoding", false)
				}
				_, innerUsed_nameassigner, _, innerErr_nameassigner := ber.DecodeTLV(innerData_nameassigner, opts...)
				if innerErr_nameassigner != nil {
					return qualifyBERError(innerErr_nameassigner, "nameAssigner", "decoding", false)
				}
				if innerUsed_nameassigner != len(innerData_nameassigner) {
					return qualifyBERError(ber.ErrExtraData, "nameAssigner", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "nameAssigner", innerData_nameassigner)
				var dec_nameassigner DirectoryString
				if unmErr := dec_nameassigner.UnmarshalBER(innerData_nameassigner, ber.ChildDecodeOptions(opts, "nameAssigner")...); unmErr != nil {
					return qualifyBERError(unmErr, "nameAssigner", "decoding", false)
				}
				v.NameAssigner = &dec_nameassigner
				if offset > len(content) || n_nameassigner < 0 || n_nameassigner > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
	{
		ber.MarkPreflightTarget(opts, "partyName", content[offset:])
		decodedTag_partyname, n_partyname, innerData_partyname, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "partyName", "decoding", false)
		}
		if decodedTag_partyname.Class != tag.ClassContextSpecific || decodedTag_partyname.Number != 1 || decodedTag_partyname.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_partyname), "partyName", "decoding", false)
		}
		_, innerUsed_partyname, _, innerErr_partyname := ber.DecodeTLV(innerData_partyname, opts...)
		if innerErr_partyname != nil {
			return qualifyBERError(innerErr_partyname, "partyName", "decoding", false)
		}
		if innerUsed_partyname != len(innerData_partyname) {
			return qualifyBERError(ber.ErrExtraData, "partyName", "decoding", false)
		}
		// Decode inner value from explicit tag wrapper
		ber.MarkPreflightTarget(opts, "partyName", innerData_partyname)
		if unmErr := v.PartyName.UnmarshalBER(innerData_partyname, ber.ChildDecodeOptions(opts, "partyName")...); unmErr != nil {
			return qualifyBERError(unmErr, "partyName", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_partyname < 0 || n_partyname > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_partyname
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EDIPartyName", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERSubjectDirectoryAttributes encodes a SubjectDirectoryAttributes list to BER.
func MarshalBERSubjectDirectoryAttributes(collection *SubjectDirectoryAttributes, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERSubjectDirectoryAttributes(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERSubjectDirectoryAttributes(collection *SubjectDirectoryAttributes, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "SubjectDirectoryAttributes", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERSubjectDirectoryAttributes encodes a SubjectDirectoryAttributes list to DER.
func MarshalDERSubjectDirectoryAttributes(collection *SubjectDirectoryAttributes) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "SubjectDirectoryAttributes", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
		return nil, fmt.Errorf("%s: %w", "encoding SubjectDirectoryAttributes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERSubjectDirectoryAttributes decodes a SubjectDirectoryAttributes list from BER.
func UnmarshalBERSubjectDirectoryAttributes(data []byte, opts ...ber.DecodeOption) (returnValue *SubjectDirectoryAttributes, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERSubjectDirectoryAttributes(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SubjectDirectoryAttributes", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SubjectDirectoryAttributes", Cause: ber.ErrExtraData}
	}
	var result []Attribute
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem Attribute
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "SubjectDirectoryAttributes", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SubjectDirectoryAttributes{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERSubjectDirectoryAttributes(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes BasicConstraints to BER format.
func (v *BasicConstraints) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BasicConstraints receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BasicConstraints) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CA != nil {
		var enc_ca []byte
		if ber.BERReplayEnabled(opts) && v.CARaw_ != 0 && *v.CA {
			enc_ca = ber.EncodeBooleanRaw(v.CARaw_)
		} else {
			enc_ca = ber.EncodeBoolean(*v.CA)
		}
		children = append(children, enc_ca...)
	}
	if v.PathLenConstraint != nil {
		if !(v.PathLenConstraint.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
			if constraintErr := ber.CheckEncodedValue(opts, "pathLenConstraint", "(0..MAX)", fmt.Sprint(v.PathLenConstraint)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pathlenconstraint, encodeErr_enc_pathlenconstraint := ber.EncodeBigInt(v.PathLenConstraint)
		if encodeErr_enc_pathlenconstraint != nil {
			return nil, qualifyBERError(encodeErr_enc_pathlenconstraint, "pathLenConstraint", "encoding", false)
		}
		children = append(children, enc_pathlenconstraint...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes BasicConstraints to DER format.
func (v *BasicConstraints) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BasicConstraints receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CA != nil {
		enc_ca := ber.EncodeBoolean(*v.CA)
		if string(enc_ca) != "\x01\x01\x00" {
			children = append(children, enc_ca...)
		}
	}
	if v.PathLenConstraint != nil {
		if !(v.PathLenConstraint.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
			if constraintErr := ber.CheckEncodedValue(nil, "pathLenConstraint", "(0..MAX)", fmt.Sprint(v.PathLenConstraint)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pathlenconstraint, encodeErr_enc_pathlenconstraint := ber.EncodeBigInt(v.PathLenConstraint)
		if encodeErr_enc_pathlenconstraint != nil {
			return nil, qualifyBERError(encodeErr_enc_pathlenconstraint, "pathLenConstraint", "encoding", true)
		}
		children = append(children, enc_pathlenconstraint...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding BasicConstraints as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes BasicConstraints from BER/DER format.
func (v *BasicConstraints) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BasicConstraints destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe BasicConstraints
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = BasicConstraints{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding BasicConstraints SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "cA", content[offset:])
				val_ca, raw_ca, n, err := ber.DecodeBoolean(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cA", "decoding", false)
				}
				v.CA = &val_ca
				v.CARaw_ = raw_ca
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	// Decode pathLenConstraint
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "pathLenConstraint", content[offset:])
				val_pathlenconstraint, n, err := ber.DecodeBigInt(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "pathLenConstraint", "decoding", false)
				}
				v.PathLenConstraint = val_pathlenconstraint
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if !(v.PathLenConstraint.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
					if constraintErr := ber.CheckDecodedValue(opts, "pathLenConstraint", "(0..MAX)", fmt.Sprint(v.PathLenConstraint)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "BasicConstraints", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes NameConstraints to BER format.
func (v *NameConstraints) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: NameConstraints receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NameConstraints) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PermittedSubtrees != nil {
		if len((v.PermittedSubtrees).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "permittedSubtrees", "SIZE (1..MAX)", len((v.PermittedSubtrees).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_permittedsubtrees, err := MarshalBERGeneralSubtrees(v.PermittedSubtrees, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "permittedSubtrees"))...)
		if err != nil {
			return nil, qualifyBERError(err, "permittedSubtrees", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.PermittedSubtreesIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_permittedsubtrees)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_permittedsubtrees, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "permittedSubtrees", "encoding", false)
				}
			}
		} else {
			retagged_enc_permittedsubtrees, tagErr_enc_permittedsubtrees := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_permittedsubtrees)
			if tagErr_enc_permittedsubtrees != nil {
				return nil, qualifyBERError(tagErr_enc_permittedsubtrees, "permittedSubtrees", "encoding", false)
			}
			enc_permittedsubtrees = retagged_enc_permittedsubtrees
		}
		children = append(children, enc_permittedsubtrees...)
	}
	if v.ExcludedSubtrees != nil {
		if len((v.ExcludedSubtrees).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "excludedSubtrees", "SIZE (1..MAX)", len((v.ExcludedSubtrees).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_excludedsubtrees, err := MarshalBERGeneralSubtrees(v.ExcludedSubtrees, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "excludedSubtrees"))...)
		if err != nil {
			return nil, qualifyBERError(err, "excludedSubtrees", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.ExcludedSubtreesIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_excludedsubtrees)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_excludedsubtrees, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "excludedSubtrees", "encoding", false)
				}
			}
		} else {
			retagged_enc_excludedsubtrees, tagErr_enc_excludedsubtrees := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_excludedsubtrees)
			if tagErr_enc_excludedsubtrees != nil {
				return nil, qualifyBERError(tagErr_enc_excludedsubtrees, "excludedSubtrees", "encoding", false)
			}
			enc_excludedsubtrees = retagged_enc_excludedsubtrees
		}
		children = append(children, enc_excludedsubtrees...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes NameConstraints to DER format.
func (v *NameConstraints) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NameConstraints receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PermittedSubtrees != nil {
		if len((v.PermittedSubtrees).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "permittedSubtrees", "SIZE (1..MAX)", len((v.PermittedSubtrees).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_permittedsubtrees, err := MarshalDERGeneralSubtrees(v.PermittedSubtrees)
		if err != nil {
			return nil, qualifyBERError(err, "permittedSubtrees", "encoding", true)
		}
		retagged_enc_permittedsubtrees, tagErr_enc_permittedsubtrees := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_permittedsubtrees)
		if tagErr_enc_permittedsubtrees != nil {
			return nil, qualifyBERError(tagErr_enc_permittedsubtrees, "permittedSubtrees", "encoding", true)
		}
		enc_permittedsubtrees = retagged_enc_permittedsubtrees
		children = append(children, enc_permittedsubtrees...)
	}
	if v.ExcludedSubtrees != nil {
		if len((v.ExcludedSubtrees).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "excludedSubtrees", "SIZE (1..MAX)", len((v.ExcludedSubtrees).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_excludedsubtrees, err := MarshalDERGeneralSubtrees(v.ExcludedSubtrees)
		if err != nil {
			return nil, qualifyBERError(err, "excludedSubtrees", "encoding", true)
		}
		retagged_enc_excludedsubtrees, tagErr_enc_excludedsubtrees := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_excludedsubtrees)
		if tagErr_enc_excludedsubtrees != nil {
			return nil, qualifyBERError(tagErr_enc_excludedsubtrees, "excludedSubtrees", "encoding", true)
		}
		enc_excludedsubtrees = retagged_enc_excludedsubtrees
		children = append(children, enc_excludedsubtrees...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding NameConstraints as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes NameConstraints from BER/DER format.
func (v *NameConstraints) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NameConstraints destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe NameConstraints
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = NameConstraints{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding NameConstraints SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "permittedSubtrees", content[offset:])
				decodedTag_permittedsubtrees, n_permittedsubtrees, rawVal_permittedsubtrees, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "permittedSubtrees", "decoding", false)
				}
				if decodedTag_permittedsubtrees.Class != tag.ClassContextSpecific || decodedTag_permittedsubtrees.Number != 0 || decodedTag_permittedsubtrees.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_permittedsubtrees), "permittedSubtrees", "decoding", false)
				}
				reconstructed_permittedsubtrees, reconstructionErr_permittedsubtrees := ber.EncodeSequence(rawVal_permittedsubtrees)
				if reconstructionErr_permittedsubtrees != nil {
					return qualifyBERError(reconstructionErr_permittedsubtrees, "permittedSubtrees", "decoding", false)
				}
				dec_permittedsubtrees, unmErr := UnmarshalBERGeneralSubtrees(reconstructed_permittedsubtrees, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "permittedSubtrees"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "permittedSubtrees", "decoding", false)
				}
				v.PermittedSubtrees = dec_permittedsubtrees
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset > len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.PermittedSubtreesIndef_ = true
					}
				}
				if offset > len(content) || n_permittedsubtrees < 0 || n_permittedsubtrees > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_permittedsubtrees
				if len((v.PermittedSubtrees).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "permittedSubtrees", "SIZE (1..MAX)", len((v.PermittedSubtrees).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode excludedSubtrees
	v.ExcludedSubtreesIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "excludedSubtrees", content[offset:])
				decodedTag_excludedsubtrees, n_excludedsubtrees, rawVal_excludedsubtrees, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "excludedSubtrees", "decoding", false)
				}
				if decodedTag_excludedsubtrees.Class != tag.ClassContextSpecific || decodedTag_excludedsubtrees.Number != 1 || decodedTag_excludedsubtrees.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_excludedsubtrees), "excludedSubtrees", "decoding", false)
				}
				reconstructed_excludedsubtrees, reconstructionErr_excludedsubtrees := ber.EncodeSequence(rawVal_excludedsubtrees)
				if reconstructionErr_excludedsubtrees != nil {
					return qualifyBERError(reconstructionErr_excludedsubtrees, "excludedSubtrees", "decoding", false)
				}
				dec_excludedsubtrees, unmErr := UnmarshalBERGeneralSubtrees(reconstructed_excludedsubtrees, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "excludedSubtrees"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "excludedSubtrees", "decoding", false)
				}
				v.ExcludedSubtrees = dec_excludedsubtrees
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ExcludedSubtreesIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_excludedsubtrees < 0 || n_excludedsubtrees >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_excludedsubtrees
				if len((v.ExcludedSubtrees).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "excludedSubtrees", "SIZE (1..MAX)", len((v.ExcludedSubtrees).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "NameConstraints", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERGeneralSubtrees encodes a GeneralSubtrees list to BER.
func MarshalBERGeneralSubtrees(collection *GeneralSubtrees, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERGeneralSubtrees(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERGeneralSubtrees(collection *GeneralSubtrees, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "GeneralSubtrees", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERGeneralSubtrees encodes a GeneralSubtrees list to DER.
func MarshalDERGeneralSubtrees(collection *GeneralSubtrees) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "GeneralSubtrees", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
		return nil, fmt.Errorf("%s: %w", "encoding GeneralSubtrees as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERGeneralSubtrees decodes a GeneralSubtrees list from BER.
func UnmarshalBERGeneralSubtrees(data []byte, opts ...ber.DecodeOption) (returnValue *GeneralSubtrees, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERGeneralSubtrees(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding GeneralSubtrees", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "GeneralSubtrees", Cause: ber.ErrExtraData}
	}
	var result []GeneralSubtree
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem GeneralSubtree
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "GeneralSubtrees", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &GeneralSubtrees{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERGeneralSubtrees(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes GeneralSubtree to BER format.
func (v *GeneralSubtree) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: GeneralSubtree receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *GeneralSubtree) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_base, err := v.Base.MarshalBER(ber.ChildEncodeOptions(opts, "base")...)
	if err != nil {
		return nil, qualifyBERError(err, "base", "encoding", false)
	}
	children = append(children, enc_base...)
	if v.Minimum != nil {
		if !(v.Minimum.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
			if constraintErr := ber.CheckEncodedValue(opts, "minimum", "(0..MAX)", fmt.Sprint(v.Minimum)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_minimum, encodeErr_enc_minimum := ber.EncodeBigInt(v.Minimum)
		if encodeErr_enc_minimum != nil {
			return nil, qualifyBERError(encodeErr_enc_minimum, "minimum", "encoding", false)
		}
		retagged_enc_minimum, tagErr_enc_minimum := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_minimum)
		if tagErr_enc_minimum != nil {
			return nil, qualifyBERError(tagErr_enc_minimum, "minimum", "encoding", false)
		}
		enc_minimum = retagged_enc_minimum
		children = append(children, enc_minimum...)
	}
	if v.Maximum != nil {
		if !(v.Maximum.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
			if constraintErr := ber.CheckEncodedValue(opts, "maximum", "(0..MAX)", fmt.Sprint(v.Maximum)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximum, encodeErr_enc_maximum := ber.EncodeBigInt(v.Maximum)
		if encodeErr_enc_maximum != nil {
			return nil, qualifyBERError(encodeErr_enc_maximum, "maximum", "encoding", false)
		}
		retagged_enc_maximum, tagErr_enc_maximum := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_maximum)
		if tagErr_enc_maximum != nil {
			return nil, qualifyBERError(tagErr_enc_maximum, "maximum", "encoding", false)
		}
		enc_maximum = retagged_enc_maximum
		children = append(children, enc_maximum...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes GeneralSubtree to DER format.
func (v *GeneralSubtree) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: GeneralSubtree receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_base, err := v.Base.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "base", "encoding", true)
	}
	children = append(children, enc_base...)
	if v.Minimum != nil {
		if !(v.Minimum.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
			if constraintErr := ber.CheckEncodedValue(nil, "minimum", "(0..MAX)", fmt.Sprint(v.Minimum)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_minimum, encodeErr_enc_minimum := ber.EncodeBigInt(v.Minimum)
		if encodeErr_enc_minimum != nil {
			return nil, qualifyBERError(encodeErr_enc_minimum, "minimum", "encoding", true)
		}
		if string(enc_minimum) != "\x02\x01\x00" {
			retagged_enc_minimum, tagErr_enc_minimum := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_minimum)
			if tagErr_enc_minimum != nil {
				return nil, qualifyBERError(tagErr_enc_minimum, "minimum", "encoding", true)
			}
			enc_minimum = retagged_enc_minimum
			children = append(children, enc_minimum...)
		}
	}
	if v.Maximum != nil {
		if !(v.Maximum.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
			if constraintErr := ber.CheckEncodedValue(nil, "maximum", "(0..MAX)", fmt.Sprint(v.Maximum)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximum, encodeErr_enc_maximum := ber.EncodeBigInt(v.Maximum)
		if encodeErr_enc_maximum != nil {
			return nil, qualifyBERError(encodeErr_enc_maximum, "maximum", "encoding", true)
		}
		retagged_enc_maximum, tagErr_enc_maximum := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_maximum)
		if tagErr_enc_maximum != nil {
			return nil, qualifyBERError(tagErr_enc_maximum, "maximum", "encoding", true)
		}
		enc_maximum = retagged_enc_maximum
		children = append(children, enc_maximum...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding GeneralSubtree as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes GeneralSubtree from BER/DER format.
func (v *GeneralSubtree) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: GeneralSubtree destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe GeneralSubtree
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = GeneralSubtree{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding GeneralSubtree SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GeneralSubtree", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode base
	if offset >= len(content) {
		return fmt.Errorf("missing required field base")
	}
	{
		ber.MarkPreflightTarget(opts, "base", content[offset:])
		// Decode nested CHOICE (GeneralName)
		_, n_base, _, tlvErr_base := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_base != nil {
			return qualifyBERError(tlvErr_base, "base", "decoding", false)
		}
		if offset > len(content) || n_base < 0 || n_base > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Base.UnmarshalBER(content[offset:offset+n_base], ber.ChildDecodeOptions(opts, "base")...); unmErr != nil {
			return qualifyBERError(unmErr, "base", "decoding", false)
		}
		if offset > len(content) || n_base < 0 || n_base > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_base
	}
	// Decode minimum
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "minimum", content[offset:])
				decodedTag_minimum, n_minimum, rawVal_minimum, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "minimum", "decoding", false)
				}
				if decodedTag_minimum.Class != tag.ClassContextSpecific || decodedTag_minimum.Number != 0 || decodedTag_minimum.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_minimum), "minimum", "decoding", false)
				}
				decVal_minimum, intErr := ber.DecodeBigIntValue(rawVal_minimum)
				if intErr != nil {
					return qualifyBERError(intErr, "minimum", "decoding", false)
				}
				v.Minimum = decVal_minimum
				if offset < 0 || offset >
					len(content) || n_minimum < 0 || n_minimum > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_minimum
				if !(v.Minimum.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
					if constraintErr := ber.CheckDecodedValue(opts, "minimum", "(0..MAX)", fmt.Sprint(v.Minimum)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode maximum
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "maximum", content[offset:])
				decodedTag_maximum, n_maximum, rawVal_maximum, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "maximum", "decoding", false)
				}
				if decodedTag_maximum.Class != tag.ClassContextSpecific || decodedTag_maximum.Number != 1 || decodedTag_maximum.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_maximum), "maximum", "decoding", false)
				}
				decVal_maximum, intErr := ber.DecodeBigIntValue(rawVal_maximum)
				if intErr != nil {
					return qualifyBERError(intErr, "maximum", "decoding", false)
				}
				v.Maximum = decVal_maximum
				if offset < 0 || offset >
					len(content) || n_maximum < 0 || n_maximum > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_maximum
				if !(v.Maximum.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
					if constraintErr := ber.CheckDecodedValue(opts, "maximum", "(0..MAX)", fmt.Sprint(v.Maximum)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "GeneralSubtree", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PolicyConstraints to BER format.
func (v *PolicyConstraints) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PolicyConstraints receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PolicyConstraints) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.RequireExplicitPolicy != nil {
		if !(v.RequireExplicitPolicy.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
			if constraintErr := ber.CheckEncodedValue(opts, "requireExplicitPolicy", "(0..MAX)", fmt.Sprint(v.RequireExplicitPolicy)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_requireexplicitpolicy, encodeErr_enc_requireexplicitpolicy := ber.EncodeBigInt(v.RequireExplicitPolicy)
		if encodeErr_enc_requireexplicitpolicy != nil {
			return nil, qualifyBERError(encodeErr_enc_requireexplicitpolicy, "requireExplicitPolicy", "encoding", false)
		}
		retagged_enc_requireexplicitpolicy, tagErr_enc_requireexplicitpolicy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_requireexplicitpolicy)
		if tagErr_enc_requireexplicitpolicy != nil {
			return nil, qualifyBERError(tagErr_enc_requireexplicitpolicy, "requireExplicitPolicy", "encoding", false)
		}
		enc_requireexplicitpolicy = retagged_enc_requireexplicitpolicy
		children = append(children, enc_requireexplicitpolicy...)
	}
	if v.InhibitPolicyMapping != nil {
		if !(v.InhibitPolicyMapping.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
			if constraintErr := ber.CheckEncodedValue(opts, "inhibitPolicyMapping", "(0..MAX)", fmt.Sprint(v.InhibitPolicyMapping)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_inhibitpolicymapping, encodeErr_enc_inhibitpolicymapping := ber.EncodeBigInt(v.InhibitPolicyMapping)
		if encodeErr_enc_inhibitpolicymapping != nil {
			return nil, qualifyBERError(encodeErr_enc_inhibitpolicymapping, "inhibitPolicyMapping", "encoding", false)
		}
		retagged_enc_inhibitpolicymapping, tagErr_enc_inhibitpolicymapping := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_inhibitpolicymapping)
		if tagErr_enc_inhibitpolicymapping != nil {
			return nil, qualifyBERError(tagErr_enc_inhibitpolicymapping, "inhibitPolicyMapping", "encoding", false)
		}
		enc_inhibitpolicymapping = retagged_enc_inhibitpolicymapping
		children = append(children, enc_inhibitpolicymapping...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PolicyConstraints to DER format.
func (v *PolicyConstraints) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PolicyConstraints receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.RequireExplicitPolicy != nil {
		if !(v.RequireExplicitPolicy.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
			if constraintErr := ber.CheckEncodedValue(nil, "requireExplicitPolicy", "(0..MAX)", fmt.Sprint(v.RequireExplicitPolicy)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_requireexplicitpolicy, encodeErr_enc_requireexplicitpolicy := ber.EncodeBigInt(v.RequireExplicitPolicy)
		if encodeErr_enc_requireexplicitpolicy != nil {
			return nil, qualifyBERError(encodeErr_enc_requireexplicitpolicy, "requireExplicitPolicy", "encoding", true)
		}
		retagged_enc_requireexplicitpolicy, tagErr_enc_requireexplicitpolicy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_requireexplicitpolicy)
		if tagErr_enc_requireexplicitpolicy != nil {
			return nil, qualifyBERError(tagErr_enc_requireexplicitpolicy, "requireExplicitPolicy", "encoding", true)
		}
		enc_requireexplicitpolicy = retagged_enc_requireexplicitpolicy
		children = append(children, enc_requireexplicitpolicy...)
	}
	if v.InhibitPolicyMapping != nil {
		if !(v.InhibitPolicyMapping.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
			if constraintErr := ber.CheckEncodedValue(nil, "inhibitPolicyMapping", "(0..MAX)", fmt.Sprint(v.InhibitPolicyMapping)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_inhibitpolicymapping, encodeErr_enc_inhibitpolicymapping := ber.EncodeBigInt(v.InhibitPolicyMapping)
		if encodeErr_enc_inhibitpolicymapping != nil {
			return nil, qualifyBERError(encodeErr_enc_inhibitpolicymapping, "inhibitPolicyMapping", "encoding", true)
		}
		retagged_enc_inhibitpolicymapping, tagErr_enc_inhibitpolicymapping := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_inhibitpolicymapping)
		if tagErr_enc_inhibitpolicymapping != nil {
			return nil, qualifyBERError(tagErr_enc_inhibitpolicymapping, "inhibitPolicyMapping", "encoding", true)
		}
		enc_inhibitpolicymapping = retagged_enc_inhibitpolicymapping
		children = append(children, enc_inhibitpolicymapping...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PolicyConstraints as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes PolicyConstraints from BER/DER format.
func (v *PolicyConstraints) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PolicyConstraints destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PolicyConstraints
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = PolicyConstraints{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PolicyConstraints SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "requireExplicitPolicy", content[offset:])
				decodedTag_requireexplicitpolicy, n_requireexplicitpolicy, rawVal_requireexplicitpolicy, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "requireExplicitPolicy", "decoding", false)
				}
				if decodedTag_requireexplicitpolicy.Class != tag.ClassContextSpecific || decodedTag_requireexplicitpolicy.Number != 0 || decodedTag_requireexplicitpolicy.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_requireexplicitpolicy), "requireExplicitPolicy", "decoding", false)
				}
				decVal_requireexplicitpolicy, intErr := ber.DecodeBigIntValue(rawVal_requireexplicitpolicy)
				if intErr != nil {
					return qualifyBERError(intErr, "requireExplicitPolicy", "decoding", false)
				}
				v.RequireExplicitPolicy = decVal_requireexplicitpolicy
				if offset > len(content) || n_requireexplicitpolicy < 0 || n_requireexplicitpolicy >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_requireexplicitpolicy
				if !(v.RequireExplicitPolicy.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
					if constraintErr := ber.CheckDecodedValue(opts, "requireExplicitPolicy", "(0..MAX)", fmt.Sprint(v.RequireExplicitPolicy)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode inhibitPolicyMapping
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "inhibitPolicyMapping", content[offset:])
				decodedTag_inhibitpolicymapping, n_inhibitpolicymapping, rawVal_inhibitpolicymapping, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "inhibitPolicyMapping", "decoding", false)
				}
				if decodedTag_inhibitpolicymapping.Class != tag.ClassContextSpecific || decodedTag_inhibitpolicymapping.Number != 1 || decodedTag_inhibitpolicymapping.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_inhibitpolicymapping), "inhibitPolicyMapping", "decoding", false)
				}
				decVal_inhibitpolicymapping, intErr := ber.DecodeBigIntValue(rawVal_inhibitpolicymapping)
				if intErr != nil {
					return qualifyBERError(intErr, "inhibitPolicyMapping", "decoding", false)
				}
				v.InhibitPolicyMapping = decVal_inhibitpolicymapping
				if offset < 0 || offset >
					len(content) || n_inhibitpolicymapping < 0 || n_inhibitpolicymapping >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_inhibitpolicymapping
				if !(v.InhibitPolicyMapping.Cmp(runtime.MustParseBigIntDecimal("0")) >= 0) {
					if constraintErr := ber.CheckDecodedValue(opts, "inhibitPolicyMapping", "(0..MAX)", fmt.Sprint(v.InhibitPolicyMapping)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PolicyConstraints", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERCRLDistributionPoints encodes a CRLDistributionPoints list to BER.
func MarshalBERCRLDistributionPoints(collection *CRLDistributionPoints, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERCRLDistributionPoints(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERCRLDistributionPoints(collection *CRLDistributionPoints, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "CRLDistributionPoints", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERCRLDistributionPoints encodes a CRLDistributionPoints list to DER.
func MarshalDERCRLDistributionPoints(collection *CRLDistributionPoints) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "CRLDistributionPoints", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
		return nil, fmt.Errorf("%s: %w", "encoding CRLDistributionPoints as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERCRLDistributionPoints decodes a CRLDistributionPoints list from BER.
func UnmarshalBERCRLDistributionPoints(data []byte, opts ...ber.DecodeOption) (returnValue *CRLDistributionPoints, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERCRLDistributionPoints(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding CRLDistributionPoints", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CRLDistributionPoints", Cause: ber.ErrExtraData}
	}
	var result []DistributionPoint
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem DistributionPoint
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "CRLDistributionPoints", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &CRLDistributionPoints{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERCRLDistributionPoints(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes DistributionPoint to BER format.
func (v *DistributionPoint) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DistributionPoint receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DistributionPoint) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.DistributionPoint != nil {
		enc_distributionpoint, err := v.DistributionPoint.MarshalBER(ber.ChildEncodeOptions(opts, "distributionPoint")...)
		if err != nil {
			return nil, qualifyBERError(err, "distributionPoint", "encoding", false)
		}
		{
			var encodeErr error
			enc_distributionpoint, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_distributionpoint)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "distributionPoint", "encoding", false)
			}
		}
		children = append(children, enc_distributionpoint...)
	}
	if v.Reasons != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.Reasons.Bytes, v.Reasons.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "reasons", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.Reasons.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_reasons, encodeErr_enc_reasons := ber.EncodeBitString(v.Reasons.Bytes, ber.UnusedBitCount(v.Reasons.BitLength))
		if encodeErr_enc_reasons != nil {
			return nil, qualifyBERError(encodeErr_enc_reasons, "reasons", "encoding", false)
		}
		retagged_enc_reasons, tagErr_enc_reasons := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_reasons)
		if tagErr_enc_reasons != nil {
			return nil, qualifyBERError(tagErr_enc_reasons, "reasons", "encoding", false)
		}
		enc_reasons = retagged_enc_reasons
		children = append(children, enc_reasons...)
	}
	if v.CRLIssuer != nil {
		if len((v.CRLIssuer).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "cRLIssuer", "SIZE (1..MAX)", len((v.CRLIssuer).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_crlissuer, err := MarshalBERGeneralNames(v.CRLIssuer, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "cRLIssuer"))...)
		if err != nil {
			return nil, qualifyBERError(err, "cRLIssuer", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.CRLIssuerIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_crlissuer)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_crlissuer, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "cRLIssuer", "encoding", false)
				}
			}
		} else {
			retagged_enc_crlissuer, tagErr_enc_crlissuer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_crlissuer)
			if tagErr_enc_crlissuer != nil {
				return nil, qualifyBERError(tagErr_enc_crlissuer, "cRLIssuer", "encoding", false)
			}
			enc_crlissuer = retagged_enc_crlissuer
		}
		children = append(children, enc_crlissuer...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DistributionPoint to DER format.
func (v *DistributionPoint) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DistributionPoint receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.DistributionPoint != nil {
		enc_distributionpoint, err := v.DistributionPoint.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "distributionPoint", "encoding", true)
		}
		{
			var encodeErr error
			enc_distributionpoint, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_distributionpoint)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "distributionPoint", "encoding", true)
			}
		}
		children = append(children, enc_distributionpoint...)
	}
	if v.Reasons != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.Reasons.Bytes, v.Reasons.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "reasons", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.Reasons.Bytes, v.Reasons.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "reasons", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.Reasons.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_reasons, encodeErr_enc_reasons := ber.EncodeDERNamedBitString(v.Reasons.Bytes, v.Reasons.BitLength)
		if encodeErr_enc_reasons != nil {
			return nil, qualifyBERError(encodeErr_enc_reasons, "reasons", "encoding", true)
		}
		retagged_enc_reasons, tagErr_enc_reasons := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_reasons)
		if tagErr_enc_reasons != nil {
			return nil, qualifyBERError(tagErr_enc_reasons, "reasons", "encoding", true)
		}
		enc_reasons = retagged_enc_reasons
		children = append(children, enc_reasons...)
	}
	if v.CRLIssuer != nil {
		if len((v.CRLIssuer).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "cRLIssuer", "SIZE (1..MAX)", len((v.CRLIssuer).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_crlissuer, err := MarshalDERGeneralNames(v.CRLIssuer)
		if err != nil {
			return nil, qualifyBERError(err, "cRLIssuer", "encoding", true)
		}
		retagged_enc_crlissuer, tagErr_enc_crlissuer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_crlissuer)
		if tagErr_enc_crlissuer != nil {
			return nil, qualifyBERError(tagErr_enc_crlissuer, "cRLIssuer", "encoding", true)
		}
		enc_crlissuer = retagged_enc_crlissuer
		children = append(children, enc_crlissuer...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding DistributionPoint as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes DistributionPoint from BER/DER format.
func (v *DistributionPoint) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DistributionPoint destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe DistributionPoint
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = DistributionPoint{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding DistributionPoint SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "distributionPoint", content[offset:])
				decodedTag_distributionpoint, n_distributionpoint, innerData_distributionpoint, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "distributionPoint", "decoding", false)
				}
				if decodedTag_distributionpoint.Class != tag.ClassContextSpecific || decodedTag_distributionpoint.Number != 0 || decodedTag_distributionpoint.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_distributionpoint), "distributionPoint", "decoding", false)
				}
				_, innerUsed_distributionpoint, _, innerErr_distributionpoint := ber.DecodeTLV(innerData_distributionpoint, opts...)
				if innerErr_distributionpoint != nil {
					return qualifyBERError(innerErr_distributionpoint, "distributionPoint", "decoding", false)
				}
				if innerUsed_distributionpoint != len(innerData_distributionpoint) {
					return qualifyBERError(ber.ErrExtraData, "distributionPoint", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "distributionPoint", innerData_distributionpoint)
				var dec_distributionpoint DistributionPointName
				if unmErr := dec_distributionpoint.UnmarshalBER(innerData_distributionpoint, ber.ChildDecodeOptions(opts, "distributionPoint")...); unmErr != nil {
					return qualifyBERError(unmErr, "distributionPoint", "decoding", false)
				}
				v.DistributionPoint = &dec_distributionpoint
				if offset > len(content) || n_distributionpoint < 0 || n_distributionpoint > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_distributionpoint
			}
		}
	}
	// Decode reasons
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "reasons", content[offset:])
				decodedTag_reasons, n_reasons, rawVal_reasons, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "reasons", "decoding", false)
				}
				if decodedTag_reasons.Class != tag.ClassContextSpecific || decodedTag_reasons.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reasons), "reasons", "decoding", false)
				}
				bsBytes_reasons, bsUnused_reasons, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_reasons.Constructed, rawVal_reasons, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "reasons", "decoding", false)
				}
				bsBitLength_reasons, bsLenErr_reasons := ber.BitStringBitLength(len(bsBytes_reasons), bsUnused_reasons)
				if bsLenErr_reasons != nil {
					return qualifyBERError(bsLenErr_reasons, "reasons", "decoding", false)
				}
				tmp_reasons := runtime.BitString{Bytes: bsBytes_reasons, BitLength: bsBitLength_reasons}
				v.Reasons = &tmp_reasons
				if offset < 0 || offset >
					len(content) || n_reasons < 0 || n_reasons > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
				ber.MarkPreflightTarget(opts, "cRLIssuer", content[offset:])
				decodedTag_crlissuer, n_crlissuer, rawVal_crlissuer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cRLIssuer", "decoding", false)
				}
				if decodedTag_crlissuer.Class != tag.ClassContextSpecific || decodedTag_crlissuer.Number != 2 || decodedTag_crlissuer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_crlissuer), "cRLIssuer", "decoding", false)
				}
				reconstructed_crlissuer, reconstructionErr_crlissuer := ber.EncodeSequence(rawVal_crlissuer)
				if reconstructionErr_crlissuer != nil {
					return qualifyBERError(reconstructionErr_crlissuer, "cRLIssuer", "decoding", false)
				}
				dec_crlissuer, unmErr := UnmarshalBERGeneralNames(reconstructed_crlissuer, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "cRLIssuer"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "cRLIssuer", "decoding", false)
				}
				v.CRLIssuer = dec_crlissuer
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.CRLIssuerIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_crlissuer < 0 || n_crlissuer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_crlissuer
				if len((v.CRLIssuer).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "cRLIssuer", "SIZE (1..MAX)", len((v.CRLIssuer).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DistributionPoint", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes DistributionPointName to BER format.
func (v *DistributionPointName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DistributionPointName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DistributionPointName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case DistributionPointNameChoiceFullName:
		enc_0, err := MarshalBERGeneralNames(v.FullName, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "fullName"))...)
		if err != nil {
			return nil, qualifyBERError(err, "fullName", "encoding", false)
		}
		if len((v.FullName).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "fullName", "SIZE (1..MAX)", len((v.FullName).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "fullName", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case DistributionPointNameChoiceNameRelativeToCRLIssuer:
		enc_1, err := MarshalBERRelativeDistinguishedName(v.NameRelativeToCRLIssuer, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "nameRelativeToCRLIssuer"))...)
		if err != nil {
			return nil, qualifyBERError(err, "nameRelativeToCRLIssuer", "encoding", false)
		}
		if len((v.NameRelativeToCRLIssuer).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "nameRelativeToCRLIssuer", "SIZE (1..MAX)", len((v.NameRelativeToCRLIssuer).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "nameRelativeToCRLIssuer", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DistributionPointName", v.Choice)
	}
}

// MarshalDER encodes DistributionPointName to DER format.
func (v *DistributionPointName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DistributionPointName receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case DistributionPointNameChoiceFullName:
		enc_der_0, err := MarshalDERGeneralNames(v.FullName)
		if err != nil {
			return nil, qualifyBERError(err, "fullName", "encoding", true)
		}
		if len((v.FullName).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "fullName", "SIZE (1..MAX)", len((v.FullName).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "fullName", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "fullName", "encoding", true)
		}
		return enc_der_0, nil
	case DistributionPointNameChoiceNameRelativeToCRLIssuer:
		enc_der_1, err := MarshalDERRelativeDistinguishedName(v.NameRelativeToCRLIssuer)
		if err != nil {
			return nil, qualifyBERError(err, "nameRelativeToCRLIssuer", "encoding", true)
		}
		if len((v.NameRelativeToCRLIssuer).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "nameRelativeToCRLIssuer", "SIZE (1..MAX)", len((v.NameRelativeToCRLIssuer).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "nameRelativeToCRLIssuer", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "nameRelativeToCRLIssuer", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case DistributionPointNameChoiceFullName:
			return nil, qualifyBERError(err, "fullName", "encoding", true)
		case DistributionPointNameChoiceNameRelativeToCRLIssuer:
			return nil, qualifyBERError(err, "nameRelativeToCRLIssuer", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding DistributionPointName as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes DistributionPointName from BER/DER format.
func (v *DistributionPointName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DistributionPointName destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe DistributionPointName
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = DistributionPointName{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for DistributionPointName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DistributionPointName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding DistributionPointName CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DistributionPointName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = DistributionPointNameChoiceFullName
		ber.MarkPreflightTarget(opts, "fullName", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "fullName", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERGeneralNames(reconstructed, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "fullName"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "fullName", "decoding", false)
		}
		v.FullName = dec
		if len((v.FullName).Values) < 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "fullName", "SIZE (1..MAX)", len((v.FullName).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = DistributionPointNameChoiceNameRelativeToCRLIssuer
		ber.MarkPreflightTarget(opts, "nameRelativeToCRLIssuer", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "nameRelativeToCRLIssuer", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSet(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERRelativeDistinguishedName(reconstructed, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "nameRelativeToCRLIssuer"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "nameRelativeToCRLIssuer", "decoding", false)
		}
		v.NameRelativeToCRLIssuer = dec
		if len((v.NameRelativeToCRLIssuer).Values) < 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "nameRelativeToCRLIssuer", "SIZE (1..MAX)", len((v.NameRelativeToCRLIssuer).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for DistributionPointName CHOICE", peekTag)
	}
	return nil
}

// MarshalBERExtKeyUsageSyntax encodes a ExtKeyUsageSyntax list to BER.
func MarshalBERExtKeyUsageSyntax(collection *ExtKeyUsageSyntax, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERExtKeyUsageSyntax(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERExtKeyUsageSyntax(collection *ExtKeyUsageSyntax, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "ExtKeyUsageSyntax", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, oidErr := ber.EncodeObjectIdentifierChecked(elem)
		if oidErr != nil {
			return nil, qualifyBERError(oidErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERExtKeyUsageSyntax encodes a ExtKeyUsageSyntax list to DER.
func MarshalDERExtKeyUsageSyntax(collection *ExtKeyUsageSyntax) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "ExtKeyUsageSyntax", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, oidErr := ber.EncodeObjectIdentifierChecked(elem)
		if oidErr != nil {
			return nil, qualifyBERError(oidErr, fmt.Sprintf("element[%d]",
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
		return nil, fmt.Errorf("%s: %w", "encoding ExtKeyUsageSyntax as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERExtKeyUsageSyntax decodes a ExtKeyUsageSyntax list from BER.
func UnmarshalBERExtKeyUsageSyntax(data []byte, opts ...ber.DecodeOption) (returnValue *ExtKeyUsageSyntax, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERExtKeyUsageSyntax(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding ExtKeyUsageSyntax", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ExtKeyUsageSyntax", Cause: ber.ErrExtraData}
	}
	var result []KeyPurposeId
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, oidErr := ber.DecodeObjectIdentifier(elementData, opts...)
		if oidErr != nil {
			return nil, qualifyBERError(oidErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		result = append(result, KeyPurposeId(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "ExtKeyUsageSyntax", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &ExtKeyUsageSyntax{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERExtKeyUsageSyntax(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERAuthorityInfoAccessSyntax encodes a AuthorityInfoAccessSyntax list to BER.
func MarshalBERAuthorityInfoAccessSyntax(collection *AuthorityInfoAccessSyntax, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERAuthorityInfoAccessSyntax(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERAuthorityInfoAccessSyntax(collection *AuthorityInfoAccessSyntax, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "AuthorityInfoAccessSyntax", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERAuthorityInfoAccessSyntax encodes a AuthorityInfoAccessSyntax list to DER.
func MarshalDERAuthorityInfoAccessSyntax(collection *AuthorityInfoAccessSyntax) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "AuthorityInfoAccessSyntax", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
		return nil, fmt.Errorf("%s: %w", "encoding AuthorityInfoAccessSyntax as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERAuthorityInfoAccessSyntax decodes a AuthorityInfoAccessSyntax list from BER.
func UnmarshalBERAuthorityInfoAccessSyntax(data []byte, opts ...ber.DecodeOption) (returnValue *AuthorityInfoAccessSyntax, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERAuthorityInfoAccessSyntax(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding AuthorityInfoAccessSyntax", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AuthorityInfoAccessSyntax", Cause: ber.ErrExtraData}
	}
	var result []AccessDescription
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem AccessDescription
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "AuthorityInfoAccessSyntax", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &AuthorityInfoAccessSyntax{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERAuthorityInfoAccessSyntax(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes AccessDescription to BER format.
func (v *AccessDescription) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AccessDescription receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AccessDescription) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_accessmethod, oidErr := ber.EncodeObjectIdentifierChecked(v.AccessMethod)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "accessMethod", "encoding", false)
	}
	children = append(children, enc_accessmethod...)
	enc_accesslocation, err := v.AccessLocation.MarshalBER(ber.ChildEncodeOptions(opts, "accessLocation")...)
	if err != nil {
		return nil, qualifyBERError(err, "accessLocation", "encoding", false)
	}
	children = append(children, enc_accesslocation...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AccessDescription to DER format.
func (v *AccessDescription) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AccessDescription receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_accessmethod, oidErr := ber.EncodeObjectIdentifierChecked(v.AccessMethod)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "accessMethod", "encoding", true)
	}
	children = append(children, enc_accessmethod...)
	enc_accesslocation, err := v.AccessLocation.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "accessLocation", "encoding", true)
	}
	children = append(children, enc_accesslocation...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AccessDescription as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes AccessDescription from BER/DER format.
func (v *AccessDescription) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AccessDescription destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AccessDescription
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = AccessDescription{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding AccessDescription SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AccessDescription", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode accessMethod
	if offset >= len(content) {
		return fmt.Errorf("missing required field accessMethod")
	}
	{
		ber.MarkPreflightTarget(opts, "accessMethod", content[offset:])
		val_accessmethod, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "accessMethod", "decoding", false)
		}
		v.AccessMethod = val_accessmethod
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	// Decode accessLocation
	if offset >= len(content) {
		return fmt.Errorf("missing required field accessLocation")
	}
	{
		ber.MarkPreflightTarget(opts, "accessLocation", content[offset:])
		// Decode nested CHOICE (GeneralName)
		_, n_accesslocation, _, tlvErr_accesslocation := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_accesslocation != nil {
			return qualifyBERError(tlvErr_accesslocation, "accessLocation", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_accesslocation < 0 || n_accesslocation >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.AccessLocation.UnmarshalBER(content[offset:offset+n_accesslocation], ber.ChildDecodeOptions(opts, "accessLocation")...); unmErr != nil {
			return qualifyBERError(unmErr, "accessLocation", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_accesslocation < 0 || n_accesslocation >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_accesslocation
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AccessDescription", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERSubjectInfoAccessSyntax encodes a SubjectInfoAccessSyntax list to BER.
func MarshalBERSubjectInfoAccessSyntax(collection *SubjectInfoAccessSyntax, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERSubjectInfoAccessSyntax(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERSubjectInfoAccessSyntax(collection *SubjectInfoAccessSyntax, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "SubjectInfoAccessSyntax", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERSubjectInfoAccessSyntax encodes a SubjectInfoAccessSyntax list to DER.
func MarshalDERSubjectInfoAccessSyntax(collection *SubjectInfoAccessSyntax) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "SubjectInfoAccessSyntax", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
		return nil, fmt.Errorf("%s: %w", "encoding SubjectInfoAccessSyntax as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERSubjectInfoAccessSyntax decodes a SubjectInfoAccessSyntax list from BER.
func UnmarshalBERSubjectInfoAccessSyntax(data []byte, opts ...ber.DecodeOption) (returnValue *SubjectInfoAccessSyntax, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERSubjectInfoAccessSyntax(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SubjectInfoAccessSyntax", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SubjectInfoAccessSyntax", Cause: ber.ErrExtraData}
	}
	var result []AccessDescription
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem AccessDescription
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "SubjectInfoAccessSyntax", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SubjectInfoAccessSyntax{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERSubjectInfoAccessSyntax(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes IssuingDistributionPoint to BER format.
func (v *IssuingDistributionPoint) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: IssuingDistributionPoint receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IssuingDistributionPoint) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.DistributionPoint != nil {
		enc_distributionpoint, err := v.DistributionPoint.MarshalBER(ber.ChildEncodeOptions(opts, "distributionPoint")...)
		if err != nil {
			return nil, qualifyBERError(err, "distributionPoint", "encoding", false)
		}
		{
			var encodeErr error
			enc_distributionpoint, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_distributionpoint)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "distributionPoint", "encoding", false)
			}
		}
		children = append(children, enc_distributionpoint...)
	}
	if v.OnlyContainsUserCerts != nil {
		var enc_onlycontainsusercerts []byte
		if ber.BERReplayEnabled(opts) && v.OnlyContainsUserCertsRaw_ != 0 && *v.OnlyContainsUserCerts {
			enc_onlycontainsusercerts = ber.EncodeBooleanRaw(v.OnlyContainsUserCertsRaw_)
		} else {
			enc_onlycontainsusercerts = ber.EncodeBoolean(*v.OnlyContainsUserCerts)
		}
		retagged_enc_onlycontainsusercerts, tagErr_enc_onlycontainsusercerts := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_onlycontainsusercerts)
		if tagErr_enc_onlycontainsusercerts != nil {
			return nil, qualifyBERError(tagErr_enc_onlycontainsusercerts, "onlyContainsUserCerts", "encoding", false)
		}
		enc_onlycontainsusercerts = retagged_enc_onlycontainsusercerts
		children = append(children, enc_onlycontainsusercerts...)
	}
	if v.OnlyContainsCACerts != nil {
		var enc_onlycontainscacerts []byte
		if ber.BERReplayEnabled(opts) && v.OnlyContainsCACertsRaw_ != 0 && *v.OnlyContainsCACerts {
			enc_onlycontainscacerts = ber.EncodeBooleanRaw(v.OnlyContainsCACertsRaw_)
		} else {
			enc_onlycontainscacerts = ber.EncodeBoolean(*v.OnlyContainsCACerts)
		}
		retagged_enc_onlycontainscacerts, tagErr_enc_onlycontainscacerts := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_onlycontainscacerts)
		if tagErr_enc_onlycontainscacerts != nil {
			return nil, qualifyBERError(tagErr_enc_onlycontainscacerts, "onlyContainsCACerts", "encoding", false)
		}
		enc_onlycontainscacerts = retagged_enc_onlycontainscacerts
		children = append(children, enc_onlycontainscacerts...)
	}
	if v.OnlySomeReasons != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.OnlySomeReasons.Bytes, v.OnlySomeReasons.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "onlySomeReasons", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.OnlySomeReasons.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_onlysomereasons, encodeErr_enc_onlysomereasons := ber.EncodeBitString(v.OnlySomeReasons.Bytes, ber.UnusedBitCount(v.OnlySomeReasons.BitLength))
		if encodeErr_enc_onlysomereasons != nil {
			return nil, qualifyBERError(encodeErr_enc_onlysomereasons, "onlySomeReasons", "encoding", false)
		}
		retagged_enc_onlysomereasons, tagErr_enc_onlysomereasons := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_onlysomereasons)
		if tagErr_enc_onlysomereasons != nil {
			return nil, qualifyBERError(tagErr_enc_onlysomereasons, "onlySomeReasons", "encoding", false)
		}
		enc_onlysomereasons = retagged_enc_onlysomereasons
		children = append(children, enc_onlysomereasons...)
	}
	if v.IndirectCRL != nil {
		var enc_indirectcrl []byte
		if ber.BERReplayEnabled(opts) && v.IndirectCRLRaw_ != 0 && *v.IndirectCRL {
			enc_indirectcrl = ber.EncodeBooleanRaw(v.IndirectCRLRaw_)
		} else {
			enc_indirectcrl = ber.EncodeBoolean(*v.IndirectCRL)
		}
		retagged_enc_indirectcrl, tagErr_enc_indirectcrl := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_indirectcrl)
		if tagErr_enc_indirectcrl != nil {
			return nil, qualifyBERError(tagErr_enc_indirectcrl, "indirectCRL", "encoding", false)
		}
		enc_indirectcrl = retagged_enc_indirectcrl
		children = append(children, enc_indirectcrl...)
	}
	if v.OnlyContainsAttributeCerts != nil {
		var enc_onlycontainsattributecerts []byte
		if ber.BERReplayEnabled(opts) && v.OnlyContainsAttributeCertsRaw_ != 0 && *v.OnlyContainsAttributeCerts {
			enc_onlycontainsattributecerts = ber.EncodeBooleanRaw(v.OnlyContainsAttributeCertsRaw_)
		} else {
			enc_onlycontainsattributecerts = ber.EncodeBoolean(*v.OnlyContainsAttributeCerts)
		}
		retagged_enc_onlycontainsattributecerts, tagErr_enc_onlycontainsattributecerts := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_onlycontainsattributecerts)
		if tagErr_enc_onlycontainsattributecerts != nil {
			return nil, qualifyBERError(tagErr_enc_onlycontainsattributecerts, "onlyContainsAttributeCerts", "encoding", false)
		}
		enc_onlycontainsattributecerts = retagged_enc_onlycontainsattributecerts
		children = append(children, enc_onlycontainsattributecerts...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IssuingDistributionPoint to DER format.
func (v *IssuingDistributionPoint) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IssuingDistributionPoint receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.DistributionPoint != nil {
		enc_distributionpoint, err := v.DistributionPoint.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "distributionPoint", "encoding", true)
		}
		{
			var encodeErr error
			enc_distributionpoint, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_distributionpoint)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "distributionPoint", "encoding", true)
			}
		}
		children = append(children, enc_distributionpoint...)
	}
	if v.OnlyContainsUserCerts != nil {
		enc_onlycontainsusercerts := ber.EncodeBoolean(*v.OnlyContainsUserCerts)
		if string(enc_onlycontainsusercerts) != "\x01\x01\x00" {
			retagged_enc_onlycontainsusercerts, tagErr_enc_onlycontainsusercerts := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_onlycontainsusercerts)
			if tagErr_enc_onlycontainsusercerts != nil {
				return nil, qualifyBERError(tagErr_enc_onlycontainsusercerts, "onlyContainsUserCerts", "encoding", true)
			}
			enc_onlycontainsusercerts = retagged_enc_onlycontainsusercerts
			children = append(children, enc_onlycontainsusercerts...)
		}
	}
	if v.OnlyContainsCACerts != nil {
		enc_onlycontainscacerts := ber.EncodeBoolean(*v.OnlyContainsCACerts)
		if string(enc_onlycontainscacerts) != "\x01\x01\x00" {
			retagged_enc_onlycontainscacerts, tagErr_enc_onlycontainscacerts := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_onlycontainscacerts)
			if tagErr_enc_onlycontainscacerts != nil {
				return nil, qualifyBERError(tagErr_enc_onlycontainscacerts, "onlyContainsCACerts", "encoding", true)
			}
			enc_onlycontainscacerts = retagged_enc_onlycontainscacerts
			children = append(children, enc_onlycontainscacerts...)
		}
	}
	if v.OnlySomeReasons != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.OnlySomeReasons.Bytes, v.OnlySomeReasons.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "onlySomeReasons", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.OnlySomeReasons.Bytes, v.OnlySomeReasons.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "onlySomeReasons", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.OnlySomeReasons.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_onlysomereasons, encodeErr_enc_onlysomereasons := ber.EncodeDERNamedBitString(v.OnlySomeReasons.Bytes, v.OnlySomeReasons.BitLength)
		if encodeErr_enc_onlysomereasons != nil {
			return nil, qualifyBERError(encodeErr_enc_onlysomereasons, "onlySomeReasons", "encoding", true)
		}
		retagged_enc_onlysomereasons, tagErr_enc_onlysomereasons := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_onlysomereasons)
		if tagErr_enc_onlysomereasons != nil {
			return nil, qualifyBERError(tagErr_enc_onlysomereasons, "onlySomeReasons", "encoding", true)
		}
		enc_onlysomereasons = retagged_enc_onlysomereasons
		children = append(children, enc_onlysomereasons...)
	}
	if v.IndirectCRL != nil {
		enc_indirectcrl := ber.EncodeBoolean(*v.IndirectCRL)
		if string(enc_indirectcrl) != "\x01\x01\x00" {
			retagged_enc_indirectcrl, tagErr_enc_indirectcrl := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_indirectcrl)
			if tagErr_enc_indirectcrl != nil {
				return nil, qualifyBERError(tagErr_enc_indirectcrl, "indirectCRL", "encoding", true)
			}
			enc_indirectcrl = retagged_enc_indirectcrl
			children = append(children, enc_indirectcrl...)
		}
	}
	if v.OnlyContainsAttributeCerts != nil {
		enc_onlycontainsattributecerts := ber.EncodeBoolean(*v.OnlyContainsAttributeCerts)
		if string(enc_onlycontainsattributecerts) != "\x01\x01\x00" {
			retagged_enc_onlycontainsattributecerts, tagErr_enc_onlycontainsattributecerts := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_onlycontainsattributecerts)
			if tagErr_enc_onlycontainsattributecerts != nil {
				return nil, qualifyBERError(tagErr_enc_onlycontainsattributecerts, "onlyContainsAttributeCerts", "encoding", true)
			}
			enc_onlycontainsattributecerts = retagged_enc_onlycontainsattributecerts
			children = append(children, enc_onlycontainsattributecerts...)
		}
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IssuingDistributionPoint as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes IssuingDistributionPoint from BER/DER format.
func (v *IssuingDistributionPoint) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IssuingDistributionPoint destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe IssuingDistributionPoint
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = IssuingDistributionPoint{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding IssuingDistributionPoint SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "distributionPoint", content[offset:])
				decodedTag_distributionpoint, n_distributionpoint, innerData_distributionpoint, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "distributionPoint", "decoding", false)
				}
				if decodedTag_distributionpoint.Class != tag.ClassContextSpecific || decodedTag_distributionpoint.Number != 0 || decodedTag_distributionpoint.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_distributionpoint), "distributionPoint", "decoding", false)
				}
				_, innerUsed_distributionpoint, _, innerErr_distributionpoint := ber.DecodeTLV(innerData_distributionpoint, opts...)
				if innerErr_distributionpoint != nil {
					return qualifyBERError(innerErr_distributionpoint, "distributionPoint", "decoding", false)
				}
				if innerUsed_distributionpoint != len(innerData_distributionpoint) {
					return qualifyBERError(ber.ErrExtraData, "distributionPoint", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "distributionPoint", innerData_distributionpoint)
				var dec_distributionpoint DistributionPointName
				if unmErr := dec_distributionpoint.UnmarshalBER(innerData_distributionpoint, ber.ChildDecodeOptions(opts, "distributionPoint")...); unmErr != nil {
					return qualifyBERError(unmErr, "distributionPoint", "decoding", false)
				}
				v.DistributionPoint = &dec_distributionpoint
				if offset > len(content) || n_distributionpoint < 0 || n_distributionpoint > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_distributionpoint
			}
		}
	}
	// Decode onlyContainsUserCerts
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "onlyContainsUserCerts", content[offset:])
				decodedTag_onlycontainsusercerts, n_onlycontainsusercerts, rawVal_onlycontainsusercerts, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "onlyContainsUserCerts", "decoding", false)
				}
				if decodedTag_onlycontainsusercerts.Class != tag.ClassContextSpecific || decodedTag_onlycontainsusercerts.Number != 1 || decodedTag_onlycontainsusercerts.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_onlycontainsusercerts), "onlyContainsUserCerts", "decoding", false)
				}
				decVal_onlycontainsusercerts, boolErr := ber.DecodeBooleanValue(rawVal_onlycontainsusercerts)
				if boolErr != nil {
					return qualifyBERError(boolErr, "onlyContainsUserCerts", "decoding", false)
				}
				if len(rawVal_onlycontainsusercerts) == 1 && rawVal_onlycontainsusercerts[0] != 0 && rawVal_onlycontainsusercerts[0] != 0xff {
					ber.MarkBERNonCanonical(opts)
				}
				if len(rawVal_onlycontainsusercerts) == 1 {
					v.OnlyContainsUserCertsRaw_ = rawVal_onlycontainsusercerts[0]
				}
				v.OnlyContainsUserCerts = &decVal_onlycontainsusercerts
				if offset < 0 || offset >
					len(content) || n_onlycontainsusercerts < 0 || n_onlycontainsusercerts >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_onlycontainsusercerts
			}
		}
	}
	// Decode onlyContainsCACerts
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "onlyContainsCACerts", content[offset:])
				decodedTag_onlycontainscacerts, n_onlycontainscacerts, rawVal_onlycontainscacerts, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "onlyContainsCACerts", "decoding", false)
				}
				if decodedTag_onlycontainscacerts.Class != tag.ClassContextSpecific || decodedTag_onlycontainscacerts.Number != 2 || decodedTag_onlycontainscacerts.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_onlycontainscacerts), "onlyContainsCACerts", "decoding", false)
				}
				decVal_onlycontainscacerts, boolErr := ber.DecodeBooleanValue(rawVal_onlycontainscacerts)
				if boolErr != nil {
					return qualifyBERError(boolErr, "onlyContainsCACerts", "decoding", false)
				}
				if len(rawVal_onlycontainscacerts) == 1 && rawVal_onlycontainscacerts[0] != 0 && rawVal_onlycontainscacerts[0] != 0xff {
					ber.MarkBERNonCanonical(opts)
				}
				if len(rawVal_onlycontainscacerts) == 1 {
					v.OnlyContainsCACertsRaw_ = rawVal_onlycontainscacerts[0]
				}
				v.OnlyContainsCACerts = &decVal_onlycontainscacerts
				if offset < 0 || offset >
					len(content) || n_onlycontainscacerts < 0 || n_onlycontainscacerts >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_onlycontainscacerts
			}
		}
	}
	// Decode onlySomeReasons
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "onlySomeReasons", content[offset:])
				decodedTag_onlysomereasons, n_onlysomereasons, rawVal_onlysomereasons, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "onlySomeReasons", "decoding", false)
				}
				if decodedTag_onlysomereasons.Class != tag.ClassContextSpecific || decodedTag_onlysomereasons.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_onlysomereasons), "onlySomeReasons", "decoding", false)
				}
				bsBytes_onlysomereasons, bsUnused_onlysomereasons, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_onlysomereasons.Constructed, rawVal_onlysomereasons, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "onlySomeReasons", "decoding", false)
				}
				bsBitLength_onlysomereasons, bsLenErr_onlysomereasons := ber.BitStringBitLength(len(bsBytes_onlysomereasons), bsUnused_onlysomereasons)
				if bsLenErr_onlysomereasons != nil {
					return qualifyBERError(bsLenErr_onlysomereasons, "onlySomeReasons", "decoding", false)
				}
				tmp_onlysomereasons := runtime.BitString{Bytes: bsBytes_onlysomereasons, BitLength: bsBitLength_onlysomereasons}
				v.OnlySomeReasons = &tmp_onlysomereasons
				if offset < 0 || offset >
					len(content) || n_onlysomereasons < 0 || n_onlysomereasons > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_onlysomereasons
			}
		}
	}
	// Decode indirectCRL
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "indirectCRL", content[offset:])
				decodedTag_indirectcrl, n_indirectcrl, rawVal_indirectcrl, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "indirectCRL", "decoding", false)
				}
				if decodedTag_indirectcrl.Class != tag.ClassContextSpecific || decodedTag_indirectcrl.Number != 4 || decodedTag_indirectcrl.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_indirectcrl), "indirectCRL", "decoding", false)
				}
				decVal_indirectcrl, boolErr := ber.DecodeBooleanValue(rawVal_indirectcrl)
				if boolErr != nil {
					return qualifyBERError(boolErr, "indirectCRL", "decoding", false)
				}
				if len(rawVal_indirectcrl) == 1 && rawVal_indirectcrl[0] != 0 && rawVal_indirectcrl[0] != 0xff {
					ber.MarkBERNonCanonical(opts)
				}
				if len(rawVal_indirectcrl) == 1 {
					v.IndirectCRLRaw_ = rawVal_indirectcrl[0]
				}
				v.IndirectCRL = &decVal_indirectcrl
				if offset < 0 || offset >
					len(content) || n_indirectcrl < 0 || n_indirectcrl > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_indirectcrl
			}
		}
	}
	// Decode onlyContainsAttributeCerts
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "onlyContainsAttributeCerts", content[offset:])
				decodedTag_onlycontainsattributecerts, n_onlycontainsattributecerts, rawVal_onlycontainsattributecerts, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "onlyContainsAttributeCerts", "decoding", false)
				}
				if decodedTag_onlycontainsattributecerts.Class != tag.ClassContextSpecific || decodedTag_onlycontainsattributecerts.Number != 5 || decodedTag_onlycontainsattributecerts.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_onlycontainsattributecerts), "onlyContainsAttributeCerts", "decoding", false)
				}
				decVal_onlycontainsattributecerts, boolErr := ber.DecodeBooleanValue(rawVal_onlycontainsattributecerts)
				if boolErr != nil {
					return qualifyBERError(boolErr, "onlyContainsAttributeCerts", "decoding", false)
				}
				if len(rawVal_onlycontainsattributecerts) == 1 && rawVal_onlycontainsattributecerts[0] != 0 && rawVal_onlycontainsattributecerts[0] != 0xff {
					ber.MarkBERNonCanonical(opts)
				}
				if len(rawVal_onlycontainsattributecerts) == 1 {
					v.OnlyContainsAttributeCertsRaw_ = rawVal_onlycontainsattributecerts[0]
				}
				v.OnlyContainsAttributeCerts = &decVal_onlycontainsattributecerts
				if offset < 0 || offset >
					len(content) || n_onlycontainsattributecerts < 0 || n_onlycontainsattributecerts >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
func MarshalBERPolicyInformationPolicyQualifiers(collection *PolicyInformationPolicyQualifiers, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERPolicyInformationPolicyQualifiers(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERPolicyInformationPolicyQualifiers(collection *PolicyInformationPolicyQualifiers, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "PolicyInformation-policyQualifiers", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERPolicyInformationPolicyQualifiers encodes a PolicyInformationPolicyQualifiers list to DER.
func MarshalDERPolicyInformationPolicyQualifiers(collection *PolicyInformationPolicyQualifiers) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "PolicyInformation-policyQualifiers", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
		return nil, fmt.Errorf("%s: %w", "encoding PolicyInformationPolicyQualifiers as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERPolicyInformationPolicyQualifiers decodes a PolicyInformationPolicyQualifiers list from BER.
func UnmarshalBERPolicyInformationPolicyQualifiers(data []byte, opts ...ber.DecodeOption) (returnValue *PolicyInformationPolicyQualifiers, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERPolicyInformationPolicyQualifiers(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding PolicyInformationPolicyQualifiers", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PolicyInformationPolicyQualifiers", Cause: ber.ErrExtraData}
	}
	var result []PolicyQualifierInfo
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem PolicyQualifierInfo
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "PolicyInformation-policyQualifiers", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &PolicyInformationPolicyQualifiers{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERPolicyInformationPolicyQualifiers(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERNoticeReferenceNoticeNumbers encodes a NoticeReferenceNoticeNumbers list to BER.
func MarshalBERNoticeReferenceNoticeNumbers(collection *NoticeReferenceNoticeNumbers, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERNoticeReferenceNoticeNumbers(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERNoticeReferenceNoticeNumbers(collection *NoticeReferenceNoticeNumbers, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if elem == nil {
			return nil, qualifyBERError(fmt.Errorf("%w: required INTEGER is nil", ber.ErrInvalidValue), fmt.Sprintf("element[%d]", elemIndex), "encoding", false)
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeBigInt(elem)
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERNoticeReferenceNoticeNumbers encodes a NoticeReferenceNoticeNumbers list to DER.
func MarshalDERNoticeReferenceNoticeNumbers(collection *NoticeReferenceNoticeNumbers) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if elem == nil {
			return nil, qualifyBERError(fmt.Errorf("%w: required INTEGER is nil", ber.ErrInvalidValue), fmt.Sprintf("element[%d]", elemIndex), "encoding", false)
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeBigInt(elem)
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
		return nil, fmt.Errorf("%s: %w", "encoding NoticeReferenceNoticeNumbers as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERNoticeReferenceNoticeNumbers decodes a NoticeReferenceNoticeNumbers list from BER.
func UnmarshalBERNoticeReferenceNoticeNumbers(data []byte, opts ...ber.DecodeOption) (returnValue *NoticeReferenceNoticeNumbers, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERNoticeReferenceNoticeNumbers(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding NoticeReferenceNoticeNumbers", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "NoticeReferenceNoticeNumbers", Cause: ber.ErrExtraData}
	}
	var result []*big.Int
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, intErr := ber.DecodeBigInt(elementData, opts...)
		if intErr != nil {
			return nil, qualifyBERError(intErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		result = append(result, val)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	decoded := &NoticeReferenceNoticeNumbers{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERNoticeReferenceNoticeNumbers(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes PolicyMappingsElem to BER format.
func (v *PolicyMappingsElem) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PolicyMappingsElem receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PolicyMappingsElem) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_issuerdomainpolicy, oidErr := ber.EncodeObjectIdentifierChecked(v.IssuerDomainPolicy)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "issuerDomainPolicy", "encoding", false)
	}
	children = append(children, enc_issuerdomainpolicy...)
	enc_subjectdomainpolicy, oidErr := ber.EncodeObjectIdentifierChecked(v.SubjectDomainPolicy)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "subjectDomainPolicy", "encoding", false)
	}
	children = append(children, enc_subjectdomainpolicy...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PolicyMappingsElem to DER format.
func (v *PolicyMappingsElem) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PolicyMappingsElem receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_issuerdomainpolicy, oidErr := ber.EncodeObjectIdentifierChecked(v.IssuerDomainPolicy)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "issuerDomainPolicy", "encoding", true)
	}
	children = append(children, enc_issuerdomainpolicy...)
	enc_subjectdomainpolicy, oidErr := ber.EncodeObjectIdentifierChecked(v.SubjectDomainPolicy)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "subjectDomainPolicy", "encoding", true)
	}
	children = append(children, enc_subjectdomainpolicy...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PolicyMappingsElem as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes PolicyMappingsElem from BER/DER format.
func (v *PolicyMappingsElem) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PolicyMappingsElem destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PolicyMappingsElem
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = PolicyMappingsElem{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PolicyMappingsElem SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PolicyMappingsElem", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode issuerDomainPolicy
	if offset >= len(content) {
		return fmt.Errorf("missing required field issuerDomainPolicy")
	}
	{
		ber.MarkPreflightTarget(opts, "issuerDomainPolicy", content[offset:])
		val_issuerdomainpolicy, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "issuerDomainPolicy", "decoding", false)
		}
		v.IssuerDomainPolicy = val_issuerdomainpolicy
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	// Decode subjectDomainPolicy
	if offset >= len(content) {
		return fmt.Errorf("missing required field subjectDomainPolicy")
	}
	{
		ber.MarkPreflightTarget(opts, "subjectDomainPolicy", content[offset:])
		val_subjectdomainpolicy, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "subjectDomainPolicy", "decoding", false)
		}
		v.SubjectDomainPolicy = val_subjectdomainpolicy
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PolicyMappingsElem", Cause: ber.ErrExtraData}
	}
	return nil
}
