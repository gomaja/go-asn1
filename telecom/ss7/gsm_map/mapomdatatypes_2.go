// Code generated from ASN.1 module "MAP-OM-DataTypes". DO NOT EDIT.

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

// OMActivateTraceModeArg represents the ASN.1 type ActivateTraceModeArg (SEQUENCE).
type OMActivateTraceModeArg struct {
	Imsi               *CommonDataTypesIMSI                  `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference     OMTraceReference                      `asn1:"tag:1,context,implicit"`
	TraceType          OMTraceType                           `asn1:"tag:2,context,implicit"`
	OmcId              *CommonDataTypesAddressString         `asn1:"tag:3,context,implicit,optional" json:"OmcId,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceReference2    *OMTraceReference2                    `asn1:"tag:5,context,implicit,optional" json:"TraceReference2,omitempty"`
	TraceDepthList     *OMTraceDepthList                     `asn1:"tag:6,context,implicit,optional" json:"TraceDepthList,omitempty"`
	TraceNETypeList    *OMTraceNETypeList                    `asn1:"tag:7,context,implicit,optional" json:"TraceNETypeList,omitempty"`
	TraceInterfaceList *OMTraceInterfaceList                 `asn1:"tag:8,context,implicit,optional" json:"TraceInterfaceList,omitempty"`
	TraceEventList     *OMTraceEventList                     `asn1:"tag:9,context,implicit,optional" json:"TraceEventList,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// OMTraceReference represents the ASN.1 type TraceReference (OCTET_STRING).
type OMTraceReference = []byte

// OMTraceReference2 represents the ASN.1 type TraceReference2 (OCTET_STRING).
type OMTraceReference2 = []byte

// OMTraceRecordingSessionReference represents the ASN.1 type TraceRecordingSessionReference (OCTET_STRING).
type OMTraceRecordingSessionReference = []byte

// OMTraceType represents the ASN.1 type TraceType (INTEGER).
type OMTraceType = int64

// OMTraceDepthList represents the ASN.1 type TraceDepthList (SEQUENCE).
type OMTraceDepthList struct {
	MscSTraceDepth *OMTraceDepth `asn1:"tag:0,context,implicit,optional" json:"MscSTraceDepth,omitempty"`
	MgwTraceDepth  *OMTraceDepth `asn1:"tag:1,context,implicit,optional" json:"MgwTraceDepth,omitempty"`
	SgsnTraceDepth *OMTraceDepth `asn1:"tag:2,context,implicit,optional" json:"SgsnTraceDepth,omitempty"`
	GgsnTraceDepth *OMTraceDepth `asn1:"tag:3,context,implicit,optional" json:"GgsnTraceDepth,omitempty"`
	RncTraceDepth  *OMTraceDepth `asn1:"tag:4,context,implicit,optional" json:"RncTraceDepth,omitempty"`
	BmscTraceDepth *OMTraceDepth `asn1:"tag:5,context,implicit,optional" json:"BmscTraceDepth,omitempty"`
	ExtCount_      int64         `asn1:"-" json:"-"`
	ExtPresent_    []bool        `asn1:"-" json:"-"`
	ExtData_       [][]byte      `asn1:"-" json:"-"`
}

// OMTraceDepth represents the ASN.1 ENUMERATED type TraceDepth.
type OMTraceDepth int64

const (
	OMTraceDepthMinimum OMTraceDepth = 0
	OMTraceDepthMedium  OMTraceDepth = 1
	OMTraceDepthMaximum OMTraceDepth = 2
)

func (v OMTraceDepth) String() string {
	switch v {
	case OMTraceDepthMinimum:
		return "minimum"
	case OMTraceDepthMedium:
		return "medium"
	case OMTraceDepthMaximum:
		return "maximum"
	default:
		return "unknown"
	}
}

// OMTraceNETypeList represents the ASN.1 type TraceNE-TypeList (BIT_STRING).
type OMTraceNETypeList = runtime.BitString

// OMTraceInterfaceList represents the ASN.1 type TraceInterfaceList (SEQUENCE).
type OMTraceInterfaceList struct {
	MscSList    *OMMSCSInterfaceList `asn1:"tag:0,context,implicit,optional" json:"MscSList,omitempty"`
	MgwList     *OMMGWInterfaceList  `asn1:"tag:1,context,implicit,optional" json:"MgwList,omitempty"`
	SgsnList    *OMSGSNInterfaceList `asn1:"tag:2,context,implicit,optional" json:"SgsnList,omitempty"`
	GgsnList    *OMGGSNInterfaceList `asn1:"tag:3,context,implicit,optional" json:"GgsnList,omitempty"`
	RncList     *OMRNCInterfaceList  `asn1:"tag:4,context,implicit,optional" json:"RncList,omitempty"`
	BmscList    *OMBMSCInterfaceList `asn1:"tag:5,context,implicit,optional" json:"BmscList,omitempty"`
	ExtCount_   int64                `asn1:"-" json:"-"`
	ExtPresent_ []bool               `asn1:"-" json:"-"`
	ExtData_    [][]byte             `asn1:"-" json:"-"`
}

// OMMSCSInterfaceList represents the ASN.1 type MSC-S-InterfaceList (BIT_STRING).
type OMMSCSInterfaceList = runtime.BitString

// OMMGWInterfaceList represents the ASN.1 type MGW-InterfaceList (BIT_STRING).
type OMMGWInterfaceList = runtime.BitString

// OMSGSNInterfaceList represents the ASN.1 type SGSN-InterfaceList (BIT_STRING).
type OMSGSNInterfaceList = runtime.BitString

// OMGGSNInterfaceList represents the ASN.1 type GGSN-InterfaceList (BIT_STRING).
type OMGGSNInterfaceList = runtime.BitString

// OMRNCInterfaceList represents the ASN.1 type RNC-InterfaceList (BIT_STRING).
type OMRNCInterfaceList = runtime.BitString

// OMBMSCInterfaceList represents the ASN.1 type BMSC-InterfaceList (BIT_STRING).
type OMBMSCInterfaceList = runtime.BitString

// OMTraceEventList represents the ASN.1 type TraceEventList (SEQUENCE).
type OMTraceEventList struct {
	MscSList    *OMMSCSEventList `asn1:"tag:0,context,implicit,optional" json:"MscSList,omitempty"`
	MgwList     *OMMGWEventList  `asn1:"tag:1,context,implicit,optional" json:"MgwList,omitempty"`
	SgsnList    *OMSGSNEventList `asn1:"tag:2,context,implicit,optional" json:"SgsnList,omitempty"`
	GgsnList    *OMGGSNEventList `asn1:"tag:3,context,implicit,optional" json:"GgsnList,omitempty"`
	BmscList    *OMBMSCEventList `asn1:"tag:4,context,implicit,optional" json:"BmscList,omitempty"`
	ExtCount_   int64            `asn1:"-" json:"-"`
	ExtPresent_ []bool           `asn1:"-" json:"-"`
	ExtData_    [][]byte         `asn1:"-" json:"-"`
}

// OMMSCSEventList represents the ASN.1 type MSC-S-EventList (BIT_STRING).
type OMMSCSEventList = runtime.BitString

// OMMGWEventList represents the ASN.1 type MGW-EventList (BIT_STRING).
type OMMGWEventList = runtime.BitString

// OMSGSNEventList represents the ASN.1 type SGSN-EventList (BIT_STRING).
type OMSGSNEventList = runtime.BitString

// OMGGSNEventList represents the ASN.1 type GGSN-EventList (BIT_STRING).
type OMGGSNEventList = runtime.BitString

// OMBMSCEventList represents the ASN.1 type BMSC-EventList (BIT_STRING).
type OMBMSCEventList = runtime.BitString

// OMTracePropagationList represents the ASN.1 type TracePropagationList (SEQUENCE).
type OMTracePropagationList struct {
	TraceReference                 *OMTraceReference                 `asn1:"tag:0,context,implicit,optional" json:"TraceReference,omitempty"`
	TraceType                      *OMTraceType                      `asn1:"tag:1,context,implicit,optional" json:"TraceType,omitempty"`
	TraceReference2                *OMTraceReference2                `asn1:"tag:2,context,implicit,optional" json:"TraceReference2,omitempty"`
	TraceRecordingSessionReference *OMTraceRecordingSessionReference `asn1:"tag:3,context,implicit,optional" json:"TraceRecordingSessionReference,omitempty"`
	RncTraceDepth                  *OMTraceDepth                     `asn1:"tag:4,context,implicit,optional" json:"RncTraceDepth,omitempty"`
	RncInterfaceList               *OMRNCInterfaceList               `asn1:"tag:5,context,implicit,optional" json:"RncInterfaceList,omitempty"`
	MscSTraceDepth                 *OMTraceDepth                     `asn1:"tag:6,context,implicit,optional" json:"MscSTraceDepth,omitempty"`
	MscSInterfaceList              *OMMSCSInterfaceList              `asn1:"tag:7,context,implicit,optional" json:"MscSInterfaceList,omitempty"`
	MscSEventList                  *OMMSCSEventList                  `asn1:"tag:8,context,implicit,optional" json:"MscSEventList,omitempty"`
	MgwTraceDepth                  *OMTraceDepth                     `asn1:"tag:9,context,implicit,optional" json:"MgwTraceDepth,omitempty"`
	MgwInterfaceList               *OMMGWInterfaceList               `asn1:"tag:10,context,implicit,optional" json:"MgwInterfaceList,omitempty"`
	MgwEventList                   *OMMGWEventList                   `asn1:"tag:11,context,implicit,optional" json:"MgwEventList,omitempty"`
	ExtCount_                      int64                             `asn1:"-" json:"-"`
	ExtPresent_                    []bool                            `asn1:"-" json:"-"`
	ExtData_                       [][]byte                          `asn1:"-" json:"-"`
}

// OMActivateTraceModeRes represents the ASN.1 type ActivateTraceModeRes (SEQUENCE).
type OMActivateTraceModeRes struct {
	ExtensionContainer    *ExtensionDataTypesExtensionContainer `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceSupportIndicator *struct{}                             `asn1:"tag:1,context,implicit,optional" json:"TraceSupportIndicator,omitempty"`
	ExtCount_             int64                                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                                `asn1:"-" json:"-"`
	ExtData_              [][]byte                              `asn1:"-" json:"-"`
}

// OMDeactivateTraceModeArg represents the ASN.1 type DeactivateTraceModeArg (SEQUENCE).
type OMDeactivateTraceModeArg struct {
	Imsi               *CommonDataTypesIMSI                  `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference     OMTraceReference                      `asn1:"tag:1,context,implicit"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceReference2    *OMTraceReference2                    `asn1:"tag:3,context,implicit,optional" json:"TraceReference2,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// OMDeactivateTraceModeRes represents the ASN.1 type DeactivateTraceModeRes (SEQUENCE).
type OMDeactivateTraceModeRes struct {
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// MarshalBER encodes OMActivateTraceModeArg to BER format.
func (v *OMActivateTraceModeArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	enc_tracereference = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_tracereference)
	children = append(children, enc_tracereference...)
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	enc_tracetype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_tracetype)
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		enc_omcid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_omcid)
		children = append(children, enc_omcid...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceReference2 != nil {
		enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		enc_tracereference2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_tracereference2)
		children = append(children, enc_tracereference2...)
	}
	if v.TraceDepthList != nil {
		enc_tracedepthlist, err := v.TraceDepthList.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding traceDepthList: %w", err)
		}
		enc_tracedepthlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_tracedepthlist)
		children = append(children, enc_tracedepthlist...)
	}
	if v.TraceNETypeList != nil {
		enc_tracenetypelist := ber.EncodeBitString(v.TraceNETypeList.Bytes, (8-(v.TraceNETypeList.BitLength%8))%8)
		enc_tracenetypelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_tracenetypelist)
		children = append(children, enc_tracenetypelist...)
	}
	if v.TraceInterfaceList != nil {
		enc_traceinterfacelist, err := v.TraceInterfaceList.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding traceInterfaceList: %w", err)
		}
		enc_traceinterfacelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_traceinterfacelist)
		children = append(children, enc_traceinterfacelist...)
	}
	if v.TraceEventList != nil {
		enc_traceeventlist, err := v.TraceEventList.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding traceEventList: %w", err)
		}
		enc_traceeventlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_traceeventlist)
		children = append(children, enc_traceeventlist...)
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

// MarshalDER encodes OMActivateTraceModeArg to DER format.
func (v *OMActivateTraceModeArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding OMActivateTraceModeArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OMActivateTraceModeArg from BER/DER format.
func (v *OMActivateTraceModeArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OMActivateTraceModeArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMActivateTraceModeArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				tmp_imsi := CommonDataTypesIMSI(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode traceReference
	if offset >= len(content) {
		return fmt.Errorf("missing required field traceReference")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for traceReference, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding traceReference: %w", err)
	}
	if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
		return fmt.Errorf("decoding traceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference)
	}
	v.TraceReference = OMTraceReference(rawVal_tracereference)
	offset += n_tracereference
	// Decode traceType
	if offset >= len(content) {
		return fmt.Errorf("missing required field traceType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for traceType, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding traceType: %w", err)
	}
	if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 2 || decodedTag_tracetype.Constructed != false {
		return fmt.Errorf("decoding traceType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracetype)
	}
	decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
	if intErr != nil {
		return fmt.Errorf("decoding traceType: %w", intErr)
	}
	v.TraceType = OMTraceType(decVal_tracetype)
	offset += n_tracetype
	// Decode omc-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_omcid, n_omcid, rawVal_omcid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding omc-Id: %w", err)
				}
				if decodedTag_omcid.Class != tag.ClassContextSpecific || decodedTag_omcid.Number != 3 {
					return fmt.Errorf("decoding omc-Id: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_omcid)
				}
				tmp_omcid := CommonDataTypesAddressString(rawVal_omcid)
				v.OmcId = &tmp_omcid
				offset += n_omcid
			}
		}
	}
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode traceReference2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_tracereference2, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceReference2: %w", err)
				}
				if decodedTag_tracereference2.Class != tag.ClassContextSpecific || decodedTag_tracereference2.Number != 5 {
					return fmt.Errorf("decoding traceReference2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference2)
				}
				tmp_tracereference2 := OMTraceReference2(rawVal_tracereference2)
				v.TraceReference2 = &tmp_tracereference2
				offset += n_tracereference2
			}
		}
	}
	// Decode traceDepthList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_tracedepthlist, n_tracedepthlist, rawVal_tracedepthlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceDepthList: %w", err)
				}
				if decodedTag_tracedepthlist.Class != tag.ClassContextSpecific || decodedTag_tracedepthlist.Number != 6 || decodedTag_tracedepthlist.Constructed != true {
					return fmt.Errorf("decoding traceDepthList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracedepthlist)
				}
				reconstructed_tracedepthlist := ber.EncodeSequence(rawVal_tracedepthlist)
				var dec_tracedepthlist OMTraceDepthList
				if unmErr := dec_tracedepthlist.UnmarshalBER(reconstructed_tracedepthlist); unmErr != nil {
					return fmt.Errorf("decoding traceDepthList: %w", unmErr)
				}
				v.TraceDepthList = &dec_tracedepthlist
				offset += n_tracedepthlist
			}
		}
	}
	// Decode traceNE-TypeList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_tracenetypelist, n_tracenetypelist, rawVal_tracenetypelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceNE-TypeList: %w", err)
				}
				if decodedTag_tracenetypelist.Class != tag.ClassContextSpecific || decodedTag_tracenetypelist.Number != 7 {
					return fmt.Errorf("decoding traceNE-TypeList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracenetypelist)
				}
				bsBytes_tracenetypelist, bsUnused_tracenetypelist, bsErr := ber.DecodeBitStringValue(rawVal_tracenetypelist)
				if bsErr != nil {
					return fmt.Errorf("decoding traceNE-TypeList: %w", bsErr)
				}
				tmp_tracenetypelist := runtime.BitString{Bytes: bsBytes_tracenetypelist, BitLength: len(bsBytes_tracenetypelist)*8 - bsUnused_tracenetypelist}
				v.TraceNETypeList = &tmp_tracenetypelist
				offset += n_tracenetypelist
			}
		}
	}
	// Decode traceInterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_traceinterfacelist, n_traceinterfacelist, rawVal_traceinterfacelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceInterfaceList: %w", err)
				}
				if decodedTag_traceinterfacelist.Class != tag.ClassContextSpecific || decodedTag_traceinterfacelist.Number != 8 || decodedTag_traceinterfacelist.Constructed != true {
					return fmt.Errorf("decoding traceInterfaceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_traceinterfacelist)
				}
				reconstructed_traceinterfacelist := ber.EncodeSequence(rawVal_traceinterfacelist)
				var dec_traceinterfacelist OMTraceInterfaceList
				if unmErr := dec_traceinterfacelist.UnmarshalBER(reconstructed_traceinterfacelist); unmErr != nil {
					return fmt.Errorf("decoding traceInterfaceList: %w", unmErr)
				}
				v.TraceInterfaceList = &dec_traceinterfacelist
				offset += n_traceinterfacelist
			}
		}
	}
	// Decode traceEventList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_traceeventlist, n_traceeventlist, rawVal_traceeventlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceEventList: %w", err)
				}
				if decodedTag_traceeventlist.Class != tag.ClassContextSpecific || decodedTag_traceeventlist.Number != 9 || decodedTag_traceeventlist.Constructed != true {
					return fmt.Errorf("decoding traceEventList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_traceeventlist)
				}
				reconstructed_traceeventlist := ber.EncodeSequence(rawVal_traceeventlist)
				var dec_traceeventlist OMTraceEventList
				if unmErr := dec_traceeventlist.UnmarshalBER(reconstructed_traceeventlist); unmErr != nil {
					return fmt.Errorf("decoding traceEventList: %w", unmErr)
				}
				v.TraceEventList = &dec_traceeventlist
				offset += n_traceeventlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMActivateTraceModeArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OMTraceDepthList to BER format.
func (v *OMTraceDepthList) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		enc_mscstracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_mscstracedepth)
		children = append(children, enc_mscstracedepth...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		enc_mgwtracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_mgwtracedepth)
		children = append(children, enc_mgwtracedepth...)
	}
	if v.SgsnTraceDepth != nil {
		enc_sgsntracedepth := ber.EncodeEnumerated(int64(*v.SgsnTraceDepth))
		enc_sgsntracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_sgsntracedepth)
		children = append(children, enc_sgsntracedepth...)
	}
	if v.GgsnTraceDepth != nil {
		enc_ggsntracedepth := ber.EncodeEnumerated(int64(*v.GgsnTraceDepth))
		enc_ggsntracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_ggsntracedepth)
		children = append(children, enc_ggsntracedepth...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		enc_rnctracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_rnctracedepth)
		children = append(children, enc_rnctracedepth...)
	}
	if v.BmscTraceDepth != nil {
		enc_bmsctracedepth := ber.EncodeEnumerated(int64(*v.BmscTraceDepth))
		enc_bmsctracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_bmsctracedepth)
		children = append(children, enc_bmsctracedepth...)
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

// MarshalDER encodes OMTraceDepthList to DER format.
func (v *OMTraceDepthList) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding OMTraceDepthList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OMTraceDepthList from BER/DER format.
func (v *OMTraceDepthList) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OMTraceDepthList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMTraceDepthList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_mscstracedepth, n_mscstracedepth, rawVal_mscstracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", err)
				}
				if decodedTag_mscstracedepth.Class != tag.ClassContextSpecific || decodedTag_mscstracedepth.Number != 0 || decodedTag_mscstracedepth.Constructed != false {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscstracedepth)
				}
				decVal_mscstracedepth, intErr := ber.DecodeIntegerValue(rawVal_mscstracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", intErr)
				}
				tmp_mscstracedepth := OMTraceDepth(decVal_mscstracedepth)
				v.MscSTraceDepth = &tmp_mscstracedepth
				offset += n_mscstracedepth
			}
		}
	}
	// Decode mgw-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_mgwtracedepth, n_mgwtracedepth, rawVal_mgwtracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", err)
				}
				if decodedTag_mgwtracedepth.Class != tag.ClassContextSpecific || decodedTag_mgwtracedepth.Number != 1 || decodedTag_mgwtracedepth.Constructed != false {
					return fmt.Errorf("decoding mgw-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwtracedepth)
				}
				decVal_mgwtracedepth, intErr := ber.DecodeIntegerValue(rawVal_mgwtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", intErr)
				}
				tmp_mgwtracedepth := OMTraceDepth(decVal_mgwtracedepth)
				v.MgwTraceDepth = &tmp_mgwtracedepth
				offset += n_mgwtracedepth
			}
		}
	}
	// Decode sgsn-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_sgsntracedepth, n_sgsntracedepth, rawVal_sgsntracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgsn-TraceDepth: %w", err)
				}
				if decodedTag_sgsntracedepth.Class != tag.ClassContextSpecific || decodedTag_sgsntracedepth.Number != 2 || decodedTag_sgsntracedepth.Constructed != false {
					return fmt.Errorf("decoding sgsn-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsntracedepth)
				}
				decVal_sgsntracedepth, intErr := ber.DecodeIntegerValue(rawVal_sgsntracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding sgsn-TraceDepth: %w", intErr)
				}
				tmp_sgsntracedepth := OMTraceDepth(decVal_sgsntracedepth)
				v.SgsnTraceDepth = &tmp_sgsntracedepth
				offset += n_sgsntracedepth
			}
		}
	}
	// Decode ggsn-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_ggsntracedepth, n_ggsntracedepth, rawVal_ggsntracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ggsn-TraceDepth: %w", err)
				}
				if decodedTag_ggsntracedepth.Class != tag.ClassContextSpecific || decodedTag_ggsntracedepth.Number != 3 || decodedTag_ggsntracedepth.Constructed != false {
					return fmt.Errorf("decoding ggsn-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ggsntracedepth)
				}
				decVal_ggsntracedepth, intErr := ber.DecodeIntegerValue(rawVal_ggsntracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding ggsn-TraceDepth: %w", intErr)
				}
				tmp_ggsntracedepth := OMTraceDepth(decVal_ggsntracedepth)
				v.GgsnTraceDepth = &tmp_ggsntracedepth
				offset += n_ggsntracedepth
			}
		}
	}
	// Decode rnc-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_rnctracedepth, n_rnctracedepth, rawVal_rnctracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", err)
				}
				if decodedTag_rnctracedepth.Class != tag.ClassContextSpecific || decodedTag_rnctracedepth.Number != 4 || decodedTag_rnctracedepth.Constructed != false {
					return fmt.Errorf("decoding rnc-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnctracedepth)
				}
				decVal_rnctracedepth, intErr := ber.DecodeIntegerValue(rawVal_rnctracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", intErr)
				}
				tmp_rnctracedepth := OMTraceDepth(decVal_rnctracedepth)
				v.RncTraceDepth = &tmp_rnctracedepth
				offset += n_rnctracedepth
			}
		}
	}
	// Decode bmsc-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_bmsctracedepth, n_bmsctracedepth, rawVal_bmsctracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding bmsc-TraceDepth: %w", err)
				}
				if decodedTag_bmsctracedepth.Class != tag.ClassContextSpecific || decodedTag_bmsctracedepth.Number != 5 || decodedTag_bmsctracedepth.Constructed != false {
					return fmt.Errorf("decoding bmsc-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bmsctracedepth)
				}
				decVal_bmsctracedepth, intErr := ber.DecodeIntegerValue(rawVal_bmsctracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding bmsc-TraceDepth: %w", intErr)
				}
				tmp_bmsctracedepth := OMTraceDepth(decVal_bmsctracedepth)
				v.BmscTraceDepth = &tmp_bmsctracedepth
				offset += n_bmsctracedepth
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMTraceDepthList", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OMTraceInterfaceList to BER format.
func (v *OMTraceInterfaceList) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MscSList != nil {
		enc_mscslist := ber.EncodeBitString(v.MscSList.Bytes, (8-(v.MscSList.BitLength%8))%8)
		enc_mscslist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_mscslist)
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		enc_mgwlist := ber.EncodeBitString(v.MgwList.Bytes, (8-(v.MgwList.BitLength%8))%8)
		enc_mgwlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_mgwlist)
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		enc_sgsnlist := ber.EncodeBitString(v.SgsnList.Bytes, (8-(v.SgsnList.BitLength%8))%8)
		enc_sgsnlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_sgsnlist)
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		enc_ggsnlist := ber.EncodeBitString(v.GgsnList.Bytes, (8-(v.GgsnList.BitLength%8))%8)
		enc_ggsnlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_ggsnlist)
		children = append(children, enc_ggsnlist...)
	}
	if v.RncList != nil {
		enc_rnclist := ber.EncodeBitString(v.RncList.Bytes, (8-(v.RncList.BitLength%8))%8)
		enc_rnclist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_rnclist)
		children = append(children, enc_rnclist...)
	}
	if v.BmscList != nil {
		enc_bmsclist := ber.EncodeBitString(v.BmscList.Bytes, (8-(v.BmscList.BitLength%8))%8)
		enc_bmsclist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_bmsclist)
		children = append(children, enc_bmsclist...)
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

// MarshalDER encodes OMTraceInterfaceList to DER format.
func (v *OMTraceInterfaceList) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding OMTraceInterfaceList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OMTraceInterfaceList from BER/DER format.
func (v *OMTraceInterfaceList) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OMTraceInterfaceList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMTraceInterfaceList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_mscslist, n_mscslist, rawVal_mscslist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-List: %w", err)
				}
				if decodedTag_mscslist.Class != tag.ClassContextSpecific || decodedTag_mscslist.Number != 0 {
					return fmt.Errorf("decoding msc-s-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscslist)
				}
				bsBytes_mscslist, bsUnused_mscslist, bsErr := ber.DecodeBitStringValue(rawVal_mscslist)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-List: %w", bsErr)
				}
				tmp_mscslist := runtime.BitString{Bytes: bsBytes_mscslist, BitLength: len(bsBytes_mscslist)*8 - bsUnused_mscslist}
				v.MscSList = &tmp_mscslist
				offset += n_mscslist
			}
		}
	}
	// Decode mgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_mgwlist, n_mgwlist, rawVal_mgwlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-List: %w", err)
				}
				if decodedTag_mgwlist.Class != tag.ClassContextSpecific || decodedTag_mgwlist.Number != 1 {
					return fmt.Errorf("decoding mgw-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwlist)
				}
				bsBytes_mgwlist, bsUnused_mgwlist, bsErr := ber.DecodeBitStringValue(rawVal_mgwlist)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-List: %w", bsErr)
				}
				tmp_mgwlist := runtime.BitString{Bytes: bsBytes_mgwlist, BitLength: len(bsBytes_mgwlist)*8 - bsUnused_mgwlist}
				v.MgwList = &tmp_mgwlist
				offset += n_mgwlist
			}
		}
	}
	// Decode sgsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_sgsnlist, n_sgsnlist, rawVal_sgsnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgsn-List: %w", err)
				}
				if decodedTag_sgsnlist.Class != tag.ClassContextSpecific || decodedTag_sgsnlist.Number != 2 {
					return fmt.Errorf("decoding sgsn-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnlist)
				}
				bsBytes_sgsnlist, bsUnused_sgsnlist, bsErr := ber.DecodeBitStringValue(rawVal_sgsnlist)
				if bsErr != nil {
					return fmt.Errorf("decoding sgsn-List: %w", bsErr)
				}
				tmp_sgsnlist := runtime.BitString{Bytes: bsBytes_sgsnlist, BitLength: len(bsBytes_sgsnlist)*8 - bsUnused_sgsnlist}
				v.SgsnList = &tmp_sgsnlist
				offset += n_sgsnlist
			}
		}
	}
	// Decode ggsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_ggsnlist, n_ggsnlist, rawVal_ggsnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ggsn-List: %w", err)
				}
				if decodedTag_ggsnlist.Class != tag.ClassContextSpecific || decodedTag_ggsnlist.Number != 3 {
					return fmt.Errorf("decoding ggsn-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ggsnlist)
				}
				bsBytes_ggsnlist, bsUnused_ggsnlist, bsErr := ber.DecodeBitStringValue(rawVal_ggsnlist)
				if bsErr != nil {
					return fmt.Errorf("decoding ggsn-List: %w", bsErr)
				}
				tmp_ggsnlist := runtime.BitString{Bytes: bsBytes_ggsnlist, BitLength: len(bsBytes_ggsnlist)*8 - bsUnused_ggsnlist}
				v.GgsnList = &tmp_ggsnlist
				offset += n_ggsnlist
			}
		}
	}
	// Decode rnc-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_rnclist, n_rnclist, rawVal_rnclist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rnc-List: %w", err)
				}
				if decodedTag_rnclist.Class != tag.ClassContextSpecific || decodedTag_rnclist.Number != 4 {
					return fmt.Errorf("decoding rnc-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnclist)
				}
				bsBytes_rnclist, bsUnused_rnclist, bsErr := ber.DecodeBitStringValue(rawVal_rnclist)
				if bsErr != nil {
					return fmt.Errorf("decoding rnc-List: %w", bsErr)
				}
				tmp_rnclist := runtime.BitString{Bytes: bsBytes_rnclist, BitLength: len(bsBytes_rnclist)*8 - bsUnused_rnclist}
				v.RncList = &tmp_rnclist
				offset += n_rnclist
			}
		}
	}
	// Decode bmsc-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_bmsclist, n_bmsclist, rawVal_bmsclist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding bmsc-List: %w", err)
				}
				if decodedTag_bmsclist.Class != tag.ClassContextSpecific || decodedTag_bmsclist.Number != 5 {
					return fmt.Errorf("decoding bmsc-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bmsclist)
				}
				bsBytes_bmsclist, bsUnused_bmsclist, bsErr := ber.DecodeBitStringValue(rawVal_bmsclist)
				if bsErr != nil {
					return fmt.Errorf("decoding bmsc-List: %w", bsErr)
				}
				tmp_bmsclist := runtime.BitString{Bytes: bsBytes_bmsclist, BitLength: len(bsBytes_bmsclist)*8 - bsUnused_bmsclist}
				v.BmscList = &tmp_bmsclist
				offset += n_bmsclist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMTraceInterfaceList", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OMTraceEventList to BER format.
func (v *OMTraceEventList) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MscSList != nil {
		enc_mscslist := ber.EncodeBitString(v.MscSList.Bytes, (8-(v.MscSList.BitLength%8))%8)
		enc_mscslist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_mscslist)
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		enc_mgwlist := ber.EncodeBitString(v.MgwList.Bytes, (8-(v.MgwList.BitLength%8))%8)
		enc_mgwlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_mgwlist)
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		enc_sgsnlist := ber.EncodeBitString(v.SgsnList.Bytes, (8-(v.SgsnList.BitLength%8))%8)
		enc_sgsnlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_sgsnlist)
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		enc_ggsnlist := ber.EncodeBitString(v.GgsnList.Bytes, (8-(v.GgsnList.BitLength%8))%8)
		enc_ggsnlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_ggsnlist)
		children = append(children, enc_ggsnlist...)
	}
	if v.BmscList != nil {
		enc_bmsclist := ber.EncodeBitString(v.BmscList.Bytes, (8-(v.BmscList.BitLength%8))%8)
		enc_bmsclist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_bmsclist)
		children = append(children, enc_bmsclist...)
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

// MarshalDER encodes OMTraceEventList to DER format.
func (v *OMTraceEventList) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding OMTraceEventList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OMTraceEventList from BER/DER format.
func (v *OMTraceEventList) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OMTraceEventList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMTraceEventList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_mscslist, n_mscslist, rawVal_mscslist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-List: %w", err)
				}
				if decodedTag_mscslist.Class != tag.ClassContextSpecific || decodedTag_mscslist.Number != 0 {
					return fmt.Errorf("decoding msc-s-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscslist)
				}
				bsBytes_mscslist, bsUnused_mscslist, bsErr := ber.DecodeBitStringValue(rawVal_mscslist)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-List: %w", bsErr)
				}
				tmp_mscslist := runtime.BitString{Bytes: bsBytes_mscslist, BitLength: len(bsBytes_mscslist)*8 - bsUnused_mscslist}
				v.MscSList = &tmp_mscslist
				offset += n_mscslist
			}
		}
	}
	// Decode mgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_mgwlist, n_mgwlist, rawVal_mgwlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-List: %w", err)
				}
				if decodedTag_mgwlist.Class != tag.ClassContextSpecific || decodedTag_mgwlist.Number != 1 {
					return fmt.Errorf("decoding mgw-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwlist)
				}
				bsBytes_mgwlist, bsUnused_mgwlist, bsErr := ber.DecodeBitStringValue(rawVal_mgwlist)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-List: %w", bsErr)
				}
				tmp_mgwlist := runtime.BitString{Bytes: bsBytes_mgwlist, BitLength: len(bsBytes_mgwlist)*8 - bsUnused_mgwlist}
				v.MgwList = &tmp_mgwlist
				offset += n_mgwlist
			}
		}
	}
	// Decode sgsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_sgsnlist, n_sgsnlist, rawVal_sgsnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgsn-List: %w", err)
				}
				if decodedTag_sgsnlist.Class != tag.ClassContextSpecific || decodedTag_sgsnlist.Number != 2 {
					return fmt.Errorf("decoding sgsn-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnlist)
				}
				bsBytes_sgsnlist, bsUnused_sgsnlist, bsErr := ber.DecodeBitStringValue(rawVal_sgsnlist)
				if bsErr != nil {
					return fmt.Errorf("decoding sgsn-List: %w", bsErr)
				}
				tmp_sgsnlist := runtime.BitString{Bytes: bsBytes_sgsnlist, BitLength: len(bsBytes_sgsnlist)*8 - bsUnused_sgsnlist}
				v.SgsnList = &tmp_sgsnlist
				offset += n_sgsnlist
			}
		}
	}
	// Decode ggsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_ggsnlist, n_ggsnlist, rawVal_ggsnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ggsn-List: %w", err)
				}
				if decodedTag_ggsnlist.Class != tag.ClassContextSpecific || decodedTag_ggsnlist.Number != 3 {
					return fmt.Errorf("decoding ggsn-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ggsnlist)
				}
				bsBytes_ggsnlist, bsUnused_ggsnlist, bsErr := ber.DecodeBitStringValue(rawVal_ggsnlist)
				if bsErr != nil {
					return fmt.Errorf("decoding ggsn-List: %w", bsErr)
				}
				tmp_ggsnlist := runtime.BitString{Bytes: bsBytes_ggsnlist, BitLength: len(bsBytes_ggsnlist)*8 - bsUnused_ggsnlist}
				v.GgsnList = &tmp_ggsnlist
				offset += n_ggsnlist
			}
		}
	}
	// Decode bmsc-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_bmsclist, n_bmsclist, rawVal_bmsclist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding bmsc-List: %w", err)
				}
				if decodedTag_bmsclist.Class != tag.ClassContextSpecific || decodedTag_bmsclist.Number != 4 {
					return fmt.Errorf("decoding bmsc-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bmsclist)
				}
				bsBytes_bmsclist, bsUnused_bmsclist, bsErr := ber.DecodeBitStringValue(rawVal_bmsclist)
				if bsErr != nil {
					return fmt.Errorf("decoding bmsc-List: %w", bsErr)
				}
				tmp_bmsclist := runtime.BitString{Bytes: bsBytes_bmsclist, BitLength: len(bsBytes_bmsclist)*8 - bsUnused_bmsclist}
				v.BmscList = &tmp_bmsclist
				offset += n_bmsclist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMTraceEventList", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OMTracePropagationList to BER format.
func (v *OMTracePropagationList) MarshalBER() ([]byte, error) {
	var children []byte
	if v.TraceReference != nil {
		enc_tracereference := ber.EncodeOctetString([]byte(*v.TraceReference))
		enc_tracereference = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_tracereference)
		children = append(children, enc_tracereference...)
	}
	if v.TraceType != nil {
		enc_tracetype := ber.EncodeInteger(int64(*v.TraceType))
		enc_tracetype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_tracetype)
		children = append(children, enc_tracetype...)
	}
	if v.TraceReference2 != nil {
		enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		enc_tracereference2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_tracereference2)
		children = append(children, enc_tracereference2...)
	}
	if v.TraceRecordingSessionReference != nil {
		enc_tracerecordingsessionreference := ber.EncodeOctetString([]byte(*v.TraceRecordingSessionReference))
		enc_tracerecordingsessionreference = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_tracerecordingsessionreference)
		children = append(children, enc_tracerecordingsessionreference...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		enc_rnctracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_rnctracedepth)
		children = append(children, enc_rnctracedepth...)
	}
	if v.RncInterfaceList != nil {
		enc_rncinterfacelist := ber.EncodeBitString(v.RncInterfaceList.Bytes, (8-(v.RncInterfaceList.BitLength%8))%8)
		enc_rncinterfacelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_rncinterfacelist)
		children = append(children, enc_rncinterfacelist...)
	}
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		enc_mscstracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_mscstracedepth)
		children = append(children, enc_mscstracedepth...)
	}
	if v.MscSInterfaceList != nil {
		enc_mscsinterfacelist := ber.EncodeBitString(v.MscSInterfaceList.Bytes, (8-(v.MscSInterfaceList.BitLength%8))%8)
		enc_mscsinterfacelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_mscsinterfacelist)
		children = append(children, enc_mscsinterfacelist...)
	}
	if v.MscSEventList != nil {
		enc_mscseventlist := ber.EncodeBitString(v.MscSEventList.Bytes, (8-(v.MscSEventList.BitLength%8))%8)
		enc_mscseventlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_mscseventlist)
		children = append(children, enc_mscseventlist...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		enc_mgwtracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_mgwtracedepth)
		children = append(children, enc_mgwtracedepth...)
	}
	if v.MgwInterfaceList != nil {
		enc_mgwinterfacelist := ber.EncodeBitString(v.MgwInterfaceList.Bytes, (8-(v.MgwInterfaceList.BitLength%8))%8)
		enc_mgwinterfacelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_mgwinterfacelist)
		children = append(children, enc_mgwinterfacelist...)
	}
	if v.MgwEventList != nil {
		enc_mgweventlist := ber.EncodeBitString(v.MgwEventList.Bytes, (8-(v.MgwEventList.BitLength%8))%8)
		enc_mgweventlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_mgweventlist)
		children = append(children, enc_mgweventlist...)
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

// MarshalDER encodes OMTracePropagationList to DER format.
func (v *OMTracePropagationList) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding OMTracePropagationList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OMTracePropagationList from BER/DER format.
func (v *OMTracePropagationList) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OMTracePropagationList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMTracePropagationList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode traceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceReference: %w", err)
				}
				if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 0 {
					return fmt.Errorf("decoding traceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference)
				}
				tmp_tracereference := OMTraceReference(rawVal_tracereference)
				v.TraceReference = &tmp_tracereference
				offset += n_tracereference
			}
		}
	}
	// Decode traceType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceType: %w", err)
				}
				if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 1 || decodedTag_tracetype.Constructed != false {
					return fmt.Errorf("decoding traceType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracetype)
				}
				decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
				if intErr != nil {
					return fmt.Errorf("decoding traceType: %w", intErr)
				}
				tmp_tracetype := OMTraceType(decVal_tracetype)
				v.TraceType = &tmp_tracetype
				offset += n_tracetype
			}
		}
	}
	// Decode traceReference2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_tracereference2, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceReference2: %w", err)
				}
				if decodedTag_tracereference2.Class != tag.ClassContextSpecific || decodedTag_tracereference2.Number != 2 {
					return fmt.Errorf("decoding traceReference2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference2)
				}
				tmp_tracereference2 := OMTraceReference2(rawVal_tracereference2)
				v.TraceReference2 = &tmp_tracereference2
				offset += n_tracereference2
			}
		}
	}
	// Decode traceRecordingSessionReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_tracerecordingsessionreference, n_tracerecordingsessionreference, rawVal_tracerecordingsessionreference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceRecordingSessionReference: %w", err)
				}
				if decodedTag_tracerecordingsessionreference.Class != tag.ClassContextSpecific || decodedTag_tracerecordingsessionreference.Number != 3 {
					return fmt.Errorf("decoding traceRecordingSessionReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracerecordingsessionreference)
				}
				tmp_tracerecordingsessionreference := OMTraceRecordingSessionReference(rawVal_tracerecordingsessionreference)
				v.TraceRecordingSessionReference = &tmp_tracerecordingsessionreference
				offset += n_tracerecordingsessionreference
			}
		}
	}
	// Decode rnc-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_rnctracedepth, n_rnctracedepth, rawVal_rnctracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", err)
				}
				if decodedTag_rnctracedepth.Class != tag.ClassContextSpecific || decodedTag_rnctracedepth.Number != 4 || decodedTag_rnctracedepth.Constructed != false {
					return fmt.Errorf("decoding rnc-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnctracedepth)
				}
				decVal_rnctracedepth, intErr := ber.DecodeIntegerValue(rawVal_rnctracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", intErr)
				}
				tmp_rnctracedepth := OMTraceDepth(decVal_rnctracedepth)
				v.RncTraceDepth = &tmp_rnctracedepth
				offset += n_rnctracedepth
			}
		}
	}
	// Decode rnc-InterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_rncinterfacelist, n_rncinterfacelist, rawVal_rncinterfacelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rnc-InterfaceList: %w", err)
				}
				if decodedTag_rncinterfacelist.Class != tag.ClassContextSpecific || decodedTag_rncinterfacelist.Number != 5 {
					return fmt.Errorf("decoding rnc-InterfaceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rncinterfacelist)
				}
				bsBytes_rncinterfacelist, bsUnused_rncinterfacelist, bsErr := ber.DecodeBitStringValue(rawVal_rncinterfacelist)
				if bsErr != nil {
					return fmt.Errorf("decoding rnc-InterfaceList: %w", bsErr)
				}
				tmp_rncinterfacelist := runtime.BitString{Bytes: bsBytes_rncinterfacelist, BitLength: len(bsBytes_rncinterfacelist)*8 - bsUnused_rncinterfacelist}
				v.RncInterfaceList = &tmp_rncinterfacelist
				offset += n_rncinterfacelist
			}
		}
	}
	// Decode msc-s-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_mscstracedepth, n_mscstracedepth, rawVal_mscstracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", err)
				}
				if decodedTag_mscstracedepth.Class != tag.ClassContextSpecific || decodedTag_mscstracedepth.Number != 6 || decodedTag_mscstracedepth.Constructed != false {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscstracedepth)
				}
				decVal_mscstracedepth, intErr := ber.DecodeIntegerValue(rawVal_mscstracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", intErr)
				}
				tmp_mscstracedepth := OMTraceDepth(decVal_mscstracedepth)
				v.MscSTraceDepth = &tmp_mscstracedepth
				offset += n_mscstracedepth
			}
		}
	}
	// Decode msc-s-InterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_mscsinterfacelist, n_mscsinterfacelist, rawVal_mscsinterfacelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-InterfaceList: %w", err)
				}
				if decodedTag_mscsinterfacelist.Class != tag.ClassContextSpecific || decodedTag_mscsinterfacelist.Number != 7 {
					return fmt.Errorf("decoding msc-s-InterfaceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscsinterfacelist)
				}
				bsBytes_mscsinterfacelist, bsUnused_mscsinterfacelist, bsErr := ber.DecodeBitStringValue(rawVal_mscsinterfacelist)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-InterfaceList: %w", bsErr)
				}
				tmp_mscsinterfacelist := runtime.BitString{Bytes: bsBytes_mscsinterfacelist, BitLength: len(bsBytes_mscsinterfacelist)*8 - bsUnused_mscsinterfacelist}
				v.MscSInterfaceList = &tmp_mscsinterfacelist
				offset += n_mscsinterfacelist
			}
		}
	}
	// Decode msc-s-EventList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_mscseventlist, n_mscseventlist, rawVal_mscseventlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-EventList: %w", err)
				}
				if decodedTag_mscseventlist.Class != tag.ClassContextSpecific || decodedTag_mscseventlist.Number != 8 {
					return fmt.Errorf("decoding msc-s-EventList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscseventlist)
				}
				bsBytes_mscseventlist, bsUnused_mscseventlist, bsErr := ber.DecodeBitStringValue(rawVal_mscseventlist)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-EventList: %w", bsErr)
				}
				tmp_mscseventlist := runtime.BitString{Bytes: bsBytes_mscseventlist, BitLength: len(bsBytes_mscseventlist)*8 - bsUnused_mscseventlist}
				v.MscSEventList = &tmp_mscseventlist
				offset += n_mscseventlist
			}
		}
	}
	// Decode mgw-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_mgwtracedepth, n_mgwtracedepth, rawVal_mgwtracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", err)
				}
				if decodedTag_mgwtracedepth.Class != tag.ClassContextSpecific || decodedTag_mgwtracedepth.Number != 9 || decodedTag_mgwtracedepth.Constructed != false {
					return fmt.Errorf("decoding mgw-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwtracedepth)
				}
				decVal_mgwtracedepth, intErr := ber.DecodeIntegerValue(rawVal_mgwtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", intErr)
				}
				tmp_mgwtracedepth := OMTraceDepth(decVal_mgwtracedepth)
				v.MgwTraceDepth = &tmp_mgwtracedepth
				offset += n_mgwtracedepth
			}
		}
	}
	// Decode mgw-InterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_mgwinterfacelist, n_mgwinterfacelist, rawVal_mgwinterfacelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-InterfaceList: %w", err)
				}
				if decodedTag_mgwinterfacelist.Class != tag.ClassContextSpecific || decodedTag_mgwinterfacelist.Number != 10 {
					return fmt.Errorf("decoding mgw-InterfaceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwinterfacelist)
				}
				bsBytes_mgwinterfacelist, bsUnused_mgwinterfacelist, bsErr := ber.DecodeBitStringValue(rawVal_mgwinterfacelist)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-InterfaceList: %w", bsErr)
				}
				tmp_mgwinterfacelist := runtime.BitString{Bytes: bsBytes_mgwinterfacelist, BitLength: len(bsBytes_mgwinterfacelist)*8 - bsUnused_mgwinterfacelist}
				v.MgwInterfaceList = &tmp_mgwinterfacelist
				offset += n_mgwinterfacelist
			}
		}
	}
	// Decode mgw-EventList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_mgweventlist, n_mgweventlist, rawVal_mgweventlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-EventList: %w", err)
				}
				if decodedTag_mgweventlist.Class != tag.ClassContextSpecific || decodedTag_mgweventlist.Number != 11 {
					return fmt.Errorf("decoding mgw-EventList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgweventlist)
				}
				bsBytes_mgweventlist, bsUnused_mgweventlist, bsErr := ber.DecodeBitStringValue(rawVal_mgweventlist)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-EventList: %w", bsErr)
				}
				tmp_mgweventlist := runtime.BitString{Bytes: bsBytes_mgweventlist, BitLength: len(bsBytes_mgweventlist)*8 - bsUnused_mgweventlist}
				v.MgwEventList = &tmp_mgweventlist
				offset += n_mgweventlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMTracePropagationList", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OMActivateTraceModeRes to BER format.
func (v *OMActivateTraceModeRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceSupportIndicator != nil {
		enc_tracesupportindicator := ber.EncodeNull()
		enc_tracesupportindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_tracesupportindicator)
		children = append(children, enc_tracesupportindicator...)
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

// MarshalDER encodes OMActivateTraceModeRes to DER format.
func (v *OMActivateTraceModeRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding OMActivateTraceModeRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OMActivateTraceModeRes from BER/DER format.
func (v *OMActivateTraceModeRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OMActivateTraceModeRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMActivateTraceModeRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 0 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
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
	// Decode traceSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_tracesupportindicator, n_tracesupportindicator, rawVal_tracesupportindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceSupportIndicator: %w", err)
				}
				if decodedTag_tracesupportindicator.Class != tag.ClassContextSpecific || decodedTag_tracesupportindicator.Number != 1 || decodedTag_tracesupportindicator.Constructed != false {
					return fmt.Errorf("decoding traceSupportIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracesupportindicator)
				}
				if len(rawVal_tracesupportindicator) != 0 {
					return fmt.Errorf("decoding traceSupportIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_tracesupportindicator))
				}
				v.TraceSupportIndicator = &struct{}{}
				offset += n_tracesupportindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMActivateTraceModeRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OMDeactivateTraceModeArg to BER format.
func (v *OMDeactivateTraceModeArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	enc_tracereference = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_tracereference)
	children = append(children, enc_tracereference...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceReference2 != nil {
		enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		enc_tracereference2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_tracereference2)
		children = append(children, enc_tracereference2...)
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

// MarshalDER encodes OMDeactivateTraceModeArg to DER format.
func (v *OMDeactivateTraceModeArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding OMDeactivateTraceModeArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OMDeactivateTraceModeArg from BER/DER format.
func (v *OMDeactivateTraceModeArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OMDeactivateTraceModeArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMDeactivateTraceModeArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				tmp_imsi := CommonDataTypesIMSI(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode traceReference
	if offset >= len(content) {
		return fmt.Errorf("missing required field traceReference")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for traceReference, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding traceReference: %w", err)
	}
	if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
		return fmt.Errorf("decoding traceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference)
	}
	v.TraceReference = OMTraceReference(rawVal_tracereference)
	offset += n_tracereference
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 2 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
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
	// Decode traceReference2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_tracereference2, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceReference2: %w", err)
				}
				if decodedTag_tracereference2.Class != tag.ClassContextSpecific || decodedTag_tracereference2.Number != 3 {
					return fmt.Errorf("decoding traceReference2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference2)
				}
				tmp_tracereference2 := OMTraceReference2(rawVal_tracereference2)
				v.TraceReference2 = &tmp_tracereference2
				offset += n_tracereference2
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMDeactivateTraceModeArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OMDeactivateTraceModeRes to BER format.
func (v *OMDeactivateTraceModeRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_extensioncontainer)
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

// MarshalDER encodes OMDeactivateTraceModeRes to DER format.
func (v *OMDeactivateTraceModeRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding OMDeactivateTraceModeRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OMDeactivateTraceModeRes from BER/DER format.
func (v *OMDeactivateTraceModeRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OMDeactivateTraceModeRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMDeactivateTraceModeRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 0 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
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
			return &ber.DecodeError{Offset: offset, TypeName: "OMDeactivateTraceModeRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
