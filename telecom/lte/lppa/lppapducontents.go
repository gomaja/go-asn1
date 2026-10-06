// Code generated from ASN.1 module "LPPA-PDU-Contents". DO NOT EDIT.

package lppa

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = per.NewBitBuffer
)

// ECIDMeasurementInitiationRequest represents the ASN.1 type E-CIDMeasurementInitiationRequest (SEQUENCE).
type ECIDMeasurementInitiationRequest struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// ECIDMeasurementInitiationResponse represents the ASN.1 type E-CIDMeasurementInitiationResponse (SEQUENCE).
type ECIDMeasurementInitiationResponse struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// ECIDMeasurementInitiationFailure represents the ASN.1 type E-CIDMeasurementInitiationFailure (SEQUENCE).
type ECIDMeasurementInitiationFailure struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// ECIDMeasurementFailureIndication represents the ASN.1 type E-CIDMeasurementFailureIndication (SEQUENCE).
type ECIDMeasurementFailureIndication struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// ECIDMeasurementReport represents the ASN.1 type E-CIDMeasurementReport (SEQUENCE).
type ECIDMeasurementReport struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// ECIDMeasurementTerminationCommand represents the ASN.1 type E-CIDMeasurementTerminationCommand (SEQUENCE).
type ECIDMeasurementTerminationCommand struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// OTDOAInformationRequest represents the ASN.1 type OTDOAInformationRequest (SEQUENCE).
type OTDOAInformationRequest struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// OTDOAInformationType represents the ASN.1 type OTDOA-Information-Type (SEQUENCE_OF).

type OTDOAInformationType = []ProtocolIESingleContainer

// OTDOAInformationTypeItem represents the ASN.1 type OTDOA-Information-Type-Item (SEQUENCE).
type OTDOAInformationTypeItem struct {
	OTDOAInformationTypeItem OTDOAInformationItem       `asn1:"tag:0,context,implicit"`
	IEExtensions             ProtocolExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	IEExtensionsIndef_       bool                       `asn1:"-" json:"-"`
	ExtCount_                int64                      `asn1:"-" json:"-"`
	ExtPresent_              []bool                     `asn1:"-" json:"-"`
	ExtData_                 [][]byte                   `asn1:"-" json:"-"`
	PERPadding_              per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_           []per.CompletePadding      `asn1:"-" json:"-"`
}

// OTDOAInformationResponse represents the ASN.1 type OTDOAInformationResponse (SEQUENCE).
type OTDOAInformationResponse struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// OTDOAInformationFailure represents the ASN.1 type OTDOAInformationFailure (SEQUENCE).
type OTDOAInformationFailure struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// UTDOAInformationRequest represents the ASN.1 type UTDOAInformationRequest (SEQUENCE).
type UTDOAInformationRequest struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// UTDOAInformationResponse represents the ASN.1 type UTDOAInformationResponse (SEQUENCE).
type UTDOAInformationResponse struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// UTDOAInformationFailure represents the ASN.1 type UTDOAInformationFailure (SEQUENCE).
type UTDOAInformationFailure struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// UTDOAInformationUpdate represents the ASN.1 type UTDOAInformationUpdate (SEQUENCE).
type UTDOAInformationUpdate struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// AssistanceInformationControl represents the ASN.1 type AssistanceInformationControl (SEQUENCE).
type AssistanceInformationControl struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// AssistanceInformationFeedback represents the ASN.1 type AssistanceInformationFeedback (SEQUENCE).
type AssistanceInformationFeedback struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// ErrorIndication represents the ASN.1 type ErrorIndication (SEQUENCE).
type ErrorIndication struct {
	ProtocolIEs       ProtocolIEContainer   `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// PrivateMessage represents the ASN.1 type PrivateMessage (SEQUENCE).
type PrivateMessage struct {
	PrivateIEs       PrivateIEContainer    `asn1:"tag:0,context,implicit"`
	PrivateIEsIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_        int64                 `asn1:"-" json:"-"`
	ExtPresent_      []bool                `asn1:"-" json:"-"`
	ExtData_         [][]byte              `asn1:"-" json:"-"`
	PERPadding_      per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_   []per.CompletePadding `asn1:"-" json:"-"`
}

// MarshalAPER encodes ECIDMeasurementInitiationRequest to APER format.
func (v *ECIDMeasurementInitiationRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ECIDMeasurementInitiationRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ECIDMeasurementInitiationRequest from APER format.
func (v *ECIDMeasurementInitiationRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationRequest")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationRequest")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ECIDMeasurementInitiationRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ECIDMeasurementInitiationRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes ECIDMeasurementInitiationResponse to APER format.
func (v *ECIDMeasurementInitiationResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ECIDMeasurementInitiationResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ECIDMeasurementInitiationResponse from APER format.
func (v *ECIDMeasurementInitiationResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationResponse")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationResponse")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ECIDMeasurementInitiationResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ECIDMeasurementInitiationResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes ECIDMeasurementInitiationFailure to APER format.
func (v *ECIDMeasurementInitiationFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ECIDMeasurementInitiationFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ECIDMeasurementInitiationFailure from APER format.
func (v *ECIDMeasurementInitiationFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationFailure")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationFailure")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ECIDMeasurementInitiationFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ECIDMeasurementInitiationFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes ECIDMeasurementFailureIndication to APER format.
func (v *ECIDMeasurementFailureIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ECIDMeasurementFailureIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ECIDMeasurementFailureIndication from APER format.
func (v *ECIDMeasurementFailureIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementFailureIndication")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementFailureIndication")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ECIDMeasurementFailureIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ECIDMeasurementFailureIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes ECIDMeasurementReport to APER format.
func (v *ECIDMeasurementReport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ECIDMeasurementReport) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ECIDMeasurementReport from APER format.
func (v *ECIDMeasurementReport) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementReport")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementReport")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ECIDMeasurementReport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ECIDMeasurementReport{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes ECIDMeasurementTerminationCommand to APER format.
func (v *ECIDMeasurementTerminationCommand) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ECIDMeasurementTerminationCommand) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ECIDMeasurementTerminationCommand from APER format.
func (v *ECIDMeasurementTerminationCommand) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementTerminationCommand")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementTerminationCommand")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ECIDMeasurementTerminationCommand) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ECIDMeasurementTerminationCommand{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes OTDOAInformationRequest to APER format.
func (v *OTDOAInformationRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *OTDOAInformationRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes OTDOAInformationRequest from APER format.
func (v *OTDOAInformationRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationRequest")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationRequest")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *OTDOAInformationRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = OTDOAInformationRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPEROTDOAInformationTypeListValue struct{ Value OTDOAInformationType }

// OTDOAInformationTypeComplete carries a complete OTDOAInformationType encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOAInformationTypeComplete struct {
	Value       OTDOAInformationType
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *OTDOAInformationTypeComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPEROTDOAInformationTypeTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *OTDOAInformationTypeComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPEROTDOAInformationTypeFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationType")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationType")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPEROTDOAInformationType encodes a OTDOAInformationType list to APER.
func MarshalAPEROTDOAInformationType(list OTDOAInformationTypeComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPEROTDOAInformationTypeTo appends a OTDOAInformationType list to bb.
func MarshalAPEROTDOAInformationTypeTo(list OTDOAInformationType, bb *per.BitBuffer) error {
	v := asn1cAPEROTDOAInformationTypeListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPEROTDOAInformationType decodes a OTDOAInformationType list from APER.
func UnmarshalAPEROTDOAInformationType(data []byte) (OTDOAInformationTypeComplete, error) {
	var value OTDOAInformationTypeComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPEROTDOAInformationTypeFrom decodes a OTDOAInformationType list from bb.
func UnmarshalAPEROTDOAInformationTypeFrom(bb *per.BitBuffer) (OTDOAInformationType, error) {
	var v asn1cAPEROTDOAInformationTypeListValue
	if err := unmarshalAPEROTDOAInformationTypeInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPEROTDOAInformationTypeInto(v *asn1cAPEROTDOAInformationTypeListValue, bb *per.BitBuffer) error {
	v.Value = make(OTDOAInformationType, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ProtocolIESingleContainer
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes OTDOAInformationTypeItem to APER format.
func (v *OTDOAInformationTypeItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *OTDOAInformationTypeItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.OTDOAInformationTypeItem), 10, true); err != nil {
		return fmt.Errorf("encoding oTDOA-Information-Type-Item: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes OTDOAInformationTypeItem from APER format.
func (v *OTDOAInformationTypeItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationTypeItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationTypeItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *OTDOAInformationTypeItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = OTDOAInformationTypeItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_otdoainformationtypeitem, err := per.DecodeEnumeratedAligned(bb, 10, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationTypeItem")
	}
	v.OTDOAInformationTypeItem = OTDOAInformationItem(val_otdoainformationtypeitem)
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes OTDOAInformationResponse to APER format.
func (v *OTDOAInformationResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *OTDOAInformationResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes OTDOAInformationResponse from APER format.
func (v *OTDOAInformationResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationResponse")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationResponse")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *OTDOAInformationResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = OTDOAInformationResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes OTDOAInformationFailure to APER format.
func (v *OTDOAInformationFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *OTDOAInformationFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes OTDOAInformationFailure from APER format.
func (v *OTDOAInformationFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationFailure")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationFailure")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *OTDOAInformationFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = OTDOAInformationFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes UTDOAInformationRequest to APER format.
func (v *UTDOAInformationRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *UTDOAInformationRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes UTDOAInformationRequest from APER format.
func (v *UTDOAInformationRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationRequest")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationRequest")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *UTDOAInformationRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UTDOAInformationRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes UTDOAInformationResponse to APER format.
func (v *UTDOAInformationResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *UTDOAInformationResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes UTDOAInformationResponse from APER format.
func (v *UTDOAInformationResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationResponse")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationResponse")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *UTDOAInformationResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UTDOAInformationResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes UTDOAInformationFailure to APER format.
func (v *UTDOAInformationFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *UTDOAInformationFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes UTDOAInformationFailure from APER format.
func (v *UTDOAInformationFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationFailure")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationFailure")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *UTDOAInformationFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UTDOAInformationFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes UTDOAInformationUpdate to APER format.
func (v *UTDOAInformationUpdate) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *UTDOAInformationUpdate) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes UTDOAInformationUpdate from APER format.
func (v *UTDOAInformationUpdate) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationUpdate")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationUpdate")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *UTDOAInformationUpdate) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UTDOAInformationUpdate{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes AssistanceInformationControl to APER format.
func (v *AssistanceInformationControl) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *AssistanceInformationControl) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes AssistanceInformationControl from APER format.
func (v *AssistanceInformationControl) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationControl")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationControl")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *AssistanceInformationControl) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = AssistanceInformationControl{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes AssistanceInformationFeedback to APER format.
func (v *AssistanceInformationFeedback) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *AssistanceInformationFeedback) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes AssistanceInformationFeedback from APER format.
func (v *AssistanceInformationFeedback) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFeedback")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFeedback")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *AssistanceInformationFeedback) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = AssistanceInformationFeedback{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes ErrorIndication to APER format.
func (v *ErrorIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ErrorIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ErrorIndication from APER format.
func (v *ErrorIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ErrorIndication")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ErrorIndication")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ErrorIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ErrorIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes PrivateMessage to APER format.
func (v *PrivateMessage) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *PrivateMessage) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.PrivateIEs)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_privateies < 0 || fragmentOffset_privateies > int64(len(v.PrivateIEs)) || fragmentLength_privateies < 0 || fragmentLength_privateies > int64(len(v.PrivateIEs[fragmentOffset_privateies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PrivateIEs[fragmentOffset_privateies : fragmentOffset_privateies+fragmentLength_privateies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding privateIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding privateIEs: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes PrivateMessage from APER format.
func (v *PrivateMessage) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PrivateMessage")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PrivateMessage")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *PrivateMessage) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PrivateMessage{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.PrivateIEs = make(PrivateIEContainer, 0)
	_, errCollection_privateies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_privateies < 0 || fragmentLength_privateies < 0 || fragmentLength_privateies > int64(^uint(0)>>1) || fragmentOffset_privateies > int64(^uint(0)>>1)-fragmentLength_privateies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_privateies; i++ {
			var elem PrivateIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PrivateIEs[%d]", fragmentOffset_privateies+i))
			}
			v.PrivateIEs = append(v.PrivateIEs, elem)
		}
		return nil
	})
	if errCollection_privateies != nil {
		return runtime.WrapDecodePath(errCollection_privateies, "PrivateIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}
