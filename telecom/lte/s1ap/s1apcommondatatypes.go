// Code generated from ASN.1 module "S1AP-CommonDataTypes". DO NOT EDIT.

package s1ap

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

// Criticality represents the ASN.1 ENUMERATED type Criticality.
type Criticality int64

const (
	CriticalityReject Criticality = 0
	CriticalityIgnore Criticality = 1
	CriticalityNotify Criticality = 2
)

func (v Criticality) String() string {
	switch v {
	case CriticalityReject:
		return "reject"
	case CriticalityIgnore:
		return "ignore"
	case CriticalityNotify:
		return "notify"
	default:
		return "unknown"
	}
}

// Presence represents the ASN.1 ENUMERATED type Presence.
type Presence int64

const (
	PresenceOptional    Presence = 0
	PresenceConditional Presence = 1
	PresenceMandatory   Presence = 2
)

func (v Presence) String() string {
	switch v {
	case PresenceOptional:
		return "optional"
	case PresenceConditional:
		return "conditional"
	case PresenceMandatory:
		return "mandatory"
	default:
		return "unknown"
	}
}

// PrivateIEID choice constants.
const (
	PrivateIEIDChoiceLocal  = 1
	PrivateIEIDChoiceGlobal = 2
)

// PrivateIEID represents the ASN.1 CHOICE type PrivateIE-ID.
type PrivateIEID struct {
	Choice int
	Local  *int64                   `json:"Local,omitempty"`
	Global runtime.ObjectIdentifier `json:"Global,omitempty"`
}

// NewPrivateIEIDLocal creates a PrivateIE-ID with the local alternative.
func NewPrivateIEIDLocal(v int64) PrivateIEID {
	return PrivateIEID{
		Choice: PrivateIEIDChoiceLocal,
		Local:  &v,
	}
}

// NewPrivateIEIDGlobal creates a PrivateIE-ID with the global alternative.
func NewPrivateIEIDGlobal(v runtime.ObjectIdentifier) PrivateIEID {
	return PrivateIEID{
		Choice: PrivateIEIDChoiceGlobal,
		Global: v,
	}
}

// ProcedureCode represents the ASN.1 type ProcedureCode (INTEGER).
type ProcedureCode = int64

// ProtocolExtensionID represents the ASN.1 type ProtocolExtensionID (INTEGER).
type ProtocolExtensionID = int64

// ProtocolIEID represents the ASN.1 type ProtocolIE-ID (INTEGER).
type ProtocolIEID = int64

// TriggeringMessage represents the ASN.1 ENUMERATED type TriggeringMessage.
type TriggeringMessage int64

const (
	TriggeringMessageInitiatingMessage    TriggeringMessage = 0
	TriggeringMessageSuccessfulOutcome    TriggeringMessage = 1
	TriggeringMessageUnsuccessfullOutcome TriggeringMessage = 2
)

func (v TriggeringMessage) String() string {
	switch v {
	case TriggeringMessageInitiatingMessage:
		return "initiating-message"
	case TriggeringMessageSuccessfulOutcome:
		return "successful-outcome"
	case TriggeringMessageUnsuccessfullOutcome:
		return "unsuccessfull-outcome"
	default:
		return "unknown"
	}
}

// MarshalAPER encodes PrivateIEID to APER format.
func (v *PrivateIEID) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *PrivateIEID) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case PrivateIEIDChoiceLocal:
		if err := per.EncodeIntegerAligned(bb, int64(*v.Local), int64Ptr(0), int64Ptr(65535), false); err != nil {
			return fmt.Errorf("encoding local: %w", err)
		}
	case PrivateIEIDChoiceGlobal:
		if err := per.EncodeObjectIdentifierAligned(bb, []uint64(v.Global)); err != nil {
			return fmt.Errorf("encoding global: %w", err)
		}
	default:
		return fmt.Errorf("unknown PrivateIEID choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes PrivateIEID from APER format.
func (v *PrivateIEID) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalAPERFrom(bb)
}

func (v *PrivateIEID) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case PrivateIEIDChoiceLocal:
		val_local, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
		if err != nil {
			return fmt.Errorf("decoding local: %w", err)
		}
		v.Local = &val_local
	case PrivateIEIDChoiceGlobal:
		val_global, err := per.DecodeObjectIdentifierAligned(bb)
		if err != nil {
			return fmt.Errorf("decoding global: %w", err)
		}
		v.Global = runtime.ObjectIdentifier(val_global)
	}
	return nil
}
