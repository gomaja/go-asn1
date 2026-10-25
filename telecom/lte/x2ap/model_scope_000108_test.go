// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
)

func replayBoundEnvelopeDecode(v *s20.X2APPDU, raw []byte) error {
	_, err := v.UnmarshalAPER(raw)
	return err
}
