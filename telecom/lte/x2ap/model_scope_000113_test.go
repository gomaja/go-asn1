// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
)

func replayBoundEnvelopeDecode(v *s19.X2APPDU, raw []byte) error {
	_, err := v.UnmarshalAPER(raw)
	return err
}
