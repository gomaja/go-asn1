// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
)

func uEX2APIDreplayBoundCodecOps(c s11.UEX2APIDValueCodec, raw []byte) replayBoundOps {
	v, _, _ := c.DecodeAPER(raw)
	return replayBoundOps{decode: func() error { _, _, err := c.DecodeAPER(raw); return err }, encode: func() ([]byte, error) { return c.EncodeAPER(v) }}
}
