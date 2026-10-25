// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
)

func globalGNBIDreplayBoundCodecOps(c s05.GlobalGNBIDValueCodec, raw []byte) replayBoundOps {
	v, _, _ := c.DecodeAPER(raw)
	return replayBoundOps{decode: func() error { _, _, err := c.DecodeAPER(raw); return err }, encode: func() ([]byte, error) { return c.EncodeAPER(v) }}
}
