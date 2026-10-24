// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
)

func successfulOutcomereplayBoundCodecOps(c s18.SuccessfulOutcomeValueCodec, raw []byte) replayBoundOps {
	v, _, _ := c.DecodeAPER(raw)
	return replayBoundOps{decode: func() error { _, _, err := c.DecodeAPER(raw); return err }, encode: func() ([]byte, error) { return c.EncodeAPER(v) }}
}
