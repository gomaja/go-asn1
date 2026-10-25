// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

func errorIndicationIEFieldreplayBoundCodecOps(c ErrorIndicationIEFieldValueCodec, raw []byte) replayBoundOps {
	v, _, _ := c.DecodeAPER(raw)
	return replayBoundOps{decode: func() error { _, _, err := c.DecodeAPER(raw); return err }, encode: func() ([]byte, error) { return c.EncodeAPER(v) }}
}
