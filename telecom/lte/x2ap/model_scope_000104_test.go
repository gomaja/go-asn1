// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

func replayBoundWrap(raw []byte, id int64) []byte {
	bb := aper.NewBitBuffer()
	replayBoundNeed(aper.EncodeIntegerAligned(bb, id, replayBoundInt(0), replayBoundInt(65535), false))
	replayBoundNeed(aper.EncodeEnumeratedAligned(bb, 1, 3, false))
	replayBoundNeed(aper.EncodeOpenTypeAligned(bb, raw))
	return bb.CompleteBytes()
}
