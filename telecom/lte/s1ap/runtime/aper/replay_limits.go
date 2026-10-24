// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay_limits.go; SHA-256 7f235df67c7304b0d887c664688001baad26fc5d8f400f6a3913869b1df23f22.
package aper

// replayCursor reads saved framing in original bit alignment. X.691 (02/2021)
// §§11.1.4,11.2.2,11.9.3.8,23.8 define these already-verified boundaries.
type replayCursor struct {
	wire             WireSpan
	segment          int
	offset, position uint64
}

func (c *replayCursor) part() BitSpan {
	if len(c.wire.segments) != 0 {
		return c.wire.segments[c.segment]
	}
	return BitSpan{Start: c.wire.start, End: c.wire.end}
}
func (c *replayCursor) skip(n uint64) bool {
	for n != 0 {
		if len(c.wire.segments) != 0 && c.segment >= len(c.wire.segments) {
			return false
		}
		p := c.part()
		if p.End < p.Start || c.offset > p.End-p.Start {
			return false
		}
		available := p.End - p.Start - c.offset
		if available == 0 {
			if len(c.wire.segments) == 0 {
				return false
			}
			c.segment++
			c.offset = 0
			continue
		}
		take := min(n, available)
		c.offset += take
		c.position += take
		n -= take
	}
	return true
}
func (c *replayCursor) read(n uint64) (uint64, bool) {
	var value uint64
	for range n {
		if len(c.wire.segments) != 0 && c.segment >= len(c.wire.segments) {
			return 0, false
		}
		p := c.part()
		if c.offset == p.End-p.Start {
			if !c.skip(1) {
				return 0, false
			}
			c.offset--
			c.position--
			p = c.part()
		}
		bit := p.Start + c.offset
		if bit/8 >= uint64(len(c.wire.original)) {
			return 0, false
		}
		value = value<<1 | uint64(c.wire.original[bit/8]>>(7-bit%8)&1)
		c.offset++
		c.position++
	}
	return value, true
}
func (c *replayCursor) align() bool {
	first := c.wire.start
	if len(c.wire.segments) != 0 {
		first = c.wire.segments[0].Start
	}
	return c.skip((8 - (first+c.position)%8) % 8)
}
func chargeChoiceReplay(wire WireSpan, budget *DecodeBudget) error {
	bb := NewBudgetBuffer(budget)
	cursor := replayCursor{wire: wire}
	extension, ok := cursor.read(1)
	if !ok {
		return bb.resourceError("invalid retained CHOICE framing")
	}
	if extension == 0 {
		return nil
	}
	large, ok := cursor.read(1)
	if !ok {
		return bb.resourceError("invalid retained CHOICE index")
	}
	if large == 0 {
		_, ok = cursor.read(6)
	} else {
		if !cursor.align() {
			return bb.resourceError("invalid retained CHOICE alignment")
		}
		size, valid := cursor.read(8)
		ok = valid && size < 128 && cursor.skip(size*8)
	}
	if !ok || !cursor.align() {
		return bb.resourceError("invalid retained CHOICE index")
	}
	var total uint64
	for {
		if err := bb.ChargeFragment(); err != nil {
			return err
		}
		first, ok := cursor.read(8)
		if !ok {
			return bb.resourceError("invalid retained open length")
		}
		length := first
		more := false
		if first&128 != 0 {
			if first&64 != 0 {
				length = (first & 63) * 16384
				more = true
			} else {
				last, ok := cursor.read(8)
				if !ok {
					return bb.resourceError("invalid retained open length")
				}
				length = (first&63)*256 + last
			}
		}
		maximum := bb.openTypeMaximum()
		if total > maximum || length > maximum-total {
			return bb.resourceError("open type bytes exceeded")
		}
		total += length
		if !cursor.skip(length * 8) {
			return bb.resourceError("invalid retained open contents")
		}
		if !more {
			return nil
		}
	}
}
