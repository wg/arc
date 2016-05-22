//
// poly1305_32.go: 32->64 bit multiplies, 64 bit additions
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to poly1305, using the creative
// commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package poly1305

import (
	"encoding/binary"
	"unsafe"
)

type implState struct {
	r   [5]uint32
	h   [5]uint32
	pad [4]uint32
}

func (impl *implState) init(key []byte) {
	//
	// poly1305-donna-32.h:poly1305_init()
	//

	// r &= 0xffffffc0ffffffc0ffffffc0fffffff
	if isLittleEndian {
		impl.r[0] = *(*uint32)(unsafe.Pointer(&key[0])) & 0x3ffffff
		impl.r[1] = (*(*uint32)(unsafe.Pointer(&key[3])) >> 2) & 0x3ffff03
		impl.r[2] = (*(*uint32)(unsafe.Pointer(&key[6])) >> 4) & 0x3ffc0ff
		impl.r[3] = (*(*uint32)(unsafe.Pointer(&key[9])) >> 6) & 0x3f03fff
		impl.r[4] = (*(*uint32)(unsafe.Pointer(&key[12])) >> 8) & 0x00fffff
	} else {
		impl.r[0] = binary.LittleEndian.Uint32(key[0:]) & 0x3ffffff
		impl.r[1] = (binary.LittleEndian.Uint32(key[3:]) >> 2) & 0x3ffff03
		impl.r[2] = (binary.LittleEndian.Uint32(key[6:]) >> 4) & 0x3ffc0ff
		impl.r[3] = (binary.LittleEndian.Uint32(key[9:]) >> 6) & 0x3f03fff
		impl.r[4] = (binary.LittleEndian.Uint32(key[12:]) >> 8) & 0x00fffff
	}

	// h = 0
	for i := range impl.h {
		impl.h[i] = 0
	}

	// save pad for later
	impl.pad[0] = binary.LittleEndian.Uint32(key[16:])
	impl.pad[1] = binary.LittleEndian.Uint32(key[20:])
	impl.pad[2] = binary.LittleEndian.Uint32(key[24:])
	impl.pad[3] = binary.LittleEndian.Uint32(key[28:])
}

func (impl *implState) clear() {
	for i := range impl.h {
		impl.h[i] = 0
	}
	for i := range impl.r {
		impl.r[i] = 0
	}
	for i := range impl.pad {
		impl.pad[i] = 0
	}
}

func (impl *implState) blocks(m []byte, bytes int, isFinal bool) {
	//
	// poly1305-donna-32.h:poly1305_blocks()
	//

	var hibit uint32
	var d0, d1, d2, d3, d4 uint64
	var c uint32
	if !isFinal {
		hibit = 1 << 24 // 1 << 128
	}
	r0, r1, r2, r3, r4 := impl.r[0], impl.r[1], impl.r[2], impl.r[3], impl.r[4]
	s1, s2, s3, s4 := r1*5, r2*5, r3*5, r4*5
	h0, h1, h2, h3, h4 := impl.h[0], impl.h[1], impl.h[2], impl.h[3], impl.h[4]

	for bytes >= BlockSize {
		// h += m[i]
		if isLittleEndian {
			h0 += *(*uint32)(unsafe.Pointer(&m[0])) & 0x3ffffff
			h1 += (*(*uint32)(unsafe.Pointer(&m[3])) >> 2) & 0x3ffffff
			h2 += (*(*uint32)(unsafe.Pointer(&m[6])) >> 4) & 0x3ffffff
			h3 += (*(*uint32)(unsafe.Pointer(&m[9])) >> 6) & 0x3ffffff
			h4 += (*(*uint32)(unsafe.Pointer(&m[12])) >> 8) | hibit
		} else {
			h0 += binary.LittleEndian.Uint32(m[0:]) & 0x3ffffff
			h1 += (binary.LittleEndian.Uint32(m[3:]) >> 2) & 0x3ffffff
			h2 += (binary.LittleEndian.Uint32(m[6:]) >> 4) & 0x3ffffff
			h3 += (binary.LittleEndian.Uint32(m[9:]) >> 6) & 0x3ffffff
			h4 += (binary.LittleEndian.Uint32(m[12:]) >> 8) | hibit
		}

		// h *= r
		d0 = (uint64(h0) * uint64(r0)) + (uint64(h1) * uint64(s4)) + (uint64(h2) * uint64(s3)) + (uint64(h3) * uint64(s2)) + (uint64(h4) * uint64(s1))
		d1 = (uint64(h0) * uint64(r1)) + (uint64(h1) * uint64(r0)) + (uint64(h2) * uint64(s4)) + (uint64(h3) * uint64(s3)) + (uint64(h4) * uint64(s2))
		d2 = (uint64(h0) * uint64(r2)) + (uint64(h1) * uint64(r1)) + (uint64(h2) * uint64(r0)) + (uint64(h3) * uint64(s4)) + (uint64(h4) * uint64(s3))
		d3 = (uint64(h0) * uint64(r3)) + (uint64(h1) * uint64(r2)) + (uint64(h2) * uint64(r1)) + (uint64(h3) * uint64(r0)) + (uint64(h4) * uint64(s4))
		d4 = (uint64(h0) * uint64(r4)) + (uint64(h1) * uint64(r3)) + (uint64(h2) * uint64(r2)) + (uint64(h3) * uint64(r1)) + (uint64(h4) * uint64(r0))

		// (partial) h %= p
		c = uint32(d0 >> 26)
		h0 = uint32(d0) & 0x3ffffff

		d1 += uint64(c)
		c = uint32(d1 >> 26)
		h1 = uint32(d1) & 0x3ffffff

		d2 += uint64(c)
		c = uint32(d2 >> 26)
		h2 = uint32(d2) & 0x3ffffff

		d3 += uint64(c)
		c = uint32(d3 >> 26)
		h3 = uint32(d3) & 0x3ffffff

		d4 += uint64(c)
		c = uint32(d4 >> 26)
		h4 = uint32(d4) & 0x3ffffff

		h0 += c * 5
		c = h0 >> 26
		h0 = h0 & 0x3ffffff

		h1 += c

		m = m[BlockSize:]
		bytes -= BlockSize
	}

	impl.h[0], impl.h[1], impl.h[2], impl.h[3], impl.h[4] = h0, h1, h2, h3, h4
}

func (impl *implState) finish(mac *[Size]byte) {
	//
	// poly1305-donna-32.h:poly1305_finish()
	//

	var c uint32
	var g0, g1, g2, g3, g4 uint32
	var f uint64
	var mask uint32

	// fully carry h
	h0, h1, h2, h3, h4 := impl.h[0], impl.h[1], impl.h[2], impl.h[3], impl.h[4]
	c = h1 >> 26
	h1 &= 0x3ffffff

	h2 += c
	c = h2 >> 26
	h2 &= 0x3ffffff

	h3 += c
	c = h3 >> 26
	h3 &= 0x3ffffff

	h4 += c
	c = h4 >> 26
	h4 &= 0x3ffffff

	h0 += c * 5
	c = h0 >> 26
	h0 &= 0x3ffffff

	h1 += c

	// compute h + -p
	g0 = h0 + 5
	c = g0 >> 26
	g0 &= 0x3ffffff

	g1 = h1 + c
	c = g1 >> 26
	g1 &= 0x3ffffff

	g2 = h2 + c
	c = g2 >> 26
	g2 &= 0x3ffffff

	g3 = h3 + c
	c = g3 >> 26
	g3 &= 0x3ffffff

	g4 = h4 + c - (1 << 26)

	// select h if h < p, or h + -p if h >= p
	mask = (g4 >> ((4 * 8) - 1)) - 1
	g0 &= mask
	g1 &= mask
	g2 &= mask
	g3 &= mask
	g4 &= mask
	mask = ^mask
	h0 = (h0 & mask) | g0
	h1 = (h1 & mask) | g1
	h2 = (h2 & mask) | g2
	h3 = (h3 & mask) | g3
	h4 = (h4 & mask) | g4

	// h = h % (2^128)
	h0 = ((h0) | (h1 << 26)) & 0xffffffff
	h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff
	h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff

	// mac = (h + pad) % (2^128)
	f = uint64(h0) + uint64(impl.pad[0])
	h0 = uint32(f)

	f = uint64(h1) + uint64(impl.pad[1]) + (f >> 32)
	h1 = uint32(f)

	f = uint64(h2) + uint64(impl.pad[2]) + (f >> 32)
	h2 = uint32(f)

	f = uint64(h3) + uint64(impl.pad[3]) + (f >> 32)
	h3 = uint32(f)

	if isLittleEndian {
		macArr := (*[4]uint32)(unsafe.Pointer(&mac[0]))
		macArr[0] = h0
		macArr[1] = h1
		macArr[2] = h2
		macArr[3] = h3
	} else {
		binary.LittleEndian.PutUint32(mac[0:], h0)
		binary.LittleEndian.PutUint32(mac[4:], h1)
		binary.LittleEndian.PutUint32(mac[8:], h2)
		binary.LittleEndian.PutUint32(mac[12:], h3)
	}
}

var _ implInterface = (*implState)(nil)
