//
// poly1305.go: Poly1305 MAC.
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to poly1305, using the creative
// commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// Package poly1305 is a Poly1305 MAC implementation.  It is different from the
// golang.org/x/crypto implementation in that it exports a hash.Hash interface
// to support incremental updates.
//
// The implementation is based on Andrew Moon's poly1305-donna.
package poly1305

import (
	"crypto/subtle"
	"errors"
	"hash"
	"runtime"
	"unsafe"
)

const (
	// KeySize is the Poly1305 key size in bytes.
	KeySize = 32

	// Size is the Poly1305 MAC size in bytes.
	Size = 16

	// BlockSize is the Poly1305 block size in bytes.
	BlockSize = 16
)

var (
	// ErrInvalidKeySize is the error returned when an invalid sized key is
	// encountered.
	ErrInvalidKeySize = errors.New("poly1305: invalid key size")

	// ErrInvalidMacSize is the error returned when an invalid sized MAC is
	// encountered.
	ErrInvalidMacSize = errors.New("poly1305: invalid mac size")

	isLittleEndian = false
)

type implInterface interface {
	init(key []byte)
	clear()
	blocks(m []byte, bytes int, isFinal bool)
	finish(mac *[Size]byte)
}

// Poly1305 is an instance of the Poly1305 MAC algorithm.
type Poly1305 struct {
	impl     implState
	leftover int
	buffer   [BlockSize]byte
}

// Write adds more data to the running hash.  It never returns an error.
func (st *Poly1305) Write(p []byte) (n int, err error) {
	//
	// poly1305-donna.c:poly1305_update()
	//

	m := p
	bytes := len(m)

	// handle leftover
	if st.leftover > 0 {
		want := BlockSize - st.leftover
		if want > bytes {
			want = bytes
		}
		for i := 0; i < want; i++ {
			st.buffer[st.leftover+i] = m[i]
		}
		bytes -= want
		m = m[want:]
		st.leftover += want
		if st.leftover < BlockSize {
			return len(p), nil
		}
		st.impl.blocks(st.buffer[:], BlockSize, false)
		st.leftover = 0
	}

	// process full blocks
	if bytes >= BlockSize {
		want := bytes & (^(BlockSize - 1))
		st.impl.blocks(m, want, false)
		m = m[want:]
		bytes -= want
	}

	// store leftover
	if bytes > 0 {
		for i := 0; i < bytes; i++ {
			st.buffer[st.leftover+i] = m[i]
		}
		st.leftover += bytes
	}

	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.  It does
// not change the underlying hash state.
func (st *Poly1305) Sum(b []byte) []byte {
	var mac [Size]byte
	tmp := *st
	tmp.finish(&mac)
	return append(b, mac[:]...)
}

// Reset clears the internal hash state and panic()s, because calling this is a
// sign that the user is doing something unadvisable.
func (st *Poly1305) Reset() {
	st.Clear() // Obliterate the state before panic().

	// Poly1305 keys are one time use only.
	panic("poly1305: Reset() is not supported")
}

// Size returns the number of bytes Sum will return.
func (st *Poly1305) Size() int {
	return Size
}

// BlockSize returns the hash's underlying block size.
func (st *Poly1305) BlockSize() int {
	return BlockSize
}

// Init (re-)initializes the hash instance with a given key.
func (st *Poly1305) Init(key []byte) {
	if len(key) != KeySize {
		panic(ErrInvalidKeySize)
	}

	st.impl.init(key)
	st.leftover = 0
}

// Clear purges the sensitive material in hash's internal state.
func (st *Poly1305) Clear() {
	st.impl.clear()
}

func (st *Poly1305) finish(mac *[Size]byte) {
	// process the remaining block
	if st.leftover > 0 {
		st.buffer[st.leftover] = 1
		for i := st.leftover + 1; i < BlockSize; i++ {
			st.buffer[i] = 0
		}
		st.impl.blocks(st.buffer[:], BlockSize, true)
	}

	st.impl.finish(mac)
	st.impl.clear()
}

// New returns a new Poly1305 instance keyed with the supplied key.
func New(key []byte) (*Poly1305, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	h := &Poly1305{}
	h.Init(key)
	return h, nil
}

// Sum does exactly what golang.org/x/crypto/poly1305.Sum() does.
func Sum(mac *[Size]byte, m []byte, key *[KeySize]byte) {
	var h Poly1305
	h.Init(key[:])
	h.Write(m)
	h.finish(mac)
}

// Verify does exactly what golang.org/x/crypto/poly1305.Verify does.
func Verify(mac *[Size]byte, m []byte, key *[KeySize]byte) bool {
	var m2 [Size]byte
	Sum(&m2, m, key)
	return subtle.ConstantTimeCompare(mac[:], m2[:]) == 1
}

func init() {
	// Use the UTF-32 (UCS-4) Byte Order Mark to detect host byte order,
	// which enables the further use of 'unsafe' for added performance.
	const bomLE = 0x0000feff
	bom := [4]byte{0xff, 0xfe, 0x00, 0x00}

	// ARM doesn't get the spiffy fast code since it's picky wrt alignment
	// and I doubt Go does the right thing.
	if runtime.GOARCH != "arm" {
		bomHost := *(*uint32)(unsafe.Pointer(&bom[0]))
		if bomHost == 0x0000feff { // Little endian, use unsafe.
			isLittleEndian = true
		}
	}
}

var _ hash.Hash = (*Poly1305)(nil)
