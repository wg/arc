package argon2

import (
	"hash"
	"testing"

	"github.com/dchest/blake2b"
)

const version uint32 = 0x13
const mode = 0 // Argon2d

/*

inputs:

 P message
 S nonce
 K secret key (optional)
 X associated data (optional)

 p parallelism
 m memory size
 n iterations

*/

func argon2(output, P, S, K, X []byte, p, m, n uint32, t *testing.T) {
	if p == 0 || m == 0 || n == 0 {
		panic("argon: internal error: invalid params")
	}
	if m%(p*4) != 0 {
		panic("argon: internal error: invalid m")
	}

	m0 := m
	if m < 8*p {
		m = 8 * p
	}

	// Argon2 operates over a matrix of 1024-byte blocks
	b := make([][128]uint64, m)
	q := m / p // length of each lane
	g := q / 4 // length of each segment

	var scratch [72]byte
	var btmp [1024]byte
	var btmp2 [128]uint64

	// Compute a hash of all the input parameters
	h := blake2b.New512()
	lh := newLongHash(h)

	put32(scratch[0:4], p)
	put32(scratch[4:8], uint32(len(output)))
	put32(scratch[8:12], m0)
	put32(scratch[12:16], n)
	put32(scratch[16:20], version)
	put32(scratch[20:24], mode)
	h.Write(scratch[:24])

	put32(scratch[0:4], uint32(len(P)))
	h.Write(scratch[0:4])
	h.Write(P)

	put32(scratch[0:4], uint32(len(S)))
	h.Write(scratch[0:4])
	h.Write(S)

	put32(scratch[0:4], uint32(len(K)))
	h.Write(scratch[0:4])
	h.Write(K)

	put32(scratch[0:4], uint32(len(X)))
	h.Write(scratch[0:4])
	h.Write(X)

	h.Sum(scratch[:0])
	h.Reset()

	// Use the hash to initialize the first two columns of the matrix
	for lane := uint32(0); lane < p; lane++ {
		// scratch[0:64] is the parameter hash
		put32(scratch[64:], 0)
		put32(scratch[68:], lane)

		lh.Init(len(btmp))
		lh.Write(scratch[:72])
		lh.Hash(btmp[:])
		for i := range b[0] {
			b[lane*q+0][i] = read64(btmp[i*8:])
		}

		scratch[64] = 1
		lh.Init(len(btmp))
		lh.Write(scratch[:72])
		lh.Hash(btmp[:])
		for i := range b[0] {
			b[lane*q+1][i] = read64(btmp[i*8:])
		}
	}

	if t != nil {
		t.Logf("Iterations: %d, Memory: %d KiB, Parallelism: %d lanes, Tag length: %d bytes", n, m, p, len(output))
		t.Logf("Password[%d]: % x", len(P), P)
		t.Logf("Nonce[%d]: % x", len(S), S)
		t.Logf("Secret[%d]: % x", len(K), K)
		t.Logf("Associated data[%d]: % x", len(X), X)
		t.Logf("Input hash: % x", scratch[:64])
	}

	for i := range scratch {
		scratch[i] = 0
	}
	for i := range btmp {
		btmp[i] = 0
	}

	// Get down to business
	for k := uint32(0); k < n; k++ {
		if t != nil {
			t.Log()
			t.Logf(" After pass %d:", k)
		}
		for slice := uint32(0); slice < 4; slice++ {
			for lane := uint32(0); lane < p; lane++ {
				i := uint32(0)
				if k == 0 && slice == 0 {
					i = 2
				}
				j := lane*q + slice*g + i
				for ; i < g; i, j = i+1, j+1 {
					prev := j - 1
					if i == 0 && slice == 0 {
						prev = lane*q + q - 1
					}

					rand := b[prev][0]
					rslice, rlane, ri := index(rand, q, g, p, k, slice, lane, i, t)
					j0 := rlane*q + rslice*g + ri

					block(&b[j], &btmp2, &b[prev], &b[j0])
				}
			}
		}
		if t != nil {
			for i := range b {
				t.Logf("  Block %.4d [0]: %x", i, b[i][0])
			}
		}
	}

	// XOR the blocks in the last column together
	for lane := uint32(0); lane < p-1; lane++ {
		for i, v := range b[lane*q+q-1] {
			b[m-1][i] ^= v
		}
	}

	// Output
	for i, v := range b[m-1] {
		btmp[i*8] = uint8(v)
		btmp[i*8+1] = uint8(v >> 8)
		btmp[i*8+2] = uint8(v >> 16)
		btmp[i*8+3] = uint8(v >> 24)
		btmp[i*8+4] = uint8(v >> 32)
		btmp[i*8+5] = uint8(v >> 40)
		btmp[i*8+6] = uint8(v >> 48)
		btmp[i*8+7] = uint8(v >> 56)
	}
	if t != nil {
		t.Logf("Final block: %x", btmp[:])
	}
	lh.Init(len(output))
	lh.Write(btmp[:])
	lh.Hash(output)
	if t != nil {
		t.Logf("Output: % X", output)
	}
}

func index(rand uint64, q, g, p, k, slice, lane, i uint32, t *testing.T) (rslice, rlane, ri uint32) {
	rlane = uint32(rand>>32) % p

	var start, max uint32
	if k == 0 {
		start = 0
		if slice == 0 || lane == rlane {
			// All blocks in this lane so far
			max = slice*g + i
		} else {
			// All blocks in another lane
			// in slices prior to the current slice
			max = slice * g
		}
	} else {
		start = (slice + 1) % 4 * g
		if lane == rlane {
			// All blocks in this lane
			max = 3*g + i
		} else {
			// All blocks in another lane
			// except the current slice
			max = 3 * g
		}
	}
	if i == 0 || lane == rlane {
		max -= 1
	}

	phi := rand & 0xFFFFFFFF
	phi = phi * phi >> 32
	phi = phi * uint64(max) >> 32
	ri = uint32((uint64(start) + uint64(max) - 1 - phi) % uint64(q))

	if t != nil {
		i0 := lane*q + slice*g + i
		j0 := rlane*q + ri
		t.Logf("  i = %d(%d,%d,%d), rand = %d, max = %d, start = %d, phi = %d, j = %d(%d,%d,%d)", i0, lane, slice, i, rand, max, start, phi, j0, rlane, rslice, ri)
	}

	return rslice, rlane, ri
}

type longHash struct {
	buf [64]uint8
	h   hash.Hash
	h0  hash.Hash // large hash
	h1  hash.Hash // small hash
	n   int
}

func newLongHash(h hash.Hash) *longHash {
	return &longHash{h: h}
}

// Init readies longHash for an output of length n.
func (lh *longHash) Init(n int) {
	lh.n = n
	lh.h.Reset()
	lh.h0 = lh.h
	lh.h1 = lh.h
	var err error
	if n < 64 {
		lh.h0, err = blake2b.New(&blake2b.Config{Size: uint8(n)})
	} else if n%64 != 0 {
		n := 33 + (n+31)%32
		lh.h1, err = blake2b.New(&blake2b.Config{Size: uint8(n)})
	}
	if err != nil {
		panic(err)
	}
	put32(lh.buf[:4], uint32(n))
	lh.Write(lh.buf[:4])
}

func (lh *longHash) Write(b []byte) {
	lh.h0.Write(b)
}

func (lh *longHash) Hash(out []byte) {
	if len(out) != lh.n {
		panic("argon2: wrong output length in longHash")
	}

	if len(out) <= 64 {
		lh.h0.Sum(out[:0])
		return
	}

	lh.h0.Sum(lh.buf[:0])
	copy(out, lh.buf[:32])
	for out = out[32:]; len(out) > 64; out = out[32:] {
		lh.h0.Reset()
		lh.h0.Write(lh.buf[:])
		lh.h0.Sum(lh.buf[:0])
		copy(out, lh.buf[:32])
	}
	if lh.h0 == lh.h1 {
		lh.h1.Reset()
	}
	lh.h1.Write(lh.buf[:])
	lh.h1.Sum(out[:0])
}

func put32(b []uint8, v uint32) {
	b[0] = uint8(v)
	b[1] = uint8(v >> 8)
	b[2] = uint8(v >> 16)
	b[3] = uint8(v >> 24)
}

func read64(b []uint8) uint64 {
	return uint64(b[0]) |
		uint64(b[1])<<8 |
		uint64(b[2])<<16 |
		uint64(b[3])<<24 |
		uint64(b[4])<<32 |
		uint64(b[5])<<40 |
		uint64(b[6])<<48 |
		uint64(b[7])<<56
}
