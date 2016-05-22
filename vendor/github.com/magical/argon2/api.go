// Package argon2 implements version 1.3 of the Argon2 password hashing scheme
// designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich,
// as specified in the document
//
//     https://github.com/P-H-C/phc-winner-argon2/raw/54617af02de0055b90e39c4204058bb9a84c2b78/argon2-specs.pdf
//
// Warning: This package is currently unstable; Argon2 has not yet been
// finalized and is still undergoing design tweaks.
package argon2

import "errors"

const (
	maxPar = 255

	maxIter = 1<<32 - 1

	minMemory = 8
	maxMemory = 1<<32 - 1

	minSalt     = 8
	maxSalt     = 1<<32 - 1
	maxPassword = 1<<32 - 1
)

// Key derives a key from the password, salt, and cost parameters.
//
// The salt must be at least 8 bytes long.
//
// Mem is the amount of memory to use in kibibytes.
// Mem must be at least 8*p, and will be rounded to a multiple of 4*p.
func Key(password, salt []byte, n, par int, mem int64, keyLen int) ([]byte, error) {
	if int64(len(password)) > maxPassword {
		return nil, errors.New("argon: password too long")
	}

	if len(salt) < minSalt {
		return nil, errors.New("argon: salt too short")
	} else if int64(len(salt)) > maxSalt {
		return nil, errors.New("argon: salt too long")
	}

	if n < 1 || int64(n) > maxIter {
		return nil, errors.New("argon: invalid n")
	}

	if par < 1 || par > maxPar {
		return nil, errors.New("argon: invalid par")
	}

	if mem < minMemory || mem > maxMemory {
		return nil, errors.New("argon: invalid mem")
	}

	// Round down to a multiple of 4 * par
	mem = mem / (4 * int64(par)) * (4 * int64(par))

	if mem < 8*int64(par) {
		mem = 8 * int64(par)
	}

	// TODO: test keyLen

	output := make([]byte, keyLen)
	argon2(output, password, salt, nil, nil, uint32(par), uint32(mem), uint32(n), nil)
	return output, nil
}
