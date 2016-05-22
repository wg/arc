// Copyright (C) 2016 - Will Glozer. All rights reserved.

package ecies

import (
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
	"schwanenlied.me/yawning/x448"
)

var ErrX448 = errors.New("curve448: key exchange failed")

func GenerateCurve25519Key(rand io.Reader, public, private *[32]byte) error {
	_, err := io.ReadFull(rand, private[:])
	if err != nil {
		return err
	}
	curve25519.ScalarBaseMult(public, private)
	return nil
}

func GenerateCurve448Key(rand io.Reader, public, private *[56]byte) error {
	_, err := io.ReadFull(rand, private[:])
	if err != nil {
		return err
	}
	x448.ScalarBaseMult(public, private)
	return nil
}

func X25519(secret, public, private *[32]byte) error {
	curve25519.ScalarMult(secret, private, public)
	return nil
}

func X448(secret, public, private *[56]byte) error {
	if x448.ScalarMult(secret, private, public) != 0 {
		return ErrX448
	}
	return nil
}
