// Copyright (C) 2016 - Will Glozer. All rights reserved.

package ecies

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func Test_X25519_RFC7748(t *testing.T) {
	const keySize = 32

	unhex := func(s string) *[keySize]byte {
		var out [keySize]byte
		switch n, err := hex.Decode(out[:], []byte(s)); {
		case err != nil:
			t.Fatal(err)
		case n != keySize:
			t.Fatalf("%d != %d", n, keySize)
		}
		return &out
	}

	var (
		alicePrivateKey = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
		alicePublicKey  = unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
		bobPrivateKey   = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
		bobPublicKey    = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
		expectedSecret  = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
		sharedSecret    [keySize]byte
	)

	_ = alicePublicKey
	_ = bobPrivateKey

	err := X25519(&sharedSecret, bobPublicKey, alicePrivateKey)

	if err != nil {
		t.Fatal("key exchange failed", err)
	}

	if !bytes.Equal(sharedSecret[:], expectedSecret[:]) {
		t.Fatal("shared secret incorrect")
	}
}

func Test_X448_RFC7748(t *testing.T) {
	const keySize = 56

	unhex := func(s ...string) *[keySize]byte {
		var out [keySize]byte
		var in []byte

		for i := range s {
			in = append(in, []byte(s[i])...)
		}

		switch n, err := hex.Decode(out[:], in); {
		case err != nil:
			t.Fatal(err)
		case n != keySize:
			t.Fatalf("%d != %d", n, keySize)
		}
		return &out
	}

	var (
		alicePrivateKey = unhex(
			"9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d",
			"d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
		)
		alicePublicKey = unhex(
			"9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c",
			"22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
		)
		bobPrivateKey = unhex(
			"1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d",
			"6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
		)
		bobPublicKey = unhex(
			"3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430",
			"27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
		)
		expectedSecret = unhex(
			"07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b",
			"b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
		)
		sharedSecret [keySize]byte
	)

	_ = alicePublicKey
	_ = bobPrivateKey

	err := X448(&sharedSecret, bobPublicKey, alicePrivateKey)

	if err != nil {
		t.Fatal("key exchange failed", err)
	}

	if !bytes.Equal(sharedSecret[:], expectedSecret[:]) {
		t.Fatal("shared secret incorrect")
	}
}

func Test_X25519_EphemeralStatic(t *testing.T) {
	const keySize = 32

	var (
		aliceStaticPublic     [keySize]byte
		aliceStaticPrivate    [keySize]byte
		aliceEphemeralPublic  [keySize]byte
		aliceEphemeralPrivate [keySize]byte
		bobStaticPublic       [keySize]byte
		bobStaticPrivate      [keySize]byte
		aliceSecret           [keySize]byte
		bobSecret             [keySize]byte
	)

	GenerateCurve25519Key(rand.Reader, &aliceStaticPublic, &aliceStaticPrivate)
	GenerateCurve25519Key(rand.Reader, &aliceEphemeralPublic, &aliceEphemeralPrivate)
	GenerateCurve25519Key(rand.Reader, &bobStaticPublic, &bobStaticPrivate)

	X25519(&aliceSecret, &bobStaticPublic, &aliceEphemeralPrivate)
	X25519(&bobSecret, &aliceEphemeralPublic, &bobStaticPrivate)

	if !bytes.Equal(aliceSecret[:], bobSecret[:]) {
		t.Fatal("alice's shared secret != bob's shared secret")
	}
}

func Test_X448_EphemeralStatic(t *testing.T) {
	const keySize = 56

	var (
		aliceStaticPublic     [keySize]byte
		aliceStaticPrivate    [keySize]byte
		aliceEphemeralPublic  [keySize]byte
		aliceEphemeralPrivate [keySize]byte
		bobStaticPublic       [keySize]byte
		bobStaticPrivate      [keySize]byte
		aliceSecret           [keySize]byte
		bobSecret             [keySize]byte
	)

	GenerateCurve448Key(rand.Reader, &aliceStaticPublic, &aliceStaticPrivate)
	GenerateCurve448Key(rand.Reader, &aliceEphemeralPublic, &aliceEphemeralPrivate)
	GenerateCurve448Key(rand.Reader, &bobStaticPublic, &bobStaticPrivate)

	X448(&aliceSecret, &bobStaticPublic, &aliceEphemeralPrivate)
	X448(&bobSecret, &aliceEphemeralPublic, &bobStaticPrivate)

	if !bytes.Equal(aliceSecret[:], bobSecret[:]) {
		t.Fatal("alice's shared secret != bob's shared secret")
	}
}
