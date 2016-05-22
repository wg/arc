// Copyright (C) 2016 - Will Glozer. All rights reserved.

package ecies

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/dchest/blake2b"
	"github.com/wg/ecies/xchacha20poly1305"
)

func TestXChaCha20Poly1305KeySetup(t *testing.T) {
	secret := []byte("secret")

	cfg := blake2b.Config{Size: xchacha20poly1305.KeySize}
	hash, err := blake2b.New(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	hash.Write(secret)
	key := hash.Sum(nil)

	box, err := newXChaCha20Poly1305Box(secret)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(box.key[:], key) {
		t.Fatal("box key initialization incorrect")
	}
}

func TestXChaCha20Poly1305Box(t *testing.T) {
	const tagSize = xchacha20poly1305.TagSize

	var (
		key    [xchacha20poly1305.KeySize]byte
		nonce  [xchacha20poly1305.NonceSize]byte
		msg    [64]byte
		raw    [len(msg) + tagSize]byte
		sealed [len(msg) + tagSize]byte
		opened [len(msg) + tagSize]byte
		box    Box
	)

	rand.Read(key[:])
	rand.Read(nonce[:])
	rand.Read(msg[:])
	copy(box.key[:], key[:])

	c := xchacha20poly1305.New(&key, &nonce)
	c.Encrypt(raw[:], msg[:])
	c.Tag(raw[len(msg):len(msg)])

	err := box.Seal(sealed[:], msg[:], nonce[:])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sealed[:len(msg)], raw[:len(msg)]) {
		t.Fatal("sealed ciphertext != raw ciphertext")
	}

	if !bytes.Equal(sealed[len(msg):], raw[len(msg):]) {
		t.Fatal("sealed auth tag != raw auth tag")
	}

	err = box.Open(opened[:], sealed[:], nonce[:])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(opened[:len(msg)], msg[:]) {
		t.Fatal("opened plaintext != original plaintext")
	}
}

func TestXChaCha20Poly1305BoxInPlace(t *testing.T) {
	const tagSize = xchacha20poly1305.TagSize

	var (
		key   [xchacha20poly1305.KeySize]byte
		nonce [xchacha20poly1305.NonceSize]byte
		msg   [64]byte
		raw   [len(msg) + tagSize]byte
		dst   [len(msg) + tagSize]byte
		box   Box
	)

	rand.Read(key[:])
	rand.Read(nonce[:])
	rand.Read(msg[:])
	copy(dst[:], msg[:])
	copy(box.key[:], key[:])

	c := xchacha20poly1305.New(&key, &nonce)
	c.Encrypt(raw[:], msg[:])
	c.Tag(raw[len(msg):len(msg)])

	err := box.Seal(dst[:], dst[:len(msg)], nonce[:])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(dst[:len(msg)], raw[:len(msg)]) {
		t.Fatal("sealed ciphertext != raw ciphertext")
	}

	if !bytes.Equal(dst[len(msg):], raw[len(msg):]) {
		t.Fatal("sealed auth tag != raw auth tag")
	}

	err = box.Open(dst[:], dst[:], nonce[:])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(dst[:len(msg)], msg[:]) {
		t.Fatal("opened plaintext != original plaintext")
	}
}
