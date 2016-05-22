// Copyright (C) 2016 - Will Glozer. All rights reserved.

package ecies

type Cipher interface {
	Init(key, nonce []byte) error
	Auth(src []byte)
	Decrypt(dst, src []byte)
	Encrypt(dst, src []byte)
	Tag(tag []byte) []byte
	Reset()
	TagSize() int
}
