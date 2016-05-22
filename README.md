# arc - secure file archiver

arc is a file archiver designed to manage secure and stable archives
suitable for storage and transmission. arc archives are standard tar
archives compressed with gzip and then encrypted with the XChaCha20+
Poly1305 authenticated encryption mode.

arc is distributed as open source code and static executables with
no external dependencies.

## Security

arc archives are designed for secure storage and transmission and
must not allow decryption or tampering by an attacker without the
appropriate encryption key.

However, arc has not been subject to peer review and the specific
algorithm combinations used have not been standardized.

arc archives are encrypted with XChaCha20 + Poly1305 using the
same algorithm as NaCl's secretbox but substituting XChaCha20 for
XSalsa20. This algorithm is similar to the ChaCha20 + Poly1305
AEAD mode defined in RFC 7539 but uses a longer random nonce and
does not include lengths in the authentication tag computation.

The XChaCha20 + Poly1305 key is derived in one of three ways:

  1. from a password using the Argon2 KDF
  2. from a static-ephemeral ECDH key exchange
  3. from a random key split into n shards

See the Archive sections below for details of each.

## Stability

arc archives are designed for long-term storage and their content
should be extractable using hardware and software that does not
exist at the time the archive was created.

A decrypted archive is a standard gzip-compressed tar archive for
which there exist a wide variety of open source tools & libraries
capable of reading and extracting their contents. Should that fail
the tar and gzip formats are well documented and reasonably simple
to implement.

Decryption is more difficult due to rapid advances in the state of
the art and arc's desire for strong security. However portable open
source C implementations of each algorithm are available, and the
implementations arc uses are written in Go, a language designed for
long-term backwards compatibility.

See the Compatibility section which follows for important caveats
and read FORMAT for the specific disk format arc uses as a header
for the encrypted tar+gzip stream.

## Compatibility

arc releases follow the semantic versioning scheme and the major
version will be incremented when the on-disk format changes.

Each release of arc will support a single version of the on-disk
format and any security flaws will cause a new release with the
version incremented and support for the flawed method dropped.

This means future versions of arc may not be capable of extracting
old archives so copies of arc in binary and/or source form should
be kept alongside the archives themselves.

## Password Archives

A password, cost parameters, and cryptographically secure random salt
are used as input to the Argon2 password hashing function to derive
the encryption key used to encrypt & decrypt the archive.

## Curve448 Archives

A Curve448 key pair is generated via arc's --keygen option.

Encryption uses the public key and an ephemeral private key as input
to the X448 ECDH key exchange function and the resulting shared secret
is hashed with BLAKE2b to derive the encryption key. The corresponding
ephemeral public key is embedded in the archive and used with the
static private key to decrypt the archive.

This method is suitable for transmitting archives to another party or
for use on a system that may become compromised after the archive is
created.

## Shard Archives

The encryption key is cryptographically secure random bytes that are
split into n shards using Shamir's Secret Sharing algorithm. One
archive is generated for each shard and k must be present to recreate
the key and decrypt the archive.

This method is most suitable for small archives that will be stored
or transmitted via multiple channels where k - 1 can be compromised
with no loss in archive security.

## License

Copyright (C) 2016 Will Glozer.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

## Acknowledgments

arc contains code from a number of open source projects including
Yawning Angel's chacha20, poly1305, and x448 libraries, Dmitry
Chestnykh's blake2b, Coda Hale's sss, Andrw Ekstedt's argon2, Klaus
Post's optimized compression packages and Jesse van den Kieboom's
go-flags. See NOTICE for license details.

## Cryptography Notice

This distribution includes cryptographic software. The country in
which you currently reside may have restrictions on the import,
possession, use, and/or re-export to another country, of encryption
software. BEFORE using any encryption software, please check your
country's laws, regulations and policies concerning the import,
possession, or use, and re-export of encryption software, to see if
this is permitted. See <http://www.wassenaar.org/> for more
information.

The U.S. Government Department of Commerce, Bureau of Industry and
Security (BIS), has classified this software as Export Commodity
Control Number (ECCN) 5D002.C.1, which includes information security
software using or performing cryptographic functions with asymmetric
algorithms. The form and manner of this distribution makes it
eligible for export under the License Exception ENC Technology
Software Unrestricted (TSU) exception (see the BIS Export
Administration Regulations, Section 740.13) for both object code and
source code.
