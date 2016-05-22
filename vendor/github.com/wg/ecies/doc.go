// Copyright (C) 2016 - Will Glozer. All rights reserved.

/*
Package ecies provides a convenient interface to a number of Elliptic Curve
Integrated Encryption Schemes and their corresponding primitives: Curve25519,
Curve448 AKA Ed448-Goldilocks, XChaCha20, Poly1305, and BLAKE2b.

This package has not been subject to peer review and the specific algorithm
combinations have not been standardized.

The cryptographic core is provided by Yawning Angel's excellent open-source x448,
ChaCha20, and Poly1305 libraries, but any mistakes are the fault of Will Glozer.
*/
package ecies
