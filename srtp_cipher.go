// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import "github.com/pion/rtp"

// cipher represents a implementation of one
// of the SRTP Specific ciphers.
type srtpCipher interface {
	// AuthTagRTPLen/AuthTagRTCPLen return auth key length of the cipher.
	// See the note below.
	AuthTagRTPLen() (int, error)
	AuthTagRTCPLen() (int, error)
	// AEADAuthTagLen returns AEAD auth key length of the cipher.
	// See the note below.
	AEADAuthTagLen() (int, error)
	getRTCPIndex([]byte) uint32

	// indexOverKdr is r = packet index DIV key derivation rate (RFC 3711
	// section 4.3). It selects the session key set the packet is protected
	// with. A zero key derivation rate always passes zero here, preserving the
	// single-key behavior.
	encryptRTP([]byte, *rtp.Header, int, []byte, uint32, uint64, bool) ([]byte, error)
	encryptRTCP([]byte, []byte, uint32, uint32, uint64) ([]byte, error)

	decryptRTP([]byte, []byte, *rtp.Header, int, uint32, uint64, bool) ([]byte, error)
	decryptRTCP([]byte, []byte, uint32, uint32, uint64) ([]byte, error)
	setCryptex(bool)
}

/*
NOTE: Auth tag and AEAD auth tag are placed at the different position in SRTCP

In non-AEAD cipher, the authentication tag is placed *after* the ESRTCP word
(Encrypted-flag and SRTCP index).

> AES_128_CM_HMAC_SHA1_80
> | RTCP Header | Encrypted payload |E| SRTCP Index | Auth tag |
>                                   ^               |----------|
>                                   |                ^
>                                   |                authTagLen=10
>                                   aeadAuthTagLen=0

In AEAD cipher, the AEAD authentication tag is embedded in the ciphertext.
It is *before* the ESRTCP word (Encrypted-flag and SRTCP index).

> AEAD_AES_128_GCM
> | RTCP Header | Encrypted payload | AEAD auth tag |E| SRTCP Index |
>                                   |---------------|               ^
>                                    ^                              authTagLen=0
>                                    aeadAuthTagLen=16

See https://tools.ietf.org/html/rfc7714 for the full specifications.
*/
