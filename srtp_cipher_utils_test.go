// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" // nolint:gosec
)

// deriveSessionKeys should be used in tests only.
// RFCs test vectors specifes derived keys to use,
// this struct is used to inject them into the cipher in tests.
type derivedSessionKeys struct {
	srtpSessionKey      []byte
	srtpSessionSalt     []byte
	srtpSessionAuthTag  []byte
	srtcpSessionKey     []byte
	srtcpSessionSalt    []byte
	srtcpSessionAuthTag []byte
}

func newSrtpCipherAesCmHmacSha1WithDerivedKeys(
	profile ProtectionProfile,
	keys derivedSessionKeys,
	encryptSRTP, encryptSRTCP bool,
) (*srtpCipherAesCmHmacSha1, error) {
	if profile == ProtectionProfileNullHmacSha1_80 || profile == ProtectionProfileNullHmacSha1_32 {
		encryptSRTP = false
		encryptSRTCP = false
	}

	srtpCipher := &srtpCipherAesCmHmacSha1{
		protectionProfileWithArgs: protectionProfileWithArgs{ProtectionProfile: profile},
		srtpEncrypted:             encryptSRTP,
		srtcpEncrypted:            encryptSRTCP,
		srtpDerivedKeys:           map[uint64]*srtpAesCmHmacSha1Keys{},
		srtcpDerivedKeys:          map[uint64]*srtpAesCmHmacSha1Keys{},
	}

	derivedKeys := &srtpAesCmHmacSha1Keys{
		srtpSessionSalt:  keys.srtpSessionSalt,
		srtpSessionAuth:  hmac.New(sha1.New, keys.srtpSessionAuthTag),
		srtcpSessionSalt: keys.srtcpSessionSalt,
		srtcpSessionAuth: hmac.New(sha1.New, keys.srtcpSessionAuthTag),
	}

	var err error
	if derivedKeys.srtpBlock, err = aes.NewCipher(keys.srtpSessionKey); err != nil {
		return nil, err
	}

	if derivedKeys.srtcpBlock, err = aes.NewCipher(keys.srtcpSessionKey); err != nil {
		return nil, err
	}

	// Test-vector ciphers carry no master key material, so only the initial
	// (r == 0) key set exists; this mirrors a zero key derivation rate.
	srtpCipher.srtpDerivedKeys[0] = derivedKeys
	srtpCipher.srtcpDerivedKeys[0] = derivedKeys

	return srtpCipher, nil
}

func newSrtpCipherAeadAesGcmWithDerivedKeys(
	profile ProtectionProfile,
	keys derivedSessionKeys,
	encryptSRTP, encryptSRTCP bool,
) (*srtpCipherAeadAesGcm, error) {
	srtpCipher := &srtpCipherAeadAesGcm{
		protectionProfileWithArgs: protectionProfileWithArgs{ProtectionProfile: profile},
		srtpEncrypted:             encryptSRTP,
		srtcpEncrypted:            encryptSRTCP,
		srtpDerivedKeys:           map[uint64]*srtpAeadAesGcmKeys{},
		srtcpDerivedKeys:          map[uint64]*srtpAeadAesGcmKeys{},
	}

	srtpBlock, err := aes.NewCipher(keys.srtpSessionKey)
	if err != nil {
		return nil, err
	}

	srtpAEAD, err := cipher.NewGCM(srtpBlock)
	if err != nil {
		return nil, err
	}

	srtcpBlock, err := aes.NewCipher(keys.srtcpSessionKey)
	if err != nil {
		return nil, err
	}

	srtcpAEAD, err := cipher.NewGCM(srtcpBlock)
	if err != nil {
		return nil, err
	}

	derivedKeys := &srtpAeadAesGcmKeys{
		srtpCipher:       srtpAEAD,
		srtcpCipher:      srtcpAEAD,
		srtpSessionSalt:  keys.srtpSessionSalt,
		srtcpSessionSalt: keys.srtcpSessionSalt,
	}

	// Test-vector ciphers carry no master key material, so only the initial
	// (r == 0) key set exists; this mirrors a zero key derivation rate.
	srtpCipher.srtpDerivedKeys[0] = derivedKeys
	srtpCipher.srtcpDerivedKeys[0] = derivedKeys

	return srtpCipher, nil
}

// createContextWithCipher creates a new SRTP Context with a pre-created cipher. This is used for testing purposes only.
func createContextWithCipher(profile ProtectionProfile, cipher srtpCipher) (*Context, error) {
	ctx := &Context{
		srtpSSRCStates:  map[uint32]*srtpSSRCState{},
		srtcpSSRCStates: map[uint32]*srtcpSSRCState{},
		profile:         profile,
		mkis:            map[string]srtpCipher{},
		cipher:          cipher,
	}
	err := SRTPNoReplayProtection()(ctx)
	if err != nil {
		return nil, err
	}
	err = SRTCPNoReplayProtection()(ctx)
	if err != nil {
		return nil, err
	}
	ctx.constructed = true

	return ctx, nil
}
