// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"testing"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kdrTestProfiles covers every cipher family: AES-CM/HMAC-SHA1, the
// authenticated-encryption GCM profiles and the NULL cipher profile.
func kdrTestProfiles(t *testing.T) []ProtectionProfile {
	t.Helper()

	return []ProtectionProfile{
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_80,
		ProtectionProfileAeadAes128Gcm,
		ProtectionProfileAeadAes256Gcm,
		ProtectionProfileNullHmacSha1_80,
	}
}

func kdrMasterKeyAndSalt(t *testing.T, profile ProtectionProfile) ([]byte, []byte) {
	t.Helper()

	keyLen, err := profile.KeyLen()
	require.NoError(t, err)
	saltLen, err := profile.SaltLen()
	require.NoError(t, err)

	masterKey := make([]byte, keyLen)
	masterSalt := make([]byte, saltLen)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	for i := range masterSalt {
		masterSalt[i] = byte(0xa0 + i)
	}

	return masterKey, masterSalt
}

func kdrRTCPPacket(testSSRC uint32) []byte {
	raw, err := (&rtcp.SenderReport{SSRC: testSSRC}).Marshal()
	if err != nil {
		panic(err)
	}

	return raw
}

func kdrRTPPacket(testSSRC uint32, sequenceNumber uint16) []byte {
	pkt := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			SSRC:           testSSRC,
			SequenceNumber: sequenceNumber,
		},
		Payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	raw, err := pkt.Marshal()
	if err != nil {
		panic(err)
	}

	return raw
}

// TestKeyDerivationRateRTPBoundaryRotation checks that RTP session keys rotate
// exactly on index DIV kdrValue boundaries and that a context without KDR keeps a
// single key set forever.
func TestKeyDerivationRateRTPBoundaryRotation(t *testing.T) {
	const (
		kdrValue = uint64(4)
		testSSRC = uint32(0xcafebabe)
	)

	for _, profile := range kdrTestProfiles(t) {
		t.Run(profile.String(), func(t *testing.T) {
			masterKey, masterSalt := kdrMasterKeyAndSalt(t, profile)

			send, err := CreateContext(masterKey, masterSalt, profile, KeyDerivationRate(kdrValue))
			require.NoError(t, err)
			recv, err := CreateContext(masterKey, masterSalt, profile,
				KeyDerivationRate(kdrValue), SRTPReplayProtection(64))
			require.NoError(t, err)

			var previousPeriodEncrypted []byte
			for seq := uint16(0); seq < 12; seq++ {
				plain := kdrRTPPacket(testSSRC, seq)

				encrypted, err := send.EncryptRTP(nil, plain, nil)
				require.NoError(t, err)

				decrypted, err := recv.DecryptRTP(nil, encrypted, nil)
				require.NoError(t, err)
				assert.Equal(t, plain, decrypted)

				expectedR := uint64(seq) / kdrValue

				switch sendCipher := send.cipher.(type) {
				case *srtpCipherAesCmHmacSha1:
					_, ok := sendCipher.srtpDerivedKeys[expectedR]
					assert.True(t, ok, "missing RTP key set for r=%d", expectedR)
				case *srtpCipherAeadAesGcm:
					_, ok := sendCipher.srtpDerivedKeys[expectedR]
					assert.True(t, ok, "missing RTP key set for r=%d", expectedR)
				}

				// The first packet of a new derivation period must not be protected
				// with the key set of the previous period.
				if seq%uint16(kdrValue) == 0 && seq > 0 {
					assert.NotEqual(t, previousPeriodEncrypted, encrypted,
						"key derivation did not rotate at r=%d boundary", expectedR)
				}
				previousPeriodEncrypted = encrypted
			}
		})
	}
}

// TestKeyDerivationRateRTPReorderAndReplayWindow delivers packets out of order
// and re-sends an old packet after newer periods have been seen. The receiver
// must pick the key set of the packet's own period and must never fall back
// onto the current (newer) keys.
func TestKeyDerivationRateRTPReorderAndReplayWindow(t *testing.T) {
	const (
		kdrValue = uint64(3)
		testSSRC = uint32(0xcafebabe)
	)

	for _, profile := range kdrTestProfiles(t) {
		t.Run(profile.String(), func(t *testing.T) {
			masterKey, masterSalt := kdrMasterKeyAndSalt(t, profile)

			send, err := CreateContext(masterKey, masterSalt, profile, KeyDerivationRate(kdrValue))
			require.NoError(t, err)
			recv, err := CreateContext(masterKey, masterSalt, profile,
				KeyDerivationRate(kdrValue), SRTPReplayProtection(64))
			require.NoError(t, err)

			// Encrypt a contiguous range; each entry keeps the plaintext so the
			// receiver can verify every packet after reordering.
			type packet struct {
				plain, encrypted []byte
			}
			packets := make([]packet, 12)
			for i := range packets {
				packets[i].plain = kdrRTPPacket(testSSRC, uint16(i))
				packets[i].encrypted, err = send.EncryptRTP(nil, packets[i].plain, nil)
				require.NoError(t, err)
			}

			// Out-of-order arrival spanning multiple derivation periods.
			order := []int{2, 0, 5, 1, 8, 3, 11, 4, 7, 6, 10, 9}
			received := make(map[int]bool)
			for _, i := range order {
				decrypted, err := recv.DecryptRTP(nil, packets[i].encrypted, nil)
				require.NoError(t, err, "packet seq=%d (r=%d) rejected after reorder", i, uint64(i)/kdrValue)
				assert.Equal(t, packets[i].plain, decrypted)
				received[i] = true
			}
			assert.Len(t, received, len(packets))

			// Replay: every already-accepted packet must be rejected by the replay
			// detector rather than silently re-accepted with the wrong key set.
			for _, i := range order {
				_, err = recv.DecryptRTP(nil, packets[i].encrypted, nil)
				assert.Error(t, err, "replayed packet seq=%d was accepted", i)
			}
		})
	}
}

// TestKeyDerivationRateRTPSequenceRollover crosses a 16-bit sequence number
// rollover: the derivation index must follow the 48-bit ROC||SEQ index, so
// keys keep rotating monotonically instead of resetting to r == 0.
func TestKeyDerivationRateRTPSequenceRollover(t *testing.T) {
	const (
		kdrValue = uint64(4)
		testSSRC = uint32(0x11223344)
	)

	for _, profile := range kdrTestProfiles(t) {
		t.Run(profile.String(), func(t *testing.T) {
			masterKey, masterSalt := kdrMasterKeyAndSalt(t, profile)

			send, err := CreateContext(masterKey, masterSalt, profile, KeyDerivationRate(kdrValue))
			require.NoError(t, err)
			recv, err := CreateContext(masterKey, masterSalt, profile,
				KeyDerivationRate(kdrValue), SRTPReplayProtection(64))
			require.NoError(t, err)

			// Start just below the rollover and cover two derivation periods on
			// each side of it.
			start := uint32(maxSequenceNumber) - 5
			count := uint32(12)
			for i := uint32(0); i < count; i++ {
				index48 := start + i
				seq := uint16(index48)
				plain := kdrRTPPacket(testSSRC, seq)

				encrypted, err := send.EncryptRTP(nil, plain, nil)
				require.NoError(t, err)

				// The sender must have derived the key set for the full 48-bit
				// index, not the wrapped 16-bit sequence number alone.
				expectedR := uint64(index48) / kdrValue
				switch sendCipher := send.cipher.(type) {
				case *srtpCipherAesCmHmacSha1:
					_, ok := sendCipher.srtpDerivedKeys[expectedR]
					assert.True(t, ok, "missing RTP key set for r=%d after rollover", expectedR)
				case *srtpCipherAeadAesGcm:
					_, ok := sendCipher.srtpDerivedKeys[expectedR]
					assert.True(t, ok, "missing RTP key set for r=%d after rollover", expectedR)
				}

				decrypted, err := recv.DecryptRTP(nil, encrypted, nil)
				require.NoError(t, err)
				assert.Equal(t, plain, decrypted)
			}

			// The wrapped sequence numbers must never have been re-derived as the
			// initial r == 0 keys: the highest period must be present as well.
			highestR := uint64(start+count-1) / kdrValue
			switch sendCipher := send.cipher.(type) {
			case *srtpCipherAesCmHmacSha1:
				assert.Contains(t, sendCipher.srtpDerivedKeys, highestR)
			case *srtpCipherAeadAesGcm:
				assert.Contains(t, sendCipher.srtpDerivedKeys, highestR)
			}
		})
	}
}

// TestKeyDerivationRateRTCPIndependentOfRTP ensures RTP and RTCP each derive
// keys from their own packet index spaces (RFC 3711 section 4.3.2). A burst of
// RTP traffic must not advance the RTCP derivation period, and vice versa.
func TestKeyDerivationRateRTCPIndependentOfRTP(t *testing.T) {
	const (
		kdrValue = uint64(3)
		testSSRC = uint32(0x55667788)
	)

	for _, profile := range kdrTestProfiles(t) {
		t.Run(profile.String(), func(t *testing.T) {
			masterKey, masterSalt := kdrMasterKeyAndSalt(t, profile)

			send, err := CreateContext(masterKey, masterSalt, profile,
				KeyDerivationRate(kdrValue), SRTCPReplayProtection(64))
			require.NoError(t, err)
			recv, err := CreateContext(masterKey, masterSalt, profile,
				KeyDerivationRate(kdrValue), SRTPReplayProtection(64), SRTCPReplayProtection(64))
			require.NoError(t, err)

			// Send enough RTP packets to cross several RTP derivation periods.
			for seq := uint16(0); seq < 10; seq++ {
				plain := kdrRTPPacket(testSSRC, seq)
				encrypted, err := send.EncryptRTP(nil, plain, nil)
				require.NoError(t, err)
				decrypted, err := recv.DecryptRTP(nil, encrypted, nil)
				require.NoError(t, err)
				assert.Equal(t, plain, decrypted)
			}

			// The first RTCP packet still uses r == 0 because RTCP indices start
			// at one and have not crossed a kdrValue boundary yet.
			rtcpPlain := kdrRTCPPacket(testSSRC)
			rtcpEncrypted, err := send.EncryptRTCP(nil, rtcpPlain, nil)
			require.NoError(t, err)
			rtcpDecrypted, err := recv.DecryptRTCP(nil, rtcpEncrypted, nil)
			require.NoError(t, err)
			assert.Equal(t, rtcpPlain, rtcpDecrypted)

			switch sendCipher := send.cipher.(type) {
			case *srtpCipherAesCmHmacSha1:
				assert.Contains(t, sendCipher.srtcpDerivedKeys, uint64(0))
				// RTP reached r == 3 while RTCP is still at r == 0.
				assert.Contains(t, sendCipher.srtpDerivedKeys, uint64(3))
			case *srtpCipherAeadAesGcm:
				assert.Contains(t, sendCipher.srtcpDerivedKeys, uint64(0))
				assert.Contains(t, sendCipher.srtpDerivedKeys, uint64(3))
			}

			// Cross an RTCP derivation boundary: packets kdrValue+1..2*kdrValue use r == 1.
			var secondPeriodCiphertext []byte
			for i := uint64(1); i <= 2*kdrValue; i++ {
				encrypted, err := send.EncryptRTCP(nil, rtcpPlain, nil)
				require.NoError(t, err)
				decrypted, err := recv.DecryptRTCP(nil, encrypted, nil)
				require.NoError(t, err)
				assert.Equal(t, rtcpPlain, decrypted)
				if i == kdrValue+1 {
					secondPeriodCiphertext = encrypted
				}
			}
			require.NotEmpty(t, secondPeriodCiphertext)

			switch sendCipher := send.cipher.(type) {
			case *srtpCipherAesCmHmacSha1:
				assert.Contains(t, sendCipher.srtcpDerivedKeys, uint64(1))
			case *srtpCipherAeadAesGcm:
				assert.Contains(t, sendCipher.srtcpDerivedKeys, uint64(1))
			}

			// An out-of-order RTCP packet from the first derivation period must
			// still decrypt with the cached r == 0 key set. Replay protection may
			// reject the duplicate, but the error must be a replay rejection rather
			// than an auth-tag failure, which would indicate a wrong-period key.
			firstPeriodDecrypted, err := recv.DecryptRTCP(nil, rtcpEncrypted, nil)
			if err == nil {
				assert.Equal(t, rtcpPlain, firstPeriodDecrypted)
			} else {
				assert.ErrorIs(t, err, errDuplicated)
			}
		})
	}
}

// TestKeyDerivationRateZeroKeepsSingleKeySet locks in the legacy behavior:
// without the option (or with an explicit zero rate) only the initial r == 0
// key set exists and the wire output is identical to a context without KDR.
func TestKeyDerivationRateZeroKeepsSingleKeySet(t *testing.T) {
	const testSSRC = uint32(0x99aabbcc)

	for _, profile := range kdrTestProfiles(t) {
		t.Run(profile.String(), func(t *testing.T) {
			masterKey, masterSalt := kdrMasterKeyAndSalt(t, profile)

			legacy, err := CreateContext(masterKey, masterSalt, profile)
			require.NoError(t, err)
			explicitZero, err := CreateContext(masterKey, masterSalt, profile, KeyDerivationRate(0))
			require.NoError(t, err)

			plain := kdrRTPPacket(testSSRC, 7)
			legacyEncrypted, err := legacy.EncryptRTP(nil, plain, nil)
			require.NoError(t, err)
			zeroEncrypted, err := explicitZero.EncryptRTP(nil, plain, nil)
			require.NoError(t, err)
			assert.Equal(t, legacyEncrypted, zeroEncrypted)

			rtcpPlain := kdrRTCPPacket(testSSRC)
			legacyRTCP, err := legacy.EncryptRTCP(nil, rtcpPlain, nil)
			require.NoError(t, err)
			zeroRTCP, err := explicitZero.EncryptRTCP(nil, rtcpPlain, nil)
			require.NoError(t, err)
			assert.Equal(t, legacyRTCP, zeroRTCP)

			switch c := explicitZero.cipher.(type) {
			case *srtpCipherAesCmHmacSha1:
				assert.Len(t, c.srtpDerivedKeys, 1)
				assert.Len(t, c.srtcpDerivedKeys, 1)
				assert.Contains(t, c.srtpDerivedKeys, uint64(0))
			case *srtpCipherAeadAesGcm:
				assert.Len(t, c.srtpDerivedKeys, 1)
				assert.Len(t, c.srtcpDerivedKeys, 1)
				assert.Contains(t, c.srtpDerivedKeys, uint64(0))
			}
		})
	}
}

// TestKeyDerivationRateSendReceiveInterop rotates keys through several periods
// using two fully independent contexts, verifying every encrypted packet is
// decryptable by the peer and vice versa (identical derivation boundaries on
// both sending and receiving sides).
func TestKeyDerivationRateSendReceiveInterop(t *testing.T) {
	const (
		kdrValue = uint64(5)
		testSSRC = uint32(0x0badc0de)
	)

	for _, profile := range kdrTestProfiles(t) {
		t.Run(profile.String(), func(t *testing.T) {
			masterKey, masterSalt := kdrMasterKeyAndSalt(t, profile)

			alice, err := CreateContext(masterKey, masterSalt, profile,
				KeyDerivationRate(kdrValue), SRTPReplayProtection(128), SRTCPReplayProtection(128))
			require.NoError(t, err)
			bob, err := CreateContext(masterKey, masterSalt, profile,
				KeyDerivationRate(kdrValue), SRTPReplayProtection(128), SRTCPReplayProtection(128))
			require.NoError(t, err)

			for seq := uint16(0); seq < 40; seq++ {
				plain := kdrRTPPacket(testSSRC, seq)

				aliceToBob, err := alice.EncryptRTP(nil, plain, nil)
				require.NoError(t, err)
				decrypted, err := bob.DecryptRTP(nil, aliceToBob, nil)
				require.NoError(t, err)
				assert.Equal(t, plain, decrypted)

				bobToAlice, err := bob.EncryptRTP(nil, plain, nil)
				require.NoError(t, err)
				decrypted, err = alice.DecryptRTP(nil, bobToAlice, nil)
				require.NoError(t, err)
				assert.Equal(t, plain, decrypted)
			}

			for i := 0; i < 12; i++ {
				rtcpPlain := kdrRTCPPacket(testSSRC)

				encrypted, err := alice.EncryptRTCP(nil, rtcpPlain, nil)
				require.NoError(t, err)
				decrypted, err := bob.DecryptRTCP(nil, encrypted, nil)
				require.NoError(t, err)
				assert.Equal(t, rtcpPlain, decrypted)
			}
		})
	}
}

// TestKeyDerivationRateOverflowRejectsData exercises the safety requirement
// that data is refused instead of being protected with an unencodable r.
func TestKeyDerivationRateOverflowRejectsData(t *testing.T) {
	c := &Context{keyDerivationRate: 1}

	// The highest value encodable in the six-octet derivation field is accepted.
	r, err := c.keyDerivationIndex(maxKeyDerivationRateIndex)
	require.NoError(t, err)
	assert.Equal(t, maxKeyDerivationRateIndex, r)

	// Anything beyond it is refused instead of being truncated into the field.
	_, err = c.keyDerivationIndex(maxKeyDerivationRateIndex + 1)
	assert.ErrorIs(t, err, errKeyDerivationRateOverflow)

	// A real context applies the same boundary at the top of the RTP index
	// space (ROC maxROC, SEQ maxSequenceNumber == index 2^48 - 1).
	const overflowSSRC = uint32(0x12345678)
	masterKey := make([]byte, 16)
	masterSalt := make([]byte, 14)
	recv, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_80,
		KeyDerivationRate(1))
	require.NoError(t, err)
	recv.SetROC(overflowSSRC, maxROC)

	r, err = recv.keyDerivationIndex(maxKeyDerivationRateIndex)
	require.NoError(t, err)
	assert.Equal(t, maxKeyDerivationRateIndex, r)

	// Zero rate always maps to r == 0, even for huge indices (DIV 0 convention).
	c.keyDerivationRate = 0
	r, err = c.keyDerivationIndex(^uint64(0))
	require.NoError(t, err)
	assert.Zero(t, r)
}

// TestKeyDerivationRateOptionLifecycle checks the option is construction-only,
// matching the RFC requirement that kdrValue is fixed for the master key lifetime.
func TestKeyDerivationRateOptionLifecycle(t *testing.T) {
	t.Run("sets value during construction", func(t *testing.T) {
		c := &Context{}
		require.NoError(t, KeyDerivationRate(42)(c))
		assert.Equal(t, uint64(42), c.keyDerivationRate)
	})

	t.Run("rejected on constructed context", func(t *testing.T) {
		ctx := constructedContext(t)
		err := KeyDerivationRate(42)(ctx)
		assert.ErrorIs(t, err, ErrContextOptionNotUpdatable)
	})

	t.Run("survives MKI context rebuild", func(t *testing.T) {
		masterKey := make([]byte, 16)
		masterSalt := make([]byte, 14)
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_80,
			KeyDerivationRate(7))
		require.NoError(t, err)

		rebuilt, err := ctx.contextWithKey(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_80)
		require.NoError(t, err)
		assert.Equal(t, uint64(7), rebuilt.keyDerivationRate)
	})
}
