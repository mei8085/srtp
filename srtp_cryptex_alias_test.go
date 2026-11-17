// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"encoding/binary"
	"slices"
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin down the aliasing rules of the Cryptex (RFC 9335) header
// reordering helpers.
//
// The Cryptex wire format places the 4-byte header-extension block before the
// CSRC list, while an unprotected RTP packet carries them in the opposite
// order. moveHeaderExtensionBeforeCSRCs / moveCSRCsBeforeHeaderExtension
// perform this swap in place inside the caller's packet buffer, and the
// extension payload slices inside rtp.Header keep aliasing that same buffer
// across the whole operation. Because the reordering moves the bytes that sit
// directly behind the authenticated header boundary, an out-of-bounds write or
// a missed restore here would silently turn authenticated data into mutable
// data. The tests below verify:
//   - the two reordering helpers are exact inverses and never write past the
//     packet length (guard bytes surrounding the buffer would catch that);
//   - overlapping in-place copies preserve every byte and every aliased
//     extension payload;
//   - truncated packets fail through the public API with an explicit error,
//     without panicking or corrupting any state that outlives the call;
//   - well-formed packets retain their encryption semantics across the
//     supported buffer layouts: separate buffers and in-place buffers whose
//     dst and src share a start address (partially overlapping slices are
//     rejected by the underlying AEAD primitives and are not a valid layout).

// reorderCryptexReference is an independent, allocation-based reference
// implementation of the Cryptex reordering used only as an oracle in tests.
func reorderCryptexReference(buf []byte, nCSRC int) []byte {
	csrcLen := nCSRC * 4
	out := make([]byte, 0, len(buf))
	out = append(out, buf[:minSrtpHeaderSize]...)
	out = append(out, buf[minSrtpHeaderSize+csrcLen:minSrtpHeaderSize+csrcLen+extensionHeaderSize]...)
	out = append(out, buf[minSrtpHeaderSize:minSrtpHeaderSize+csrcLen]...)
	out = append(out, buf[minSrtpHeaderSize+csrcLen+extensionHeaderSize:]...)

	return out
}

// buildCryptexRawPacket assembles an RTP packet with CSRCs followed by an RFC
// 8285 header extension (the pre-Cryptex on-the-wire order) plus a payload.
func buildCryptexRawPacket(t *testing.T, profile uint16, seq uint16, nCSRC int, extPayloadLen int) []byte {
	t.Helper()

	header := rtp.Header{
		Version:          2,
		Marker:           true,
		PayloadType:      0x6F,
		SequenceNumber:   seq,
		Timestamp:        0xDECAFBAD,
		SSRC:             0xCAFEBABE,
		Extension:        true,
		ExtensionProfile: profile,
	}
	for i := 0; i < nCSRC; i++ {
		header.CSRC = append(header.CSRC, 0x1000+uint32(i))
	}
	extPayload := make([]byte, extPayloadLen)
	for i := range extPayload {
		extPayload[i] = byte(0xA0 + i)
	}
	require.NoError(t, header.SetExtension(1, extPayload))

	rawHeader, err := header.Marshal()
	require.NoError(t, err)

	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	return append(slices.Clone(rawHeader), payload...)
}

// TestCryptexReorderRoundTrip verifies that the two reordering helpers are
// exact inverses for every CSRC/extension shape, and that their result matches
// an independent reference implementation.
func TestCryptexReorderRoundTrip(t *testing.T) {
	profiles := []uint16{rtp.ExtensionProfileOneByte, rtp.ExtensionProfileTwoByte}

	for _, profile := range profiles {
		for nCSRC := 1; nCSRC <= 4; nCSRC++ {
			for _, extPayloadLen := range []int{1, 4, 7, 16} {
				raw := buildCryptexRawPacket(t, profile, uint16(nCSRC), nCSRC, extPayloadLen)

				var header rtp.Header
				_, err := header.Unmarshal(raw)
				require.NoError(t, err)
				require.NotEmpty(t, header.Extensions)
				require.Len(t, header.CSRC, nCSRC)

				// The extension payload slice aliases the packet buffer. Its offset
				// is structural: fixed header, CSRCs, the 4-byte extension block
				// header, then the one/two-byte extension element header.
				aliasedPayload := header.GetExtension(1)
				require.NotEmpty(t, aliasedPayload)
				extElementHeaderLen := 1
				if profile == rtp.ExtensionProfileTwoByte {
					extElementHeaderLen = 2
				}
				payloadOffset := minSrtpHeaderSize + nCSRC*4 + extensionHeaderSize + extElementHeaderLen
				require.Equal(t, &raw[payloadOffset], &aliasedPayload[0],
					"extension payload must alias the input buffer before reordering")

				original := slices.Clone(raw)

				moveHeaderExtensionBeforeCSRCs(&header, raw)
				assert.Equal(t, reorderCryptexReference(original, nCSRC), raw,
					"extension-before-CSRC reordering must match the reference implementation")

				// After reordering, the ext header sits right after the 12-byte
				// fixed RTP header and carries the Cryptex profile once encrypted.
				assert.Equal(t, profile, binary.BigEndian.Uint16(raw[minSrtpHeaderSize:]))

				moveCSRCsBeforeHeaderExtension(&header, raw)
				assert.Equal(t, original, raw,
					"moving CSRCs back must restore the packet byte-for-byte")

				// The aliased extension payload still observes the same content.
				assert.Equal(t, original[payloadOffset:payloadOffset+len(aliasedPayload)],
					aliasedPayload,
					"aliased extension payload must be preserved across the full round trip")
			}
		}
	}
}

// TestCryptexReorderGuardBytes surrounds a packet with sentinel guard bytes
// and reorders it in place. Any write outside the packet's length would
// overwrite a guard byte, turning an out-of-bounds write into a test failure.
func TestCryptexReorderGuardBytes(t *testing.T) {
	const (
		guardPrefix = 8
		guardSuffix = 8
		guardValue  = byte(0xDD)
	)

	raw := buildCryptexRawPacket(t, rtp.ExtensionProfileOneByte, 0x1234, 3, 11)

	backing := make([]byte, guardPrefix+len(raw)+guardSuffix)
	for i := range backing {
		backing[i] = guardValue
	}
	packet := backing[guardPrefix : guardPrefix+len(raw)]
	copy(packet, raw)

	var header rtp.Header
	_, err := header.Unmarshal(packet)
	require.NoError(t, err)

	moveHeaderExtensionBeforeCSRCs(&header, packet)
	moveCSRCsBeforeHeaderExtension(&header, packet)

	assert.Equal(t, raw, packet, "packet content must survive reordering inside a guarded buffer")
	assert.Equal(t, bytesRepeated(guardValue, guardPrefix), backing[:guardPrefix],
		"reordering must not write before the packet boundary")
	assert.Equal(t, bytesRepeated(guardValue, guardSuffix), backing[guardPrefix+len(raw):],
		"reordering must not write past the packet boundary")
}

// TestCryptexReorderErrorRestoresBuffer drives the public encrypt/decrypt
// entry points with a failing inner transform and checks that the Cryptex
// reordering is fully rolled back: the caller's buffer must come back
// byte-identical, so an error can never leave an authenticated region in a
// reordered (and therefore mis-authenticated) state.
func TestCryptexReorderErrorRestoresBuffer(t *testing.T) {
	raw := buildCryptexRawPacket(t, rtp.ExtensionProfileOneByte, 0x3344, 2, 5)

	var header rtp.Header
	_, err := header.Unmarshal(raw)
	require.NoError(t, err)

	injectedErr := errBadIVLength

	t.Run("encrypt restores on transform error", func(t *testing.T) {
		buf := slices.Clone(raw)
		err := encryptCryptexRTP(buf, buf, true, &header, func(dst, plaintext []byte, headerLen int) error {
			return injectedErr
		})
		assert.ErrorIs(t, err, injectedErr)
		assert.Equal(t, raw, buf, "failed encryption must restore the original packet layout")
	})

	t.Run("decrypt restores on transform error", func(t *testing.T) {
		buf := slices.Clone(raw)
		err := decryptCryptexRTP(buf, buf, true, &header, len(raw), func(dst, ciphertext []byte, headerLen int) error {
			return injectedErr
		})
		assert.ErrorIs(t, err, injectedErr)
		assert.Equal(t, raw, buf, "failed decryption must restore the original packet layout")
	})
}

// TestCryptexAliasBoundaryEncryptDecrypt runs encrypt/decrypt round trips under
// every supported buffer layout and proves the authenticated header bytes are
// never altered by the reordering machinery.
func TestCryptexAliasBoundaryEncryptDecrypt(t *testing.T) {
	profiles := []ProtectionProfile{
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAeadAes128Gcm,
	}

	for _, profile := range profiles {
		t.Run(profile.String(), func(t *testing.T) {
			keyLen, err := profile.KeyLen()
			require.NoError(t, err)
			saltLen, err := profile.SaltLen()
			require.NoError(t, err)
			key := make([]byte, keyLen)
			salt := make([]byte, saltLen)
			for i := range key {
				key[i] = byte(i + 1)
			}

			encryptCtx, err := CreateContext(key, salt, profile, Cryptex(CryptexModeEnabled))
			require.NoError(t, err)
			decryptCtx, err := CreateContext(key, salt, profile, Cryptex(CryptexModeEnabled))
			require.NoError(t, err)

			for nCSRC := 1; nCSRC <= 3; nCSRC++ {
				plain := buildCryptexRawPacket(t, rtp.ExtensionProfileOneByte,
					uint16(0x4000+nCSRC), nCSRC, 6)
				plainCopy := slices.Clone(plain)

				t.Run("separate buffers", func(t *testing.T) {
					encrypted, err := encryptCtx.EncryptRTP(nil, slices.Clone(plain), &rtp.Header{})
					require.NoError(t, err)

					// The fixed RTP header stays in the clear and unchanged.
					assert.Equal(t, plain[:minSrtpHeaderSize], encrypted[:minSrtpHeaderSize],
						"the authenticated fixed header must not be modified")

					var decryptedHeader rtp.Header
					decrypted, err := decryptCtx.DecryptRTP(nil, slices.Clone(encrypted), &decryptedHeader)
					require.NoError(t, err)
					assert.Equal(t, plainCopy, decrypted)
					assert.Len(t, decryptedHeader.CSRC, nCSRC)
					assert.Equal(t, uint16(rtp.ExtensionProfileOneByte), decryptedHeader.ExtensionProfile)
				})

				t.Run("same buffer", func(t *testing.T) {
					src := make([]byte, 0, len(plain)+32)
					src = append(src, plain...)
					encrypted, err := encryptCtx.EncryptRTP(src, src, &rtp.Header{})
					require.NoError(t, err)
					require.True(t, isSameBuffer(encrypted, src))

					dst := make([]byte, 0, len(encrypted)+32)
					dst = append(dst, encrypted...)
					decrypted, err := decryptCtx.DecryptRTP(dst, dst, &rtp.Header{})
					require.NoError(t, err)
					assert.Equal(t, plainCopy, decrypted)
					require.True(t, isSameBuffer(decrypted, dst))
				})

				t.Run("same buffer with leading spare capacity", func(t *testing.T) {
					// The documented in-place contract: dst and src must start at the
					// same address. A leading allocation offset keeps extra capacity
					// ahead of the packet while both slices share a start address, so
					// isSameBuffer still classifies the call correctly.
					backing := make([]byte, 16, 16+len(plain)+32)
					src := backing[16:]
					src = append(src, plain...)
					dst := backing[16:16]

					encrypted, err := encryptCtx.EncryptRTP(dst, src, &rtp.Header{})
					require.NoError(t, err)
					require.True(t, isSameBuffer(encrypted, src))
					assert.Equal(t, plain[:minSrtpHeaderSize], encrypted[:minSrtpHeaderSize])

					decBacking := make([]byte, 8, 8+len(encrypted)+32)
					decSrc := decBacking[8:]
					decSrc = append(decSrc, encrypted...)
					decDst := decBacking[8:8]
					decrypted, err := decryptCtx.DecryptRTP(decDst, decSrc, &rtp.Header{})
					require.NoError(t, err)
					assert.Equal(t, plainCopy, decrypted)
					require.True(t, isSameBuffer(decrypted, decSrc))
				})

				t.Run("tight in-place buffer grown by the library", func(t *testing.T) {
					// dst starts empty on the same address and lacks the capacity for
					// the auth tag, so growBufferSize must relocate it without ever
					// aliasing the source memory.
					src := make([]byte, 0)
					src = append(src, plain...)
					dst := src[:0]

					encrypted, err := encryptCtx.EncryptRTP(dst, src, &rtp.Header{})
					require.NoError(t, err)
					assert.Equal(t, plain[:minSrtpHeaderSize], encrypted[:minSrtpHeaderSize])

					var decryptedHeader rtp.Header
					decrypted, err := decryptCtx.DecryptRTP(nil, slices.Clone(encrypted), &decryptedHeader)
					require.NoError(t, err)
					assert.Equal(t, plainCopy, decrypted)
				})
			}
		})
	}
}

// TestCryptexBufferAliasBoundary pins the aliasing contract that the Cryptex
// in-place reordering relies on. Two slices are treated as the same buffer
// only when they start at the same address; partially overlapping windows of
// one backing array are distinct buffers and must never be passed as dst/src
// to the crypto primitives, since Go's AEAD implementation rejects overlap
// with a panic. The reordering helpers themselves only use overlapping
// copies of the same slice (exercised by FuzzCryptexReorder).
func TestCryptexBufferAliasBoundary(t *testing.T) {
	backing := make([]byte, 64)

	// Identical start addresses, independent length/capacity views: same buffer.
	assert.True(t, isSameBuffer(backing[0:10], backing[0:5]))
	assert.True(t, isSameBuffer(backing[16:32], backing[16:20]))
	// Zero-length views at the same start still resolve to one address.
	assert.True(t, isSameBuffer(backing[:0], backing[:4]))
	// Different start addresses, even within one allocation: distinct buffers.
	assert.False(t, isSameBuffer(backing[0:16], backing[8:24]))
	assert.False(t, isSameBuffer(backing[0:8], backing[32:40]))
	// A fresh allocation can never alias the original.
	assert.False(t, isSameBuffer(backing, make([]byte, 64)))
	// Empty slices carry no backing memory.
	assert.True(t, isSameBuffer(nil, nil)) //nolint:testifylint
	assert.False(t, isSameBuffer(nil, backing))
}

// TestCryptexMalformedPacketsAreContained feeds malformed Cryptex packets to
// DecryptRTP and asserts two things: every malformed packet produces an
// explicit error without panicking, and a valid packet processed afterwards
// still decrypts correctly, proving the failure did not pollute the context.
// All calls here use a separate destination, so the caller's ciphertext must
// additionally come back byte-identical.
func TestCryptexMalformedPacketsAreContained(t *testing.T) {
	key := make([]byte, 16)
	salt := make([]byte, 12) // AES-GCM profiles use a 12-byte master salt
	for i := range key {
		key[i] = byte(0x30 + i)
	}

	encryptCtx, err := CreateContext(key, salt, ProtectionProfileAeadAes128Gcm, Cryptex(CryptexModeEnabled))
	require.NoError(t, err)
	decryptCtx, err := CreateContext(key, salt, ProtectionProfileAeadAes128Gcm, Cryptex(CryptexModeEnabled))
	require.NoError(t, err)

	plain := buildCryptexRawPacket(t, rtp.ExtensionProfileOneByte, 0x5566, 2, 8)
	validEncrypted, err := encryptCtx.EncryptRTP(nil, plain, &rtp.Header{})
	require.NoError(t, err)
	expectedPlain := slices.Clone(plain)

	mutate := func(t *testing.T, name string, mutateFn func([]byte) []byte) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			// Re-encrypt for every subtest so the replay/cipher state is comparable.
			packet := mutateFn(slices.Clone(validEncrypted))
			inputSnapshot := slices.Clone(packet)

			var header rtp.Header
			decrypted, err := decryptCtx.DecryptRTP(nil, packet, &header)
			assert.Error(t, err, "malformed packet must be rejected with an explicit error")
			assert.Nil(t, decrypted, "a rejected packet must not yield plaintext")
			assert.Equal(t, inputSnapshot, packet,
				"failed decryption must leave the caller's ciphertext buffer untouched")

			// The next, well-formed packet must still decrypt correctly.
			var goodHeader rtp.Header
			goodPlain, goodErr := decryptCtx.DecryptRTP(nil, slices.Clone(validEncrypted), &goodHeader)
			require.NoError(t, goodErr, "context must stay usable after a malformed packet")
			assert.Equal(t, expectedPlain, goodPlain)
		})
	}

	mutate(t, "truncated inside fixed header", func(p []byte) []byte {
		return p[:minSrtpHeaderSize-1]
	})
	mutate(t, "truncated inside reordered CSRC region", func(p []byte) []byte {
		return p[:minSrtpHeaderSize+2]
	})
	mutate(t, "truncated to header only", func(p []byte) []byte {
		return p[:minSrtpHeaderSize+extensionHeaderSize]
	})
	mutate(t, "truncated auth tag", func(p []byte) []byte {
		return p[:len(p)-4]
	})
	mutate(t, "flipped authenticated header byte", func(p []byte) []byte {
		p[8] ^= 0x01 // SSRC byte: authenticated AAD

		return p
	})
	mutate(t, "flipped extension profile byte", func(p []byte) []byte {
		p[minSrtpHeaderSize] ^= 0xFF

		return p
	})
	mutate(t, "flipped encrypted payload byte", func(p []byte) []byte {
		p[len(p)/2] ^= 0x80

		return p
	})
	mutate(t, "flipped auth tag byte", func(p []byte) []byte {
		p[len(p)-1] ^= 0x01

		return p
	})
}

// TestCryptexInPlaceFailureRollback exercises the AES-CTR profile, whose
// stream transform never aborts mid-way: when authentication of an in-place
// packet fails, the Cryptex reordering rollback must still restore the
// caller's buffer to the exact original ciphertext. This pins the
// moveCSRCsBeforeHeaderExtension error-path used by decryptCryptexRTP.
func TestCryptexInPlaceFailureRollback(t *testing.T) {
	const profile = ProtectionProfileAes128CmHmacSha1_80
	keyLen, err := profile.KeyLen()
	require.NoError(t, err)
	saltLen, err := profile.SaltLen()
	require.NoError(t, err)
	key := make([]byte, keyLen)
	salt := make([]byte, saltLen)
	for i := range key {
		key[i] = byte(i + 1)
	}

	encryptCtx, err := CreateContext(key, salt, profile, Cryptex(CryptexModeEnabled))
	require.NoError(t, err)
	decryptCtx, err := CreateContext(key, salt, profile, Cryptex(CryptexModeEnabled))
	require.NoError(t, err)

	plain := buildCryptexRawPacket(t, rtp.ExtensionProfileOneByte, 0x7788, 3, 10)
	encrypted, err := encryptCtx.EncryptRTP(nil, plain, &rtp.Header{})
	require.NoError(t, err)

	for _, name := range []string{"authenticated header", "encrypted payload", "auth tag"} {
		t.Run(name, func(t *testing.T) {
			buf := make([]byte, 0, len(encrypted)+16)
			buf = append(buf, encrypted...)

			switch name {
			case "authenticated header":
				buf[9] ^= 0x02 // SSRC byte covered by the HMAC
			case "encrypted payload":
				buf[len(buf)/2] ^= 0x40
			case "auth tag":
				buf[len(buf)-1] ^= 0x7F
			}
			// Snapshot after tampering. The HMAC check precedes decryption, so the
			// rollback contract is that the exact bytes handed in come back out:
			// the Cryptex reordering must be undone without touching anything else.
			tampered := slices.Clone(buf)

			_, decErr := decryptCtx.DecryptRTP(buf[:0], buf, &rtp.Header{})
			assert.ErrorIs(t, decErr, ErrFailedToVerifyAuthTag,
				"tampered packet must fail authentication explicitly")
			assert.Equal(t, tampered, buf,
				"failed in-place CTR decryption must roll the Cryptex reordering back")
		})
	}
}

// FuzzCryptexReorder fuzzes the in-place reordering helpers directly. The
// reordering copies overlap inside one buffer; the fuzzer verifies the copies
// never escape the buffer, round-trip exactly, and keep every aliased
// extension payload consistent.
func FuzzCryptexReorder(f *testing.F) {
	for _, nCSRC := range []int{1, 2, 4} {
		for _, extLen := range []int{1, 4, 16} {
			f.Add(uint16(nCSRC), uint16(extLen), uint16(8), uint8(0))
		}
	}
	f.Add(uint16(15), uint16(16), uint16(64), uint8(1))

	f.Fuzz(func(t *testing.T, nCSRC16, extLen16, payloadLen16 uint16, profileByte uint8) {
		nCSRC := int(nCSRC16%15) + 1 // CC is a 4-bit field, 1..15

		var profile uint16 = rtp.ExtensionProfileOneByte
		if profileByte&1 == 1 {
			profile = rtp.ExtensionProfileTwoByte
		}
		// RFC 8285 limits one-byte extension payloads to 16 bytes, two-byte to 255.
		maxExtLen := 255
		if profile == rtp.ExtensionProfileOneByte {
			maxExtLen = 16
		}
		extPayloadLen := int(extLen16%uint16(maxExtLen)) + 1
		payloadLen := int(payloadLen16%128) + 1

		header := rtp.Header{
			Version:          2,
			PayloadType:      96,
			SequenceNumber:   0xF00D,
			Timestamp:        0x11223344,
			SSRC:             0x55667788,
			Extension:        true,
			ExtensionProfile: profile,
			CSRC:             make([]uint32, nCSRC),
		}
		for i := range header.CSRC {
			header.CSRC[i] = uint32(0x9000 + i)
		}
		extPayload := make([]byte, extPayloadLen)
		for i := range extPayload {
			extPayload[i] = byte(i * 7)
		}
		require.NoError(t, header.SetExtension(1, extPayload))

		rawHeader, err := header.Marshal()
		require.NoError(t, err)
		buf := make([]byte, 0, len(rawHeader)+payloadLen)
		buf = append(buf, rawHeader...)
		for i := 0; i < payloadLen; i++ {
			buf = append(buf, byte(i*3+1))
		}

		// Embed the packet between guard bytes so an out-of-range write fails.
		const guard = 8
		backing := make([]byte, guard+len(buf)+guard)
		packet := backing[guard : guard+len(buf)]
		copy(packet, buf)
		original := slices.Clone(packet)

		var parsed rtp.Header
		_, err = parsed.Unmarshal(packet)
		require.NoError(t, err)
		aliased := parsed.GetExtension(1)
		require.NotEmpty(t, aliased)

		moveHeaderExtensionBeforeCSRCs(&parsed, packet)
		assert.Equal(t, reorderCryptexReference(original, nCSRC), packet,
			"extension-before-CSRC reordering must match the reference implementation")
		moveCSRCsBeforeHeaderExtension(&parsed, packet)

		assert.Equal(t, original, packet, "reordering must be reversible byte-for-byte")
		// Structural offset of the extension payload, independent of the 4-byte
		// padding that rtp.Header.Unmarshal includes in its returned header length.
		extElementHeaderLen := 1
		if profile == rtp.ExtensionProfileTwoByte {
			extElementHeaderLen = 2
		}
		payloadOffset := minSrtpHeaderSize + nCSRC*4 + extensionHeaderSize + extElementHeaderLen
		assert.Equal(t, original[payloadOffset:payloadOffset+len(aliased)], aliased,
			"aliased extension payload must survive reordering")
		assert.Equal(t, make([]byte, guard), backing[:guard], "prefix guard overwritten")
		assert.Equal(t, make([]byte, guard), backing[guard+len(packet):], "suffix guard overwritten")
	})
}

// FuzzCryptexEncryptDecryptBuffers fuzzes the full EncryptRTP/DecryptRTP
// Cryptex path with attacker-controlled packet bytes and buffer layouts. It
// proves that truncated or overlapping data never causes an out-of-bounds
// access or a panic, malformed packets only fail explicitly without
// contaminating the next operation, and well-formed packets always round-trip
// to the original plaintext.
func FuzzCryptexEncryptDecryptBuffers(f *testing.F) {
	// Seed with RFC 9335 shapes: one/two-byte extensions, with and without CSRCs.
	for _, seed := range []struct {
		nCSRC      uint16
		extLen     uint16
		payloadLen uint16
		twoByte    uint8
		layout     uint8
		truncate   uint16
		mutateByte uint16
	}{
		{0, 4, 16, 0, 0, 0, 0},
		{2, 6, 16, 0, 1, 0, 0},
		{3, 8, 24, 1, 2, 0, 0},
		{1, 1, 8, 0, 0, 12, 0},  // truncated packet
		{2, 4, 16, 0, 1, 0, 14}, // authenticated-header mutation
	} {
		f.Add(seed.nCSRC, seed.extLen, seed.payloadLen, seed.twoByte, seed.layout,
			seed.truncate, seed.mutateByte)
	}

	f.Fuzz(func(t *testing.T, nCSRC16, extLen16, payloadLen16 uint16,
		twoByte uint8, layout uint8, truncate16, mutateByte16 uint16,
	) {
		nCSRC := int(nCSRC16 % 16) // 0..15; 0 means no CSRCs

		var profile uint16 = rtp.ExtensionProfileOneByte
		if twoByte&1 == 1 {
			profile = rtp.ExtensionProfileTwoByte
		}
		// RFC 8285 limits one-byte extension payloads to 16 bytes, two-byte to 255.
		maxExtLen := 255
		if profile == rtp.ExtensionProfileOneByte {
			maxExtLen = 16
		}
		extPayloadLen := int(extLen16%uint16(maxExtLen)) + 1
		payloadLen := int(payloadLen16%256) + 1

		header := rtp.Header{
			Version:          2,
			Marker:           true,
			PayloadType:      97,
			SequenceNumber:   0x7788,
			Timestamp:        0xAAAABBBB,
			SSRC:             0xCCCCDDDD,
			Extension:        true,
			ExtensionProfile: profile,
			CSRC:             make([]uint32, nCSRC),
		}
		for i := range header.CSRC {
			header.CSRC[i] = uint32(0x2000 + i)
		}
		extPayload := make([]byte, extPayloadLen)
		for i := range extPayload {
			extPayload[i] = byte(i + 1)
		}
		require.NoError(t, header.SetExtension(1, extPayload))

		rawHeader, err := header.Marshal()
		require.NoError(t, err)
		plain := make([]byte, 0, len(rawHeader)+payloadLen)
		plain = append(plain, rawHeader...)
		for i := 0; i < payloadLen; i++ {
			plain = append(plain, byte(i+1))
		}
		plainSnapshot := slices.Clone(plain)

		// Fresh contexts per iteration: no replay state leaks between cases, and
		// any internal buffer contamination becomes visible on the next call.
		newContexts := func(t *testing.T) (*Context, *Context) {
			t.Helper()
			enc, err := CreateContext(make([]byte, 16), make([]byte, 12),
				ProtectionProfileAeadAes128Gcm, Cryptex(CryptexModeEnabled))
			require.NoError(t, err)
			dec, err := CreateContext(make([]byte, 16), make([]byte, 12),
				ProtectionProfileAeadAes128Gcm, Cryptex(CryptexModeEnabled))
			require.NoError(t, err)

			return enc, dec
		}

		encryptCtx, decryptCtx := newContexts(t)

		var encrypted []byte
		require.NotPanics(t, func() {
			encrypted, err = encryptCtx.EncryptRTP(nil, slices.Clone(plain), &rtp.Header{})
		})
		require.NoError(t, err)
		require.NotEmpty(t, encrypted)
		// Authenticated, unencrypted fixed header survives encryption untouched.
		require.Equal(t, plain[:minSrtpHeaderSize], encrypted[:minSrtpHeaderSize])
		// Encryption must not have modified the caller's plaintext.
		require.Equal(t, plainSnapshot, plain)

		// Build the receive buffer according to the fuzzed layout.
		truncate := int(truncate16) % (len(encrypted) + 1)
		inputLen := len(encrypted) - truncate
		if inputLen < 0 {
			inputLen = 0
		}

		var input []byte
		inPlace := layout%3 != 0
		switch layout % 3 {
		case 0:
			// Fresh allocation, separate dst.
			input = slices.Clone(encrypted[:inputLen])
		case 1:
			// Same buffer for dst and src, spare capacity at the tail.
			buf := make([]byte, 0, len(encrypted)+32)
			buf = append(buf, encrypted[:inputLen]...)
			input = buf
		default:
			// In-place buffer whose shared start address sits behind a leading
			// capacity region: dst and src still begin at the same address, which
			// is the exact aliasing rule isSameBuffer recognizes.
			const head = 24
			backing := make([]byte, head, head+len(encrypted)+32)
			input = backing[head:]
			input = append(input, encrypted[:inputLen]...)
		}
		inputBefore := slices.Clone(input)

		mutateByte := int(mutateByte16)
		shouldMutate := mutateByte16 != 0 && inputLen > 0
		if shouldMutate {
			input[mutateByte%inputLen] ^= byte(mutateByte>>8) | 0x01
			inputBefore = slices.Clone(input)
		}

		var (
			decrypted []byte
			decErr    error
		)
		require.NotPanics(t, func() {
			var dst []byte
			if inPlace {
				dst = input[:0] // in-place: dst and src share the start address
			}
			decrypted, decErr = decryptCtx.DecryptRTP(dst, input, &rtp.Header{})
		})

		wellFormed := truncate == 0 && !shouldMutate
		switch {
		case wellFormed:
			require.NoError(t, decErr)
			require.Equal(t, plainSnapshot, decrypted,
				"valid Cryptex packet must restore the exact plaintext under any buffer layout")
		default:
			require.Error(t, decErr, "truncated/mutated packet must fail explicitly")
			require.Nil(t, decrypted, "failed decryption must not return plaintext")
			if !inPlace {
				// A separate destination must never touch the caller's source
				// buffer. In-place callers explicitly allow the buffer to be
				// overwritten, including by a failed AEAD Open that aborts
				// before the Cryptex reordering can be rolled back.
				require.Equal(t, inputBefore, input,
					"separate-buffer decryption must not mutate the caller's input buffer")
			}
		}

		// Containment check: regardless of what happened above, a pristine valid
		// packet must still decrypt correctly on the same context.
		goodPlain, goodErr := decryptCtx.DecryptRTP(nil, slices.Clone(encrypted), &rtp.Header{})
		require.NoError(t, goodErr, "a failed packet must not pollute the next processing")
		require.Equal(t, plainSnapshot, goodPlain)
	})
}

// bytesRepeated returns a slice of length n filled with value b.
func bytesRepeated(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}

	return out
}
