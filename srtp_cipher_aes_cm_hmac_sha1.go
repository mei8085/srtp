// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec
	"crypto/subtle"
	"encoding/binary"
	"hash"

	"github.com/pion/rtp"
)

// srtpAesCmHmacSha1Keys is the set of AES-CM/HMAC-SHA1 session keys derived
// for one key derivation index r = packet index DIV key derivation rate.
type srtpAesCmHmacSha1Keys struct {
	srtpSessionSalt []byte
	srtpSessionAuth hash.Hash
	srtpBlock       cipher.Block

	srtcpSessionSalt []byte
	srtcpSessionAuth hash.Hash
	srtcpBlock       cipher.Block
}

// deriveSrtpAesCmHmacSha1Keys derives the complete AES-CM/HMAC-SHA1 session
// key set for the given key derivation index r from the master key and salt,
// following RFC 3711 section 4.3.
func deriveSrtpAesCmHmacSha1Keys(
	profile protectionProfileWithArgs, masterKey, masterSalt []byte, indexOverKdr uint64,
) (*srtpAesCmHmacSha1Keys, error) {
	keys := &srtpAesCmHmacSha1Keys{}

	srtpSessionKey, err := aesCmKeyDerivation(labelSRTPEncryption, masterKey, masterSalt, indexOverKdr, len(masterKey))
	if err != nil {
		return nil, err
	} else if keys.srtpBlock, err = aes.NewCipher(srtpSessionKey); err != nil {
		return nil, err
	}

	srtcpSessionKey, err := aesCmKeyDerivation(labelSRTCPEncryption, masterKey, masterSalt, indexOverKdr, len(masterKey))
	if err != nil {
		return nil, err
	} else if keys.srtcpBlock, err = aes.NewCipher(srtcpSessionKey); err != nil {
		return nil, err
	}

	if keys.srtpSessionSalt, err = aesCmKeyDerivation(
		labelSRTPSalt, masterKey, masterSalt, indexOverKdr, len(masterSalt),
	); err != nil {
		return nil, err
	} else if keys.srtcpSessionSalt, err = aesCmKeyDerivation(
		labelSRTCPSalt, masterKey, masterSalt, indexOverKdr, len(masterSalt),
	); err != nil {
		return nil, err
	}

	authKeyLen, err := profile.AuthKeyLen()
	if err != nil {
		return nil, err
	}

	srtpSessionAuthTag, err := aesCmKeyDerivation(
		labelSRTPAuthenticationTag, masterKey, masterSalt, indexOverKdr, authKeyLen,
	)
	if err != nil {
		return nil, err
	}

	srtcpSessionAuthTag, err := aesCmKeyDerivation(
		labelSRTCPAuthenticationTag, masterKey, masterSalt, indexOverKdr, authKeyLen,
	)
	if err != nil {
		return nil, err
	}

	keys.srtcpSessionAuth = hmac.New(sha1.New, srtcpSessionAuthTag)
	keys.srtpSessionAuth = hmac.New(sha1.New, srtpSessionAuthTag)

	return keys, nil
}

type srtpCipherAesCmHmacSha1 struct {
	protectionProfileWithArgs

	// Master key material used to derive session keys lazily for every key
	// derivation index. Both are nil when the cipher was built directly from
	// pre-derived session keys (test vectors); in that case only the r == 0
	// key set exists.
	masterKey, masterSalt []byte

	// Session key sets keyed by the RTP/SRTCP key derivation index r. RTP and
	// RTCP use separate caches because their packet indices (and therefore r)
	// advance independently. Caching every seen r is what allows out-of-order
	// packets and packets inside the replay window to be processed with the
	// keys they were originally protected with.
	srtpDerivedKeys  map[uint64]*srtpAesCmHmacSha1Keys
	srtcpDerivedKeys map[uint64]*srtpAesCmHmacSha1Keys

	srtpEncrypted  bool
	srtcpEncrypted bool

	mki []byte

	useCryptex bool

	// Pre-allocated buffers for auth tag to avoid heap allocation in hot path.
	authBuf     [4 + sha1.Size]byte // 4 bytes ROC + 20 bytes SHA1
	rtcpAuthBuf [sha1.Size]byte
}

func (s *srtpCipherAesCmHmacSha1) setCryptex(useCryptex bool) {
	s.useCryptex = useCryptex
}

//nolint:cyclop
func newSrtpCipherAesCmHmacSha1(
	profile protectionProfileWithArgs,
	masterKey, masterSalt, mki []byte,
	encryptSRTP, encryptSRTCP, useCryptex bool,
) (*srtpCipherAesCmHmacSha1, error) {
	switch profile.ProtectionProfile {
	case ProtectionProfileNullHmacSha1_80, ProtectionProfileNullHmacSha1_32:
		encryptSRTP = false
		encryptSRTCP = false
	default:
	}

	srtpCipher := &srtpCipherAesCmHmacSha1{
		protectionProfileWithArgs: profile,
		masterKey:                 append([]byte{}, masterKey...),
		masterSalt:                append([]byte{}, masterSalt...),
		srtpDerivedKeys:           map[uint64]*srtpAesCmHmacSha1Keys{},
		srtcpDerivedKeys:          map[uint64]*srtpAesCmHmacSha1Keys{},
		srtpEncrypted:             encryptSRTP,
		srtcpEncrypted:            encryptSRTCP,
		useCryptex:                useCryptex,
	}

	// The initial key derivation (r == 0) is REQUIRED by RFC 3711 section 4.3.1
	// and is the only key set ever used when the key derivation rate is zero.
	initialKeys, err := deriveSrtpAesCmHmacSha1Keys(profile, masterKey, masterSalt, 0)
	if err != nil {
		return nil, err
	}
	srtpCipher.srtpDerivedKeys[0] = initialKeys
	srtpCipher.srtcpDerivedKeys[0] = initialKeys

	mkiLen := len(mki)
	if mkiLen > 0 {
		srtpCipher.mki = make([]byte, mkiLen)
		copy(srtpCipher.mki, mki)
	}

	return srtpCipher, nil
}

// srtpKeys returns the AES-CM/HMAC-SHA1 session key set for the given RTP key
// derivation index, deriving and caching it on first use.
func (s *srtpCipherAesCmHmacSha1) srtpKeys(indexOverKdr uint64) (*srtpAesCmHmacSha1Keys, error) {
	if keys, ok := s.srtpDerivedKeys[indexOverKdr]; ok {
		return keys, nil
	}

	keys, err := deriveSrtpAesCmHmacSha1Keys(s.protectionProfileWithArgs, s.masterKey, s.masterSalt, indexOverKdr)
	if err != nil {
		return nil, err
	}
	s.srtpDerivedKeys[indexOverKdr] = keys

	return keys, nil
}

// srtcpKeys returns the AES-CM/HMAC-SHA1 session key set for the given SRTCP
// key derivation index, deriving and caching it on first use.
func (s *srtpCipherAesCmHmacSha1) srtcpKeys(indexOverKdr uint64) (*srtpAesCmHmacSha1Keys, error) {
	if keys, ok := s.srtcpDerivedKeys[indexOverKdr]; ok {
		return keys, nil
	}

	keys, err := deriveSrtpAesCmHmacSha1Keys(s.protectionProfileWithArgs, s.masterKey, s.masterSalt, indexOverKdr)
	if err != nil {
		return nil, err
	}
	s.srtcpDerivedKeys[indexOverKdr] = keys

	return keys, nil
}

func (s *srtpCipherAesCmHmacSha1) encryptRTP(
	dst []byte,
	header *rtp.Header,
	headerLen int,
	plaintext []byte,
	roc uint32,
	indexOverKdr uint64,
	rocInAuthTag bool,
) (ciphertext []byte, err error) {
	keys, err := s.srtpKeys(indexOverKdr)
	if err != nil {
		return nil, err
	}

	// Grow the given buffer to fit the output.
	authTagLen, err := s.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}
	payloadLen := len(plaintext) - headerLen
	dstLen := headerLen + payloadLen + len(s.mki) + authTagLen

	insertEmptyExtHdr := needsEmptyExtensionHeader(s.useCryptex, header)
	if insertEmptyExtHdr {
		dstLen += extensionHeaderSize
	}

	dst = growBufferSize(dst, dstLen)
	sameBuffer := isSameBuffer(dst, plaintext)

	if insertEmptyExtHdr {
		// Insert an empty extension header to plaintext using dst buffer. After this operation dst is used as the
		// plaintext buffer for next operations.
		plaintext = insertEmptyExtensionHeader(dst, plaintext, sameBuffer, header)
		sameBuffer = true
		headerLen += extensionHeaderSize
	}

	if err = s.doEncryptRTP(keys, dst, header, headerLen, plaintext, roc, rocInAuthTag, sameBuffer, payloadLen); err != nil {
		return nil, err
	}

	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1) doEncryptRTP(keys *srtpAesCmHmacSha1Keys, dst []byte, header *rtp.Header,
	headerLen int, plaintext []byte, roc uint32, rocInAuthTag bool, sameBuffer bool, payloadLen int,
) error {
	encrypt := func(dst, plaintext []byte, headerLen int) error {
		counter := generateCounter(header.SequenceNumber, roc, header.SSRC, keys.srtpSessionSalt)

		return xorBytesCTR(keys.srtpBlock, counter[:], dst[headerLen:], plaintext[headerLen:])
	}

	var err error
	switch {
	case s.useCryptex && header.Extension:
		err = encryptCryptexRTP(dst, plaintext, sameBuffer, header, encrypt)
	case s.srtpEncrypted:
		// Copy the header unencrypted.
		if !sameBuffer {
			copy(dst, plaintext[:headerLen])
		}
		// Encrypt the payload
		err = encrypt(dst, plaintext, headerLen)
	case !sameBuffer:
		copy(dst, plaintext)
	default:
	}
	if err != nil {
		return err
	}
	n := headerLen + payloadLen

	// Generate the auth tag.
	authTag, err := s.generateSrtpAuthTag(keys, dst[:n], roc, rocInAuthTag)
	if err != nil {
		return err
	}

	// Append the MKI (if used)
	if len(s.mki) > 0 {
		copy(dst[n:], s.mki)
		n += len(s.mki)
	}

	// Write the auth tag to the dest.
	copy(dst[n:], authTag)

	return nil
}

func (s *srtpCipherAesCmHmacSha1) decryptRTP(
	dst, ciphertext []byte,
	header *rtp.Header,
	headerLen int,
	roc uint32,
	indexOverKdr uint64,
	rocInAuthTag bool,
) ([]byte, error) {
	keys, err := s.srtpKeys(indexOverKdr)
	if err != nil {
		return nil, err
	}

	// Split the auth tag and the cipher text into two parts.
	authTagLen, err := s.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}

	// Split the auth tag and the cipher text into two parts.
	actualTag := ciphertext[len(ciphertext)-authTagLen:]
	ciphertext = ciphertext[:len(ciphertext)-len(s.mki)-authTagLen]

	// Generate the auth tag we expect to see from the ciphertext.
	expectedTag, err := s.generateSrtpAuthTag(keys, ciphertext, roc, rocInAuthTag)
	if err != nil {
		return nil, err
	}

	// See if the auth tag actually matches.
	// We use a constant time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare(actualTag, expectedTag) != 1 {
		return nil, ErrFailedToVerifyAuthTag
	}

	sameBuffer := isSameBuffer(dst, ciphertext)

	if err = s.doDecryptRTP(keys, dst, ciphertext, header, headerLen, roc, sameBuffer); err != nil {
		return nil, err
	}

	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1) doDecryptRTP(keys *srtpAesCmHmacSha1Keys, dst, ciphertext []byte, header *rtp.Header,
	headerLen int, roc uint32, sameBuffer bool,
) error {
	decrypt := func(dst, ciphertext []byte, headerLen int) error {
		counter := generateCounter(header.SequenceNumber, roc, header.SSRC, keys.srtpSessionSalt)

		return xorBytesCTR(keys.srtpBlock, counter[:], dst[headerLen:], ciphertext[headerLen:])
	}

	switch {
	case isCryptexPacket(header):
		err := decryptCryptexRTP(dst, ciphertext, sameBuffer, header, headerLen, decrypt)
		if err != nil {
			return err
		}
	case s.srtpEncrypted:
		// Write the plaintext header to the destination buffer.
		if !sameBuffer {
			copy(dst, ciphertext[:headerLen])
		}

		// Decrypt the ciphertext for the payload.
		err := decrypt(dst, ciphertext, headerLen)
		if err != nil {
			return err
		}
	case !sameBuffer:
		copy(dst, ciphertext)
	default:
	}

	return nil
}

func (s *srtpCipherAesCmHmacSha1) encryptRTCP(
	dst, decrypted []byte, srtcpIndex uint32, ssrc uint32, indexOverKdr uint64,
) ([]byte, error) {
	keys, err := s.srtcpKeys(indexOverKdr)
	if err != nil {
		return nil, err
	}

	authTagLen, err := s.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}
	mkiLen := len(s.mki)
	decryptedLen := len(decrypted)
	encryptedLen := decryptedLen + authTagLen + mkiLen + srtcpIndexSize

	dst = growBufferSize(dst, encryptedLen)
	sameBuffer := isSameBuffer(dst, decrypted)

	if !sameBuffer {
		copy(dst, decrypted[:srtcpHeaderSize]) // Copy the first 8 bytes (RTCP header)
	}

	// Encrypt everything after header
	if s.srtcpEncrypted {
		counter := generateCounter(uint16(srtcpIndex&0xffff), srtcpIndex>>16, ssrc, keys.srtcpSessionSalt) //nolint:gosec // G115
		if err = xorBytesCTR(keys.srtcpBlock, counter[:], dst[srtcpHeaderSize:], decrypted[srtcpHeaderSize:]); err != nil {
			return nil, err
		}

		// Add SRTCP Index and set Encryption bit
		binary.BigEndian.PutUint32(dst[decryptedLen:], srtcpIndex)
		dst[decryptedLen] |= srtcpEncryptionFlag
	} else {
		// Copy the decrypted payload as is
		if !sameBuffer {
			copy(dst[srtcpHeaderSize:], decrypted[srtcpHeaderSize:])
		}

		// Add SRTCP Index with Encryption bit cleared
		binary.BigEndian.PutUint32(dst[decryptedLen:], srtcpIndex)
	}

	n := decryptedLen + srtcpIndexSize

	// Generate the authentication tag
	authTag, err := s.generateSrtcpAuthTag(keys, dst[:n])
	if err != nil {
		return nil, err
	}

	// Include the MKI if provided
	if len(s.mki) > 0 {
		copy(dst[n:], s.mki)
		n += mkiLen
	}

	// Append the auth tag at the end of the buffer
	copy(dst[n:], authTag)

	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1) decryptRTCP(
	dst, encrypted []byte, index, ssrc uint32, indexOverKdr uint64,
) ([]byte, error) {
	keys, err := s.srtcpKeys(indexOverKdr)
	if err != nil {
		return nil, err
	}

	authTagLen, err := s.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}
	mkiLen := len(s.mki)
	encryptedLen := len(encrypted)
	decryptedLen := encryptedLen - (authTagLen + mkiLen + srtcpIndexSize)
	if decryptedLen < 8 {
		return nil, errTooShortRTCP
	}

	expectedTag, err := s.generateSrtcpAuthTag(keys, encrypted[:encryptedLen-mkiLen-authTagLen])
	if err != nil {
		return nil, err
	}

	actualTag := encrypted[encryptedLen-authTagLen:]
	if subtle.ConstantTimeCompare(actualTag, expectedTag) != 1 {
		return nil, ErrFailedToVerifyAuthTag
	}

	dst = growBufferSize(dst, decryptedLen)
	sameBuffer := isSameBuffer(dst, encrypted)

	if !sameBuffer {
		copy(dst, encrypted[:srtcpHeaderSize]) // Copy the first 8 bytes (RTCP header)
	}

	isEncrypted := encrypted[decryptedLen]&srtcpEncryptionFlag != 0
	if isEncrypted {
		counter := generateCounter(uint16(index&0xffff), index>>16, ssrc, keys.srtcpSessionSalt) //nolint:gosec // G115
		err = xorBytesCTR(keys.srtcpBlock, counter[:], dst[srtcpHeaderSize:], encrypted[srtcpHeaderSize:decryptedLen])
	} else if !sameBuffer {
		copy(dst[srtcpHeaderSize:], encrypted[srtcpHeaderSize:])
	}

	return dst, err
}

func (s *srtpCipherAesCmHmacSha1) generateSrtpAuthTag(keys *srtpAesCmHmacSha1Keys, buf []byte, roc uint32,
	rocInAuthTag bool,
) ([]byte, error) {
	// https://tools.ietf.org/html/rfc3711#section-4.2
	// In the case of SRTP, M SHALL consist of the Authenticated
	// Portion of the packet (as specified in Figure 1) concatenated with
	// the ROC, M = Authenticated Portion || ROC;
	//
	// The pre-defined authentication transform for SRTP is HMAC-SHA1
	// [RFC2104].  With HMAC-SHA1, the SRTP_PREFIX_LENGTH (Figure 3) SHALL
	// be 0.  For SRTP (respectively SRTCP), the HMAC SHALL be applied to
	// the session authentication key and M as specified above, i.e.,
	// HMAC(k_a, M).  The HMAC output SHALL then be truncated to the n_tag
	// left-most bits.
	// - Authenticated portion of the packet is everything BEFORE MKI
	// - k_a is the session message authentication key
	// - n_tag is the bit-length of the output authentication tag
	keys.srtpSessionAuth.Reset()

	if _, err := keys.srtpSessionAuth.Write(buf); err != nil {
		return nil, err
	}

	// For SRTP only, we need to hash the rollover counter as well.
	binary.BigEndian.PutUint32(s.authBuf[:4], roc)

	_, err := keys.srtpSessionAuth.Write(s.authBuf[:4])
	if err != nil {
		return nil, err
	}

	// Truncate the hash to the size indicated by the profile
	authTagLen, err := s.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}

	// Use pre-allocated buffer to avoid allocation in Sum().
	// When rocInAuthTag is true, we prepend the ROC (4 bytes) before the hash.
	var authTag []byte
	if rocInAuthTag {
		// ROC is already in buffer at [0:4], Sum will append hash starting at offset 4
		authTag = keys.srtpSessionAuth.Sum(s.authBuf[:4])[:authTagLen]
	} else {
		// No ROC prefix, Sum appends hash starting at offset 0
		authTag = keys.srtpSessionAuth.Sum(s.authBuf[:0])[:authTagLen]
	}

	return authTag, nil
}

func (s *srtpCipherAesCmHmacSha1) generateSrtcpAuthTag(keys *srtpAesCmHmacSha1Keys, buf []byte) ([]byte, error) {
	// https://tools.ietf.org/html/rfc3711#section-4.2
	//
	// The pre-defined authentication transform for SRTP is HMAC-SHA1
	// [RFC2104].  With HMAC-SHA1, the SRTP_PREFIX_LENGTH (Figure 3) SHALL
	// be 0.  For SRTP (respectively SRTCP), the HMAC SHALL be applied to
	// the session authentication key and M as specified above, i.e.,
	// HMAC(k_a, M).  The HMAC output SHALL then be truncated to the n_tag
	// left-most bits.
	// - Authenticated portion of the packet is everything BEFORE MKI
	// - k_a is the session message authentication key
	// - n_tag is the bit-length of the output authentication tag
	keys.srtcpSessionAuth.Reset()

	if _, err := keys.srtcpSessionAuth.Write(buf); err != nil {
		return nil, err
	}
	authTagLen, err := s.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}

	// Use pre-allocated buffer to avoid allocation in Sum()
	return keys.srtcpSessionAuth.Sum(s.rtcpAuthBuf[:0])[:authTagLen], nil
}

func (s *srtpCipherAesCmHmacSha1) getRTCPIndex(in []byte) uint32 {
	authTagLen, _ := s.AuthTagRTCPLen()
	tailOffset := len(in) - (authTagLen + srtcpIndexSize + len(s.mki))
	srtcpIndexBuffer := in[tailOffset : tailOffset+srtcpIndexSize]

	return binary.BigEndian.Uint32(srtcpIndexBuffer) &^ (1 << 31)
}
