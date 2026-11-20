// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/pion/rtp"
)

// srtpAeadAesGcmKeys is the set of AES-GCM session keys derived for one
// key derivation index r = packet index DIV key derivation rate.
type srtpAeadAesGcmKeys struct {
	srtpCipher, srtcpCipher cipher.AEAD

	srtpSessionSalt, srtcpSessionSalt []byte
}

// deriveSrtpAeadAesGcmKeys derives the complete AES-GCM session key set for
// the given key derivation index r from the master key and salt, following
// RFC 3711 section 4.3 and RFC 7714.
func deriveSrtpAeadAesGcmKeys(masterKey, masterSalt []byte, indexOverKdr uint64) (*srtpAeadAesGcmKeys, error) {
	keys := &srtpAeadAesGcmKeys{}

	srtpSessionKey, err := aesCmKeyDerivation(labelSRTPEncryption, masterKey, masterSalt, indexOverKdr, len(masterKey))
	if err != nil {
		return nil, err
	}

	srtpBlock, err := aes.NewCipher(srtpSessionKey)
	if err != nil {
		return nil, err
	}

	if keys.srtpCipher, err = cipher.NewGCM(srtpBlock); err != nil {
		return nil, err
	}

	srtcpSessionKey, err := aesCmKeyDerivation(labelSRTCPEncryption, masterKey, masterSalt, indexOverKdr, len(masterKey))
	if err != nil {
		return nil, err
	}

	srtcpBlock, err := aes.NewCipher(srtcpSessionKey)
	if err != nil {
		return nil, err
	}

	if keys.srtcpCipher, err = cipher.NewGCM(srtcpBlock); err != nil {
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

	return keys, nil
}

type srtpCipherAeadAesGcm struct {
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
	srtpDerivedKeys  map[uint64]*srtpAeadAesGcmKeys
	srtcpDerivedKeys map[uint64]*srtpAeadAesGcmKeys

	mki []byte

	srtpEncrypted, srtcpEncrypted bool

	useCryptex bool

	// Pre-allocated buffers for IV and AAD to avoid heap allocation in hot path
	rtpIV   [12]byte
	rtcpIV  [12]byte
	rtcpAAD [12]byte
}

func (s *srtpCipherAeadAesGcm) setCryptex(useCryptex bool) {
	s.useCryptex = useCryptex
}

func newSrtpCipherAeadAesGcm(
	profile protectionProfileWithArgs,
	masterKey, masterSalt, mki []byte,
	encryptSRTP, encryptSRTCP, useCryptex bool,
) (*srtpCipherAeadAesGcm, error) {
	srtpCipher := &srtpCipherAeadAesGcm{
		protectionProfileWithArgs: profile,
		masterKey:                 append([]byte{}, masterKey...),
		masterSalt:                append([]byte{}, masterSalt...),
		srtpDerivedKeys:           map[uint64]*srtpAeadAesGcmKeys{},
		srtcpDerivedKeys:          map[uint64]*srtpAeadAesGcmKeys{},
		srtpEncrypted:             encryptSRTP,
		srtcpEncrypted:            encryptSRTCP,
		useCryptex:                useCryptex,
	}

	// The initial key derivation (r == 0) is REQUIRED by RFC 3711 section 4.3.1
	// and is the only key set ever used when the key derivation rate is zero.
	initialKeys, err := deriveSrtpAeadAesGcmKeys(masterKey, masterSalt, 0)
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

// srtpKeys returns the AES-GCM session key set for the given RTP key
// derivation index, deriving and caching it on first use.
func (s *srtpCipherAeadAesGcm) srtpKeys(indexOverKdr uint64) (*srtpAeadAesGcmKeys, error) {
	if keys, ok := s.srtpDerivedKeys[indexOverKdr]; ok {
		return keys, nil
	}

	keys, err := deriveSrtpAeadAesGcmKeys(s.masterKey, s.masterSalt, indexOverKdr)
	if err != nil {
		return nil, err
	}
	s.srtpDerivedKeys[indexOverKdr] = keys

	return keys, nil
}

// srtcpKeys returns the AES-GCM session key set for the given SRTCP key
// derivation index, deriving and caching it on first use.
func (s *srtpCipherAeadAesGcm) srtcpKeys(indexOverKdr uint64) (*srtpAeadAesGcmKeys, error) {
	if keys, ok := s.srtcpDerivedKeys[indexOverKdr]; ok {
		return keys, nil
	}

	keys, err := deriveSrtpAeadAesGcmKeys(s.masterKey, s.masterSalt, indexOverKdr)
	if err != nil {
		return nil, err
	}
	s.srtcpDerivedKeys[indexOverKdr] = keys

	return keys, nil
}

func (s *srtpCipherAeadAesGcm) encryptRTP(
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
	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	payloadLen := len(plaintext) - headerLen
	authPartLen := headerLen + payloadLen + authTagLen
	dstLen := authPartLen + len(s.mki)
	if rocInAuthTag {
		dstLen += 4
	}

	insertEmptyExtHdr := needsEmptyExtensionHeader(s.useCryptex, header)
	if insertEmptyExtHdr {
		dstLen += extensionHeaderSize
	}

	dst = growBufferSize(dst, dstLen)
	sameBuffer := isSameBuffer(dst, plaintext)

	if insertEmptyExtHdr {
		plaintext = insertEmptyExtensionHeader(dst, plaintext, sameBuffer, header)
		sameBuffer = true
		headerLen += extensionHeaderSize
	}

	if err = s.doEncryptRTP(
		keys, dst, header, headerLen, plaintext, roc, rocInAuthTag, sameBuffer, payloadLen, authPartLen,
	); err != nil {
		return nil, err
	}

	return dst, nil
}

func (s *srtpCipherAeadAesGcm) doEncryptRTP(keys *srtpAeadAesGcmKeys, dst []byte, header *rtp.Header,
	headerLen int, plaintext []byte, roc uint32, rocInAuthTag bool, sameBuffer bool, payloadLen int, authPartLen int,
) error {
	s.rtpInitializationVector(keys, header, roc)
	encrypt := func(dst, plaintext []byte, headerLen int) error {
		keys.srtpCipher.Seal(dst[headerLen:headerLen], s.rtpIV[:], plaintext[headerLen:], plaintext[:headerLen])

		return nil
	}

	switch {
	case s.useCryptex && header.Extension:
		err := encryptCryptexRTP(dst, plaintext, sameBuffer, header, encrypt)
		if err != nil {
			return err
		}
	case s.srtpEncrypted:
		// Copy the header unencrypted.
		if !sameBuffer {
			copy(dst, plaintext[:headerLen])
		}
		keys.srtpCipher.Seal(dst[headerLen:headerLen], s.rtpIV[:], plaintext[headerLen:], dst[:headerLen])
	default:
		clearLen := headerLen + payloadLen
		if !sameBuffer {
			copy(dst, plaintext)
		}
		keys.srtpCipher.Seal(dst[clearLen:clearLen], s.rtpIV[:], nil, dst[:clearLen])
	}

	// Add MKI after the encrypted payload
	if len(s.mki) > 0 {
		copy(dst[authPartLen:], s.mki)
	}

	if rocInAuthTag {
		binary.BigEndian.PutUint32(dst[len(dst)-4:], roc)
	}

	return nil
}

func (s *srtpCipherAeadAesGcm) decryptRTP(
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

	// Grow the given buffer to fit the output.
	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	rocLen := 0
	if rocInAuthTag {
		rocLen = 4
	}
	nDst := len(ciphertext) - authTagLen - len(s.mki) - rocLen
	if nDst < headerLen {
		// Size of ciphertext is shorter than AEAD auth tag len.
		return nil, ErrFailedToVerifyAuthTag
	}
	dst = growBufferSize(dst, nDst)
	sameBuffer := isSameBuffer(dst, ciphertext)

	nEnd := len(ciphertext) - len(s.mki) - rocLen

	if err = s.doDecryptRTP(keys, dst, ciphertext, header, headerLen, roc, sameBuffer, nEnd, authTagLen); err != nil {
		return nil, err
	}

	return dst, nil
}

func (s *srtpCipherAeadAesGcm) doDecryptRTP(keys *srtpAeadAesGcmKeys, dst, ciphertext []byte, header *rtp.Header,
	headerLen int, roc uint32, sameBuffer bool, nEnd int, authTagLen int,
) error {
	s.rtpInitializationVector(keys, header, roc)
	decrypt := func(dst, ciphertext []byte, headerLen int) error {
		_, err := keys.srtpCipher.Open(dst[headerLen:headerLen], s.rtpIV[:], ciphertext[headerLen:nEnd], ciphertext[:headerLen])

		return err
	}

	switch {
	case isCryptexPacket(header):
		err := decryptCryptexRTP(dst, ciphertext, sameBuffer, header, headerLen, decrypt)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
	case s.srtpEncrypted:
		if err := decrypt(dst, ciphertext[:nEnd], headerLen); err != nil {
			return fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		// Copy the header unencrypted.
		if !sameBuffer {
			copy(dst[:headerLen], ciphertext[:headerLen])
		}
	default:
		nDataEnd := nEnd - authTagLen
		if _, err := keys.srtpCipher.Open(
			nil, s.rtpIV[:], ciphertext[nDataEnd:nEnd], ciphertext[:nDataEnd],
		); err != nil {
			return fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		// Copy the header and payload unencrypted.
		if !sameBuffer {
			copy(dst, ciphertext[:nDataEnd])
		}
	}

	return nil
}

func (s *srtpCipherAeadAesGcm) encryptRTCP(
	dst, decrypted []byte, srtcpIndex uint32, ssrc uint32, indexOverKdr uint64,
) ([]byte, error) {
	keys, err := s.srtcpKeys(indexOverKdr)
	if err != nil {
		return nil, err
	}

	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	aadPos := len(decrypted) + authTagLen
	// Grow the given buffer to fit the output.
	dst = growBufferSize(dst, aadPos+srtcpIndexSize+len(s.mki))
	sameBuffer := isSameBuffer(dst, decrypted)

	s.rtcpInitializationVector(keys, srtcpIndex, ssrc)
	if s.srtcpEncrypted {
		s.rtcpAAD = s.rtcpAdditionalAuthenticatedData(decrypted, srtcpIndex)
		if !sameBuffer {
			// Copy the header unencrypted.
			copy(dst[:srtcpHeaderSize], decrypted[:srtcpHeaderSize])
		}
		// Copy index to the proper place.
		copy(dst[aadPos:aadPos+srtcpIndexSize], s.rtcpAAD[8:12])
		keys.srtcpCipher.Seal(dst[srtcpHeaderSize:srtcpHeaderSize], s.rtcpIV[:], decrypted[srtcpHeaderSize:], s.rtcpAAD[:])
	} else {
		// Copy the packet unencrypted.
		if !sameBuffer {
			copy(dst, decrypted)
		}
		// Append the SRTCP index to the end of the packet - this will form the AAD.
		binary.BigEndian.PutUint32(dst[len(decrypted):], srtcpIndex)
		// Generate the authentication tag.
		tag := make([]byte, authTagLen)
		keys.srtcpCipher.Seal(tag[0:0], s.rtcpIV[:], nil, dst[:len(decrypted)+srtcpIndexSize])
		// Copy index to the proper place.
		copy(dst[aadPos:], dst[len(decrypted):len(decrypted)+srtcpIndexSize])
		// Copy the auth tag after RTCP payload.
		copy(dst[len(decrypted):], tag)
	}

	copy(dst[aadPos+srtcpIndexSize:], s.mki)

	return dst, nil
}

func (s *srtpCipherAeadAesGcm) decryptRTCP(
	dst, encrypted []byte, srtcpIndex, ssrc uint32, indexOverKdr uint64,
) ([]byte, error) {
	keys, err := s.srtcpKeys(indexOverKdr)
	if err != nil {
		return nil, err
	}

	aadPos := len(encrypted) - srtcpIndexSize - len(s.mki)
	// Grow the given buffer to fit the output.
	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	nDst := aadPos - authTagLen
	if nDst < 0 {
		// Size of ciphertext is shorter than AEAD auth tag len.
		return nil, ErrFailedToVerifyAuthTag
	}
	dst = growBufferSize(dst, nDst)
	sameBuffer := isSameBuffer(dst, encrypted)

	isEncrypted := encrypted[aadPos]&srtcpEncryptionFlag != 0
	s.rtcpInitializationVector(keys, srtcpIndex, ssrc)
	if isEncrypted {
		s.rtcpAAD = s.rtcpAdditionalAuthenticatedData(encrypted, srtcpIndex)
		if _, err := keys.srtcpCipher.Open(dst[srtcpHeaderSize:srtcpHeaderSize], s.rtcpIV[:], encrypted[srtcpHeaderSize:aadPos],
			s.rtcpAAD[:]); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
	} else {
		// Prepare AAD for received packet.
		dataEnd := aadPos - authTagLen
		aad := make([]byte, dataEnd+4)
		copy(aad, encrypted[:dataEnd])
		copy(aad[dataEnd:], encrypted[aadPos:aadPos+4])
		// Verify the auth tag.
		if _, err := keys.srtcpCipher.Open(nil, s.rtcpIV[:], encrypted[dataEnd:aadPos], aad); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		// Copy the unencrypted payload.
		if !sameBuffer {
			copy(dst[srtcpHeaderSize:], encrypted[srtcpHeaderSize:dataEnd])
		}
	}

	// Copy the header unencrypted.
	if !sameBuffer {
		copy(dst[:srtcpHeaderSize], encrypted[:srtcpHeaderSize])
	}

	return dst, nil
}

// The 12-octet IV used by AES-GCM SRTP is formed by first concatenating
// 2 octets of zeroes, the 4-octet SSRC, the 4-octet rollover counter
// (ROC), and the 2-octet sequence number (SEQ).  The resulting 12-octet
// value is then XORed to the 12-octet salt to form the 12-octet IV.
//
// https://tools.ietf.org/html/rfc7714#section-8.1
func (s *srtpCipherAeadAesGcm) rtpInitializationVector(keys *srtpAeadAesGcmKeys, header *rtp.Header, roc uint32) {
	s.rtpIV = [12]byte{}
	binary.BigEndian.PutUint32(s.rtpIV[2:], header.SSRC)
	binary.BigEndian.PutUint32(s.rtpIV[6:], roc)
	binary.BigEndian.PutUint16(s.rtpIV[10:], header.SequenceNumber)

	for i := range s.rtpIV {
		s.rtpIV[i] ^= keys.srtpSessionSalt[i]
	}
}

// The 12-octet IV used by AES-GCM SRTCP is formed by first
// concatenating 2 octets of zeroes, the 4-octet SSRC identifier,
// 2 octets of zeroes, a single "0" bit, and the 31-bit SRTCP index.
// The resulting 12-octet value is then XORed to the 12-octet salt to
// form the 12-octet IV.
//
// https://tools.ietf.org/html/rfc7714#section-9.1
func (s *srtpCipherAeadAesGcm) rtcpInitializationVector(keys *srtpAeadAesGcmKeys, srtcpIndex uint32, ssrc uint32) {
	s.rtcpIV = [12]byte{}
	binary.BigEndian.PutUint32(s.rtcpIV[2:], ssrc)
	binary.BigEndian.PutUint32(s.rtcpIV[8:], srtcpIndex)

	for i := range s.rtcpIV {
		s.rtcpIV[i] ^= keys.srtcpSessionSalt[i]
	}
}

// In an SRTCP packet, a 1-bit Encryption flag is prepended to the
// 31-bit SRTCP index to form a 32-bit value we shall call the
// "ESRTCP word"
//
// https://tools.ietf.org/html/rfc7714#section-17
func (s *srtpCipherAeadAesGcm) rtcpAdditionalAuthenticatedData(rtcpPacket []byte, srtcpIndex uint32) [12]byte {
	var aad [12]byte

	copy(aad[:], rtcpPacket[:8])
	binary.BigEndian.PutUint32(aad[8:], srtcpIndex)
	aad[8] |= srtcpEncryptionFlag

	return aad
}

func (s *srtpCipherAeadAesGcm) getRTCPIndex(in []byte) uint32 {
	return binary.BigEndian.Uint32(in[len(in)-len(s.mki)-srtcpIndexSize:]) &^ (srtcpEncryptionFlag << 24)
}
