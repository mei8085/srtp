// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"github.com/pion/transport/v5/replaydetector"
)

// ContextOption configures a Context using the functional options pattern.
//
// Context options are primarily intended to be passed to CreateContext during construction.
// Whether an option may also be applied to an already-constructed Context depends on that
// option's documentation; options that do not support runtime updates return
// ErrContextOptionNotUpdatable.
type ContextOption func(*Context) error

// SRTPReplayProtection sets SRTP replay protection window size.
func SRTPReplayProtection(windowSize uint) ContextOption { // nolint:revive
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.newSRTPReplayDetector = func() replaydetector.ReplayDetector {
			return replaydetector.New(windowSize, maxROC<<16|maxSequenceNumber)
		}

		return nil
	}
}

// SRTCPReplayProtection sets SRTCP replay protection window size.
func SRTCPReplayProtection(windowSize uint) ContextOption {
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.newSRTCPReplayDetector = func() replaydetector.ReplayDetector {
			return replaydetector.New(windowSize, maxSRTCPIndex)
		}

		return nil
	}
}

// SRTPNoReplayProtection disables SRTP replay protection.
func SRTPNoReplayProtection() ContextOption { // nolint:revive
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.newSRTPReplayDetector = func() replaydetector.ReplayDetector {
			return &nopReplayDetector{}
		}

		return nil
	}
}

// SRTCPNoReplayProtection disables SRTCP replay protection.
func SRTCPNoReplayProtection() ContextOption {
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.newSRTCPReplayDetector = func() replaydetector.ReplayDetector {
			return &nopReplayDetector{}
		}

		return nil
	}
}

// SRTPReplayDetectorFactory sets custom SRTP replay detector.
func SRTPReplayDetectorFactory(fn func() replaydetector.ReplayDetector) ContextOption { // nolint:revive
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.newSRTPReplayDetector = fn

		return nil
	}
}

// SRTCPReplayDetectorFactory sets custom SRTCP replay detector.
func SRTCPReplayDetectorFactory(fn func() replaydetector.ReplayDetector) ContextOption {
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.newSRTCPReplayDetector = fn

		return nil
	}
}

type nopReplayDetector struct{}

func (s *nopReplayDetector) Check(uint64) (func() bool, bool) {
	return func() bool { return true }, true
}

// MasterKeyIndicator sets RTP/RTCP MKI for the initial master key. Array passed as an argument will be
// copied as-is to encrypted SRTP/SRTCP packets, so it must be of proper length and in Big Endian format.
// All MKIs added later using Context.AddCipherForMKI must have the same length as the one used here.
func MasterKeyIndicator(mki []byte) ContextOption {
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		if len(mki) > 0 {
			c.sendMKI = make([]byte, len(mki))
			copy(c.sendMKI, mki)
		}

		return nil
	}
}

// SRTPEncryption enables SRTP encryption.
func SRTPEncryption() ContextOption { // nolint:revive
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.encryptSRTP = true

		return nil
	}
}

// SRTPNoEncryption disables SRTP encryption.
// This option is useful when you want to use NullCipher for SRTP and keep authentication only.
// It simplifies debugging and testing, but it is not recommended for production use.
//
// Note: you can also use SRTPAuthenticationTagLength(0) to disable authentication tag too.
func SRTPNoEncryption() ContextOption { // nolint:revive
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.encryptSRTP = false

		return nil
	}
}

// SRTCPEncryption enables SRTCP encryption.
func SRTCPEncryption() ContextOption {
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.encryptSRTCP = true

		return nil
	}
}

// SRTCPNoEncryption disables SRTCP encryption.
// This option is useful when you want to use NullCipher for SRTCP and keep authentication only.
// It simplifies debugging and testing, but it is not recommended for production use.
func SRTCPNoEncryption() ContextOption {
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.encryptSRTCP = false

		return nil
	}
}

// RolloverCounterCarryingTransform enables Rollover Counter Carrying Transform from RFC 4771.
// ROC value is sent in Authentication Tag of SRTP packets every rocTransmitRate packets.
//
// RFC 4771 defines 3 RCC modes. pion/srtp supports mode RCCm2 for AES-CM and NULL profiles,
// and mode RCCm3 for AES-GCM (AEAD) profiles.
//
// From RFC 4771: "[For modes RCCm1 and and RCCm3] the length of the MAC is shorter than the length
// of the authentication tag. To achieve the same (or less) MAC forgery success probability on all
// packets when using RCCm1 or RCCm2, as with the default integrity transform in RFC 3711,
// the tag-length must be set to 14 octets, which means that the length of MAC_tr is 10 octets."
//
// Protection profiles ProtectionProfile*CmHmacSha1_32 uses 4-byte SRTP auth tag, so in RCCm2 mode
// SRTP packets with ROC will not be integrity protected.
//
// You can increase the length of the authentication tag using SRTPAuthenticationTagLength option
// to mitigate this issue.
func RolloverCounterCarryingTransform(mode RCCMode, rocTransmitRate uint16) ContextOption {
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.rccMode = mode
		c.rocTransmitRate = rocTransmitRate

		return nil
	}
}

// SRTPAuthenticationTagLength sets length of SRTP authentication tag in bytes for AES-CM protection
// profiles. Decreasing the length of the authentication tag is not recommended for production use,
// as it decreases integrity protection.
//
// Zero value means that there is no authentication tag, what may be useful for debugging and testing.
//
// This option is ignored for AEAD profiles.
func SRTPAuthenticationTagLength(authTagRTPLen int) ContextOption { // nolint:revive
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.authTagRTPLen = &authTagRTPLen

		return nil
	}
}

// KeyDerivationRate sets the SRTP/SRTCP key derivation rate (kdr) from
// RFC 3711 section 4.3.
//
// A zero rate (the default) keeps the legacy behavior: the session keys are
// derived once from the master key and used for the whole lifetime of the
// master key, so existing contexts and wire output stay unchanged.
//
// A non-zero rate enables periodic session key re-derivation. For every RTP
// or RTCP packet the derivation index r = packet index DIV kdr is computed
// from the direction's own packet index (the 48-bit ROC || SEQ index for
// SRTP, the 31-bit SRTCP index for SRTCP), and the session keys used to
// protect the packet are the keys derived for that r. RTP and RTCP maintain
// independent derivation state but apply the same boundary rules, so packets
// inside the replay window, index roll-overs and out-of-order packets always
// select the keys they were originally protected with. Both communication
// peers MUST configure the same rate: the sender and the receiver derive
// identical keys for identical (label, r) pairs.
//
// The rate MUST be kept fixed for the lifetime of the associated master key
// (RFC 3711 section 4.3.1), therefore this option can only be set during
// context construction. If r cannot be encoded in the 48-bit field of the
// key derivation input (for example because the packet index space has been
// exhausted), the offending packet is rejected with an error instead of
// being protected with an incorrect key.
func KeyDerivationRate(keyDerivationRate uint64) ContextOption {
	return func(c *Context) error {
		if c.constructed {
			return ErrContextOptionNotUpdatable
		}

		c.keyDerivationRate = keyDerivationRate

		return nil
	}
}

// Cryptex allows to enable Cryptex mechanism to completely encrypt RTP Header Extensions and Contributing
// Sources, as defined in RFC 9335.
func Cryptex(cryptexMode CryptexMode) ContextOption {
	return func(c *Context) error {
		c.cryptexMode = cryptexMode

		return nil
	}
}
