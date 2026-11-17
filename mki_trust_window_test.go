// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trustWindowProfiles covers one HMAC-SHA1 (AES-CM) and one AEAD (AES-GCM)
// profile so that both the MAC-based and the AEAD MKI parsing paths are
// exercised by the trust-window tests.
var trustWindowProfiles = []ProtectionProfile{profileCTR, profileGCM}

// trustKeyMaterial derives deterministic, pairwise distinct master keys and
// salts for the given profile and seed. Each seed in [1, 255] produces
// material different from every other seed, so two MKIs can never share an
// effective key within a test.
func trustKeyMaterial(t *testing.T, profile ProtectionProfile, seed byte) (masterKey, masterSalt []byte) {
	t.Helper()

	keyLen, err := profile.KeyLen()
	require.NoError(t, err)
	saltLen, err := profile.SaltLen()
	require.NoError(t, err)

	masterKey = make([]byte, keyLen)
	masterSalt = make([]byte, saltLen)
	for i := range masterKey {
		masterKey[i] = seed*7 + byte(i) //nolint:gosec // G115 test-only derivation, factors are coprime to 256
	}
	for i := range masterSalt {
		masterSalt[i] = seed*13 + byte(i)*3 //nolint:gosec // G115 test-only derivation, factors are coprime to 256
	}

	return masterKey, masterSalt
}

func trustRTPPacket(t *testing.T, ssrc uint32, sequenceNumber uint16) []byte {
	t.Helper()

	pkt := &rtp.Packet{
		Header:  rtp.Header{SSRC: ssrc, SequenceNumber: sequenceNumber, PayloadType: 96},
		Payload: append([]byte{}, rtpTestCaseDecrypted()...),
	}
	raw, err := pkt.Marshal()
	require.NoError(t, err)

	return raw
}

func trustRTCPPacket(t *testing.T, ssrc uint32) []byte {
	t.Helper()

	raw, err := (&rtcp.SenderReport{SSRC: ssrc}).Marshal()
	require.NoError(t, err)

	return raw
}

// newTrustSender builds an encryption-only context that holds every MKI used
// by the trust-window tests, so worker goroutines can own a private sender
// and switch its sending MKI without sharing state.
func newTrustSender(t *testing.T, profile ProtectionProfile,
	mki1, mki2, mki3, key1, salt1, key2, salt2, key3, salt3 []byte,
) *Context {
	t.Helper()

	sender, err := CreateContext(key1, salt1, profile, MasterKeyIndicator(mki1))
	require.NoError(t, err)
	require.NoError(t, sender.AddCipherForMKI(mki2, key2, salt2))
	require.NoError(t, sender.AddCipherForMKI(mki3, key3, salt3))

	return sender
}

// TestMKIRemovalRevokesTrust pins the boundary of the trust window on the
// receiving side: once an MKI is removed from the context, packets carrying
// that MKI can never authenticate again, regardless of whether the sequence
// number was previously seen. Re-adding the same MKI value only re-establishes
// trust for packets protected by the newly installed key; packets captured
// under the revoked key do not regain trust.
func TestMKIRemovalRevokesTrust(t *testing.T) {
	for _, profile := range trustWindowProfiles {
		t.Run(profile.String(), func(t *testing.T) {
			mki1 := []byte{0x01, 0x02, 0x03, 0x04}
			mki2 := []byte{0x02, 0x03, 0x04, 0x05}
			mki3 := []byte{0x03, 0x04, 0x05, 0x06}

			key1, salt1 := trustKeyMaterial(t, profile, 1)
			key2, salt2 := trustKeyMaterial(t, profile, 2)
			key3, salt3 := trustKeyMaterial(t, profile, 3)

			sender := newTrustSender(t, profile, mki1, mki2, mki3,
				key1, salt1, key2, salt2, key3, salt3)
			receiver, err := CreateContext(key1, salt1, profile,
				MasterKeyIndicator(mki1), SRTPReplayProtection(64))
			require.NoError(t, err)
			require.NoError(t, receiver.AddCipherForMKI(mki2, key2, salt2))

			// The MKI currently used for sending cannot be revoked: the
			// context must keep at least one usable sending key.
			assert.ErrorIs(t, receiver.RemoveMKI(mki1), errMKIAlreadyInUse)

			// Baseline: both MKIs are inside the trust window and authenticate.
			raw1 := trustRTPPacket(t, 5000, 1000)
			encryptedMKI1, err := sender.EncryptRTP(nil, raw1, nil)
			require.NoError(t, err)

			require.NoError(t, sender.SetSendMKI(mki2))
			raw2 := trustRTPPacket(t, 5000, 1001)
			encryptedMKI2, err := sender.EncryptRTP(nil, raw2, nil)
			require.NoError(t, err)

			decrypted, err := receiver.DecryptRTP(nil, encryptedMKI1, nil)
			require.NoError(t, err)
			assert.Equal(t, raw1, decrypted)
			decrypted, err = receiver.DecryptRTP(nil, encryptedMKI2, nil)
			require.NoError(t, err)
			assert.Equal(t, raw2, decrypted)

			// A duplicate of an accepted packet is rejected, and the replay
			// check runs before the MKI lookup so the result is errDuplicated
			// rather than ErrMKINotFound.
			_, err = receiver.DecryptRTP(nil, encryptedMKI1, nil)
			assert.ErrorIs(t, err, errDuplicated)

			// Move the receiver's sending MKI away from mki1 so the old key
			// can be revoked. Removing it closes the trust window for mki1:
			// the previously accepted ciphertext is now stale and must not
			// authenticate anymore, even though its sequence number is still
			// inside the replay window.
			require.NoError(t, receiver.SetSendMKI(mki2))
			require.NoError(t, receiver.RemoveMKI(mki1))

			// A never-seen sequence number under the revoked MKI still fails
			// at the MKI lookup: revocation wins over freshness.
			require.NoError(t, sender.SetSendMKI(mki1))
			raw3 := trustRTPPacket(t, 5000, 1002)
			staleNew, err := sender.EncryptRTP(nil, raw3, nil)
			require.NoError(t, err)
			_, err = receiver.DecryptRTP(nil, staleNew, nil)
			assert.ErrorIs(t, err, ErrMKINotFound)

			// The duplicate of an old packet remains rejected after revocation.
			_, err = receiver.DecryptRTP(nil, encryptedMKI1, nil)
			assert.ErrorIs(t, err, errDuplicated)

			// The other, still-allowed MKI continues to authenticate: removing
			// one key must not widen or narrow the trust window of another.
			require.NoError(t, sender.SetSendMKI(mki2))
			raw4 := trustRTPPacket(t, 5000, 1003)
			stillGood, err := sender.EncryptRTP(nil, raw4, nil)
			require.NoError(t, err)
			decrypted, err = receiver.DecryptRTP(nil, stillGood, nil)
			require.NoError(t, err)
			assert.Equal(t, raw4, decrypted)

			// Re-adding the same MKI value with a different key does not
			// resurrect old ciphertext: trust is bound to the concrete key,
			// not the MKI label.
			require.NoError(t, receiver.AddCipherForMKI(mki1, key3, salt3))

			_, err = receiver.DecryptRTP(nil, staleNew, nil)
			assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag)

			// A packet protected by the newly installed key for the MKI value
			// is trusted again.
			require.NoError(t, receiver.AddCipherForMKI(mki3, key3, salt3))
			require.NoError(t, sender.SetSendMKI(mki3))
			// sender's mki3 already carries key3, matching the re-added key.
			raw5 := trustRTPPacket(t, 5000, 1004)
			fresh, err := sender.EncryptRTP(nil, raw5, nil)
			require.NoError(t, err)
			decrypted, err = receiver.DecryptRTP(nil, fresh, nil)
			require.NoError(t, err)
			assert.Equal(t, raw5, decrypted)

			// The last remaining sending MKI cannot be removed, so a session
			// can never be left without any usable key.
			require.NoError(t, receiver.RemoveMKI(mki1))
			assert.ErrorIs(t, receiver.RemoveMKI(mki2), errMKIAlreadyInUse)
		})
	}
}

// TestRekeyOverlapTrustWindow drives a concurrent-session style rekey where
// the old and new keys briefly coexist. During the overlap, legitimate
// packets protected by either key must be accepted (including in-flight
// packets delivered out of order), while replayed and out-of-window packets
// stay rejected. After the old MKI is revoked, packets under it lose trust
// immediately; a newly added MKI is untrusted until explicitly installed.
func TestRekeyOverlapTrustWindow(t *testing.T) {
	const ssrc = uint32(5000)
	const window = uint(64)

	for _, profile := range trustWindowProfiles {
		t.Run(profile.String(), func(t *testing.T) {
			mki1 := []byte{0x01, 0x02, 0x03, 0x04}
			mki2 := []byte{0x02, 0x03, 0x04, 0x05}
			mki3 := []byte{0x03, 0x04, 0x05, 0x06}

			key1, salt1 := trustKeyMaterial(t, profile, 1)
			key2, salt2 := trustKeyMaterial(t, profile, 2)
			key3, salt3 := trustKeyMaterial(t, profile, 3)

			sender := newTrustSender(t, profile, mki1, mki2, mki3,
				key1, salt1, key2, salt2, key3, salt3)
			receiver, err := CreateContext(key1, salt1, profile,
				MasterKeyIndicator(mki1), SRTPReplayProtection(window))
			require.NoError(t, err)
			require.NoError(t, receiver.AddCipherForMKI(mki2, key2, salt2))

			encryptWith := func(mki []byte, seq uint16) []byte {
				require.NoError(t, sender.SetSendMKI(mki))
				raw := trustRTPPacket(t, ssrc, seq)
				out, encErr := sender.EncryptRTP(nil, raw, nil)
				require.NoError(t, encErr)

				return out
			}
			decryptMustSucceed := func(ciphertext []byte, seq uint16) {
				expected := trustRTPPacket(t, ssrc, seq)
				out, decErr := receiver.DecryptRTP(nil, ciphertext, nil)
				require.NoError(t, decErr, "legitimate packet seq=%d must be accepted during rekey", seq)
				assert.Equal(t, expected, out)
			}

			// A packet encrypted under an MKI that has not been installed yet
			// is outside the trust window and must be refused before any
			// cryptographic processing.
			notYetInstalled := encryptWith(mki3, 1000)
			_, err = receiver.DecryptRTP(nil, notYetInstalled, nil)
			assert.ErrorIs(t, err, ErrMKINotFound)

			// Overlap phase: both keys trusted. The sender alternates between
			// the two keys on a single, strictly monotonic sequence-number
			// stream, as RFC 3711 requires for one SSRC. The replay detector
			// tracks the SSRC index independently of which key protected the
			// packet, so both MKIs must authenticate throughout the overlap.
			const overlapStart = uint16(1000)
			const overlapEnd = uint16(1012) // indexes 1000..1011

			// Hold back one old-key packet to prove in-flight delivery after
			// newer packets have already been accepted.
			delayedMKI1 := encryptWith(mki1, overlapStart)
			for seq := overlapStart + 1; seq < overlapEnd; seq++ {
				mki := mki1
				if seq%2 == 1 {
					mki = mki2
				}
				pkt := encryptWith(mki, seq)
				decryptMustSucceed(pkt, seq)
			}

			// The held-back packet is behind the window head but still inside
			// the window: a legitimate in-flight packet must not be wrongly
			// rejected during the rekey overlap.
			decryptMustSucceed(delayedMKI1, overlapStart)

			// Replaying that packet afterwards cannot regain trust.
			_, err = receiver.DecryptRTP(nil, delayedMKI1, nil)
			assert.ErrorIs(t, err, errDuplicated, "replaying an in-flight packet must not regain trust")

			// Replay-window boundary: a packet exactly windowSize behind the
			// head has aged out, while the packet one step newer is still
			// inside the window. Both carry a currently trusted MKI.
			head := uint16(overlapEnd - 1)
			tooOld := encryptWith(mki2, head-uint16(window))
			_, err = receiver.DecryptRTP(nil, tooOld, nil)
			assert.ErrorIs(t, err, errDuplicated, "packet outside the replay window must be rejected")
			edge := encryptWith(mki2, head-uint16(window)+1)
			decryptMustSucceed(edge, head-uint16(window)+1)

			// Revoke the old key, simulating the end of the rekey transition.
			require.NoError(t, receiver.SetSendMKI(mki2))
			require.NoError(t, receiver.RemoveMKI(mki1))

			// Packets under the revoked MKI lose trust immediately, even with
			// fresh, never-seen sequence numbers.
			revokedFresh := encryptWith(mki1, 2000)
			_, err = receiver.DecryptRTP(nil, revokedFresh, nil)
			assert.ErrorIs(t, err, ErrMKINotFound)

			// Legitimate traffic on the new key is unaffected by the removal.
			goodAfterRemove := encryptWith(mki2, 2001)
			decryptMustSucceed(goodAfterRemove, 2001)

			// A key installed after the revocation is untrusted until the
			// receiver adds it as well; afterwards its packets authenticate.
			lateMKI3Before := encryptWith(mki3, 2002)
			_, err = receiver.DecryptRTP(nil, lateMKI3Before, nil)
			assert.ErrorIs(t, err, ErrMKINotFound)

			require.NoError(t, receiver.AddCipherForMKI(mki3, key3, salt3))
			lateMKI3After := encryptWith(mki3, 2002)
			decryptMustSucceed(lateMKI3After, 2002)

			// Final trust set: mki1 stays revoked, mki2 and mki3 are trusted.
			_, err = receiver.DecryptRTP(nil, revokedFresh, nil)
			assert.ErrorIs(t, err, ErrMKINotFound)
		})
	}
}

// TestSRTCPMKIRemovalRevokesTrust mirrors TestMKIRemovalRevokesTrust for the
// SRTCP path, where the MKI sits between the SRTCP index and the auth tag.
// SRTCP index replay protection must keep rejecting duplicates, and removing
// an MKI must invalidate every RTCP packet carrying it.
func TestSRTCPMKIRemovalRevokesTrust(t *testing.T) {
	const ssrc = uint32(6000)

	for _, profile := range trustWindowProfiles {
		t.Run(profile.String(), func(t *testing.T) {
			mki1 := []byte{0x01, 0x02, 0x03, 0x04}
			mki2 := []byte{0x02, 0x03, 0x04, 0x05}
			mki3 := []byte{0x03, 0x04, 0x05, 0x06}

			key1, salt1 := trustKeyMaterial(t, profile, 1)
			key2, salt2 := trustKeyMaterial(t, profile, 2)
			key3, salt3 := trustKeyMaterial(t, profile, 3)

			sender := newTrustSender(t, profile, mki1, mki2, mki3,
				key1, salt1, key2, salt2, key3, salt3)
			receiver, err := CreateContext(key1, salt1, profile,
				MasterKeyIndicator(mki1), SRTCPReplayProtection(64))
			require.NoError(t, err)
			require.NoError(t, receiver.AddCipherForMKI(mki2, key2, salt2))

			plaintext := trustRTCPPacket(t, ssrc)

			// Three packets under mki1 establish SRTCP indexes 1..3.
			var firstEncrypted []byte
			for range 3 {
				encrypted, encErr := sender.EncryptRTCP(nil, plaintext, nil)
				require.NoError(t, encErr)
				if firstEncrypted == nil {
					firstEncrypted = encrypted
				}
				decrypted, decErr := receiver.DecryptRTCP(nil, encrypted, nil)
				require.NoError(t, decErr)
				assert.Equal(t, plaintext, decrypted)
			}

			// A retransmitted RTCP packet cannot regain trust.
			_, err = receiver.DecryptRTCP(nil, firstEncrypted, nil)
			assert.ErrorIs(t, err, errDuplicated)

			// The sending MKI cannot be removed while it is the active one.
			assert.ErrorIs(t, receiver.RemoveMKI(mki1), errMKIAlreadyInUse)

			// Revoke mki1: the old packet is still caught by replay
			// protection (the check precedes the MKI lookup), and a fresh
			// packet under the revoked MKI is refused at the lookup.
			require.NoError(t, receiver.SetSendMKI(mki2))
			require.NoError(t, receiver.RemoveMKI(mki1))

			_, err = receiver.DecryptRTCP(nil, firstEncrypted, nil)
			assert.ErrorIs(t, err, errDuplicated)

			staleFresh, err := sender.EncryptRTCP(nil, plaintext, nil)
			require.NoError(t, err)
			_, err = receiver.DecryptRTCP(nil, staleFresh, nil)
			assert.ErrorIs(t, err, ErrMKINotFound)

			// The still-allowed MKI keeps authenticating RTCP traffic.
			require.NoError(t, sender.SetSendMKI(mki2))
			good, err := sender.EncryptRTCP(nil, plaintext, nil)
			require.NoError(t, err)
			decrypted, err := receiver.DecryptRTCP(nil, good, nil)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)

			// Re-adding the MKI label under a different key does not validate
			// packets captured with the old key; only new-key packets pass.
			require.NoError(t, receiver.AddCipherForMKI(mki1, key3, salt3))
			_, err = receiver.DecryptRTCP(nil, staleFresh, nil)
			assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag)

			// Install mki3 on the receiver as well before expecting traffic
			// under that MKI value to be trusted.
			require.NoError(t, receiver.AddCipherForMKI(mki3, key3, salt3))
			require.NoError(t, sender.SetSendMKI(mki3))
			fresh, err := sender.EncryptRTCP(nil, plaintext, nil)
			require.NoError(t, err)
			decrypted, err = receiver.DecryptRTCP(nil, fresh, nil)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

// TestConcurrentMKIRekeyNoDataRace exercises the documented contract that
// MKI list mutation and packet decryption require external synchronization.
// A rekey goroutine alternates the "parking" MKI between a revoked and an
// installed state while other goroutines encrypt and decrypt steady RTP and
// RTCP traffic under the MKIs that remain installed. Run with -race to verify
// the synchronization boundary.
//
// Two receivers are used in lockstep. The replay-protected receiver handles
// steady traffic under the MKIs the rekey loop never touches, which must
// always authenticate. A second, no-replay receiver observes the parking MKI
// state through barrier-synchronized phases: in the revoked phase every probe
// must fail with ErrMKINotFound, in the installed phase every probe must
// authenticate, so the trust-window boundary is observed deterministically
// rather than left to scheduler timing. The no-replay receiver and fresh
// ROC-0 probe senders keep each probe independent of the previous one.
func TestConcurrentMKIRekeyNoDataRace(t *testing.T) {
	const (
		window      = uint(64)
		rekeyCycles = 30
		rtpWorkers  = 4
		rtcpWorkers = 2
		workRounds  = 25
	)

	profile := profileCTR
	mki1 := []byte{0x01, 0x02, 0x03, 0x04}
	mki2 := []byte{0x02, 0x03, 0x04, 0x05}
	mki3 := []byte{0x03, 0x04, 0x05, 0x06} // parking MKI: churned, never selected as active

	key1, salt1 := trustKeyMaterial(t, profile, 1)
	key2, salt2 := trustKeyMaterial(t, profile, 2)
	key3, salt3 := trustKeyMaterial(t, profile, 3)

	// receiver carries replay protection and handles the steady traffic under
	// mki1/mki2. probeReceiver has replay protection disabled and is used only
	// to observe whether the parking MKI is currently installed; it is mutated
	// in lockstep with receiver by the rekey loop.
	receiver, err := CreateContext(key1, salt1, profile,
		MasterKeyIndicator(mki1), SRTPReplayProtection(window), SRTCPReplayProtection(window))
	require.NoError(t, err)
	require.NoError(t, receiver.AddCipherForMKI(mki2, key2, salt2))
	require.NoError(t, receiver.AddCipherForMKI(mki3, key3, salt3))

	probeReceiver, err := CreateContext(key1, salt1, profile,
		MasterKeyIndicator(mki1), SRTPNoReplayProtection(), SRTCPNoReplayProtection())
	require.NoError(t, err)
	require.NoError(t, probeReceiver.AddCipherForMKI(mki2, key2, salt2))
	require.NoError(t, probeReceiver.AddCipherForMKI(mki3, key3, salt3))

	var (
		// recvMu is the external synchronization the Context contract requires:
		// a Context has no internal concurrency protection and its ciphers hold
		// reusable HMAC state, so decryption and MKI mutation must be fully
		// serialized rather than merely guarded against concurrent writes.
		recvMu     sync.Mutex
		seqCounter atomic.Uint64
		denied     atomic.Int64
		wg         sync.WaitGroup
		// barrier lets the rekey goroutine hold each trust state until every
		// probe worker has observed it, making the window boundary deterministic.
		barrier sync.WaitGroup
	)

	type probePhase struct {
		expectRemoved bool
	}
	probeChs := make([]chan probePhase, rtpWorkers)
	for workerIdx := range rtpWorkers {
		probeChs[workerIdx] = make(chan probePhase, 1)
	}

	// Rekey loop: each cycle opens a revoked phase (parking MKI removed on
	// both receivers) and, once every probe worker has observed it, opens an
	// installed phase with the same key material.
	wg.Add(1)

	go func() {
		defer wg.Done()

		for range rekeyCycles {
			recvMu.Lock()
			if removeErr := receiver.RemoveMKI(mki3); removeErr != nil {
				recvMu.Unlock()
				t.Errorf("rekey: unexpected RemoveMKI error: %v", removeErr)

				return
			}
			if removeErr := probeReceiver.RemoveMKI(mki3); removeErr != nil {
				recvMu.Unlock()
				t.Errorf("rekey: unexpected probe RemoveMKI error: %v", removeErr)

				return
			}
			recvMu.Unlock()

			barrier.Add(rtpWorkers)
			for _, ch := range probeChs {
				ch <- probePhase{expectRemoved: true}
			}
			barrier.Wait()

			recvMu.Lock()
			if addErr := receiver.AddCipherForMKI(mki3, key3, salt3); addErr != nil {
				recvMu.Unlock()
				t.Errorf("rekey: unexpected AddCipherForMKI error: %v", addErr)

				return
			}
			if addErr := probeReceiver.AddCipherForMKI(mki3, key3, salt3); addErr != nil {
				recvMu.Unlock()
				t.Errorf("rekey: unexpected probe AddCipherForMKI error: %v", addErr)

				return
			}
			recvMu.Unlock()

			barrier.Add(rtpWorkers)
			for _, ch := range probeChs {
				ch <- probePhase{expectRemoved: false}
			}
			barrier.Wait()
		}
		for _, ch := range probeChs {
			close(ch)
		}
	}()

	// Probe workers observe the parking MKI through the barrier phases on the
	// no-replay probe receiver, using a fresh ROC-0 fixed-MKI sender and a
	// constant probe sequence number on a worker-private SSRC.
	for workerIdx := range rtpWorkers {
		probeSSRC := uint32(7500 + workerIdx)
		ch := probeChs[workerIdx]
		wg.Add(1)

		go func() {
			defer wg.Done()

			for phase := range ch {
				probeSender, pErr := CreateContext(key3, salt3, profile, MasterKeyIndicator(mki3))
				if pErr != nil {
					t.Errorf("probe worker: unexpected context error: %v", pErr)
					barrier.Done()

					return
				}
				probeRaw := trustRTPPacket(t, probeSSRC, 42)
				probe, encErr := probeSender.EncryptRTP(nil, probeRaw, nil)
				if encErr != nil {
					t.Errorf("probe worker: unexpected encrypt error: %v", encErr)
					barrier.Done()

					return
				}

				recvMu.Lock()
				_, probeErr := probeReceiver.DecryptRTP(nil, probe, nil)
				recvMu.Unlock()

				if phase.expectRemoved {
					assert.ErrorIs(t, probeErr, ErrMKINotFound,
						"revoked parking MKI must not authenticate")
					if errors.Is(probeErr, ErrMKINotFound) {
						denied.Add(1)
					}
				} else {
					assert.NoError(t, probeErr,
						"reinstalled parking MKI must authenticate")
				}
				barrier.Done()
			}
		}()
	}

	// Steady RTP workers each own a private sender context and SSRC. Sequence
	// numbers come from one shared counter so no packet can trip the replay
	// detector as a duplicate. They only use MKIs the rekey loop never touches.
	for workerIdx := range rtpWorkers {
		ssrc := uint32(7000 + workerIdx)
		sender := newTrustSender(t, profile, mki1, mki2, mki3,
			key1, salt1, key2, salt2, key3, salt3)
		wg.Add(1)

		go func() {
			defer wg.Done()

			active := [][]byte{mki1, mki2}
			for round := range workRounds {
				if setErr := sender.SetSendMKI(active[round%2]); setErr != nil {
					t.Errorf("rtp worker: unexpected SetSendMKI error: %v", setErr)

					return
				}
				raw := trustRTPPacket(t, ssrc, uint16(seqCounter.Add(1))) //nolint:gosec // G115
				encrypted, encErr := sender.EncryptRTP(nil, raw, nil)
				if encErr != nil {
					t.Errorf("rtp worker: unexpected encrypt error: %v", encErr)

					return
				}

				recvMu.Lock()
				_, decErr := receiver.DecryptRTP(nil, encrypted, nil)
				recvMu.Unlock()
				if decErr != nil {
					t.Errorf("active-MKI packet must never be rejected during synchronized rekey, got %v", decErr)

					return
				}
			}
		}()
	}

	// RTCP workers each own a sender context and a unique SSRC, so per-SSRC
	// SRTCP index replay state cannot collide between goroutines. They only
	// exercise MKIs the rekey loop never touches.
	for workerIdx := range rtcpWorkers {
		ssrc := uint32(8000 + workerIdx)
		sender := newTrustSender(t, profile, mki1, mki2, mki3,
			key1, salt1, key2, salt2, key3, salt3)
		wg.Add(1)

		go func() {
			defer wg.Done()

			active := [][]byte{mki1, mki2}
			plaintext := trustRTCPPacket(t, ssrc)
			for round := range workRounds {
				if setErr := sender.SetSendMKI(active[round%2]); setErr != nil {
					t.Errorf("rtcp worker: unexpected SetSendMKI error: %v", setErr)

					return
				}
				encrypted, encErr := sender.EncryptRTCP(nil, plaintext, nil)
				if encErr != nil {
					t.Errorf("rtcp worker: unexpected encrypt error: %v", encErr)

					return
				}

				recvMu.Lock()
				decrypted, decErr := receiver.DecryptRTCP(nil, encrypted, nil)
				recvMu.Unlock()
				if decErr != nil {
					t.Errorf("active-MKI RTCP packet must never be rejected, got %v", decErr)

					return
				}
				assert.Equal(t, plaintext, decrypted)
			}
		}()
	}

	wg.Wait()

	// Every revoked phase must have been observed by every probe worker.
	assert.Equal(t, int64(rekeyCycles*rtpWorkers), denied.Load(),
		"every probe worker must observe each revoked phase")

	// Deterministic post-concurrency boundary check: restore a known trust
	// set and assert exactly the installed MKIs authenticate, and a revoked
	// one does not, regardless of what happened during the churn.
	recvMu.Lock()
	require.NoError(t, receiver.RemoveMKI(mki3))
	require.NoError(t, receiver.AddCipherForMKI(mki3, key3, salt3))
	require.NoError(t, receiver.SetSendMKI(mki2))
	require.NoError(t, receiver.RemoveMKI(mki1))
	recvMu.Unlock()

	probeDecrypt := func(mki, key, salt []byte) error {
		probeSender, pErr := CreateContext(key, salt, profile, MasterKeyIndicator(mki))
		require.NoError(t, pErr)
		raw := trustRTPPacket(t, 9000, uint16(seqCounter.Add(1))) //nolint:gosec // G115
		encrypted, encErr := probeSender.EncryptRTP(nil, raw, nil)
		require.NoError(t, encErr)

		recvMu.Lock()
		_, decErr := receiver.DecryptRTP(nil, encrypted, nil)
		recvMu.Unlock()

		return decErr
	}

	assert.ErrorIs(t, probeDecrypt(mki1, key1, salt1), ErrMKINotFound)
	require.NoError(t, probeDecrypt(mki2, key2, salt2))
	require.NoError(t, probeDecrypt(mki3, key3, salt3))

	recvMu.Lock()
	require.NoError(t, receiver.AddCipherForMKI(mki1, key1, salt1))
	recvMu.Unlock()
	require.NoError(t, probeDecrypt(mki1, key1, salt1))
}
