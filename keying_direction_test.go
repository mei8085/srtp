// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"bytes"
	"testing"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deterministicKeyingMaterialExporter is a KeyingMaterialExporter stand-in for a
// completed DTLS handshake. It returns a fixed, well-known keying material block
// so that client and server extractions can be compared byte for byte. The block
// layout is the one mandated by RFC 5764 section 4.2:
//
//	client_write_key | server_write_key | client_write_salt | server_write_salt
type deterministicKeyingMaterialExporter struct {
	material []byte
	label    string
}

func (d *deterministicKeyingMaterialExporter) ExportKeyingMaterial(label string, _ []byte, length int) ([]byte, error) {
	d.label = label
	if length > len(d.material) {
		length = len(d.material)
	}

	return append([]byte{}, d.material[:length]...), nil
}

// newDeterministicExporter builds a material block whose four sections are easy
// to tell apart: the client write key is filled with 0x10, the server write key
// with 0x20, the client write salt with 0x30 and the server write salt with 0x40.
func newDeterministicExporter(keyLen, saltLen int) *deterministicKeyingMaterialExporter {
	material := make([]byte, 0, keyLen*2+saltLen*2)
	material = append(material, bytes.Repeat([]byte{0x10}, keyLen)...)
	material = append(material, bytes.Repeat([]byte{0x20}, keyLen)...)
	material = append(material, bytes.Repeat([]byte{0x30}, saltLen)...)
	material = append(material, bytes.Repeat([]byte{0x40}, saltLen)...)

	return &deterministicKeyingMaterialExporter{material: material}
}

// dtlsSrtpProfiles is the set of protection profiles exercised below. Each SRTP
// cipher family (AES-CM/HMAC-SHA1, AEAD AES-GCM and the NULL debugging profile)
// is represented with both 128-bit and 256-bit master keys where applicable.
var dtlsSrtpProfiles = []ProtectionProfile{
	ProtectionProfileAes128CmHmacSha1_80,
	ProtectionProfileAes128CmHmacSha1_32,
	ProtectionProfileAes256CmHmacSha1_80,
	ProtectionProfileAeadAes128Gcm,
	ProtectionProfileAeadAes256Gcm,
	ProtectionProfileNullHmacSha1_80,
}

// TestExtractSessionKeysFromDTLSDirectionMapping verifies the RFC 5764 section 4.2
// direction mapping: a DTLS client maps client_write_* material to its local
// (send) keys and server_write_* material to its remote (receive) keys, while a
// DTLS server must do the exact opposite. The check runs for every protection
// profile so that key and salt lengths are validated against the exported block.
func TestExtractSessionKeysFromDTLSDirectionMapping(t *testing.T) {
	for _, profile := range dtlsSrtpProfiles {
		t.Run(profile.String(), func(t *testing.T) {
			keyLen, err := profile.KeyLen()
			require.NoError(t, err)
			saltLen, err := profile.SaltLen()
			require.NoError(t, err)

			exporter := newDeterministicExporter(keyLen, saltLen)
			clientConfig := &Config{Profile: profile}
			require.NoError(t, clientConfig.ExtractSessionKeysFromDTLS(exporter, true))

			// The exporter must be queried with the registered DTLS-SRTP label and
			// with enough material for both directions of both key and salt.
			assert.Equal(t, labelExtractorDtlsSrtp, exporter.label)
			assert.Equal(t, keyLen*2+saltLen*2, len(exporter.material))

			clientWriteKey := bytes.Repeat([]byte{0x10}, keyLen)
			serverWriteKey := bytes.Repeat([]byte{0x20}, keyLen)
			clientWriteSalt := bytes.Repeat([]byte{0x30}, saltLen)
			serverWriteSalt := bytes.Repeat([]byte{0x40}, saltLen)

			clientKeys := clientConfig.Keys
			assert.Equal(t, clientWriteKey, clientKeys.LocalMasterKey,
				"client local (send) master key must be client_write_key")
			assert.Equal(t, clientWriteSalt, clientKeys.LocalMasterSalt,
				"client local (send) master salt must be client_write_salt")
			assert.Equal(t, serverWriteKey, clientKeys.RemoteMasterKey,
				"client remote (receive) master key must be server_write_key")
			assert.Equal(t, serverWriteSalt, clientKeys.RemoteMasterSalt,
				"client remote (receive) master salt must be server_write_salt")

			serverExporter := newDeterministicExporter(keyLen, saltLen)
			serverConfig := &Config{Profile: profile}
			require.NoError(t, serverConfig.ExtractSessionKeysFromDTLS(serverExporter, false))

			serverKeys := serverConfig.Keys
			assert.Equal(t, serverWriteKey, serverKeys.LocalMasterKey,
				"server local (send) master key must be server_write_key")
			assert.Equal(t, serverWriteSalt, serverKeys.LocalMasterSalt,
				"server local (send) master salt must be server_write_salt")
			assert.Equal(t, clientWriteKey, serverKeys.RemoteMasterKey,
				"server remote (receive) master key must be client_write_key")
			assert.Equal(t, clientWriteSalt, serverKeys.RemoteMasterSalt,
				"server remote (receive) master salt must be client_write_salt")

			// The two peers must hold mirrored key sets: what is local for the
			// client is remote for the server and vice versa.
			assert.Equal(t, clientKeys.LocalMasterKey, serverKeys.RemoteMasterKey)
			assert.Equal(t, clientKeys.LocalMasterSalt, serverKeys.RemoteMasterSalt)
			assert.Equal(t, clientKeys.RemoteMasterKey, serverKeys.LocalMasterKey)
			assert.Equal(t, clientKeys.RemoteMasterSalt, serverKeys.LocalMasterSalt)

			// Every mapped key and salt has to match the length the profile derives
			// session keys from; a mismatched length would fail CreateContext later.
			mappedMaterials := []struct {
				name     string
				material []byte
				wantLen  int
			}{
				{"client local key", clientKeys.LocalMasterKey, keyLen},
				{"client local salt", clientKeys.LocalMasterSalt, saltLen},
				{"client remote key", clientKeys.RemoteMasterKey, keyLen},
				{"client remote salt", clientKeys.RemoteMasterSalt, saltLen},
				{"server local key", serverKeys.LocalMasterKey, keyLen},
				{"server local salt", serverKeys.LocalMasterSalt, saltLen},
				{"server remote key", serverKeys.RemoteMasterKey, keyLen},
				{"server remote salt", serverKeys.RemoteMasterSalt, saltLen},
			}
			for _, m := range mappedMaterials {
				assert.Len(t, m.material, m.wantLen, m.name)
			}
		})
	}
}

// extractDTLSPeerKeys runs the RFC 5764 extraction for both roles against the
// same exported material, modelling a completed DTLS handshake between a client
// and a server.
func extractDTLSPeerKeys(t *testing.T, profile ProtectionProfile, exporter KeyingMaterialExporter) (client, server SessionKeys) {
	t.Helper()

	clientConfig := &Config{Profile: profile}
	require.NoError(t, clientConfig.ExtractSessionKeysFromDTLS(exporter, true))

	serverConfig := &Config{Profile: profile}
	require.NoError(t, serverConfig.ExtractSessionKeysFromDTLS(exporter, false))

	return clientConfig.Keys, serverConfig.Keys
}

// buildDirectionContexts creates one encrypt/decrypt Context pair per direction
// from the extracted DTLS session keys.
func buildDirectionContexts(t *testing.T, profile ProtectionProfile, keys SessionKeys) (send, receive *Context) {
	t.Helper()

	send, err := CreateContext(keys.LocalMasterKey, keys.LocalMasterSalt, profile)
	require.NoError(t, err)
	receive, err = CreateContext(keys.RemoteMasterKey, keys.RemoteMasterSalt, profile)
	require.NoError(t, err)

	return send, receive
}

// TestDTLSSRTPPeerDirectionInterop proves that when both peers apply the RFC 5764
// direction mapping, packets protected with a peer's send key can be authenticated
// and restored with the opposite peer's receive key, for RTP and SRTCP alike.
func TestDTLSSRTPPeerDirectionInterop(t *testing.T) {
	const testSSRC = uint32(5000)

	rtpPlain, err := (&rtp.Packet{
		Header:  rtp.Header{Version: 2, SSRC: testSSRC, SequenceNumber: 7},
		Payload: []byte{0x00, 0x01, 0x02, 0x03, 0x04},
	}).Marshal()
	require.NoError(t, err)

	rtcpPlain, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: testSSRC}})
	require.NoError(t, err)

	for _, profile := range dtlsSrtpProfiles {
		t.Run(profile.String(), func(t *testing.T) {
			keyLen, err := profile.KeyLen()
			require.NoError(t, err)
			saltLen, err := profile.SaltLen()
			require.NoError(t, err)
			exporter := newDeterministicExporter(keyLen, saltLen)

			clientKeys, serverKeys := extractDTLSPeerKeys(t, profile, exporter)

			clientSend, clientReceive := buildDirectionContexts(t, profile, clientKeys)
			serverSend, serverReceive := buildDirectionContexts(t, profile, serverKeys)

			// Client -> server: the server's receive context holds the client write
			// key, so it must authenticate and restore a client-protected packet.
			clientRTP, err := clientSend.EncryptRTP(nil, rtpPlain, nil)
			require.NoError(t, err)
			decrypted, err := serverReceive.DecryptRTP(nil, bytes.Clone(clientRTP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtpPlain, decrypted)

			clientRTCP, err := clientSend.EncryptRTCP(nil, rtcpPlain, nil)
			require.NoError(t, err)
			decryptedRTCP, err := serverReceive.DecryptRTCP(nil, bytes.Clone(clientRTCP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtcpPlain, decryptedRTCP)

			// Server -> client uses the other half of the exported material and must
			// work just as well, proving both directions are mapped consistently.
			serverRTP, err := serverSend.EncryptRTP(nil, rtpPlain, nil)
			require.NoError(t, err)
			decrypted, err = clientReceive.DecryptRTP(nil, bytes.Clone(serverRTP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtpPlain, decrypted)

			serverRTCP, err := serverSend.EncryptRTCP(nil, rtcpPlain, nil)
			require.NoError(t, err)
			decryptedRTCP, err = clientReceive.DecryptRTCP(nil, bytes.Clone(serverRTCP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtcpPlain, decryptedRTCP)
		})
	}
}

// TestDTLSSRTPDirectionMismatchRejected verifies that mixing up the direction
// mapping is always detected as an authentication failure. The correct wiring
// (RFC 5764) is: a receiver verifies with the peer's write key. If the mapping
// is swapped and the receiver instead uses the opposite-direction material
// (the key meant for its own send side), the derived session key/salt do not
// match the sender's and every protected packet must be rejected with
// ErrFailedToVerifyAuthTag. Both RTP and SRTCP are covered, in both directions.
func TestDTLSSRTPDirectionMismatchRejected(t *testing.T) {
	const testSSRC = uint32(5000)

	rtpPlain, err := (&rtp.Packet{
		Header:  rtp.Header{Version: 2, SSRC: testSSRC, SequenceNumber: 11},
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}).Marshal()
	require.NoError(t, err)

	rtcpPlain, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: testSSRC}})
	require.NoError(t, err)

	for _, profile := range dtlsSrtpProfiles {
		t.Run(profile.String(), func(t *testing.T) {
			keyLen, err := profile.KeyLen()
			require.NoError(t, err)
			saltLen, err := profile.SaltLen()
			require.NoError(t, err)
			exporter := newDeterministicExporter(keyLen, saltLen)

			clientKeys, serverKeys := extractDTLSPeerKeys(t, profile, exporter)
			clientSend, clientReceive := buildDirectionContexts(t, profile, clientKeys)
			serverSend, serverReceive := buildDirectionContexts(t, profile, serverKeys)

			// Correct wiring first: each receive context holds the peer's write key
			// and restores a legitimate packet. This proves the material is valid and
			// that any failure below is purely a direction-mapping problem.
			encryptedRTP, err := clientSend.EncryptRTP(nil, rtpPlain, nil)
			require.NoError(t, err)
			decrypted, err := serverReceive.DecryptRTP(nil, bytes.Clone(encryptedRTP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtpPlain, decrypted)

			encryptedRTCP, err := clientSend.EncryptRTCP(nil, rtcpPlain, nil)
			require.NoError(t, err)
			decryptedRTCP, err := serverReceive.DecryptRTCP(nil, bytes.Clone(encryptedRTCP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtcpPlain, decryptedRTCP)

			// Swapped wiring: a receiver that wrongly uses the other direction's
			// material - here the client's own receive context, which holds the
			// server write key - to verify client-sent traffic must be rejected.
			_, err = clientReceive.DecryptRTP(nil, bytes.Clone(encryptedRTP), nil)
			assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag,
				"RTP packet decrypted with the wrong-direction key must fail authentication")
			_, err = clientReceive.DecryptRTCP(nil, bytes.Clone(encryptedRTCP), nil)
			assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag,
				"SRTCP packet decrypted with the wrong-direction key must fail authentication")

			// Mirror the check for server-sent traffic using the server's own receive
			// context (client write key), which is the wrong direction for that flow.
			encryptedRTP, err = serverSend.EncryptRTP(nil, rtpPlain, nil)
			require.NoError(t, err)
			decrypted, err = clientReceive.DecryptRTP(nil, bytes.Clone(encryptedRTP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtpPlain, decrypted)

			_, err = serverReceive.DecryptRTP(nil, bytes.Clone(encryptedRTP), nil)
			assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag,
				"reverse-direction RTP packet must fail authentication with swapped keys")

			encryptedRTCP, err = serverSend.EncryptRTCP(nil, rtcpPlain, nil)
			require.NoError(t, err)
			_, err = serverReceive.DecryptRTCP(nil, bytes.Clone(encryptedRTCP), nil)
			assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag,
				"reverse-direction SRTCP packet must fail authentication with swapped keys")
		})
	}
}

// TestDTLSSRTPFailedRekeyKeepsOldState verifies the atomicity of a DTLS rekey.
// updateKey builds both the new local and remote contexts before replacing either
// one, so a rejected update (here: a remote master salt with the wrong length)
// must leave the previously working send/receive state fully usable. A
// subsequently successful update must then render packets secured under the old
// keys unauthenticatable while packets secured under the new DTLS material pass.
//
// The session is wired like ExtractSessionKeysFromDTLS leaves it: the local
// context protects outbound traffic with LocalMasterKey and the remote context
// verifies inbound traffic with RemoteMasterKey. Probe packets come from
// dedicated reference contexts so per-SSRC rollover/index state of the contexts
// under test never interferes with the authentication result being asserted.
func TestDTLSSRTPFailedRekeyKeepsOldState(t *testing.T) {
	const testSSRC = uint32(5000)

	rtpPlain, err := (&rtp.Packet{
		Header:  rtp.Header{Version: 2, SSRC: testSSRC, SequenceNumber: 1},
		Payload: []byte{0x01, 0x02, 0x03, 0x04},
	}).Marshal()
	require.NoError(t, err)
	rtcpPlain, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: testSSRC}})
	require.NoError(t, err)

	for _, profile := range []ProtectionProfile{ProtectionProfileAes128CmHmacSha1_80, ProtectionProfileAeadAes128Gcm} {
		t.Run(profile.String(), func(t *testing.T) {
			keyLen, err := profile.KeyLen()
			require.NoError(t, err)
			saltLen, err := profile.SaltLen()
			require.NoError(t, err)

			oldExporter := newDeterministicExporter(keyLen, saltLen)
			oldClient, _ := extractDTLSPeerKeys(t, profile, oldExporter)

			// Session endpoint under test: local context uses the local write key,
			// remote context uses the peer's write key, exactly as the DTLS extraction
			// maps them.
			oldSend, oldReceive := buildDirectionContexts(t, profile, oldClient)

			// Reference peer for inbound probes: it protects with the key that this
			// endpoint's remote context is configured to verify.
			oldInboundSend, err := CreateContext(oldClient.RemoteMasterKey, oldClient.RemoteMasterSalt, profile)
			require.NoError(t, err)
			// Reference peer for outbound probes: it verifies with the local write key.
			oldOutboundReceive, err := CreateContext(oldClient.LocalMasterKey, oldClient.LocalMasterSalt, profile)
			require.NoError(t, err)

			// Sanity check: correctly mapped opposite-direction keys protect and
			// restore legitimate packets in both directions.
			oldRTP, err := oldInboundSend.EncryptRTP(nil, rtpPlain, nil)
			require.NoError(t, err)
			decrypted, err := oldReceive.DecryptRTP(nil, bytes.Clone(oldRTP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtpPlain, decrypted)

			oldRTCP, err := oldInboundSend.EncryptRTCP(nil, rtcpPlain, nil)
			require.NoError(t, err)
			decryptedRTCP, err := oldReceive.DecryptRTCP(nil, bytes.Clone(oldRTCP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtcpPlain, decryptedRTCP)

			outboundRTP, err := oldSend.EncryptRTP(nil, rtpPlain, nil)
			require.NoError(t, err)
			decrypted, err = oldOutboundReceive.DecryptRTP(nil, bytes.Clone(outboundRTP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtpPlain, decrypted)

			// A second DTLS handshake yields fresh material with distinct sections.
			newMaterial := make([]byte, 0, keyLen*2+saltLen*2)
			newMaterial = append(newMaterial, bytes.Repeat([]byte{0x50}, keyLen)...)
			newMaterial = append(newMaterial, bytes.Repeat([]byte{0x60}, keyLen)...)
			newMaterial = append(newMaterial, bytes.Repeat([]byte{0x70}, saltLen)...)
			newMaterial = append(newMaterial, bytes.Repeat([]byte{0x80}, saltLen)...)
			newClient, _ := extractDTLSPeerKeys(t, profile,
				&deterministicKeyingMaterialExporter{material: newMaterial})

			// The new handshake really produced different material in both directions.
			assert.False(t, bytes.Equal(oldClient.LocalMasterKey, newClient.LocalMasterKey))
			assert.False(t, bytes.Equal(oldClient.RemoteMasterKey, newClient.RemoteMasterKey))

			session := &SessionSRTP{session: session{
				localContext:  oldSend,
				remoteContext: oldReceive,
				readStreams:   map[uint32]readStream{},
			}}

			// Invalid update: the remote salt length does not match this profile, so
			// remote context construction fails before any context is replaced.
			invalidKeys := newClient
			invalidKeys.RemoteMasterSalt = make([]byte, saltLen-1)
			require.Error(t, session.UpdateKey(invalidKeys, profile))

			// Neither context may have been replaced: old state stays in place and
			// old-keyed packets continue to authenticate, so no half-applied state is
			// left behind that could silently accept mis-protected traffic.
			assert.Same(t, oldSend, session.localContext)
			assert.Same(t, oldReceive, session.remoteContext)

			_, err = session.localContext.EncryptRTP(nil, rtpPlain, nil)
			assert.NoError(t, err, "send context must remain usable after a failed rekey")
			_, err = session.remoteContext.DecryptRTP(nil, bytes.Clone(oldRTP), nil)
			assert.NoError(t, err, "receive context must still verify old-keyed RTP after a failed rekey")
			_, err = session.remoteContext.DecryptRTCP(nil, bytes.Clone(oldRTCP), nil)
			assert.NoError(t, err, "receive context must still verify old-keyed SRTCP after a failed rekey")

			// A valid rekey swaps in both new contexts atomically.
			require.NoError(t, session.UpdateKey(newClient, profile))
			assert.NotSame(t, oldSend, session.localContext)
			assert.NotSame(t, oldReceive, session.remoteContext)

			// Old-keyed packets must now be rejected by the rekeyed remote context:
			// the previous keying state cannot be reused once new DTLS material has
			// been installed. Fresh reference receivers keep per-SSRC/index state out
			// of the assertion.
			staleRTPReceiver, err := CreateContext(oldClient.RemoteMasterKey, oldClient.RemoteMasterSalt, profile)
			require.NoError(t, err)
			_, err = staleRTPReceiver.DecryptRTP(nil, bytes.Clone(oldRTP), nil)
			require.NoError(t, err, "reference old-key receiver setup check")

			_, err = session.remoteContext.DecryptRTP(nil, bytes.Clone(oldRTP), nil)
			assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag,
				"old-keyed RTP must fail authentication against the rekeyed context")

			staleRTCPReceiver, err := CreateContext(oldClient.RemoteMasterKey, oldClient.RemoteMasterSalt, profile)
			require.NoError(t, err)
			_, err = staleRTCPReceiver.DecryptRTCP(nil, bytes.Clone(oldRTCP), nil)
			require.NoError(t, err, "reference old-key SRTCP receiver setup check")

			_, err = session.remoteContext.DecryptRTCP(nil, bytes.Clone(oldRTCP), nil)
			assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag,
				"old-keyed SRTCP must fail authentication against the rekeyed context")

			// New-keyed traffic round-trips through the rekeyed contexts. A reference
			// peer protecting with the new remote key verifies against the session's
			// new remote context, and a reference peer verifying with the new local key
			// accepts traffic from the session's new local context. Separate reference
			// contexts keep rollover/index state isolated from the installed contexts.
			newInboundSend, err := CreateContext(newClient.RemoteMasterKey, newClient.RemoteMasterSalt, profile)
			require.NoError(t, err)
			newOutboundReceive, err := CreateContext(newClient.LocalMasterKey, newClient.LocalMasterSalt, profile)
			require.NoError(t, err)

			newRTP, err := newInboundSend.EncryptRTP(nil, rtpPlain, nil)
			require.NoError(t, err)
			decrypted, err = session.remoteContext.DecryptRTP(nil, bytes.Clone(newRTP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtpPlain, decrypted)

			sessionRTP, err := session.localContext.EncryptRTP(nil, rtpPlain, nil)
			require.NoError(t, err)
			decrypted, err = newOutboundReceive.DecryptRTP(nil, bytes.Clone(sessionRTP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtpPlain, decrypted)

			newRTCP, err := session.localContext.EncryptRTCP(nil, rtcpPlain, nil)
			require.NoError(t, err)
			decryptedRTCP, err = newOutboundReceive.DecryptRTCP(nil, bytes.Clone(newRTCP), nil)
			require.NoError(t, err)
			assert.Equal(t, rtcpPlain, decryptedRTCP)
		})
	}
}
