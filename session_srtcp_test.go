// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/transport/v5/packetio"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
)

const rtcpHeaderSize = 4

func TestSessionSRTCPBadInit(t *testing.T) {
	_, err := NewSessionSRTCP(nil, nil)
	assert.Error(t, err, "NewSessionSRTCP should error if no config was provided")

	_, err = NewSessionSRTCP(nil, &Config{})
	assert.Error(t, err, "NewSessionSRTCP should error if no net was provided")
}

func buildSessionSRTCP(t *testing.T) (*SessionSRTCP, net.Conn, *Config) { //nolint:dupl
	t.Helper()

	aPipe, bPipe := net.Pipe()
	config := &Config{
		Profile: ProtectionProfileAes128CmHmacSha1_80,
		Keys: SessionKeys{
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
		},
	}

	aSession, err := NewSessionSRTCP(aPipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, aSession, "NewSessionSRTCP did not error, but returned nil session")

	return aSession, bPipe, config
}

func buildSessionSRTCPPair(t *testing.T) (*SessionSRTCP, *SessionSRTCP) { //nolint:dupl
	t.Helper()

	aSession, bPipe, config := buildSessionSRTCP(t)
	bSession, err := NewSessionSRTCP(bPipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, bSession, "NewSessionSRTCP did not error, but returned nil session")

	return aSession, bSession
}

func TestSessionSRTCP(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	testPayload, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 5000}})
	assert.NoError(t, err)

	readBuffer := make([]byte, len(testPayload))
	aSession, bSession := buildSessionSRTCPPair(t)

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	_, err = aWriteStream.Write(testPayload)
	assert.NoError(t, err)

	bReadStream, _, err := bSession.AcceptStream()
	assert.NoError(t, err)

	_, err = bReadStream.Read(readBuffer)
	assert.NoError(t, err)

	assert.Equalf(t, readBuffer, testPayload,
		"Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer)

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTCPWithIODeadline(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	testPayload, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 5000}})
	assert.NoError(t, err)

	readBuffer := make([]byte, len(testPayload))
	aSession, bPipe, config := buildSessionSRTCP(t)

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	// When the other peer is not ready, the Write would be blocked if no deadline.
	assert.NoError(t, aWriteStream.SetWriteDeadline(time.Now().Add(1*time.Second)))

	_, err = aWriteStream.Write(testPayload)
	assert.Truef(t, errIsTimeout(err), "Unexpected read-error(%v)", err)

	assert.NoError(t, aWriteStream.SetWriteDeadline(time.Time{}))

	// Setup another peer.
	bSession, err := NewSessionSRTCP(bPipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, bSession, "NewSessionSRTCP did not error, but returned nil session")

	// The second attempt to write.
	_, err = aWriteStream.Write(testPayload)
	// The other peer is ready, this write attempt should work.
	assert.NoError(t, err)

	bReadStream, _, err := bSession.AcceptStream()
	assert.NoError(t, err)

	_, err = bReadStream.Read(readBuffer)
	assert.NoError(t, err)

	assert.Equalf(t, readBuffer, testPayload,
		"Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer)

	// The second Read attempt would be blocked if the deadline is not set.
	assert.NoError(t, bReadStream.SetReadDeadline(time.Now().Add(1*time.Second)))

	_, err = bReadStream.Read(readBuffer)
	assert.Truef(t, errIsTimeout(err), "Unexpected read-error(%v)", err)

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTCPOpenReadStream(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	testPayload, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 5000}})
	assert.NoError(t, err)

	readBuffer := make([]byte, len(testPayload))
	aSession, bSession := buildSessionSRTCPPair(t)

	bReadStream, err := bSession.OpenReadStream(5000)
	assert.NoError(t, err)

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	_, err = aWriteStream.Write(testPayload)
	assert.NoError(t, err)

	_, err = bReadStream.Read(readBuffer)
	assert.NoError(t, err)

	assert.Equalf(t, readBuffer, testPayload,
		"Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer)

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTCPReplayProtection(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const (
		testSSRC = 5000
	)
	aSession, bSession := buildSessionSRTCPPair(t)
	bReadStream, err := bSession.OpenReadStream(testSSRC)
	assert.NoError(t, err)

	// Generate test packets
	var packets [][]byte
	var expectedSSRC []uint32
	for i := range uint32(0x100) {
		testPacket := &rtcp.PictureLossIndication{
			MediaSSRC:  testSSRC,
			SenderSSRC: i,
		}
		expectedSSRC = append(expectedSSRC, i)
		encrypted, eerr := encryptSRTCP(aSession.session.localContext, testPacket)
		assert.NoError(t, eerr)

		packets = append(packets, encrypted)
	}

	// Receive SRTCP packets with replay protection
	var receivedSSRC []uint32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			if ssrc, perr := getSenderSSRC(t, bReadStream); perr == nil {
				receivedSSRC = append(receivedSSRC, ssrc)
			} else if errors.Is(perr, io.EOF) {
				return
			}
		}
	}()

	// Write with replay attack
	for _, p := range packets {
		_, err = aSession.session.nextConn.Write(p)
		assert.NoError(t, err)
		// Immediately replay
		_, err = aSession.session.nextConn.Write(p)
		assert.NoError(t, err)
	}
	for _, p := range packets {
		// Delayed replay
		_, err = aSession.session.nextConn.Write(p)
		assert.NoError(t, err)
	}

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
	assert.NoError(t, bReadStream.Close())

	wg.Wait()

	assert.Equalf(t, expectedSSRC, receivedSSRC,
		"Expected and received SSRCs differ,\nexpected:\n%v\nreceived:\n%v",
		expectedSSRC, receivedSSRC)
}

func TestSessionSRTCPCompoundPacket(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	testSSRCSenderReport1SR := uint32(0x902f9e2e)
	testSSRCSenderReport1RR := uint32(0xbc5e9a40)
	testSSRCCNAME := uint32(1234)
	testSSRCSenderReport2SR := uint32(0x12345678)
	aSession, bSession := buildSessionSRTCPPair(t)
	bReadStreamSR1SR, err := bSession.OpenReadStream(testSSRCSenderReport1SR)
	assert.NoError(t, err)
	bReadStreamSR1RR, err := bSession.OpenReadStream(testSSRCSenderReport1RR)
	assert.NoError(t, err)
	bReadStreamCNAME, err := bSession.OpenReadStream(testSSRCCNAME)
	assert.NoError(t, err)
	bReadStreamSR2SR, err := bSession.OpenReadStream(testSSRCSenderReport2SR)
	assert.NoError(t, err)

	// Compound packet
	// first packet - Sender Report with a Receiver Report
	// second packet - Sender Report without a Receiver Report
	cp := &rtcp.CompoundPacket{
		&rtcp.SenderReport{
			SSRC:        testSSRCSenderReport1SR,
			NTPTime:     0xda8bd1fcdddda05a,
			RTPTime:     0xaaf4edd5,
			PacketCount: 1,
			OctetCount:  2,
			Reports: []rtcp.ReceptionReport{{
				SSRC:               testSSRCSenderReport1RR,
				FractionLost:       0,
				TotalLost:          0,
				LastSequenceNumber: 0x46e1,
				Jitter:             273,
				LastSenderReport:   0x9f36432,
				Delay:              150137,
			}},
			ProfileExtensions: []byte{
				0x81, 0xca, 0x0, 0x6,
				0x2b, 0x7e, 0xc0, 0xc5,
				0x1, 0x10, 0x4c, 0x63,
				0x49, 0x66, 0x7a, 0x58,
				0x6f, 0x6e, 0x44, 0x6f,
				0x72, 0x64, 0x53, 0x65,
				0x57, 0x36, 0x0, 0x0,
			},
		},
		rtcp.NewCNAMESourceDescription(testSSRCCNAME, "cname"), // to make it a valid compound packet
		&rtcp.SenderReport{
			SSRC:        testSSRCSenderReport2SR,
			NTPTime:     0xda8bd1fcdddda05a,
			RTPTime:     0xaaf4edd5,
			PacketCount: 1,
			OctetCount:  2,
		},
	}

	done := make(chan struct{})
	go func() {
		readBuffer := make([]byte, 200)

		senderReport := &rtcp.SenderReport{}
		n, _, rerr := bReadStreamSR1SR.ReadRTCP(readBuffer)
		assert.NoError(t, rerr)
		rerr = senderReport.Unmarshal(readBuffer[:n])
		assert.NoError(t, rerr)
		assert.Equal(t, uint32(0x902f9e2e), senderReport.SSRC)
		assert.Len(t, senderReport.Reports, 1)
		assert.Equal(t, uint32(0xbc5e9a40), senderReport.Reports[0].SSRC)
		assert.Len(t, senderReport.DestinationSSRC(), 2)
		assert.ElementsMatch(t, []uint32{0x902f9e2e, 0xbc5e9a40}, senderReport.DestinationSSRC())

		// should read via receiver report embedded in sender report
		senderReport = &rtcp.SenderReport{}
		n, _, rerr = bReadStreamSR1RR.ReadRTCP(readBuffer)
		assert.NoError(t, rerr)
		rerr = senderReport.Unmarshal(readBuffer[:n])
		assert.NoError(t, rerr)
		assert.Equal(t, uint32(0x902f9e2e), senderReport.SSRC)
		assert.Len(t, senderReport.Reports, 1)
		assert.Equal(t, uint32(0xbc5e9a40), senderReport.Reports[0].SSRC)
		assert.Len(t, senderReport.DestinationSSRC(), 2)
		assert.ElementsMatch(t, []uint32{0x902f9e2e, 0xbc5e9a40}, senderReport.DestinationSSRC())

		cname := &rtcp.SourceDescription{}
		n, _, rerr = bReadStreamCNAME.ReadRTCP(readBuffer)
		assert.NoError(t, rerr)
		rerr = cname.Unmarshal(readBuffer[:n])
		assert.NoError(t, rerr)
		assert.Len(t, cname.DestinationSSRC(), 1)
		assert.Equal(t, uint32(1234), cname.DestinationSSRC()[0])

		senderReport = &rtcp.SenderReport{}
		n, _, rerr = bReadStreamSR2SR.ReadRTCP(readBuffer)
		assert.NoError(t, rerr)
		rerr = senderReport.Unmarshal(readBuffer[:n])
		assert.NoError(t, rerr)
		assert.Equal(t, uint32(0x12345678), senderReport.SSRC)
		assert.Len(t, senderReport.Reports, 0)
		assert.Len(t, senderReport.DestinationSSRC(), 1)
		assert.ElementsMatch(t, []uint32{0x12345678}, senderReport.DestinationSSRC())

		close(done)
	}()

	encrypted, err := encryptSRTCP(aSession.session.localContext, cp)
	assert.NoError(t, err)
	_, err = aSession.session.nextConn.Write(encrypted)
	assert.NoError(t, err)

	<-done

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
	assert.NoError(t, bReadStreamSR1SR.Close())
	assert.NoError(t, bReadStreamSR1RR.Close())
	assert.NoError(t, bReadStreamCNAME.Close())
	assert.NoError(t, bReadStreamSR2SR.Close())
}

func TestSessionSRTCPCompoundPacketWithEmptyDestinationSSRC(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	testSSRCSenderReportSR := uint32(0x902f9e2e)
	testSSRCSenderReportRR := uint32(0xbc5e9a40)
	// Unknown packet type (221), parsed as rtcp.RawPacket whose
	// DestinationSSRC() is empty. It should still be delivered to every
	// stream the compound packet is addressed to.
	rawPacket := rtcp.RawPacket([]byte{
		0x80, 0xdd, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04,
	})

	aSession, bSession := buildSessionSRTCPPair(t)
	bReadStreamSR, err := bSession.OpenReadStream(testSSRCSenderReportSR)
	assert.NoError(t, err)
	bReadStreamRR, err := bSession.OpenReadStream(testSSRCSenderReportRR)
	assert.NoError(t, err)

	cp := &rtcp.CompoundPacket{
		&rtcp.SenderReport{
			SSRC: testSSRCSenderReportSR,
			Reports: []rtcp.ReceptionReport{{
				SSRC: testSSRCSenderReportRR,
			}},
		},
		rtcp.NewCNAMESourceDescription(testSSRCSenderReportSR, "cname"),
		&rawPacket,
	}

	done := make(chan struct{})
	go func() {
		readBuffer := make([]byte, 200)

		// stream for the sender SSRC: SenderReport, SourceDescription, RawPacket
		_, header, rerr := bReadStreamSR.ReadRTCP(readBuffer)
		assert.NoError(t, rerr)
		assert.Equal(t, rtcp.TypeSenderReport, header.Type)

		_, header, rerr = bReadStreamSR.ReadRTCP(readBuffer)
		assert.NoError(t, rerr)
		assert.Equal(t, rtcp.TypeSourceDescription, header.Type)

		n, header, rerr := bReadStreamSR.ReadRTCP(readBuffer)
		assert.NoError(t, rerr)
		assert.Equal(t, rtcp.PacketType(221), header.Type)
		assert.Equal(t, []byte(rawPacket), readBuffer[:n])

		// stream for the reception report SSRC: SenderReport, RawPacket
		_, header, rerr = bReadStreamRR.ReadRTCP(readBuffer)
		assert.NoError(t, rerr)
		assert.Equal(t, rtcp.TypeSenderReport, header.Type)

		n, header, rerr = bReadStreamRR.ReadRTCP(readBuffer)
		assert.NoError(t, rerr)
		assert.Equal(t, rtcp.PacketType(221), header.Type)
		assert.Equal(t, []byte(rawPacket), readBuffer[:n])

		close(done)
	}()

	encrypted, err := encryptSRTCP(aSession.session.localContext, cp)
	assert.NoError(t, err)
	_, err = aSession.session.nextConn.Write(encrypted)
	assert.NoError(t, err)

	<-done

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
	assert.NoError(t, bReadStreamSR.Close())
	assert.NoError(t, bReadStreamRR.Close())

	// Each packet must have been delivered only once to each destination.
	readBuffer := make([]byte, 200)
	_, err = bReadStreamSR.Read(readBuffer)
	assert.ErrorIs(t, err, io.EOF)
	_, err = bReadStreamRR.Read(readBuffer)
	assert.ErrorIs(t, err, io.EOF)
}

func TestSessionSRTCPDuplicateDestinations(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	xr := &rtcp.ExtendedReport{SenderSSRC: 1234, Reports: []rtcp.ReportBlock{
		&rtcp.LossRLEReportBlock{SSRC: 5000, Chunks: []rtcp.Chunk{0x4006, 0x0006}},
		&rtcp.DuplicateRLEReportBlock{SSRC: 5000, Chunks: []rtcp.Chunk{0x4006, 0x0006}},
	}}
	pli := &rtcp.PictureLossIndication{MediaSSRC: 5000}
	compound, err := rtcp.Marshal([]rtcp.Packet{xr, pli})
	assert.NoError(t, err)

	aSession, bSession := buildSessionSRTCPPair(t)
	senderStream, err := bSession.OpenReadStream(1234)
	assert.NoError(t, err)
	reportStream, err := bSession.OpenReadStream(5000)
	assert.NoError(t, err)

	encrypted, err := aSession.session.localContext.EncryptRTCP(nil, compound, nil)
	assert.NoError(t, err)
	assert.NoError(t, bSession.decrypt(encrypted, nil))
	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())

	for _, testCase := range []struct {
		stream   *ReadStreamSRTCP
		expected []rtcp.Packet
	}{
		{senderStream, []rtcp.Packet{xr}},
		// Repeated SSRCs within the XR must not duplicate delivery, but
		// the separate PLI for that SSRC must still be delivered.
		{reportStream, []rtcp.Packet{xr, pli}},
	} {
		assert.NoError(t, testCase.stream.Close())
		readBuffer := make([]byte, 200)
		for _, packet := range testCase.expected {
			expected, marshalErr := packet.Marshal()
			assert.NoError(t, marshalErr)
			n, readErr := testCase.stream.Read(readBuffer)
			assert.NoError(t, readErr)
			assert.Equal(t, expected, readBuffer[:n])
		}
		_, readErr := testCase.stream.Read(readBuffer)
		assert.ErrorIs(t, readErr, io.EOF)
	}
}

func TestSessionSRTCPDecryptInvalidRTCP(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSession, bSession := buildSessionSRTCPPair(t)

	// Valid RTCP header that claims a larger length than the payload carries.
	invalidRTCP := []byte{0x81, 0xc8, 0x00, 0x0c, 0x90, 0x2f, 0x9e, 0x2e}
	encrypted, err := aSession.session.localContext.EncryptRTCP(nil, invalidRTCP, nil)
	assert.NoError(t, err)
	assert.Error(t, bSession.decrypt(encrypted, nil))

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTCPDecryptDestinationParseFailure(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	// Valid framing, but the CNAME length exceeds the packet. Destination
	// parsing appends SSRC 6000 before discovering the malformed item.
	invalidSDES := []byte{
		0x81, 0xca, 0x00, 0x02,
		0x00, 0x00, 0x17, 0x70,
		0x01, 0xff, 0x00, 0x00,
	}
	pli, err := (&rtcp.PictureLossIndication{MediaSSRC: 5000}).Marshal()
	assert.NoError(t, err)
	unknown := []byte{0x80, 0xdd, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04}

	for _, testCase := range []struct {
		name     string
		packets  [][]byte
		expected [][]byte
	}{
		{
			name:     "continue after parse failure",
			packets:  [][]byte{invalidSDES, pli},
			expected: [][]byte{pli},
		},
		{
			name:     "discard partial fallback destinations",
			packets:  [][]byte{pli, invalidSDES, unknown},
			expected: [][]byte{pli, unknown},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			aSession, bSession := buildSessionSRTCPPair(t)

			// Pre-open both streams so incorrect routing fails an assertion
			// instead of blocking while waiting for AcceptStream.
			readStream, err := bSession.OpenReadStream(5000)
			assert.NoError(t, err)
			invalidReadStream, err := bSession.OpenReadStream(6000)
			assert.NoError(t, err)

			var compound []byte
			for _, packet := range testCase.packets {
				compound = append(compound, packet...)
			}
			encrypted, err := aSession.session.localContext.EncryptRTCP(nil, compound, nil)
			assert.NoError(t, err)
			assert.Error(t, bSession.decrypt(encrypted, nil))

			// Closing the buffers allows checking for unexpected packets
			// without blocking after the queued packets have been read.
			assert.NoError(t, readStream.Close())
			assert.NoError(t, invalidReadStream.Close())

			readBuffer := make([]byte, 200)
			for _, expected := range testCase.expected {
				n, readErr := readStream.Read(readBuffer)
				assert.NoError(t, readErr)
				assert.Equal(t, expected, readBuffer[:n])
			}
			_, err = readStream.Read(readBuffer)
			assert.ErrorIs(t, err, io.EOF)
			_, err = invalidReadStream.Read(readBuffer)
			assert.ErrorIs(t, err, io.EOF)

			assert.NoError(t, aSession.Close())
			assert.NoError(t, bSession.Close())
		})
	}
}

func TestSessionSRTCPDecryptClosedSession(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSession, bSession := buildSessionSRTCPPair(t)
	assert.NoError(t, bSession.Close())

	encrypted, err := encryptSRTCP(aSession.session.localContext, &rtcp.PictureLossIndication{MediaSSRC: 5000})
	assert.NoError(t, err)
	// The session is closed, decrypt drops the packet without an error.
	assert.NoError(t, bSession.decrypt(encrypted, nil))

	assert.NoError(t, aSession.Close())
}

func TestSessionSRTCPDecryptWrongStreamType(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSession, bSession := buildSessionSRTCPPair(t)

	bSession.session.readStreamsLock.Lock()
	bSession.session.readStreams[5000] = &ReadStreamSRTP{}
	bSession.session.readStreamsLock.Unlock()

	encrypted, err := encryptSRTCP(aSession.session.localContext, &rtcp.PictureLossIndication{MediaSSRC: 5000})
	assert.NoError(t, err)
	assert.ErrorIs(t, bSession.decrypt(encrypted, nil), errFailedTypeAssertion)

	bSession.session.readStreamsLock.Lock()
	delete(bSession.session.readStreams, 5000)
	bSession.session.readStreamsLock.Unlock()

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTCPDecryptClosedReadStream(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSession, bSession := buildSessionSRTCPPair(t)

	bReadStream, err := bSession.OpenReadStream(5000)
	assert.NoError(t, err)
	// Close the underlying buffer while keeping the stream registered
	// in the session so the stream write fails.
	assert.NoError(t, bReadStream.buffer.Close())

	encrypted, err := encryptSRTCP(aSession.session.localContext, &rtcp.PictureLossIndication{MediaSSRC: 5000})
	assert.NoError(t, err)
	assert.Error(t, bSession.decrypt(encrypted, nil))

	assert.NoError(t, bReadStream.Close())
	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTCPAcceptStreamClearsTimeout(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aPipe, bPipe := net.Pipe()
	config := &Config{
		Profile: ProtectionProfileAes128CmHmacSha1_80,
		Keys: SessionKeys{
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
		},
		AcceptStreamTimeout: time.Now().Add(3 * time.Second),
	}

	aSession, err := NewSessionSRTCP(aPipe, config)
	assert.NoError(t, err)
	bSession, err := NewSessionSRTCP(bPipe, config)
	assert.NoError(t, err)

	testPayload, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 5000}})
	assert.NoError(t, err)
	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)
	_, err = aWriteStream.Write(testPayload)
	assert.NoError(t, err)

	bReadStream, ssrc, err := bSession.AcceptStream()
	assert.NoError(t, err)
	assert.Equal(t, uint32(5000), ssrc)

	assert.NoError(t, bReadStream.Close())
	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

// nolint: dupl
func TestSessionSRTCPAcceptStreamTimeout(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	pipe, _ := net.Pipe()
	config := &Config{
		Profile: ProtectionProfileAes128CmHmacSha1_80,
		Keys: SessionKeys{
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
		},
		AcceptStreamTimeout: time.Now().Add(3 * time.Second),
	}

	newSession, err := NewSessionSRTCP(pipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, newSession, "NewSessionSRTCP did not error, but returned nil session")

	_, _, err = newSession.AcceptStream()
	if !errors.Is(err, errStreamAlreadyClosed) {
		assert.NoError(t, err)
	}

	assert.NoError(t, newSession.Close())
}

func getSenderSSRC(t *testing.T, stream *ReadStreamSRTCP) (ssrc uint32, err error) {
	t.Helper()

	authTagSize, err := ProtectionProfileAes128CmHmacSha1_80.AuthTagRTCPLen()
	if err != nil {
		return 0, err
	}

	const pliPacketSize = 8
	readBuffer := make([]byte, pliPacketSize+authTagSize+srtcpIndexSize)
	n, _, err := stream.ReadRTCP(readBuffer)
	if errors.Is(err, io.EOF) {
		return 0, err
	}
	if err != nil {
		assert.NoError(t, err)

		return 0, err
	}
	pli := &rtcp.PictureLossIndication{}
	if uerr := pli.Unmarshal(readBuffer[:n]); uerr != nil {
		assert.NoError(t, uerr)

		return 0, uerr
	}

	return pli.SenderSSRC, nil
}

func TestSessionSRTCPFailedAuthDoesNotGrowStreams(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const (
		badMediaSSRC  = uint32(0xDEADBEEF)
		goodMediaSSRC = uint32(0x12345678)
	)

	aSession, bSession := buildSessionSRTCPPair(t)

	// Encrypt a PLI for badMediaSSRC with the correct key, then corrupt its auth tag
	// so that bSession's remote context rejects it without creating a stream entry.
	badEncrypted, err := encryptSRTCP(aSession.session.localContext,
		&rtcp.PictureLossIndication{MediaSSRC: badMediaSSRC})
	assert.NoError(t, err)
	badEncrypted[len(badEncrypted)-1] ^= 0xFF // corrupt last byte of auth tag

	_, err = aSession.session.nextConn.Write(badEncrypted)
	assert.NoError(t, err)

	// Write a valid PLI for goodMediaSSRC so we can synchronize via AcceptStream.
	// The read goroutine processes packets sequentially, so when AcceptStream
	// returns the bad packet has already been handled.
	goodEncrypted, err := encryptSRTCP(aSession.session.localContext,
		&rtcp.PictureLossIndication{MediaSSRC: goodMediaSSRC})
	assert.NoError(t, err)

	_, err = aSession.session.nextConn.Write(goodEncrypted)
	assert.NoError(t, err)

	_, receivedSSRC, err := bSession.AcceptStream()
	assert.NoError(t, err)
	assert.Equal(t, goodMediaSSRC, receivedSSRC, "AcceptStream must return the valid SSRC")

	bSession.session.readStreamsLock.Lock()
	streamCount := len(bSession.session.readStreams)
	_, hasBadMediaSSRC := bSession.session.readStreams[badMediaSSRC]
	bSession.session.readStreamsLock.Unlock()

	assert.Equal(t, 1, streamCount, "readStreams must not grow after failed authentication")
	assert.False(t, hasBadMediaSSRC, "readStreams must not contain the SSRC from the rejected packet")

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTCPReadWriteDoesNotAllocate(t *testing.T) {
	const testSSRC = 5000

	packets := []rtcp.Packet{
		&rtcp.SenderReport{SSRC: testSSRC},
		&rtcp.SourceDescription{Chunks: []rtcp.SourceDescriptionChunk{
			{Source: testSSRC, Items: []rtcp.SourceDescriptionItem{{Type: rtcp.SDESCNAME, Text: "test"}}},
		}},
		&rtcp.RawPacket{0x80, 0xdd, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04},
	}

	for name, replayOptions := range map[string][]ContextOption{
		"NoReplayProtection": {SRTCPNoReplayProtection()},
		"ReplayProtection":   {SRTCPReplayProtection(64)},
	} {
		t.Run(name, func(t *testing.T) {
			lim := test.TimeOut(time.Second * 5)
			defer lim.Stop()

			report := test.CheckRoutines(t)
			defer report()

			testPayload, err := rtcp.Marshal(packets)
			assert.NoError(t, err)
			readBuffer := make([]byte, len(testPayload))

			// Use GCM as in TestSessionSRTPReadWriteDoesNotAllocate to avoid
			// the CTR pool's allocations under the race detector.
			config := &Config{
				Profile: ProtectionProfileAeadAes128Gcm,
				Keys: SessionKeys{
					[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
					[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A},
					[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
					[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A},
				},
				LocalOptions:  replayOptions,
				RemoteOptions: replayOptions,
			}
			aPipe, bPipe := net.Pipe()
			aSession, err := NewSessionSRTCP(aPipe, config)
			assert.NoError(t, err)
			bSession, err := NewSessionSRTCP(bPipe, config)
			assert.NoError(t, err)

			bReadStream, err := bSession.OpenReadStream(testSSRC)
			assert.NoError(t, err)
			aWriteStream, err := aSession.OpenWriteStream()
			assert.NoError(t, err)

			roundTrip := func() (int, error) {
				if _, err := aWriteStream.Write(testPayload); err != nil {
					return 0, err
				}

				var total int
				for range packets {
					n, readErr := bReadStream.Read(readBuffer[total:])
					if readErr != nil {
						return 0, readErr
					}
					total += n
				}

				return total, nil
			}

			for range 100 {
				_, err := roundTrip()
				assert.NoError(t, err)
			}

			var roundTripErr error
			allocs := testing.AllocsPerRun(1000, func() {
				if _, err := roundTrip(); err != nil {
					roundTripErr = err
				}
			})

			assert.NoError(t, roundTripErr)
			assert.Zero(t, allocs)
			assert.Equal(t, testPayload, readBuffer)

			assert.NoError(t, aSession.Close())
			assert.NoError(t, bSession.Close())
			assert.NoError(t, bReadStream.Close())
		})
	}
}

// TestSessionSRTCPRejectedPacketKeepsReplayWindow verifies that a datagram that
// fails authentication is rejected before it can consume the replay window of an
// already established stream. The control message it carried must never be
// delivered, while the legitimate retransmission of the same index must still be
// accepted.
func TestSessionSRTCPRejectedPacketKeepsReplayWindow(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSession, bSession := buildSessionSRTCPPair(t)

	bReadStream, err := bSession.OpenReadStream(5000)
	assert.NoError(t, err)

	encrypted, err := encryptSRTCP(aSession.session.localContext,
		&rtcp.PictureLossIndication{MediaSSRC: 5000})
	assert.NoError(t, err)

	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-1] ^= 0xFF // corrupt the auth tag

	assert.Error(t, bSession.decrypt(tampered, nil),
		"a datagram with an invalid auth tag must be rejected")
	assert.NoError(t, bSession.decrypt(encrypted, nil),
		"rejecting an unauthenticated datagram must not consume the replay window")

	readBuffer := make([]byte, 200)
	n, err := bReadStream.Read(readBuffer)
	assert.NoError(t, err)
	assert.Equal(t, encryptedPayloadLength(t, encrypted), n)

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

// TestSessionSRTCPUnknownControlNotDeliveredWithoutDestination verifies that a
// control packet without any destination is not turned into trusted traffic. A
// datagram that only contains such a packet has nothing to scope it to, so it
// must neither create a stream nor notify AcceptStream.
func TestSessionSRTCPUnknownControlNotDeliveredWithoutDestination(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSession, bSession := buildSessionSRTCPPair(t)

	// Packet type 221 is unknown to pion/rtcp and is parsed as rtcp.RawPacket,
	// which reports no destination SSRC of its own.
	unknown := []byte{0x80, 0xdd, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04}
	encrypted, err := aSession.session.localContext.EncryptRTCP(nil, unknown, nil)
	assert.NoError(t, err)
	assert.NoError(t, bSession.decrypt(encrypted, nil))

	bSession.session.readStreamsLock.Lock()
	streamCount := len(bSession.session.readStreams)
	bSession.session.readStreamsLock.Unlock()
	assert.Zero(t, streamCount,
		"an unknown control packet must not establish a stream on its own")

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

// TestSessionSRTCPUnknownControlScopedToCompound verifies that an authenticated
// unknown control packet is delivered only to the streams its compound datagram
// is addressed to, and that it is not duplicated across unrelated SSRCs.
func TestSessionSRTCPUnknownControlScopedToCompound(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSession, bSession := buildSessionSRTCPPair(t)

	reportStream, err := bSession.OpenReadStream(5000)
	assert.NoError(t, err)
	unrelatedStream, err := bSession.OpenReadStream(7000)
	assert.NoError(t, err)

	pli, err := (&rtcp.PictureLossIndication{MediaSSRC: 5000}).Marshal()
	assert.NoError(t, err)
	unknown := []byte{0x80, 0xdd, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04}
	compound := append(append([]byte{}, pli...), unknown...)

	encrypted, err := aSession.session.localContext.EncryptRTCP(nil, compound, nil)
	assert.NoError(t, err)
	assert.NoError(t, bSession.decrypt(encrypted, nil))

	assert.NoError(t, reportStream.Close())
	assert.NoError(t, unrelatedStream.Close())

	readBuffer := make([]byte, 200)
	for _, expected := range [][]byte{pli, unknown} {
		n, readErr := reportStream.Read(readBuffer)
		assert.NoError(t, readErr)
		assert.Equal(t, expected, readBuffer[:n])
	}
	_, err = reportStream.Read(readBuffer)
	assert.ErrorIs(t, err, io.EOF)

	_, err = unrelatedStream.Read(readBuffer)
	assert.ErrorIs(t, err, io.EOF,
		"the unknown control packet must not be fanned out to unrelated streams")

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

// TestSessionSRTCPMalformedControlRejectedAsWhole verifies that a compound
// datagram carrying an unparsable control packet still delivers its valid
// packets, and that the malformed packet itself is never forwarded as trusted
// control information to any stream.
func TestSessionSRTCPMalformedControlRejectedAsWhole(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	// Valid framing, but the CNAME length exceeds the packet. Parsing appends
	// SSRC 6000 before discovering the malformed item.
	invalidSDES := []byte{
		0x81, 0xca, 0x00, 0x02,
		0x00, 0x00, 0x17, 0x70,
		0x01, 0xff, 0x00, 0x00,
	}
	pli, err := (&rtcp.PictureLossIndication{MediaSSRC: 5000}).Marshal()
	assert.NoError(t, err)

	aSession, bSession := buildSessionSRTCPPair(t)

	legitStream, err := bSession.OpenReadStream(5000)
	assert.NoError(t, err)
	// Pre-open the SSRC the malformed packet would partially report, so
	// leaking a delivery to it is observable instead of blocking.
	partialStream, err := bSession.OpenReadStream(6000)
	assert.NoError(t, err)

	compound := append(append([]byte{}, invalidSDES...), pli...)
	encrypted, err := aSession.session.localContext.EncryptRTCP(nil, compound, nil)
	assert.NoError(t, err)
	assert.Error(t, bSession.decrypt(encrypted, nil),
		"the malformed control packet must be reported")

	assert.NoError(t, legitStream.Close())
	assert.NoError(t, partialStream.Close())

	readBuffer := make([]byte, 200)
	n, err := legitStream.Read(readBuffer)
	assert.NoError(t, err)
	assert.Equal(t, pli, readBuffer[:n], "the valid packet must still be delivered")
	_, err = legitStream.Read(readBuffer)
	assert.ErrorIs(t, err, io.EOF)

	_, err = partialStream.Read(readBuffer)
	assert.ErrorIs(t, err, io.EOF,
		"partial destinations of a malformed packet must not receive the packet")

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

// TestSessionSRTCPUnknownControlNotDeliveredToMalformedDestination verifies
// that a packet without a destination of its own is scoped only to destinations
// of well-formed packets. SSRCs that a malformed packet partially reported
// before failing must not become delivery targets of trusted control data.
func TestSessionSRTCPUnknownControlNotDeliveredToMalformedDestination(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	// Valid framing, but the CNAME length exceeds the packet. Parsing appends
	// SSRC 6000 before discovering the malformed item.
	invalidSDES := []byte{
		0x81, 0xca, 0x00, 0x02,
		0x00, 0x00, 0x17, 0x70,
		0x01, 0xff, 0x00, 0x00,
	}
	pli, err := (&rtcp.PictureLossIndication{MediaSSRC: 5000}).Marshal()
	assert.NoError(t, err)
	unknown := []byte{0x80, 0xdd, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04}

	aSession, bSession := buildSessionSRTCPPair(t)

	legitStream, err := bSession.OpenReadStream(5000)
	assert.NoError(t, err)
	partialStream, err := bSession.OpenReadStream(6000)
	assert.NoError(t, err)

	compound := append(append(append([]byte{}, pli...), invalidSDES...), unknown...)
	encrypted, err := aSession.session.localContext.EncryptRTCP(nil, compound, nil)
	assert.NoError(t, err)
	assert.Error(t, bSession.decrypt(encrypted, nil))

	assert.NoError(t, legitStream.Close())
	assert.NoError(t, partialStream.Close())

	readBuffer := make([]byte, 200)
	for _, expected := range [][]byte{pli, unknown} {
		n, readErr := legitStream.Read(readBuffer)
		assert.NoError(t, readErr)
		assert.Equal(t, expected, readBuffer[:n])
	}
	_, err = legitStream.Read(readBuffer)
	assert.ErrorIs(t, err, io.EOF)

	_, err = partialStream.Read(readBuffer)
	assert.ErrorIs(t, err, io.EOF,
		"a partially parsed malformed destination must not receive trusted control data")

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

// TestSessionSRTCPDeliveryFailureIsIsolated verifies that a failure to queue a
// packet to one destination does not starve the other destinations of the same
// authenticated compound datagram.
func TestSessionSRTCPDeliveryFailureIsIsolated(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	xr := &rtcp.ExtendedReport{SenderSSRC: 1234, Reports: []rtcp.ReportBlock{
		&rtcp.LossRLEReportBlock{SSRC: 5000, Chunks: []rtcp.Chunk{0x4006, 0x0006}},
	}}
	pli := &rtcp.PictureLossIndication{MediaSSRC: 5000}
	compound, err := rtcp.Marshal([]rtcp.Packet{xr, pli})
	assert.NoError(t, err)

	aSession, bSession := buildSessionSRTCPPair(t)

	brokenStream, err := bSession.OpenReadStream(1234)
	assert.NoError(t, err)
	healthyStream, err := bSession.OpenReadStream(5000)
	assert.NoError(t, err)

	// Closing the buffer while the stream stays registered makes every write to
	// 1234 fail without touching the session table.
	assert.NoError(t, brokenStream.buffer.Close())

	encrypted, err := aSession.session.localContext.EncryptRTCP(nil, compound, nil)
	assert.NoError(t, err)
	assert.Error(t, bSession.decrypt(encrypted, nil), "the failed destination must be reported")

	// Both packets addressed to 5000 must still have been queued: the XR
	// references it via its report block, and the PLI is addressed to it.
	assert.NoError(t, healthyStream.Close())
	readBuffer := make([]byte, 200)
	for _, expected := range []rtcp.Packet{xr, pli} {
		expectedRaw, marshalErr := expected.Marshal()
		assert.NoError(t, marshalErr)
		n, readErr := healthyStream.Read(readBuffer)
		assert.NoError(t, readErr)
		assert.Equal(t, expectedRaw, readBuffer[:n])
	}

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

// TestSessionSRTCPFailedDeliveryLeavesNoStream verifies that a stream which
// cannot accept its first packet does not remain visible in the session. A
// subsequent datagram for a different SSRC must become the first accepted stream.
func TestSessionSRTCPFailedDeliveryLeavesNoStream(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const failingSSRC = uint32(5000)

	newConfig := func() *Config {
		return &Config{
			Profile: ProtectionProfileAes128CmHmacSha1_80,
			Keys: SessionKeys{
				[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
				[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
				[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
				[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
			},
			// A stream for failingSSRC gets a buffer that is already closed, so
			// its first write fails while any other SSRC works normally.
			BufferFactory: func(_ packetio.BufferPacketType, ssrc uint32) io.ReadWriteCloser {
				buff := &packetBuffer{Buffer: packetio.NewBuffer()}
				if ssrc == failingSSRC {
					_ = buff.Close()
				}

				return buff
			},
		}
	}

	aPipe, bPipe := net.Pipe()
	config := newConfig()
	aSession, err := NewSessionSRTCP(aPipe, config)
	assert.NoError(t, err)
	bSession, err := NewSessionSRTCP(bPipe, config)
	assert.NoError(t, err)

	failing, err := encryptSRTCP(aSession.session.localContext,
		&rtcp.PictureLossIndication{MediaSSRC: failingSSRC})
	assert.NoError(t, err)
	assert.Error(t, bSession.decrypt(failing, nil),
		"delivery to a closed stream must be reported")

	bSession.session.readStreamsLock.Lock()
	_, hasFailing := bSession.session.readStreams[failingSSRC]
	streamCount := len(bSession.session.readStreams)
	bSession.session.readStreamsLock.Unlock()
	assert.False(t, hasFailing, "a stream that accepted no packet must not stay registered")
	assert.Zero(t, streamCount)

	// A valid datagram for another SSRC still yields the first accepted stream.
	good, err := encryptSRTCP(aSession.session.localContext,
		&rtcp.PictureLossIndication{MediaSSRC: 6000})
	assert.NoError(t, err)

	accepted := make(chan uint32, 1)
	go func() {
		_, ssrc, acceptErr := bSession.AcceptStream()
		if acceptErr != nil {
			accepted <- 0

			return
		}
		accepted <- ssrc
	}()
	assert.NoError(t, bSession.decrypt(good, nil))
	assert.Equal(t, uint32(6000), <-accepted,
		"the next authenticated datagram must establish its stream")

	bSession.session.readStreamsLock.Lock()
	_, hasGood := bSession.session.readStreams[6000]
	_, stillHasFailing := bSession.session.readStreams[failingSSRC]
	bSession.session.readStreamsLock.Unlock()
	assert.True(t, hasGood, "the next authenticated datagram must establish its stream")
	assert.False(t, stillHasFailing, "the discarded stream must not come back")

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func encryptedPayloadLength(t *testing.T, encrypted []byte) int {
	t.Helper()

	authTagLen, err := ProtectionProfileAes128CmHmacSha1_80.AuthTagRTCPLen()
	assert.NoError(t, err)

	return len(encrypted) - authTagLen - srtcpIndexSize
}

func encryptSRTCP(context *Context, pkt rtcp.Packet) ([]byte, error) {
	decryptedRaw, err := pkt.Marshal()
	if err != nil {
		return nil, err
	}
	encryptInput := make([]byte, len(decryptedRaw), rtcpHeaderSize+len(decryptedRaw)+10)
	copy(encryptInput, decryptedRaw)
	encrypted, eerr := context.EncryptRTCP(encryptInput, encryptInput, nil)
	if eerr != nil {
		return nil, eerr
	}

	return encrypted, nil
}

func errIsTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "i/o timeout"): // error message when timeout before go1.15.
		return true
	case strings.Contains(s, "deadline exceeded"): // error message when timeout after go1.15.
		return true
	}

	return false
}
