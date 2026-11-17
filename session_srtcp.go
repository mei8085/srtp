// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"errors"
	"net"
	"slices"
	"time"

	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"github.com/pion/transport/v5/packetio"
)

const defaultSessionSRTCPReplayProtectionWindow = 64

// SessionSRTCP implements io.ReadWriteCloser and provides a bi-directional SRTCP session
// SRTCP itself does not have a design like this, but it is common in most applications
// for local/remote to each have their own keying material. This provides those patterns
// instead of making everyone re-implement.
type SessionSRTCP struct {
	session
	writeStream *WriteStreamSRTCP

	// rawPackets is a scratch slice used in decrypt to avoid allocations, and should only
	// be used by decrypt() and not aliased or otherwise returned to a caller.
	rawPackets []rtcp.RawPacket

	// destinationSSRCs is a scratch slice used internally in decrypt to avoid allocations.
	destinationSSRCs []uint32

	// compoundSSRCs is a scratch slice used internally in decrypt to avoid allocations. It
	// is lazily populated upon receiving an unknown RTCP type with the SSRCs of all known
	// types in a compound RTCP packet.
	compoundSSRCs []uint32
}

// NewSessionSRTCP creates a SRTCP session using conn as the underlying transport.
func NewSessionSRTCP(conn net.Conn, config *Config) (*SessionSRTCP, error) { //nolint:dupl
	if config == nil {
		return nil, errNoConfig
	} else if conn == nil {
		return nil, errNoConn
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	localOpts := append(
		[]ContextOption{},
		config.LocalOptions...,
	)
	remoteOpts := append(
		[]ContextOption{
			// Default options
			SRTCPReplayProtection(defaultSessionSRTCPReplayProtectionWindow),
		},
		config.RemoteOptions...,
	)

	srtcpSession := &SessionSRTCP{
		session: session{
			nextConn:            conn,
			localOptions:        localOpts,
			remoteOptions:       remoteOpts,
			readStreams:         map[uint32]readStream{},
			newStream:           make(chan readStream),
			acceptStreamTimeout: config.AcceptStreamTimeout,
			started:             make(chan any),
			closed:              make(chan any),
			bufferFactory:       config.BufferFactory,
			log:                 loggerFactory.NewLogger("srtp"),
		},
	}
	srtcpSession.writeStream = &WriteStreamSRTCP{srtcpSession}

	err := srtcpSession.session.start(
		config.Keys.LocalMasterKey, config.Keys.LocalMasterSalt,
		config.Keys.RemoteMasterKey, config.Keys.RemoteMasterSalt,
		config.Profile,
		srtcpSession,
	)
	if err != nil {
		return nil, err
	}

	return srtcpSession, nil
}

// OpenWriteStream returns the global write stream for the Session.
func (s *SessionSRTCP) OpenWriteStream() (*WriteStreamSRTCP, error) {
	return s.writeStream, nil
}

// OpenReadStream opens a read stream for the given SSRC, it can be used
// if you want a certain SSRC, but don't want to wait for AcceptStream.
func (s *SessionSRTCP) OpenReadStream(ssrc uint32) (*ReadStreamSRTCP, error) {
	r, _ := s.session.getOrCreateReadStream(ssrc, s, newReadStreamSRTCP)

	if readStream, ok := r.(*ReadStreamSRTCP); ok {
		return readStream, nil
	}

	return nil, errFailedTypeAssertion
}

// AcceptStream returns a stream to handle RTCP for a single SSRC.
func (s *SessionSRTCP) AcceptStream() (*ReadStreamSRTCP, uint32, error) {
	stream, ok := <-s.newStream
	if !ok {
		return nil, 0, errStreamAlreadyClosed
	}

	readStream, ok := stream.(*ReadStreamSRTCP)
	if !ok {
		return nil, 0, errFailedTypeAssertion
	}

	return readStream, stream.GetSSRC(), nil
}

// Close ends the session.
func (s *SessionSRTCP) Close() error {
	return s.session.close()
}

// Private

func (s *SessionSRTCP) write(buf []byte) (int, error) {
	if _, ok := <-s.session.started; ok {
		return 0, errStartedChannelUsedIncorrectly
	}

	pbuf, ok := bufferpool.Get().(*[]byte)
	if !ok {
		return 0, errStartedChannelUsedIncorrectly
	}
	defer bufferpool.Put(pbuf)

	s.session.localContextMutex.Lock()
	encrypted, err := s.localContext.EncryptRTCP(*pbuf, buf, nil)
	s.session.localContextMutex.Unlock()

	if err != nil {
		return 0, err
	}

	return s.session.nextConn.Write(encrypted)
}

func (s *SessionSRTCP) setWriteDeadline(t time.Time) error {
	return s.session.nextConn.SetWriteDeadline(t)
}

// dedupeSSRCs sorts and removes duplicate SSRCs in place, preserving capacity.
func dedupeSSRCs(ssrcs []uint32) []uint32 {
	// Note: sort + compact was chosen over the more obvious choice
	// of using a map to dedupe for two reasons:
	//  - It is more performant on small slices (length under ~100,
	//    which will be almost all inputs)
	//  - To avoid allocations, the map would need to be reused, and
	//    if it ever grew large then subsequent small dedupes would
	//    have degraded performance due to needing to clear a larger
	//    map.
	if len(ssrcs) < 2 {
		return ssrcs
	}
	slices.Sort(ssrcs)

	return slices.Compact(ssrcs)
}

// appendDestinationSSRCs appends destinations from packets whose SSRCs can be parsed.
func appendDestinationSSRCs(dst []uint32, pkts []rtcp.RawPacket) []uint32 {
	for _, pkt := range pkts {
		ssrcCount := len(dst)
		var err error
		dst, err = pkt.ParseDestinationSSRC(dst)
		if err != nil {
			// A failed parse may have appended partial destinations.
			dst = dst[:ssrcCount]
		}
	}

	dst = dedupeSSRCs(dst)

	return dst
}

// joinErr appends err to errs, ignoring nil. The identity of a lone error is
// preserved so callers can still match a concrete failure value.
func joinErr(errs, err error) error {
	if err == nil {
		return errs
	}
	if errs == nil {
		return err
	}

	return errors.Join(errs, err)
}

// packetDestinations returns the SSRCs pkt has to be delivered to.
//
// Packets that cannot report their destination are abnormal control messages:
// the parser may have appended partial SSRCs before failing, so the returned
// destinations are discarded and the packet is not forwarded anywhere. Packets
// that legitimately carry no destination of their own (like unknown RTCP types
// parsed as rtcp.RawPacket) are scoped to the streams the compound packet is
// addressed to; they never get a stream of their own.
func (s *SessionSRTCP) packetDestinations(
	pkt rtcp.RawPacket,
	pkts []rtcp.RawPacket,
	compoundSSRCsComputed *bool,
) ([]uint32, error) {
	var err error
	s.destinationSSRCs, err = pkt.ParseDestinationSSRC(s.destinationSSRCs[:0])
	if err != nil {
		return nil, err
	}

	destinations := dedupeSSRCs(s.destinationSSRCs)
	if len(destinations) != 0 {
		return destinations, nil
	}

	if !*compoundSSRCsComputed {
		s.compoundSSRCs = appendDestinationSSRCs(s.compoundSSRCs[:0], pkts)
		*compoundSSRCsComputed = true
	}

	return s.compoundSSRCs, nil
}

// discardStream removes a read stream that was created for this datagram but
// never accepted a packet. Closing the buffer as well releases any reader that
// raced with OpenReadStream for the same SSRC instead of leaving it blocked on a
// stream that carried no trusted data.
func (s *SessionSRTCP) discardStream(ssrc uint32, readStream *ReadStreamSRTCP) {
	if err := readStream.Close(); err != nil {
		// The stream is already gone (closed concurrently) or was not inited;
		// either way no session entry is left behind for this SSRC.
		s.session.removeReadStream(ssrc)
	}
}

// deliverToStream queues an authenticated packet to the read stream of ssrc.
//
// A stream is published to AcceptStream only once it has accepted its first
// authenticated packet: a stream that could not be written is discarded again, so
// neither AcceptStream nor a later read can observe session state that never
// carried trusted data. The returned sessionClosed flag reports that the session
// is shutting down and delivery must stop.
func (s *SessionSRTCP) deliverToStream(
	ssrc uint32,
	pkt []byte,
	attrs packetio.Attributes,
) (sessionClosed bool, err error) {
	r, isNew := s.session.getOrCreateReadStream(ssrc, s, newReadStreamSRTCP)
	if r == nil {
		return true, nil // Session has been closed
	}

	readStream, ok := r.(*ReadStreamSRTCP)
	if !ok {
		if isNew {
			s.session.removeReadStream(ssrc)
		}

		return false, errFailedTypeAssertion
	}

	if _, writeErr := readStream.write(pkt, attrs); writeErr != nil {
		if isNew {
			s.discardStream(ssrc, readStream)
		}

		return false, writeErr
	}

	if isNew {
		if !s.session.acceptStreamTimeout.IsZero() {
			_ = s.session.nextConn.SetReadDeadline(time.Time{})
		}
		s.session.newStream <- readStream // Notify AcceptStream
	}

	return false, nil
}

// deliver forwards every packet of an authenticated compound datagram to the
// streams it is addressed to. A failure for one destination is reported but does
// not stop delivery to the remaining destinations, so a rejected stream cannot
// starve a legitimate control message in the same compound.
func (s *SessionSRTCP) deliver(pkts []rtcp.RawPacket, attrs packetio.Attributes) error {
	compoundSSRCsComputed := false
	var errs error
	for _, pkt := range pkts {
		destinations, destErr := s.packetDestinations(pkt, pkts, &compoundSSRCsComputed)
		if destErr != nil {
			errs = joinErr(errs, destErr)

			continue
		}

		for _, ssrc := range destinations {
			sessionClosed, deliverErr := s.deliverToStream(ssrc, pkt, attrs)
			if sessionClosed {
				return nil // Session has been closed
			}
			errs = joinErr(errs, deliverErr)
		}
	}

	return errs
}

// decrypt is called synchronously by the session's read loop and must not
// be called concurrently. It reuses scratch buffers that are not protected
// by a mutex.
//
// The authentication boundary comes first: a datagram that does not verify is
// rejected as a whole, before any SSRC in it can create a read stream, advance
// per-SSRC replay state, or trigger an AcceptStream notification. Only once the
// compound datagram has been authenticated and split into packets is anything
// routed; see deliver for the per-packet rules.
func (s *SessionSRTCP) decrypt(buf []byte, attrs packetio.Attributes) error {
	s.session.remoteContextMutex.Lock()
	decrypted, err := s.remoteContext.DecryptRTCP(buf, buf, nil)
	s.session.remoteContextMutex.Unlock()
	if err != nil {
		return err
	}

	s.rawPackets, err = rtcp.AppendRawPackets(s.rawPackets[:0], decrypted)
	if err != nil {
		// The compound framing is broken, so no packet in it can be attributed
		// to a stream with confidence.
		return err
	}

	return s.deliver(s.rawPackets, attrs)
}

// UpdateKey resets packet state with fresh keys.
func (s *SessionSRTCP) UpdateKey(keys SessionKeys, profile ProtectionProfile) error {
	return s.session.updateKey(keys, profile)
}
