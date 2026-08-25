package engine

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/smartass08/aria2go/internal/config"
	"github.com/smartass08/aria2go/internal/core"
	"github.com/smartass08/aria2go/internal/disk"
	btpeer "github.com/smartass08/aria2go/internal/protocol/bittorrent/peer"
	"github.com/smartass08/aria2go/internal/torrent"
	"github.com/smartass08/aria2go/internal/tracker"
)

const (
	btDHTPeerInterval      = 15 * time.Minute
	btDHTPeerIntervalLow   = 5 * time.Minute
	btDHTPeerIntervalZero  = time.Minute
	btDHTPeerRetryInterval = 5 * time.Second
	btDHTMaxRetries        = 10
	btInitialPeerTimeout   = 10 * time.Second
	btUTPexMessageID       = 1
)

type btTrackerSession struct {
	list                *tracker.AnnounceList
	trackerID           string
	interval            time.Duration
	minInterval         time.Duration
	userDefinedInterval time.Duration
	prevAnnounce        time.Time
	timeout             time.Duration
}

type btTrackerAnnounceKind int

const (
	btTrackerAnnounceDefault btTrackerAnnounceKind = iota
	btTrackerAnnounceStarted
	btTrackerAnnounceCompleted
	btTrackerAnnounceStopped
)

func newBTTrackerSession(meta *torrent.MetaInfo, opts *config.Options) *btTrackerSession {
	tiers := tracker.NormalizeAnnounceTiers(meta.Announce, meta.AnnounceList, opts.BTExcludeTracker, opts.BTTracker)
	if len(tiers) == 0 {
		return nil
	}
	return &btTrackerSession{
		list:                tracker.NewAnnounceList(tiers),
		interval:            trackerDefaultInterval(),
		minInterval:         trackerDefaultInterval(),
		userDefinedInterval: btTrackerInterval(opts),
		timeout:             btTrackerTimeout(opts),
	}
}

func (s *btTrackerSession) hasTrackers() bool {
	return s != nil && s.list != nil && s.list.CountTiers() > 0
}

func (s *btTrackerSession) nextDefaultDelay() time.Duration {
	if !s.hasTrackers() {
		return 0
	}
	if s.prevAnnounce.IsZero() {
		return 0
	}
	wait := s.minInterval
	if s.userDefinedInterval > 0 {
		wait = s.userDefinedInterval
	}
	if wait <= 0 {
		wait = trackerDefaultInterval()
	}
	elapsed := time.Since(s.prevAnnounce)
	if elapsed >= wait {
		return 0
	}
	return wait - elapsed
}

func (s *btTrackerSession) runDefault(ctx context.Context, announce func(context.Context, string, tracker.AnnounceRequest) (*tracker.AnnounceResponse, error), buildReq func(event string, numWant int, trackerID string) tracker.AnnounceRequest, needMorePeers func() bool, emit func(*tracker.AnnounceResponse)) {
	if !s.hasTrackers() {
		return
	}
	_ = s.announce(ctx, btTrackerAnnounceStarted, announce, buildReq, needMorePeers(), emit)

	timer := time.NewTimer(s.nextDefaultDelay())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			_ = s.announce(ctx, btTrackerAnnounceDefault, announce, buildReq, needMorePeers(), emit)
			wait := s.nextDefaultDelay()
			if wait < 0 {
				wait = 0
			}
			timer.Reset(wait)
		}
	}
}

func (s *btTrackerSession) announceCompleted(ctx context.Context, announce func(context.Context, string, tracker.AnnounceRequest) (*tracker.AnnounceResponse, error), buildReq func(event string, numWant int, trackerID string) tracker.AnnounceRequest, needMorePeers bool, emit func(*tracker.AnnounceResponse)) error {
	return s.announce(ctx, btTrackerAnnounceCompleted, announce, buildReq, needMorePeers, emit)
}

func (s *btTrackerSession) announceStopped(ctx context.Context, announce func(context.Context, string, tracker.AnnounceRequest) (*tracker.AnnounceResponse, error), buildReq func(event string, numWant int, trackerID string) tracker.AnnounceRequest) error {
	return s.announce(ctx, btTrackerAnnounceStopped, announce, buildReq, false, nil)
}

func (s *btTrackerSession) announce(ctx context.Context, kind btTrackerAnnounceKind, announce func(context.Context, string, tracker.AnnounceRequest) (*tracker.AnnounceResponse, error), buildReq func(event string, numWant int, trackerID string) tracker.AnnounceRequest, needMorePeers bool, emit func(*tracker.AnnounceResponse)) error {
	if !s.hasTrackers() {
		return nil
	}
	if s.list.AllTiersFailed() {
		s.list.ResetTier()
	}

	switch kind {
	case btTrackerAnnounceCompleted:
		if s.list.CountCompletedAllowedTier() == 0 {
			return nil
		}
		if !s.list.CurrentTierAcceptsCompletedEvent() {
			s.list.MoveToCompletedAllowedTier()
		}
		s.list.SetEvent(tracker.AnnounceCompleted)
	case btTrackerAnnounceStopped:
		if s.list.CountStoppedAllowedTier() == 0 {
			return nil
		}
		if !s.list.CurrentTierAcceptsStoppedEvent() {
			s.list.MoveToStoppedAllowedTier()
		}
		s.list.SetEvent(tracker.AnnounceStopped)
	}

	var lastErr error
	for !s.list.AllTiersFailed() {
		event := s.list.GetEventString()
		numWant := 0
		if needMorePeers {
			numWant = 50
		}
		req := buildReq(event, numWant, s.trackerID)
		callCtx := ctx
		var cancel context.CancelFunc
		if s.timeout > 0 {
			callCtx, cancel = context.WithTimeout(ctx, s.timeout)
		}
		resp, err := announce(callCtx, s.list.GetAnnounce(), req)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			lastErr = err
			s.list.AnnounceFailure()
			continue
		}
		s.onSuccess(resp)
		s.list.AnnounceSuccess()
		s.list.ResetTier()
		s.prevAnnounce = time.Now()
		if emit != nil && needMorePeers {
			emit(resp)
		}
		return nil
	}

	s.list.ResetTier()
	s.prevAnnounce = time.Now()
	return lastErr
}

func (s *btTrackerSession) onSuccess(resp *tracker.AnnounceResponse) {
	if resp == nil {
		return
	}
	if resp.TrackerID != "" {
		s.trackerID = resp.TrackerID
	}
	if resp.Interval > 0 {
		s.interval = time.Duration(resp.Interval) * time.Second
	}
	if resp.MinInterval > 0 {
		s.minInterval = time.Duration(resp.MinInterval) * time.Second
		if s.interval > 0 && s.minInterval > s.interval {
			s.minInterval = s.interval
		}
	} else if s.interval > 0 {
		s.minInterval = s.interval
	}
	if s.minInterval <= 0 {
		s.minInterval = trackerDefaultInterval()
	}
	if s.interval <= 0 {
		s.interval = s.minInterval
	}
}

func trackerDefaultInterval() time.Duration {
	return 2 * time.Minute
}

func btTrackerTimeout(opts *config.Options) time.Duration {
	if opts == nil {
		return 60 * time.Second
	}
	if n, err := strconv.Atoi(opts.BTTrackerTimeout); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 60 * time.Second
}

func btTrackerInterval(opts *config.Options) time.Duration {
	if opts == nil {
		return 0
	}
	if n, err := strconv.Atoi(opts.BTTrackerInterval); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}

func btTrackerCryptoSupport(opts *config.Options) string {
	if opts == nil {
		return ""
	}
	if opts.BTRequireCrypto || opts.BTForceEncryption || strings.EqualFold(opts.BTMinCryptoLevel, "arc4") {
		return "requirecrypto"
	}
	return "supportcrypto"
}

func btMaxPeers(opts *config.Options) int {
	if opts == nil {
		return btPeerConnectLimit
	}
	if opts.BTMaxPeers < 0 {
		return btPeerConnectLimit
	}
	return opts.BTMaxPeers
}

func btMinPeers(maxPeers int) int {
	if maxPeers == 0 {
		return 0
	}
	minPeers := int(float64(maxPeers) * 0.8)
	if minPeers == 0 {
		minPeers = maxPeers
	}
	return minPeers
}

func btNeedsMorePeers(peerCount int, maxPeers int) bool {
	minPeers := btMinPeers(maxPeers)
	return minPeers == 0 || peerCount < minPeers
}

func btCompletedLength(adaptor disk.Adaptor, meta *torrent.MetaInfo) int64 {
	if adaptor == nil || meta == nil {
		return 0
	}
	var completed int64
	total := meta.TotalSize()
	pieceLen := meta.Info.PieceLength
	for i := 0; i < meta.NumPieces(); i++ {
		if !adaptor.Have(i) {
			continue
		}
		length := pieceLen
		if i == meta.NumPieces()-1 {
			if rem := total % pieceLen; rem > 0 {
				length = rem
			}
		}
		completed += length
	}
	return completed
}

func peerPort(addr string) uint16 {
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return 0
	}
	return uint16(port)
}

func normalizePeerAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	return net.JoinHostPort(host, port)
}

func (e *Engine) runInboundPeerBridge(ctx context.Context, swarm *btSwarm, inbound <-chan *btpeer.Conn, newPeers chan<- *peerState) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn, ok := <-inbound:
			if !ok {
				return
			}
			if conn == nil {
				continue
			}
			if err := e.configurePeerConnection(conn, swarm); err != nil {
				_ = conn.Close()
				continue
			}
			state := &peerState{
				conn:          conn,
				addr:          normalizePeerAddr(conn.RemoteAddr().String()),
				peerID:        conn.RemotePeerID(),
				pieces:        swarm.numPieces,
				incoming:      true,
				connectedAt:   time.Now(),
				amChoking:     true,
				peerChoking:   true,
				lastRateCheck: time.Now(),
			}
			select {
			case newPeers <- state:
			case <-ctx.Done():
				_ = conn.Close()
				return
			}
		}
	}
}

func (e *Engine) runPeerConnector(ctx context.Context, swarm *btSwarm, addrs <-chan string, newPeers chan<- *peerState, cfg btpeer.Config) {
	maxPeers := btMaxPeers(e.cfg)
	resultCh := make(chan peerConnectResult, 32)
	dropCh := swarm.dropCh
	pending := make(map[string]struct{})
	connected := make(map[string]struct{})
	limit := make(chan struct{}, 8)

	for {
		select {
		case <-ctx.Done():
			return
		case addr := <-dropCh:
			delete(connected, addr)
		case res := <-resultCh:
			delete(pending, res.addr)
			if res.err != nil || res.peer == nil {
				continue
			}
			connected[res.addr] = struct{}{}
			select {
			case newPeers <- res.peer:
			case <-ctx.Done():
				return
			}
		case addr, ok := <-addrs:
			if !ok {
				addrs = nil
				continue
			}
			addr = normalizePeerAddr(addr)
			if addr == "" {
				continue
			}
			if _, ok := pending[addr]; ok {
				continue
			}
			if _, ok := connected[addr]; ok {
				continue
			}
			if maxPeers > 0 && !swarm.canAcceptMorePeers(maxPeers) {
				continue
			}
			pending[addr] = struct{}{}
			limit <- struct{}{}
			go func(addr string) {
				defer func() { <-limit }()

				dialCtx, cancel := context.WithTimeout(ctx, btPeerDialTimeout)
				defer cancel()

				conn, err := e.btSession.Dial(dialCtx, e.netDialer, addr, cfg)
				if err != nil {
					e.log.Debug("BT peer dial failed", "addr", addr, "error", err)
					sendPeerConnectResult(ctx, resultCh, peerConnectResult{addr: addr, err: err})
					return
				}

				if err := e.configurePeerConnection(conn, swarm); err != nil {
					_ = conn.Close()
					sendPeerConnectResult(ctx, resultCh, peerConnectResult{addr: addr, err: err})
					return
				}

				sendPeerConnectResult(ctx, resultCh, peerConnectResult{
					addr: addr,
					peer: &peerState{
						conn:          conn,
						addr:          addr,
						peerID:        conn.RemotePeerID(),
						pieces:        swarm.numPieces,
						connectedAt:   time.Now(),
						amChoking:     true,
						peerChoking:   true,
						lastRateCheck: time.Now(),
					},
				})
			}(addr)
		}
	}
}

type peerConnectResult struct {
	addr string
	peer *peerState
	err  error
}

func sendPeerConnectResult(ctx context.Context, ch chan<- peerConnectResult, result peerConnectResult) {
	select {
	case ch <- result:
	case <-ctx.Done():
	}
}

func (e *Engine) configurePeerConnection(conn *btpeer.Conn, swarm *btSwarm) error {
	if swarm.pexEnabled && conn.PeerSupportsExtensionMessaging() {
		payload, err := btpeer.EncodeExtendedHandshakeKeys("", uint16(e.btSession.Port()), 0, map[int]uint8{
			btpeer.ExtensionUTPex: btUTPexMessageID,
		})
		if err != nil {
			return err
		}
		if err := conn.Extended(btpeer.ExtensionHandshakeID, payload); err != nil {
			return err
		}
	}
	if swarm.dhtObserver != nil && conn.PeerSupportsDHT() && e.btSession.DHTPort() > 0 {
		if err := conn.Port(uint16(e.btSession.DHTPort())); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) runDHTPeerDiscovery(ctx context.Context, infoHash [20]byte, swarm *btSwarm, out chan<- string) {
	if e.dhtServer == nil || swarm.meta.Info.Private {
		return
	}

	maxPeers := btMaxPeers(e.cfg)
	retries := 0
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		getCtx, cancel := context.WithTimeout(ctx, btTrackerTimeout(e.cfg))
		ch, err := e.dhtServer.GetPeers(getCtx, infoHash)
		if err == nil {
			for addr := range ch {
				select {
				case out <- addr.String():
				case <-ctx.Done():
					cancel()
					return
				}
			}
		}
		_ = e.dhtServer.Announce(getCtx, infoHash, e.btSession.Port())
		cancel()

		if maxPeers == 0 || swarm.peerCount() < maxPeers {
			if retries < btDHTMaxRetries {
				retries++
			}
		} else {
			retries = 0
		}
		timer.Reset(nextDHTDiscoveryDelay(swarm.peerCount(), btMinPeers(maxPeers), retries))
	}
}

func nextDHTDiscoveryDelay(peerCount, minPeers, retries int) time.Duration {
	switch {
	case minPeers == 0 || peerCount < minPeers:
		if retries > 0 {
			return btDHTPeerRetryInterval
		}
		if peerCount == 0 {
			return btDHTPeerIntervalZero
		}
		return btDHTPeerIntervalLow
	case peerCount == 0:
		return btDHTPeerIntervalZero
	default:
		return btDHTPeerInterval
	}
}

func (e *Engine) announceTracker(ctx context.Context, rawURL string, req tracker.AnnounceRequest) (*tracker.AnnounceResponse, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("tracker: parse %q: %w", rawURL, err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "udp":
		return tracker.AnnounceUDP(ctx, rawURL, req, e.netDialer)
	case "http", "https":
		return tracker.AnnounceHTTP(ctx, rawURL, req, e.httpDriver)
	default:
		return nil, fmt.Errorf("tracker: unsupported scheme %q", parsed.Scheme)
	}
}

func (e *Engine) waitForInitialPeer(ctx context.Context, peers <-chan *peerState) (*peerState, error) {
	timer := time.NewTimer(btInitialPeerTimeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, fmt.Errorf("bt: no peers available")
		case peer := <-peers:
			if peer != nil {
				return peer, nil
			}
		}
	}
}

func (e *Engine) buildTrackerRequest(meta *torrent.MetaInfo, infoHash [20]byte, rg *requestGroup, swarm *btSwarm, event string, numWant int, trackerID string) tracker.AnnounceRequest {
	completed := btCompletedLength(swarm.adaptor, meta)
	left := meta.TotalSize() - completed
	if left < 0 {
		left = 0
	}
	return tracker.AnnounceRequest{
		InfoHash:      infoHash,
		PeerID:        e.btSession.PeerID(),
		Port:          uint16(e.btSession.Port()),
		Uploaded:      swarm.uploadedLength(),
		Downloaded:    completed,
		Left:          left,
		Event:         event,
		NumWant:       numWant,
		TrackerID:     trackerID,
		CryptoSupport: btTrackerCryptoSupport(rg.opts),
		ExternalIP:    rg.opts.BTExternalIP,
	}
}

func (s *btSwarm) uploadedLength() int64 {
	s.mu.Lock()
	peers := make([]*peerState, len(s.peers))
	copy(peers, s.peers)
	s.mu.Unlock()

	var uploaded int64
	for _, peer := range peers {
		uploaded += peer.conn.Snapshot().Uploaded
	}
	return uploaded
}

func emitTrackerPeers(out chan<- string, resp *tracker.AnnounceResponse) {
	if resp == nil {
		return
	}
	for _, peer := range resp.Peers {
		select {
		case out <- net.JoinHostPort(peer.IP.String(), strconv.Itoa(int(peer.Port))):
		default:
		}
	}
	for _, peer := range resp.Peers6 {
		select {
		case out <- net.JoinHostPort(peer.IP.String(), strconv.Itoa(int(peer.Port))):
		default:
		}
	}
}

func markBTCanceled(rg *requestGroup) {
	if rg == nil {
		return
	}
	rg.setError(core.ExitRemoved, "download cancelled")
}

func completedFromBytes(rg *requestGroup) int64 {
	if rg == nil {
		return 0
	}
	return atomic.LoadInt64(&rg.bytesDownloaded)
}
