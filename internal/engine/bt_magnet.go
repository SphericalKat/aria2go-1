package engine

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/smartass08/aria2go/internal/config"
	"github.com/smartass08/aria2go/internal/core"
	"github.com/smartass08/aria2go/internal/magnet"
	btpeer "github.com/smartass08/aria2go/internal/protocol/bittorrent/peer"
	"github.com/smartass08/aria2go/internal/torrent"
	"github.com/smartass08/aria2go/internal/tracker"
)

const (
	btMetadataRequestTimeout = 20 * time.Second
	btMetadataPollInterval   = 200 * time.Millisecond
	btMetadataLocalUTPexID   = 8
	btMetadataLocalUTMetaID  = 9
)

type magnetMetadataPeer struct {
	conn *btpeer.Conn
	addr string

	remoteUTMetadataID uint8
	requested          int
	requestedAt        time.Time
	closed             bool
}

type magnetMetadataEnvelope struct {
	peer   *magnetMetadataPeer
	msg    btpeer.Message
	closed bool
	err    error
}

type magnetMetadataSession struct {
	infoHash [20]byte

	mu         sync.Mutex
	totalSize  int
	pieces     [][]byte
	received   []bool
	receivedN  int
	inflight   map[int]*magnetMetadataPeer
	peers      []*magnetMetadataPeer
	hashErrors int
}

func newMagnetMetadataSession(infoHash [20]byte, peers []*magnetMetadataPeer) *magnetMetadataSession {
	return &magnetMetadataSession{
		infoHash: infoHash,
		peers:    peers,
		inflight: make(map[int]*magnetMetadataPeer),
	}
}

func (s *magnetMetadataSession) setMetadataSize(size int) error {
	if size <= 0 {
		return fmt.Errorf("peer did not provide valid metadata_size")
	}
	if size > btpeer.MaxMetadataSize {
		return fmt.Errorf("metadata_size %d exceeds %d", size, btpeer.MaxMetadataSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.totalSize != 0 {
		if s.totalSize != size {
			return fmt.Errorf("conflicting metadata_size values %d and %d", s.totalSize, size)
		}
		return nil
	}

	s.totalSize = size
	n := (size + btpeer.MetadataPieceSize - 1) / btpeer.MetadataPieceSize
	s.pieces = make([][]byte, n)
	s.received = make([]bool, n)
	return nil
}

func (s *magnetMetadataSession) metadataSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalSize
}

func (s *magnetMetadataSession) pieceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pieces)
}

func (s *magnetMetadataSession) nextPieceFor(peer *magnetMetadataPeer) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.totalSize == 0 {
		return 0, false
	}
	for i := range s.pieces {
		if s.received[i] {
			continue
		}
		if _, ok := s.inflight[i]; ok {
			continue
		}
		s.inflight[i] = peer
		return i, true
	}
	return 0, false
}

func (s *magnetMetadataSession) clearInflight(peer *magnetMetadataPeer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if peer.requested >= 0 {
		delete(s.inflight, peer.requested)
	}
}

func (s *magnetMetadataSession) expireTimedOutRequests(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, peer := range s.peers {
		if peer.closed || peer.requested < 0 {
			continue
		}
		if now.Sub(peer.requestedAt) < btMetadataRequestTimeout {
			continue
		}
		delete(s.inflight, peer.requested)
		peer.requested = -1
		peer.requestedAt = time.Time{}
	}
}

func (s *magnetMetadataSession) storePiece(peer *magnetMetadataPeer, piece int, totalSize int, data []byte) ([]byte, error) {
	if err := s.setMetadataSize(totalSize); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if piece < 0 || piece >= len(s.pieces) {
		return nil, fmt.Errorf("metadata piece %d out of range", piece)
	}

	start := piece * btpeer.MetadataPieceSize
	want := btpeer.MetadataPieceSize
	if remain := s.totalSize - start; remain < want {
		want = remain
	}
	if want < 0 {
		return nil, fmt.Errorf("metadata piece %d exceeds metadata size", piece)
	}
	if len(data) != want {
		return nil, fmt.Errorf("metadata piece %d length %d, want %d", piece, len(data), want)
	}

	if peer.requested == piece {
		delete(s.inflight, piece)
		peer.requested = -1
		peer.requestedAt = time.Time{}
	}

	if s.received[piece] {
		return nil, nil
	}

	s.pieces[piece] = append([]byte(nil), data...)
	s.received[piece] = true
	s.receivedN++
	if s.receivedN != len(s.pieces) {
		return nil, nil
	}

	metadata := make([]byte, 0, s.totalSize)
	for i, pieceData := range s.pieces {
		if len(pieceData) == 0 {
			return nil, fmt.Errorf("metadata piece %d missing", i)
		}
		metadata = append(metadata, pieceData...)
	}
	if len(metadata) != s.totalSize {
		return nil, fmt.Errorf("metadata length %d, want %d", len(metadata), s.totalSize)
	}

	sum := sha1.Sum(metadata)
	if sum != s.infoHash {
		s.hashErrors++
		for i := range s.pieces {
			s.pieces[i] = nil
			s.received[i] = false
		}
		s.receivedN = 0
		clear(s.inflight)
		for _, p := range s.peers {
			p.requested = -1
			p.requestedAt = time.Time{}
		}
		return nil, core.WrapError(core.ExitNetworkProblem, "got wrong ut_metadata", nil)
	}

	return metadata, nil
}

func (s *magnetMetadataSession) allPeersClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, peer := range s.peers {
		if !peer.closed {
			return false
		}
	}
	return true
}

func magnetMetadataName(m *magnet.Magnet) string {
	name := m.DisplayName
	if name == "" && m.InfoHashV1 != nil {
		name = fmt.Sprintf("%x", m.InfoHashV1[:])
	}
	if name == "" {
		name = "metadata"
	}
	return "[METADATA]" + strings.ReplaceAll(name, "/", "-")
}

func savedTorrentPath(dir string, infoHash [20]byte) string {
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, fmt.Sprintf("%x.torrent", infoHash[:]))
}

func magnetAnnounceList(m *magnet.Magnet) [][]string {
	if len(m.Trackers) == 0 {
		return nil
	}
	list := make([][]string, 0, len(m.Trackers))
	for _, tr := range m.Trackers {
		if tr == "" {
			continue
		}
		list = append(list, []string{tr})
	}
	return list
}

func tryWriteSavedMetadata(path string, data []byte) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func (e *Engine) tryLoadSavedMagnetTorrent(ctx context.Context, rg *requestGroup, m *magnet.Magnet) (bool, error) {
	if !rg.opts.BTLoadSavedMetadata || m.InfoHashV1 == nil {
		return false, nil
	}

	torrentPath := savedTorrentPath(rg.opts.Dir, *m.InfoHashV1)
	torrentData, err := os.ReadFile(torrentPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, core.WrapError(core.ExitFileIOError, "read saved metadata", err)
	}

	meta, err := torrent.Load(torrentData)
	if err != nil {
		e.log.Warn("saved metadata parse failed, falling back to peer metadata", "gid", rg.gid, "path", torrentPath, "error", err)
		return false, nil
	}
	infoHash, err := meta.InfoHash()
	if err != nil {
		e.log.Warn("saved metadata infohash failed, falling back to peer metadata", "gid", rg.gid, "path", torrentPath, "error", err)
		return false, nil
	}
	if infoHash != *m.InfoHashV1 {
		e.log.Warn("saved metadata infohash mismatch, falling back to peer metadata", "gid", rg.gid, "path", torrentPath)
		return false, nil
	}

	e.log.Info("BT metadata loaded from saved torrent", "gid", rg.gid, "path", torrentPath)
	return true, e.runBTDownload(ctx, rg, torrentData)
}

func (e *Engine) collectTrackerPeerAddrs(ctx context.Context, gid core.GID, infoHash [20]byte, urls []string) []string {
	if len(urls) == 0 {
		return nil
	}

	peerID := e.btSession.PeerID()
	req := tracker.AnnounceRequest{
		InfoHash: infoHash,
		PeerID:   peerID,
		Port:     uint16(e.btSession.Port()),
		Event:    "started",
		NumWant:  50,
	}

	var addrs []string
	for _, u := range urls {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue
		}
		resp, err := tracker.AnnounceHTTP(ctx, u, req, e.httpDriver)
		if err != nil {
			e.log.Warn("BT announce failed", "gid", gid, "url", u, "error", err)
			continue
		}
		for _, p := range resp.Peers {
			addrs = append(addrs, net.JoinHostPort(p.IP.String(), fmt.Sprintf("%d", p.Port)))
		}
		for _, p := range resp.Peers6 {
			addrs = append(addrs, net.JoinHostPort(p.IP.String(), fmt.Sprintf("%d", p.Port)))
		}
		e.log.Debug("BT announce ok", "gid", gid, "url", u, "peers", len(resp.Peers))
	}
	return addrs
}

func (e *Engine) collectDHTPeerAddrs(ctx context.Context, gid core.GID, infoHash [20]byte) []string {
	if e.dhtServer == nil {
		return nil
	}

	peerCh, err := e.dhtServer.GetPeers(ctx, infoHash)
	if err != nil {
		e.log.Warn("BT DHT get peers failed", "gid", gid, "error", err)
		return nil
	}

	var addrs []string
	for peerAddr := range peerCh {
		addrs = append(addrs, peerAddr.String())
	}
	return addrs
}

func appendUniquePeerAddrs(dst []string, seen map[string]struct{}, src ...string) []string {
	for _, addr := range src {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		dst = append(dst, addr)
	}
	return dst
}

func (e *Engine) collectMagnetPeerAddrs(ctx context.Context, gid core.GID, m *magnet.Magnet) []string {
	if m.InfoHashV1 == nil {
		return nil
	}

	seen := make(map[string]struct{})
	var addrs []string
	addrs = appendUniquePeerAddrs(addrs, seen, m.Peers...)
	addrs = appendUniquePeerAddrs(addrs, seen, e.collectTrackerPeerAddrs(ctx, gid, *m.InfoHashV1, m.Trackers)...)
	addrs = appendUniquePeerAddrs(addrs, seen, e.collectDHTPeerAddrs(ctx, gid, *m.InfoHashV1)...)
	return addrs
}

func (e *Engine) btMetadataPeerConfig(infoHash [20]byte) btpeer.Config {
	return btpeer.Config{
		InfoHash:    infoHash,
		LocalPeerID: e.btSession.PeerID(),
		Reserved:    btpeer.MakeReserved(false, true, e.dhtServer != nil),
		PieceLength: btpeer.MetadataPieceSize,
		Encrypt:     btMSEEncryption(e.cfg),
		Timeout:     btTimeout(e.cfg),
	}
}

func (e *Engine) connectMetadataPeers(ctx context.Context, addrs []string, cfg btpeer.Config) []*magnetMetadataPeer {
	maxPeers := e.cfg.BTMaxPeers
	if maxPeers <= 0 {
		maxPeers = btPeerConnectLimit
	}

	limit := make(chan struct{}, 8)
	var mu sync.Mutex
	peers := make([]*magnetMetadataPeer, 0, min(maxPeers, len(addrs)))
	launched := 0

	for _, addr := range addrs {
		if launched >= maxPeers {
			break
		}
		launched++

		limit <- struct{}{}
		go func(addr string) {
			defer func() { <-limit }()

			dialCtx, cancel := context.WithTimeout(ctx, btPeerDialTimeout)
			defer cancel()

			conn, err := btpeer.Dial(dialCtx, e.netDialer, addr, cfg)
			if err != nil {
				e.log.Debug("BT metadata peer dial failed", "addr", addr, "error", err)
				return
			}
			if !conn.PeerSupportsExtensionMessaging() {
				conn.Close()
				return
			}

			peer := &magnetMetadataPeer{
				conn:      conn,
				addr:      addr,
				requested: -1,
			}

			payload, err := btpeer.EncodeExtendedHandshakeKeys("", uint16(e.btSession.Port()), 0, map[int]uint8{
				btpeer.ExtensionUTPex:      btMetadataLocalUTPexID,
				btpeer.ExtensionUTMetadata: btMetadataLocalUTMetaID,
			})
			if err == nil {
				_ = conn.Extended(btpeer.ExtensionHandshakeID, payload)
			}
			if conn.PeerSupportsDHT() && e.dhtServer != nil {
				_ = conn.Port(uint16(e.btSession.DHTPort()))
			}

			mu.Lock()
			peers = append(peers, peer)
			mu.Unlock()
		}(addr)
	}

	for i := 0; i < cap(limit); i++ {
		limit <- struct{}{}
	}

	return peers
}

func (e *Engine) readMetadataPeer(ctx context.Context, peer *magnetMetadataPeer, ch chan<- magnetMetadataEnvelope) {
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- peer.conn.Run(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			peer.conn.Close()
			return
		case err := <-runErrCh:
			select {
			case ch <- magnetMetadataEnvelope{peer: peer, closed: true, err: err}:
			case <-ctx.Done():
			}
			return
		case msg, ok := <-peer.conn.Messages():
			if !ok {
				return
			}
			select {
			case ch <- magnetMetadataEnvelope{peer: peer, msg: msg}:
			case <-ctx.Done():
			}
		}
	}
}

func (e *Engine) requestMetadataPiece(peer *magnetMetadataPeer, piece int) error {
	payload, err := btpeer.EncodeUTMetadataRequest(piece)
	if err != nil {
		return err
	}
	if err := peer.conn.Extended(peer.remoteUTMetadataID, payload); err != nil {
		return err
	}
	peer.requested = piece
	peer.requestedAt = time.Now()
	return nil
}

func (e *Engine) assignMetadataRequests(session *magnetMetadataSession, rg *requestGroup) {
	for _, peer := range session.peers {
		if peer.closed || peer.remoteUTMetadataID == 0 || peer.requested >= 0 || session.metadataSize() == 0 {
			continue
		}
		piece, ok := session.nextPieceFor(peer)
		if !ok {
			continue
		}
		if err := e.requestMetadataPiece(peer, piece); err != nil {
			session.clearInflight(peer)
			peer.requested = -1
			peer.requestedAt = time.Time{}
			e.log.Debug("BT metadata request failed", "gid", rg.gid, "addr", peer.addr, "piece", piece, "error", err)
		}
	}
}

func (e *Engine) runMagnetMetadataSession(ctx context.Context, rg *requestGroup, m *magnet.Magnet) error {
	if m.InfoHashV1 == nil {
		return core.NewError(core.ExitMagnetParseError, "magnet link missing BitTorrent v1 info hash")
	}

	rg.inMemory = true
	rg.filePath = filepath.Join(rg.opts.Dir, magnetMetadataName(m))
	rg.fileName = filepath.Base(rg.filePath)

	addrs := e.collectMagnetPeerAddrs(ctx, rg.gid, m)
	cfg := e.btMetadataPeerConfig(*m.InfoHashV1)
	peers := e.connectMetadataPeers(ctx, addrs, cfg)
	if len(peers) == 0 {
		return core.NewError(core.ExitResourceNotFound, "no peers available")
	}

	rg.numConnections.Store(int64(len(peers)))

	session := newMagnetMetadataSession(*m.InfoHashV1, peers)
	msgCh := make(chan magnetMetadataEnvelope, len(peers)*4)

	peerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, peer := range peers {
		go e.readMetadataPeer(peerCtx, peer, msgCh)
	}

	ticker := time.NewTicker(btMetadataPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case env := <-msgCh:
			if env.closed {
				env.peer.closed = true
				session.clearInflight(env.peer)
				env.peer.requested = -1
				env.peer.requestedAt = time.Time{}
				if env.err != nil && !errors.Is(env.err, context.Canceled) && !errors.Is(env.err, btpeer.ErrPeerClosed) {
					e.log.Debug("BT metadata peer closed", "gid", rg.gid, "addr", env.peer.addr, "error", env.err)
				}
				rg.numConnections.Store(int64(activeMetadataPeers(session.peers)))
				if session.allPeersClosed() {
					return core.NewError(core.ExitResourceNotFound, "no peers available")
				}
				e.assignMetadataRequests(session, rg)
				continue
			}

			switch env.msg.ID {
			case btpeer.MsgExtended:
				extID, payload, err := btpeer.UnmarshalExtended(env.msg)
				if err != nil {
					env.peer.conn.Close()
					continue
				}
				if extID == btpeer.ExtensionHandshakeID {
					hs, err := btpeer.ParseExtendedHandshake(payload)
					if err != nil {
						env.peer.conn.Close()
						continue
					}
					env.peer.remoteUTMetadataID = hs.Extensions[btpeer.ExtensionNameUTMetadata]
					if env.peer.remoteUTMetadataID == 0 || hs.MetadataSize == 0 {
						env.peer.conn.Close()
						continue
					}
					if err := session.setMetadataSize(int(hs.MetadataSize)); err != nil {
						env.peer.conn.Close()
						continue
					}
					rg.statusMu.Lock()
					rg.totalLength = int64(hs.MetadataSize)
					rg.statusMu.Unlock()
					e.assignMetadataRequests(session, rg)
					continue
				}
				if env.peer.remoteUTMetadataID == 0 || extID != btMetadataLocalUTMetaID {
					continue
				}
				msg, err := btpeer.ParseUTMetadata(payload)
				if err != nil {
					env.peer.conn.Close()
					continue
				}
				switch msg.MessageType {
				case btpeer.UTMetadataData:
					metadata, err := session.storePiece(env.peer, msg.Piece, int(msg.TotalSize), msg.Data)
					if err != nil {
						e.log.Debug("BT metadata piece rejected", "gid", rg.gid, "addr", env.peer.addr, "piece", msg.Piece, "error", err)
						env.peer.conn.Close()
						continue
					}
					rg.statusMu.Lock()
					rg.completedLength = int64(metadataCompletedBytes(session))
					rg.statusMu.Unlock()
					if metadata != nil {
						cancel()
						for _, peer := range peers {
							peer.conn.Close()
						}
						return e.finishMagnetMetadata(rg, m, metadata)
					}
					e.assignMetadataRequests(session, rg)
				case btpeer.UTMetadataReject:
					env.peer.conn.Close()
				}
			}
		case <-ticker.C:
			session.expireTimedOutRequests(time.Now())
			e.assignMetadataRequests(session, rg)
			rg.statusMu.Lock()
			rg.completedLength = int64(metadataCompletedBytes(session))
			rg.statusMu.Unlock()
		}
	}
}

func metadataCompletedBytes(session *magnetMetadataSession) int {
	session.mu.Lock()
	defer session.mu.Unlock()
	total := 0
	for _, piece := range session.pieces {
		total += len(piece)
	}
	return total
}

func activeMetadataPeers(peers []*magnetMetadataPeer) int {
	n := 0
	for _, peer := range peers {
		if !peer.closed {
			n++
		}
	}
	return n
}

func (e *Engine) finishMagnetMetadata(rg *requestGroup, m *magnet.Magnet, metadata []byte) error {
	torrentData, err := torrent.FromMetadata(metadata, magnetAnnounceList(m))
	if err != nil {
		return err
	}

	if rg.opts.BTSaveMetadata {
		torrentPath := savedTorrentPath(rg.opts.Dir, *m.InfoHashV1)
		if err := tryWriteSavedMetadata(torrentPath, torrentData); err != nil {
			return core.WrapError(core.ExitFileIOError, "save metadata", err)
		}
	}

	if rg.opts.BTMetadataOnly {
		return nil
	}

	childOpts := config.Merge(rg.opts)
	if e.keepRunning && rg.opts.PauseMetadata {
		childOpts.Pause = true
	}

	childGID, err := e.Add(AddSpec{
		Torrent:   torrentData,
		Options:   childOpts,
		BelongsTo: rg.gid,
	})
	if err != nil {
		return err
	}

	rg.statusMu.Lock()
	rg.followedBy = append(rg.followedBy, childGID)
	rg.statusMu.Unlock()
	if child, ok := e.groups.getLocked(childGID); ok {
		child.statusMu.Lock()
		child.following = rg.gid
		child.statusMu.Unlock()
		e.groups.unlock(childGID)
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
