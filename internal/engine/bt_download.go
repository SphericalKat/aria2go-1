package engine

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartass08/aria2go/internal/config"
	"github.com/smartass08/aria2go/internal/core"
	"github.com/smartass08/aria2go/internal/disk"
	"github.com/smartass08/aria2go/internal/mse"
	btpeer "github.com/smartass08/aria2go/internal/protocol/bittorrent/peer"
	"github.com/smartass08/aria2go/internal/torrent"
	"github.com/smartass08/aria2go/internal/tracker"
)

const (
	btBlockSize          = 16 * 1024
	btMaxPendingRequests = 4
	btChokeInterval      = 10 * time.Second
	btUnchokeSlots       = 3
	btEndgameThreshold   = 10
	btPeerDialTimeout    = 15 * time.Second
	btPeerConnectLimit   = 55
	btPEXInterval        = time.Minute
)

// btPieceSource adapts disk.Adaptor to btpeer.PieceSource.
type btPieceSource struct {
	adaptor   disk.Adaptor
	numPieces int
}

func (p *btPieceSource) NumPieces() int   { return p.numPieces }
func (p *btPieceSource) Have(i int) bool  { return p.adaptor.Have(i) }
func (p *btPieceSource) Bitfield() []byte { return p.adaptor.Bitfield() }

// peerState tracks a connected BT peer and its piece availability.
type peerState struct {
	conn     *btpeer.Conn
	addr     string
	peerID   [20]byte
	bitfield []byte
	pieces   int
	incoming bool

	dlBytes        int64
	lastDLSnapshot int64
	ulBytes        int64
	lastULSnapshot int64

	outstanding   int
	connectedAt   time.Time
	lastRateCheck time.Time
	pexID         uint8
	amChoking     bool
	peerChoking   bool
}

func (p *peerState) hasPiece(idx int) bool {
	if idx < 0 || idx >= p.pieces || p.bitfield == nil {
		return false
	}
	byteIdx := idx / 8
	bitIdx := 7 - (idx % 8)
	if byteIdx >= len(p.bitfield) {
		return false
	}
	return p.bitfield[byteIdx]&(1<<bitIdx) != 0
}

func (p *peerState) hasAllPieces() bool {
	if p.bitfield == nil || p.pieces == 0 {
		return false
	}
	nbytes := (p.pieces + 7) / 8
	for i := 0; i < nbytes-1; i++ {
		if p.bitfield[i] != 0xff {
			return false
		}
	}
	if nbytes > 0 {
		lastBits := p.pieces % 8
		mask := byte(0xff)
		if lastBits != 0 {
			mask = byte(0xff << (8 - lastBits))
		}
		if p.bitfield[nbytes-1] != mask {
			return false
		}
	}
	return true
}

func (p *peerState) setPiece(idx int) {
	if idx < 0 || idx >= p.pieces || p.bitfield == nil {
		return
	}
	byteIdx := idx / 8
	bitIdx := 7 - (idx % 8)
	p.bitfield[byteIdx] |= 1 << bitIdx
}

func (p *peerState) dlRate() int64 {
	snap := p.dlBytes
	delta := snap - p.lastDLSnapshot
	p.lastDLSnapshot = snap
	return delta
}

func (p *peerState) ulRate() int64 {
	snap := p.ulBytes
	delta := snap - p.lastULSnapshot
	p.lastULSnapshot = snap
	return delta
}

func (p *peerState) speedSnapshot(now time.Time) (int64, int64) {
	if p.lastRateCheck.IsZero() {
		p.lastRateCheck = now
		p.lastDLSnapshot = p.dlBytes
		p.lastULSnapshot = p.ulBytes
		return 0, 0
	}
	elapsed := now.Sub(p.lastRateCheck)
	if elapsed <= 0 {
		return 0, 0
	}
	p.lastRateCheck = now
	dl := int64(float64(p.dlRate()) / elapsed.Seconds())
	ul := int64(float64(p.ulRate()) / elapsed.Seconds())
	return dl, ul
}

// peerMsg pairs a received peer message with its source peer.
type peerMsg struct {
	src *peerState
	msg btpeer.Message
}

type droppedPeerState struct {
	peer      btpeer.PEXPeer
	droppedAt time.Time
}

// btSwarm manages peer connections and piece download state for a BT download.
type btSwarm struct {
	mu    sync.Mutex
	peers []*peerState

	adaptor     disk.Adaptor
	meta        *torrent.MetaInfo
	numPieces   int
	pieceLen    int64
	pieceHashes []byte
	discoveryCh chan<- string
	dropCh      chan string
	dhtObserver func(net.IP, uint16)
	pexEnabled  bool

	recentDropped []droppedPeerState
}

func (s *btSwarm) addPeer(p *peerState) {
	s.mu.Lock()
	s.peers = append(s.peers, p)
	s.mu.Unlock()
}

func (s *btSwarm) peerCount() int {
	s.mu.Lock()
	n := len(s.peers)
	s.mu.Unlock()
	return n
}

func (s *btSwarm) seedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for _, peer := range s.peers {
		if peer.hasAllPieces() {
			n++
		}
	}
	return n
}

func (s *btSwarm) updateStats(rg *requestGroup) {
	rg.numConnections.Store(int64(s.peerCount()))
	rg.numSeeders.Store(int64(s.seedCount()))
}

func (s *btSwarm) canAcceptMorePeers(limit int) bool {
	if limit <= 0 {
		return true
	}
	return s.peerCount() < limit
}

func (s *btSwarm) removePeer(p *peerState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, peer := range s.peers {
		if peer != p {
			continue
		}
		s.peers = append(s.peers[:i], s.peers[i+1:]...)
		break
	}

	host, _, err := net.SplitHostPort(p.addr)
	if err == nil {
		host = strings.Trim(host, "[]")
		if ip := net.ParseIP(host); ip != nil {
			s.recentDropped = append(s.recentDropped, droppedPeerState{
				peer: btpeer.PEXPeer{
					IP:     ip,
					Port:   peerPort(p.addr),
					Seeder: p.hasAllPieces(),
				},
				droppedAt: time.Now(),
			})
		}
	}
	cutoff := time.Now().Add(-btPEXInterval)
	kept := s.recentDropped[:0]
	for _, dropped := range s.recentDropped {
		if dropped.droppedAt.After(cutoff) {
			kept = append(kept, dropped)
		}
	}
	s.recentDropped = kept

	if s.dropCh != nil {
		select {
		case s.dropCh <- p.addr:
		default:
		}
	}
}

func (s *btSwarm) snapshotFreshPeers(excludeAddr string) []btpeer.PEXPeer {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-btPEXInterval)
	peers := make([]btpeer.PEXPeer, 0, len(s.peers))
	for _, peer := range s.peers {
		if peer.addr == excludeAddr || peer.connectedAt.Before(cutoff) {
			continue
		}
		host, _, err := net.SplitHostPort(peer.addr)
		if err != nil {
			continue
		}
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		peers = append(peers, btpeer.PEXPeer{
			IP:     ip,
			Port:   peerPort(peer.addr),
			Seeder: peer.hasAllPieces(),
		})
	}
	return peers
}

func (s *btSwarm) snapshotDroppedPeers(excludeAddr string) []btpeer.PEXPeer {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-btPEXInterval)
	peers := make([]btpeer.PEXPeer, 0, len(s.recentDropped))
	kept := s.recentDropped[:0]
	for _, dropped := range s.recentDropped {
		if dropped.droppedAt.After(cutoff) {
			kept = append(kept, dropped)
			addr := net.JoinHostPort(dropped.peer.IP.String(), strconv.Itoa(int(dropped.peer.Port)))
			if addr != excludeAddr {
				peers = append(peers, dropped.peer)
			}
		}
	}
	s.recentDropped = kept
	return peers
}

func (s *btSwarm) complete() bool {
	for i := 0; i < s.numPieces; i++ {
		if !s.adaptor.Have(i) {
			return false
		}
	}
	return true
}

func (s *btSwarm) missingCount() int {
	n := 0
	for i := 0; i < s.numPieces; i++ {
		if !s.adaptor.Have(i) {
			n++
		}
	}
	return n
}

func (s *btSwarm) endgameMode() bool {
	missing := s.missingCount()
	return missing > 0 && missing <= btEndgameThreshold
}

// choosePiece selects the rarest piece this peer has that we're missing.
// Matches aria2's rarest-first piece selection in DefaultPieceStorage.
func (s *btSwarm) choosePiece(p *peerState) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.choosePieceLocked(p)
}

func (s *btSwarm) choosePieceLocked(p *peerState) (int, bool) {
	avail := make(map[int]int, s.numPieces)
	for _, peer := range s.peers {
		if peer == p {
			continue
		}
		for i := 0; i < s.numPieces; i++ {
			if !s.adaptor.Have(i) && peer.hasPiece(i) {
				avail[i]++
			}
		}
	}

	best := -1
	bestAvail := -1
	for i := 0; i < s.numPieces; i++ {
		if s.adaptor.Have(i) || !p.hasPiece(i) {
			continue
		}
		a := avail[i]
		if best == -1 || a < bestAvail {
			best = i
			bestAvail = a
		}
	}
	return best, best >= 0
}

func (s *btSwarm) closeAll() {
	s.mu.Lock()
	for _, p := range s.peers {
		p.conn.Close()
	}
	s.mu.Unlock()
}

func (s *btSwarm) snapshotPeers() []PeerStatus {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	peers := make([]PeerStatus, 0, len(s.peers))
	for _, peer := range s.peers {
		host, port, err := net.SplitHostPort(peer.addr)
		if err != nil {
			host = peer.addr
			port = "0"
		}
		if peer.incoming {
			port = "0"
		}
		host = strings.Trim(host, "[]")
		downloadSpeed, uploadSpeed := peer.speedSnapshot(now)
		peers = append(peers, PeerStatus{
			PeerID:        torrentPercentEncode(peer.peerID[:]),
			IP:            host,
			Port:          port,
			Bitfield:      hex.EncodeToString(peer.bitfield),
			AmChoking:     peer.amChoking,
			PeerChoking:   peer.peerChoking,
			DownloadSpeed: downloadSpeed,
			UploadSpeed:   uploadSpeed,
			Seeder:        peer.hasAllPieces(),
		})
	}
	return peers
}

func torrentPercentEncode(data []byte) string {
	var b strings.Builder
	b.Grow(len(data) * 3)
	for _, c := range data {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte("0123456789ABCDEF"[c>>4])
			b.WriteByte("0123456789ABCDEF"[c&0x0F])
		}
	}
	return b.String()
}

func (s *btSwarm) sendPeerExchange() {
	if !s.pexEnabled {
		return
	}

	s.mu.Lock()
	peers := make([]*peerState, len(s.peers))
	copy(peers, s.peers)
	s.mu.Unlock()

	for _, peer := range peers {
		extID := peer.conn.ExtensionMessageID(btpeer.ExtensionUTPex)
		if extID == 0 {
			continue
		}
		added := s.snapshotFreshPeers(peer.addr)
		dropped := s.snapshotDroppedPeers(peer.addr)
		if len(added) == 0 && len(dropped) == 0 {
			continue
		}
		payload, err := btpeer.MarshalUTPexPayload(added, dropped)
		if err != nil {
			continue
		}
		_ = peer.conn.Extended(extID, payload)
	}
}

func (s *btSwarm) verifyPiece(idx int) error {
	blen := s.pieceLen
	if idx == s.numPieces-1 {
		rem := s.meta.TotalSize() % s.pieceLen
		if rem > 0 {
			blen = rem
		}
	}
	offset := int64(idx) * s.pieceLen
	buf := make([]byte, blen)
	n, err := s.adaptor.ReadAt(buf, offset)
	if err != nil && n == 0 {
		return fmt.Errorf("read piece %d for verify: %w", idx, err)
	}
	expected := s.pieceHashes[idx*20 : (idx+1)*20]
	actual := sha1.Sum(buf[:n])
	if actual != *(*[20]byte)(expected) {
		return fmt.Errorf("piece %d hash mismatch", idx)
	}
	s.adaptor.MarkPiece(idx, true)
	return nil
}

// doChoke implements aria2's choking algorithm (PeerChokeCommand.cc).
// Unchokes the top N peers by download rate, plus one optimistic unchoke.
// Chokes all others.
func (s *btSwarm) doChoke() {
	s.mu.Lock()
	defer s.mu.Unlock()

	type rated struct {
		p    *peerState
		rate int64
	}
	rates := make([]rated, 0, len(s.peers))
	for _, p := range s.peers {
		rates = append(rates, rated{p, p.dlRate()})
	}
	sort.Slice(rates, func(i, j int) bool {
		return rates[i].rate > rates[j].rate
	})

	unchoked := 0
	for i := range rates {
		if unchoked < btUnchokeSlots && !rates[i].p.hasAllPieces() {
			if rates[i].p.conn.Unchoke() == nil {
				rates[i].p.amChoking = false
				unchoked++
			}
		} else {
			if rates[i].p.conn.Choke() == nil {
				rates[i].p.amChoking = true
			}
		}
	}

	if len(rates) > unchoked {
		pool := rates[unchoked:]
		if len(pool) > 0 {
			opt := pool[rand.IntN(len(pool))]
			if opt.p.conn.Unchoke() == nil {
				opt.p.amChoking = false
			}
		}
	}
}

func (s *btSwarm) handleMsg(msg peerMsg) {
	switch msg.msg.ID {
	case btpeer.MsgChoke:
		s.mu.Lock()
		msg.src.peerChoking = true
		s.mu.Unlock()
	case btpeer.MsgUnchoke:
		s.mu.Lock()
		msg.src.peerChoking = false
		s.mu.Unlock()
	case btpeer.MsgBitfield:
		s.mu.Lock()
		bf := msg.msg.Payload
		nbytes := (s.numPieces + 7) / 8
		msg.src.bitfield = make([]byte, nbytes)
		copy(msg.src.bitfield, bf)
		msg.src.pieces = s.numPieces
		s.mu.Unlock()
	case btpeer.MsgHave:
		idx, err := btpeer.UnmarshalHave(msg.msg)
		if err == nil {
			s.mu.Lock()
			msg.src.setPiece(idx)
			s.mu.Unlock()
		}
	case btpeer.MsgHaveAll:
		s.mu.Lock()
		if msg.src.bitfield == nil {
			nbytes := (s.numPieces + 7) / 8
			msg.src.bitfield = make([]byte, nbytes)
		}
		for i := range msg.src.bitfield {
			msg.src.bitfield[i] = 0xff
		}
		if s.numPieces > 0 && len(msg.src.bitfield) > 0 {
			lastBits := s.numPieces % 8
			if lastBits != 0 {
				msg.src.bitfield[len(msg.src.bitfield)-1] = byte(0xff << (8 - lastBits))
			}
		}
		msg.src.pieces = s.numPieces
		s.mu.Unlock()
	case btpeer.MsgHaveNone:
		s.mu.Lock()
		if msg.src.bitfield != nil {
			for i := range msg.src.bitfield {
				msg.src.bitfield[i] = 0
			}
		}
		s.mu.Unlock()
	case btpeer.MsgExtended:
		s.handleExtended(msg)
	case btpeer.MsgPort:
		s.handlePort(msg)
	}
}

func (s *btSwarm) handleExtended(msg peerMsg) {
	extID, payload, err := btpeer.UnmarshalExtended(msg.msg)
	if err != nil {
		return
	}
	if extID == btpeer.ExtensionHandshakeID {
		hs, err := btpeer.ParseExtendedHandshake(payload)
		if err != nil {
			return
		}
		if extID := hs.Extensions[btpeer.ExtensionNameUTPex]; extID != 0 {
			msg.src.conn.SetExtensionMessageID(btpeer.ExtensionUTPex, extID)
			msg.src.pexID = extID
		}
		return
	}

	pexMsg := btpeer.NewMessage(btpeer.MsgExtended, append([]byte{extID}, payload...))
	peerExtID, pex, err := btpeer.ParseUTPex(pexMsg)
	if err != nil || peerExtID == 0 || peerExtID != msg.src.conn.ExtensionMessageID(btpeer.ExtensionUTPex) {
		return
	}
	if s.discoveryCh == nil {
		return
	}
	for _, peer := range pex.Added {
		addr := net.JoinHostPort(peer.IP.String(), strconv.Itoa(int(peer.Port)))
		select {
		case s.discoveryCh <- addr:
		default:
		}
	}
}

func (s *btSwarm) handlePort(msg peerMsg) {
	if s.dhtObserver == nil {
		return
	}
	port, err := btpeer.UnmarshalPort(msg.msg)
	if err != nil || port == 0 {
		return
	}
	host, _, err := net.SplitHostPort(msg.src.addr)
	if err != nil {
		return
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return
	}
	s.dhtObserver(ip, port)
}

// runBTDownload executes a BitTorrent download for the given requestGroup.
func (e *Engine) runBTDownload(ctx context.Context, rg *requestGroup, torrentData []byte) error {
	meta, err := torrent.Load(torrentData)
	if err != nil {
		e.log.Error("BT torrent parse failed", "gid", rg.gid, "error", err)
		rg.errCode = core.ExitTorrentParseError
		rg.errMsg = err.Error()
		return err
	}

	infoHash, err := meta.InfoHash()
	if err != nil {
		e.log.Error("BT infohash compute failed", "gid", rg.gid, "error", err)
		rg.errCode = core.ExitTorrentParseError
		rg.errMsg = err.Error()
		return err
	}
	rg.btInfoHash = fmt.Sprintf("%x", infoHash[:])

	dir := rg.opts.Dir
	if dir == "" {
		dir = "."
	}
	basePath := filepath.Join(dir, meta.Info.Name)

	outPath := rg.filePath
	if outPath == "" {
		if len(meta.Info.Files) > 0 {
			outPath = basePath
		} else {
			outPath = filepath.Join(dir, meta.Info.Name)
		}
	}

	// Resolve collision and auto-renaming for BT download under queuesMu lock to prevent race conditions
	e.queuesMu.Lock()
	targetPath := outPath
	if len(meta.Info.Files) > 0 {
		targetPath = basePath
	}

	originalPath := targetPath
	suffix := 1
	for {
		collision := false
		if e.isSameFileBeingDownloadedLocked(targetPath, rg.gid) {
			collision = true
		} else if e.controlFileAllowsResume(targetPath, rg.opts, meta.TotalSize(), meta.Info.PieceLength, infoHash[:]) {
			collision = false
		} else {
			if _, err := os.Stat(targetPath); err == nil && !rg.opts.Continue && !rg.opts.AllowOverwrite {
				collision = true
			}
		}

		if collision {
			if !rg.opts.AutoFileRenaming {
				e.log.Error("BT collision detected but auto-file-renaming is disabled", "gid", rg.gid, "path", targetPath)
				e.queuesMu.Unlock()
				if _, ok := e.groups.getLocked(rg.gid); ok {
					rg.errCode = core.ExitFileAlreadyExists
					rg.errMsg = fmt.Sprintf("file/directory already exists: %s", targetPath)
					e.groups.unlock(rg.gid)
				}
				return fmt.Errorf("file/directory already exists: %s", targetPath)
			}
			targetPath = tryAutoFileRenamingWithSuffix(originalPath, suffix)
			suffix++
		} else {
			break
		}
	}

	// Update the appropriate path
	if len(meta.Info.Files) > 0 {
		basePath = targetPath
		outPath = targetPath
	} else {
		outPath = targetPath
	}

	// Update the request group's filePath and fileName under lock
	if _, ok := e.groups.getLocked(rg.gid); ok {
		rg.filePath = outPath
		rg.fileName = filepath.Base(outPath)
		e.groups.unlock(rg.gid)
	}
	e.queuesMu.Unlock()

	e.initControlInfo(rg, outPath, meta.TotalSize(), meta.Info.PieceLength, infoHash[:])

	var alloc disk.Allocator = disk.AllocatorNone{}
	if rg.opts.FileAllocation == "trunc" {
		alloc = disk.AllocatorTrunc{}
	}

	var adaptor disk.Adaptor
	var wantedPieces []bool
	if len(meta.Info.Files) > 0 {
		files, pieceFilter, unselected, fileErr := torrentFilesToDiskEntriesWithOptions(filepath.Base(basePath), meta.Info.Files, rg.opts, meta.Info.PieceLength, meta.NumPieces())
		if fileErr != nil {
			e.log.Error("BT file option setup failed", "gid", rg.gid, "error", fileErr)
			rg.errCode = core.ExitBadOption
			rg.errMsg = fileErr.Error()
			return fileErr
		}
		wantedPieces = pieceFilter
		rg.btUnselected = append(rg.btUnselected[:0], unselected...)
		rg.statusMu.Lock()
		rg.fileEntries = append(rg.fileEntries[:0], files...)
		rg.statusMu.Unlock()
		mf, aErr := disk.NewMultiFile(dir, files, meta.Info.PieceLength, alloc)
		if aErr != nil {
			e.log.Error("BT disk setup failed", "gid", rg.gid, "error", aErr)
			rg.errCode = core.ExitFileCreateError
			rg.errMsg = aErr.Error()
			return aErr
		}
		adaptor = mf
	} else {
		if rg.opts.AllowOverwrite && !rg.opts.Continue && !e.controlLoaded(rg) {
			if truncErr := os.Truncate(outPath, 0); truncErr != nil && !os.IsNotExist(truncErr) {
				e.log.Error("BT disk truncate failed", "gid", rg.gid, "error", truncErr)
				rg.errCode = core.ExitFileIOError
				rg.errMsg = truncErr.Error()
				return truncErr
			}
		}
		sf, aErr := disk.NewSingleFile(outPath, meta.Info.Length, alloc)
		if aErr != nil {
			e.log.Error("BT disk setup failed", "gid", rg.gid, "error", aErr)
			rg.errCode = core.ExitFileCreateError
			rg.errMsg = aErr.Error()
			return aErr
		}
		rg.statusMu.Lock()
		rg.fileEntries = []disk.FileEntry{{
			Name:      outPath,
			Length:    meta.Info.Length,
			Offset:    0,
			Requested: true,
		}}
		rg.statusMu.Unlock()
		adaptor = sf
	}

	if err := adaptor.OpenForWrite(); err != nil {
		e.log.Error("BT disk open failed", "gid", rg.gid, "error", err)
		rg.errCode = core.ExitFileCreateError
		rg.errMsg = err.Error()
		adaptor.Close()
		return err
	}
	e.setControlAdaptor(rg, adaptor)
	defer adaptor.Close()
	defer e.syncControlAdaptor(rg)

	numPieces := meta.NumPieces()
	adaptor.SetPieceCount(numPieces)
	e.applyControlBitfield(rg, adaptor)
	for i, wanted := range wantedPieces {
		if !wanted {
			adaptor.MarkPiece(i, true)
		}
	}

	e.log.Info("BT download started",
		"gid", rg.gid,
		"name", meta.Info.Name,
		"size", meta.Info.Length,
		"pieces", numPieces,
		"infohash", fmt.Sprintf("%x", infoHash[:]),
	)

	if e.lpdListener != nil {
		if err := e.lpdListener.Announce([][20]byte{infoHash}, uint16(e.btSession.Port())); err != nil {
			e.log.Error("lpd announce failed", "gid", rg.gid, "error", err)
		}
	}

	peerCfg := e.btPeerConfig(meta, adaptor)
	var inboundWG sync.WaitGroup
	if err := e.btSession.EnsureListening(e.log); err != nil {
		e.log.Warn("BT listener unavailable", "gid", rg.gid, "error", err)
	}
	inboundReg, err := e.btSession.Register(peerCfg)
	if err != nil {
		e.log.Error("BT inbound registration failed", "gid", rg.gid, "error", err)
		rg.errCode = core.ExitNetworkProblem
		rg.errMsg = err.Error()
		return err
	}

	discoveryCtx, stopDiscovery := context.WithCancel(ctx)
	defer stopDiscovery()
	discoveredPeers := make(chan string, 256)
	newPeers := make(chan *peerState, 64)
	droppedPeers := make(chan string, 64)

	swarm := &btSwarm{
		adaptor:     adaptor,
		meta:        meta,
		numPieces:   numPieces,
		pieceLen:    meta.Info.PieceLength,
		pieceHashes: meta.Info.Pieces,
		discoveryCh: discoveredPeers,
		dropCh:      droppedPeers,
		pexEnabled:  rg.opts.EnablePeerExchange && !meta.Info.Private,
	}
	rg.btSwarm.Store(swarm)
	defer rg.btSwarm.Store(nil)
	if e.dhtServer != nil && !meta.Info.Private {
		swarm.dhtObserver = func(ip net.IP, port uint16) {
			e.dhtServer.ObservePeerPort(discoveryCtx, ip, port)
		}
	}

	buildTrackerReq := func(event string, numWant int, trackerID string) tracker.AnnounceRequest {
		return e.buildTrackerRequest(meta, infoHash, rg, swarm, event, numWant, trackerID)
	}
	trackerSession := newBTTrackerSession(meta, rg.opts)
	webSeeds := btWebSeedFiles(meta, rg.uris)
	announceStopped := func() {
		if trackerSession == nil {
			return
		}
		stoppedCtx, stoppedCancel := context.WithTimeout(context.Background(), btTrackerTimeout(rg.opts))
		_ = trackerSession.announceStopped(stoppedCtx, e.announceTracker, buildTrackerReq)
		stoppedCancel()
	}

	inboundWG.Add(1)
	go func() {
		defer inboundWG.Done()
		e.runInboundPeerBridge(ctx, swarm, inboundReg.C, newPeers)
	}()
	defer func() {
		inboundReg.Close()
		inboundWG.Wait()
	}()

	var discoveryWG sync.WaitGroup
	if trackerSession != nil {
		discoveryWG.Add(1)
		go func() {
			defer discoveryWG.Done()
			trackerSession.runDefault(
				discoveryCtx,
				e.announceTracker,
				buildTrackerReq,
				func() bool { return btNeedsMorePeers(swarm.peerCount(), btMaxPeers(rg.opts)) },
				func(resp *tracker.AnnounceResponse) { emitTrackerPeers(discoveredPeers, resp) },
			)
		}()
	}
	if e.dhtServer != nil && !meta.Info.Private {
		discoveryWG.Add(1)
		go func() {
			defer discoveryWG.Done()
			e.runDHTPeerDiscovery(discoveryCtx, infoHash, swarm, discoveredPeers)
		}()
	}
	discoveryWG.Add(1)
	go func() {
		defer discoveryWG.Done()
		e.runPeerConnector(discoveryCtx, swarm, discoveredPeers, newPeers, peerCfg)
	}()

	swarmCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	useWebSeed := false
	select {
	case initialPeer := <-newPeers:
		if initialPeer != nil {
			swarm.addPeer(initialPeer)
		}
	default:
		if len(webSeeds) > 0 {
			useWebSeed = true
		}
	}

	if !useWebSeed && swarm.peerCount() == 0 {
		initialPeer, peerErr := e.waitForInitialPeer(discoveryCtx, newPeers)
		if peerErr != nil {
			stopDiscovery()
			discoveryWG.Wait()
			e.log.Error("BT no peers available", "gid", rg.gid)
			rg.errCode = core.ExitResourceNotFound
			rg.errMsg = peerErr.Error()
			return peerErr
		}
		swarm.addPeer(initialPeer)
	}

	if useWebSeed {
		if err := swarm.downloadWebSeeds(swarmCtx, rg, e, webSeeds); err != nil {
			stopDiscovery()
			discoveryWG.Wait()
			announceStopped()
			return err
		}
	} else if err := swarm.downloadLoop(swarmCtx, rg, e, newPeers); err != nil {
		stopDiscovery()
		discoveryWG.Wait()
		announceStopped()
		return err
	}

	stopDiscovery()
	discoveryWG.Wait()

	if !rg.opts.BTSeedUnverified {
		e.log.Info("BT verifying pieces", "gid", rg.gid)
		if err := verifySelectedPieces(ctx, adaptor, meta, wantedPieces); err != nil {
			e.log.Error("BT verification failed", "gid", rg.gid, "error", err)
			rg.errCode = core.ExitFileIOError
			rg.errMsg = fmt.Sprintf("piece verification failed: %v", err)
			return err
		}
	}

	if trackerSession != nil {
		completeCtx, completeCancel := context.WithTimeout(context.Background(), btTrackerTimeout(rg.opts))
		_ = trackerSession.announceCompleted(
			completeCtx,
			e.announceTracker,
			buildTrackerReq,
			btNeedsMorePeers(swarm.peerCount(), btMaxPeers(rg.opts)),
			func(resp *tracker.AnnounceResponse) { emitTrackerPeers(discoveredPeers, resp) },
		)
		completeCancel()
	}

	rg.statusMu.Lock()
	rg.seeder = true
	rg.errCode = core.ExitSuccess
	rg.statusMu.Unlock()
	e.log.Info("BT download complete, entering seeding", "gid", rg.gid)
	e.emit(core.EvBTComplete, rg.gid)

	numFiles := 1
	if len(meta.Info.Files) > 0 {
		numFiles = len(meta.Info.Files)
	}
	e.runHookByName(rg, numFiles, "on-bt-download-complete")

	if err := swarm.seedLoop(ctx, rg, e, newPeers); err != nil {
		announceStopped()
		return err
	}
	announceStopped()
	if err := e.removeBTUnselectedFiles(rg); err != nil {
		e.log.Warn("BT remove-unselected-file failed", "gid", rg.gid, "error", err)
	}

	return nil
}

func (s *btSwarm) downloadLoop(ctx context.Context, rg *requestGroup, e *Engine, newPeers <-chan *peerState) error {
	msgCh := make(chan peerMsg, 64)
	var wg sync.WaitGroup

	s.mu.Lock()
	for _, p := range s.peers {
		wg.Add(1)
		go s.readPeer(ctx, &wg, p, msgCh)
	}
	s.mu.Unlock()

	chokeTicker := time.NewTicker(btChokeInterval)
	defer chokeTicker.Stop()

	reqTicker := time.NewTicker(100 * time.Millisecond)
	defer reqTicker.Stop()

	pexTicker := time.NewTicker(btPEXInterval)
	defer pexTicker.Stop()

	bf := s.adaptor.Bitfield()
	s.mu.Lock()
	for _, p := range s.peers {
		p.conn.Bitfield(bf)
	}
	s.mu.Unlock()
	s.updateStats(rg)

	for !s.complete() {
		select {
		case <-ctx.Done():
			wg.Wait()
			rg.setError(core.ExitRemoved, "download cancelled")
			return ctx.Err()

		case peer := <-newPeers:
			if peer == nil {
				continue
			}
			s.addPeer(peer)
			_ = peer.conn.Bitfield(s.adaptor.Bitfield())
			s.updateStats(rg)
			wg.Add(1)
			go s.readPeer(ctx, &wg, peer, msgCh)

		case msg, ok := <-msgCh:
			if !ok {
				continue
			}
			s.handleMsg(msg)
			s.updateStats(rg)

			if msg.msg.ID == btpeer.MsgPiece {
				s.handlePiece(ctx, msg, rg, e)
			} else if msg.msg.ID == btpeer.MsgRequest {
				s.handleRequest(ctx, msg, rg, e)
			}

		case <-chokeTicker.C:
			s.doChoke()

		case <-reqTicker.C:
			s.requestPieces()

		case <-pexTicker.C:
			s.sendPeerExchange()
		}
	}

	s.closeAll()
	wg.Wait()
	return nil
}

func (s *btSwarm) seedLoop(ctx context.Context, rg *requestGroup, e *Engine, newPeers <-chan *peerState) error {
	policy := newBTSeedPolicy(rg, s.meta.TotalSize())
	if policy.shouldStop(rg) {
		return nil
	}

	msgCh := make(chan peerMsg, 64)
	var wg sync.WaitGroup

	chokeTicker := time.NewTicker(btChokeInterval)
	defer chokeTicker.Stop()
	checkTicker := time.NewTicker(250 * time.Millisecond)
	defer checkTicker.Stop()

	s.updateStats(rg)

	for {
		select {
		case <-ctx.Done():
			s.closeAll()
			wg.Wait()
			rg.setError(core.ExitRemoved, "download cancelled")
			return ctx.Err()

		case peer := <-newPeers:
			if peer == nil {
				continue
			}
			s.addPeer(peer)
			_ = peer.conn.Bitfield(s.adaptor.Bitfield())
			s.updateStats(rg)
			wg.Add(1)
			go s.readPeer(ctx, &wg, peer, msgCh)

		case msg, ok := <-msgCh:
			if !ok {
				continue
			}
			s.handleMsg(msg)
			s.updateStats(rg)
			if msg.msg.ID == btpeer.MsgRequest {
				s.handleRequest(ctx, msg, rg, e)
			}

		case <-chokeTicker.C:
			s.doChoke()
			s.updateStats(rg)

		case <-checkTicker.C:
			if policy.shouldStop(rg) {
				s.closeAll()
				wg.Wait()
				s.updateStats(rg)
				return nil
			}
		}
	}
}

func (s *btSwarm) downloadWebSeeds(ctx context.Context, rg *requestGroup, e *Engine, files []btWebSeedFile) error {
	for pieceIdx := 0; pieceIdx < s.numPieces; pieceIdx++ {
		if s.adaptor.Have(pieceIdx) {
			continue
		}
		select {
		case <-ctx.Done():
			rg.setError(core.ExitRemoved, "download cancelled")
			return ctx.Err()
		default:
		}
		if err := s.downloadWebSeedPiece(ctx, rg, e, pieceIdx, files); err != nil {
			rg.errCode = protocolErrorCode(err)
			rg.errMsg = err.Error()
			return err
		}
	}
	return nil
}

func (s *btSwarm) downloadWebSeedPiece(ctx context.Context, rg *requestGroup, e *Engine, pieceIdx int, files []btWebSeedFile) error {
	pieceStart := int64(pieceIdx) * s.pieceLen
	pieceLength := s.pieceLengthAt(pieceIdx)
	pieceEnd := pieceStart + pieceLength
	buf := make([]byte, int(pieceLength))

	for _, file := range files {
		if len(file.urls) == 0 || file.length == 0 {
			continue
		}
		segmentStart := maxInt64(pieceStart, file.offset)
		segmentEnd := minInt64(pieceEnd, file.offset+file.length)
		if segmentStart >= segmentEnd {
			continue
		}

		fileOffset := segmentStart - file.offset
		segmentLen := segmentEnd - segmentStart
		dst := buf[int(segmentStart-pieceStart):int(segmentEnd-pieceStart)]
		if err := e.downloadWebSeedRange(ctx, rg, file.urls, fileOffset, segmentLen, dst); err != nil {
			return err
		}
	}

	n, err := s.adaptor.WriteAt(buf, pieceStart)
	if err != nil {
		return fmt.Errorf("bt webseed write piece %d: %w", pieceIdx, err)
	}
	atomic.AddInt64(&rg.bytesDownloaded, int64(n))
	if err := s.verifyPiece(pieceIdx); err != nil {
		s.adaptor.MarkPiece(pieceIdx, false)
		e.markControlPiece(rg, pieceIdx, false)
		return err
	}
	e.markControlPiece(rg, pieceIdx, true)
	return nil
}

func (e *Engine) downloadWebSeedRange(ctx context.Context, rg *requestGroup, urls []string, offset, length int64, dst []byte) error {
	if int64(len(dst)) != length {
		return fmt.Errorf("bt webseed: destination length mismatch: got %d want %d", len(dst), length)
	}

	var firstErr error
	for _, rawURL := range urls {
		driver, err := e.httpDriverForURIWithAcceptEncoding(rg, rawURL, "")
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		body, err := driver.Download(ctx, rawURL, offset, length)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		n, readErr := io.ReadFull(body, dst)
		closeErr := body.Close()
		if readErr == nil && n == len(dst) {
			if err := e.rateGlobal.Wait(ctx, n); err != nil {
				return err
			}
			if rg.downloadLimit != nil {
				if err := rg.downloadLimit.Wait(ctx, n); err != nil {
					return err
				}
			}
			return nil
		}
		if firstErr == nil {
			if readErr != nil {
				firstErr = readErr
			} else {
				firstErr = closeErr
			}
		}
	}

	if firstErr == nil {
		firstErr = fmt.Errorf("bt webseed: no usable source")
	}
	return firstErr
}

func (s *btSwarm) pieceLengthAt(pieceIdx int) int64 {
	if pieceIdx == s.numPieces-1 {
		if rem := s.meta.TotalSize() % s.pieceLen; rem > 0 {
			return rem
		}
	}
	return s.pieceLen
}

func (s *btSwarm) handlePiece(ctx context.Context, msg peerMsg, rg *requestGroup, e *Engine) {
	pieceIdx, offset, data, err := btpeer.UnmarshalPiece(msg.msg)
	if err != nil {
		return
	}

	if len(data) > 0 {
		if err := e.rateGlobal.Wait(ctx, len(data)); err != nil {
			return
		}
		if rg.downloadLimit != nil {
			if err := rg.downloadLimit.Wait(ctx, len(data)); err != nil {
				return
			}
		}
	}

	absOffset := int64(pieceIdx)*s.pieceLen + int64(offset)
	n, werr := s.adaptor.WriteAt(data, absOffset)
	if werr != nil {
		return
	}

	s.mu.Lock()
	msg.src.dlBytes += int64(n)
	msg.src.outstanding--
	s.mu.Unlock()

	atomic.AddInt64(&rg.bytesDownloaded, int64(n))

	pieceBlkLen := int64(s.pieceLen)
	if pieceIdx == s.numPieces-1 {
		rem := s.meta.TotalSize() % s.pieceLen
		if rem > 0 {
			pieceBlkLen = rem
		}
	}

	if absOffset+int64(n) >= int64(pieceIdx)*s.pieceLen+pieceBlkLen {
		if verr := s.verifyPiece(pieceIdx); verr != nil {
			s.adaptor.MarkPiece(pieceIdx, false)
			e.markControlPiece(rg, pieceIdx, false)
			return
		}
		e.markControlPiece(rg, pieceIdx, true)

		s.mu.Lock()
		for _, p := range s.peers {
			p.conn.Have(pieceIdx)
		}
		s.mu.Unlock()
		return
	}

	// Request next block in this piece
	nextOffset := offset + len(data)
	nextLen := btBlockSize
	if nextOffset+nextLen > int(pieceBlkLen) {
		nextLen = int(pieceBlkLen) - nextOffset
	}
	if nextLen > 0 {
		msg.src.conn.Request(pieceIdx, nextOffset, nextLen)
		s.mu.Lock()
		msg.src.outstanding++
		s.mu.Unlock()
	}
}

func (s *btSwarm) handleRequest(ctx context.Context, msg peerMsg, rg *requestGroup, e *Engine) {
	pieceIdx, offset, length, err := btpeer.UnmarshalRequest(msg.msg)
	if err != nil {
		return
	}

	if !s.adaptor.Have(pieceIdx) {
		return
	}

	blen := s.pieceLen
	if pieceIdx == s.numPieces-1 {
		rem := s.meta.TotalSize() % s.pieceLen
		if rem > 0 {
			blen = rem
		}
	}

	if offset+length > int(blen) {
		length = int(blen) - offset
	}
	if length <= 0 {
		return
	}

	buf := make([]byte, length)
	absOffset := int64(pieceIdx)*s.pieceLen + int64(offset)
	n, rerr := s.adaptor.ReadAt(buf, absOffset)
	if rerr != nil || n < length {
		return
	}

	if err := e.rateGlobalUp.Wait(ctx, n); err != nil {
		return
	}
	if rg.uploadLimit != nil {
		if err := rg.uploadLimit.Wait(ctx, n); err != nil {
			return
		}
	}

	if err := msg.src.conn.Piece(pieceIdx, offset, buf[:n]); err != nil {
		return
	}
	s.mu.Lock()
	msg.src.ulBytes += int64(n)
	s.mu.Unlock()
	atomic.AddInt64(&rg.bytesUploaded, int64(n))
	atomic.AddInt64(&rg.sessionUploaded, int64(n))
	e.addBTUploadLength(rg, int64(n))
}

func (s *btSwarm) requestPieces() {
	s.mu.Lock()
	defer s.mu.Unlock()

	endgame := s.endgameMode()
	for _, p := range s.peers {
		if p.outstanding >= btMaxPendingRequests {
			continue
		}

		pieceIdx, ok := s.choosePieceLocked(p)
		if !ok {
			continue
		}

		blen := int(s.pieceLen)
		if pieceIdx == s.numPieces-1 {
			rem := s.meta.TotalSize() % s.pieceLen
			if rem > 0 {
				blen = int(rem)
			}
		}

		blockLen := btBlockSize
		if blockLen > blen {
			blockLen = blen
		}

		p.conn.Request(pieceIdx, 0, blockLen)
		p.outstanding++

		// Endgame: request same piece from all other peers that have it
		if endgame {
			for _, q := range s.peers {
				if q == p || q.outstanding >= btMaxPendingRequests*2 {
					continue
				}
				if q.hasPiece(pieceIdx) {
					q.conn.Request(pieceIdx, 0, blockLen)
					q.outstanding++
				}
			}
		}
	}
}

func (s *btSwarm) readPeer(ctx context.Context, wg *sync.WaitGroup, p *peerState, msgCh chan peerMsg) {
	defer wg.Done()
	defer s.removePeer(p)

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- p.conn.Run(ctx)
	}()
	ch := p.conn.Messages()
	for {
		select {
		case <-ctx.Done():
			p.conn.Close()
			return
		case <-runErrCh:
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			select {
			case msgCh <- peerMsg{src: p, msg: msg}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (e *Engine) btPeerConfig(meta *torrent.MetaInfo, adaptor disk.Adaptor) btpeer.Config {
	infoHash, _ := meta.InfoHash()
	numPieces := meta.NumPieces()

	peerID := e.btSession.PeerID()

	pexEnabled := e.cfg.EnablePeerExchange && !meta.Info.Private
	dhtEnabled := e.dhtServer != nil && !meta.Info.Private
	reserved := btpeer.MakeReserved(false, pexEnabled, dhtEnabled)

	src := &btPieceSource{
		adaptor:   adaptor,
		numPieces: numPieces,
	}

	return btpeer.Config{
		InfoHash:    infoHash,
		LocalPeerID: peerID,
		Reserved:    reserved,
		Pieces:      src,
		PieceLength: meta.Info.PieceLength,
		Encrypt:     btMSEEncryption(e.cfg),
		Timeout:     btTimeout(e.cfg),
	}
}

func btMSEEncryption(opts *config.Options) mse.Mode {
	if opts.BTRequireCrypto || opts.BTForceEncryption {
		return mse.Require
	}
	if strings.EqualFold(opts.BTMinCryptoLevel, "arc4") {
		return mse.Prefer
	}
	return mse.Allow
}

func btTimeout(opts *config.Options) time.Duration {
	if opts.BTTimeout != "" {
		if n, err := strconv.Atoi(opts.BTTimeout); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 180 * time.Second
}

func (e *Engine) collectPeers(ctx context.Context, meta *torrent.MetaInfo, gid core.GID) []string {
	infohash, err := meta.InfoHash()
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var addrs []string
	addrs = appendUniquePeerAddrs(addrs, seen, e.collectTrackerPeerAddrs(ctx, gid, infohash, announceURLs(meta))...)
	if !meta.Info.Private {
		addrs = appendUniquePeerAddrs(addrs, seen, e.collectDHTPeerAddrs(ctx, gid, infohash)...)
	}
	return addrs
}

func (e *Engine) connectPeers(ctx context.Context, swarm *btSwarm, addrs []string, cfg btpeer.Config) {
	maxPeers := e.cfg.BTMaxPeers
	if maxPeers <= 0 {
		maxPeers = btPeerConnectLimit
	}

	limit := make(chan struct{}, 8)
	var mu sync.Mutex
	connected := 0

	for _, addr := range addrs {
		mu.Lock()
		if connected >= maxPeers {
			mu.Unlock()
			break
		}
		connected++
		mu.Unlock()

		limit <- struct{}{}
		go func(addr string) {
			defer func() { <-limit }()

			dialCtx, cancel := context.WithTimeout(ctx, btPeerDialTimeout)
			defer cancel()

			conn, err := e.btSession.Dial(dialCtx, e.netDialer, addr, cfg)
			if err != nil {
				e.log.Debug("BT peer dial failed", "addr", addr, "error", err)
				return
			}

			swarm.addPeer(&peerState{
				conn:   conn,
				addr:   addr,
				pieces: swarm.numPieces,
			})
		}(addr)
	}

	for i := 0; i < cap(limit); i++ {
		limit <- struct{}{}
	}
}

func verifyAllPieces(ctx context.Context, adaptor disk.Adaptor, meta *torrent.MetaInfo) error {
	return verifySelectedPieces(ctx, adaptor, meta, nil)
}

func verifySelectedPieces(ctx context.Context, adaptor disk.Adaptor, meta *torrent.MetaInfo, wanted []bool) error {
	pieceLen := meta.Info.PieceLength
	pieces := meta.Info.Pieces
	buf := make([]byte, pieceLen)
	for i := 0; i < meta.NumPieces(); i++ {
		if len(wanted) > 0 && !wanted[i] {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		offset := int64(i) * pieceLen
		n, rErr := adaptor.ReadAt(buf, offset)
		if rErr != nil && n == 0 {
			return fmt.Errorf("read piece %d: %w", i, rErr)
		}
		expected := pieces[i*20 : (i+1)*20]
		actual := sha1Sum(buf[:n])
		if actual != *(*[20]byte)(expected) {
			return fmt.Errorf("piece %d hash mismatch", i)
		}
	}
	return nil
}

func announceURLs(meta *torrent.MetaInfo) []string {
	if meta.AnnounceList != nil {
		var urls []string
		for _, tier := range meta.AnnounceList {
			urls = append(urls, tier...)
		}
		return urls
	}
	if meta.Announce != "" {
		return []string{meta.Announce}
	}
	return nil
}

func sha1Sum(data []byte) [20]byte {
	return sha1.Sum(data)
}

func torrentFilesToDiskEntries(files []torrent.FileInfo) []disk.FileEntry {
	entries := make([]disk.FileEntry, len(files))
	var offset int64
	for i, f := range files {
		path := path.Join(f.Path...)
		entries[i] = disk.FileEntry{
			Name:      path,
			Length:    f.Length,
			Offset:    offset,
			Requested: true,
		}
		offset += f.Length
	}
	return entries
}

func torrentFilesToDiskEntriesWithOptions(root string, files []torrent.FileInfo, opts *config.Options, pieceLen int64, numPieces int) ([]disk.FileEntry, []bool, []string, error) {
	selected, err := parseBTSelectedFiles("", len(files))
	if err != nil {
		return nil, nil, nil, err
	}
	if opts != nil {
		selected, err = parseBTSelectedFiles(opts.SelectFile, len(files))
		if err != nil {
			return nil, nil, nil, err
		}
	}
	indexOut, err := parseBTIndexOut(nil, len(files))
	if err != nil {
		return nil, nil, nil, err
	}
	if opts != nil {
		indexOut, err = parseBTIndexOut(opts.IndexOut, len(files))
		if err != nil {
			return nil, nil, nil, err
		}
	}

	pieceFilter := selectedPiecesForFiles(files, selected, pieceLen, numPieces)
	entries := make([]disk.FileEntry, len(files))
	var unselected []string
	var offset int64
	for i, f := range files {
		name := path.Join(append([]string{root}, f.Path...)...)
		if mapped, ok := indexOut[i]; ok {
			name = filepath.Clean(mapped)
		}
		requested := len(selected) == 0 || selected[i]
		touchedBySelectedPiece := requested || fileOverlapsWantedPiece(offset, f.Length, pieceLen, pieceFilter)
		length := f.Length
		if !touchedBySelectedPiece {
			length = 0
		}
		entries[i] = disk.FileEntry{
			Name:      name,
			Length:    length,
			Offset:    offset,
			Requested: requested,
		}
		if !requested {
			unselected = append(unselected, name)
		}
		offset += f.Length
	}

	return entries, pieceFilter, unselected, nil
}

type btWebSeedFile struct {
	offset int64
	length int64
	urls   []string
}

type btSeedPolicy struct {
	started         time.Time
	shareRatio      float64
	seedTime        time.Duration
	seedTimeDefined bool
	completedLength int64
}

func newBTSeedPolicy(rg *requestGroup, completedLength int64) btSeedPolicy {
	policy := btSeedPolicy{
		started:         time.Now(),
		completedLength: completedLength,
	}
	if rg == nil || rg.opts == nil {
		return policy
	}
	if ratio, err := strconv.ParseFloat(strings.TrimSpace(rg.opts.SeedRatio), 64); err == nil && ratio > 0 {
		policy.shareRatio = ratio
	}
	if seedTimeText := strings.TrimSpace(rg.opts.SeedTime); seedTimeText != "" {
		if minutes, err := strconv.ParseFloat(seedTimeText, 64); err == nil && minutes >= 0 {
			policy.seedTimeDefined = true
			policy.seedTime = time.Duration(minutes * float64(time.Minute))
		}
	}
	return policy
}

func (p btSeedPolicy) shouldStop(rg *requestGroup) bool {
	if p.seedTimeDefined && time.Since(p.started) >= p.seedTime {
		return true
	}
	if p.shareRatio > 0 {
		if p.completedLength == 0 {
			return true
		}
		return float64(btUploadLength(rg)) >= p.shareRatio*float64(p.completedLength)
	}
	return false
}

func btUploadLength(rg *requestGroup) int64 {
	if rg == nil {
		return 0
	}
	rg.controlMu.Lock()
	defer rg.controlMu.Unlock()
	if rg.controlInfo == nil {
		return rg.sessionUploaded
	}
	return rg.controlInfo.UploadLength
}

func btWebSeedFiles(meta *torrent.MetaInfo, extraURIs []string) []btWebSeedFile {
	urls := btCombineWebSeedURLs(meta.URLList, extraURIs)
	if len(urls) == 0 {
		return nil
	}

	if len(meta.Info.Files) == 0 {
		return []btWebSeedFile{{
			offset: 0,
			length: meta.Info.Length,
			urls:   btSingleFileWebSeedURLs(meta.Info.Name, urls),
		}}
	}

	files := make([]btWebSeedFile, 0, len(meta.Info.Files))
	var offset int64
	for _, file := range meta.Info.Files {
		relPath := btPercentEncodeTorrentPath(file.Path)
		fileURLs := make([]string, 0, len(urls))
		for _, base := range urls {
			fileURLs = append(fileURLs, btMultiFileWebSeedURL(base, relPath))
		}
		files = append(files, btWebSeedFile{
			offset: offset,
			length: file.Length,
			urls:   fileURLs,
		})
		offset += file.Length
	}
	return files
}

func btCombineWebSeedURLs(urlList []string, extraURIs []string) []string {
	urls := make([]string, 0, len(urlList)+len(extraURIs))
	for _, raw := range append(append([]string(nil), urlList...), extraURIs...) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
			continue
		}
		urls = append(urls, raw)
	}
	if len(urls) == 0 {
		return nil
	}
	sort.Strings(urls)
	out := urls[:0]
	for _, raw := range urls {
		if len(out) == 0 || out[len(out)-1] != raw {
			out = append(out, raw)
		}
	}
	return append([]string(nil), out...)
}

func btSingleFileWebSeedURLs(name string, bases []string) []string {
	urls := make([]string, 0, len(bases))
	encodedName := url.PathEscape(name)
	for _, base := range bases {
		if strings.HasSuffix(base, "/") {
			urls = append(urls, base+encodedName)
			continue
		}
		urls = append(urls, base)
	}
	return urls
}

func btMultiFileWebSeedURL(base string, relPath string) string {
	if strings.HasSuffix(base, "/") {
		return base + relPath
	}
	return base + "/" + relPath
}

func btPercentEncodeTorrentPath(parts []string) string {
	escaped := make([]string, len(parts))
	for i, part := range parts {
		escaped[i] = url.PathEscape(part)
	}
	return strings.Join(escaped, "/")
}

func (e *Engine) removeBTUnselectedFiles(rg *requestGroup) error {
	if rg == nil || rg.opts == nil || !rg.opts.BTRemoveUnselectedFile || rg.inMemory || len(rg.btUnselected) == 0 {
		return nil
	}
	dir := rg.opts.Dir
	if dir == "" {
		dir = "."
	}

	var firstErr error
	for _, rel := range rg.btUnselected {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func parseBTSelectedFiles(expr string, n int) ([]bool, error) {
	if expr == "" || n <= 1 {
		return nil, nil
	}
	selected := make([]bool, n)
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("select-file: empty index")
		}
		startText, endText, hasRange := strings.Cut(part, "-")
		start, err := strconv.Atoi(strings.TrimSpace(startText))
		if err != nil || start <= 0 {
			return nil, fmt.Errorf("select-file: invalid index %q", part)
		}
		end := start
		if hasRange {
			end, err = strconv.Atoi(strings.TrimSpace(endText))
			if err != nil || end <= 0 || end < start {
				return nil, fmt.Errorf("select-file: invalid range %q", part)
			}
		}
		if start > n || end > n {
			return nil, fmt.Errorf("select-file: index out of range %q", part)
		}
		for i := start; i <= end; i++ {
			selected[i-1] = true
		}
	}
	for _, ok := range selected {
		if ok {
			return selected, nil
		}
	}
	return nil, fmt.Errorf("select-file: no files selected")
}

func parseBTIndexOut(values []string, n int) (map[int]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	indexOut := make(map[int]string, len(values))
	for _, value := range values {
		indexText, path, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(indexText) == "" || path == "" {
			return nil, fmt.Errorf("index-out: invalid mapping %q", value)
		}
		index, err := strconv.Atoi(strings.TrimSpace(indexText))
		if err != nil || index <= 0 || index > n {
			return nil, fmt.Errorf("index-out: index out of range %q", value)
		}
		if filepath.IsAbs(path) {
			return nil, fmt.Errorf("index-out: path must be relative %q", value)
		}
		indexOut[index-1] = path
	}
	return indexOut, nil
}

func selectedPiecesForFiles(files []torrent.FileInfo, selected []bool, pieceLen int64, numPieces int) []bool {
	if len(selected) == 0 || pieceLen <= 0 || numPieces <= 0 {
		return nil
	}
	wanted := make([]bool, numPieces)
	var offset int64
	for i, file := range files {
		if i < len(selected) && selected[i] && file.Length > 0 {
			startPiece := offset / pieceLen
			endPiece := (offset + file.Length - 1) / pieceLen
			for piece := startPiece; piece <= endPiece && piece < int64(numPieces); piece++ {
				wanted[piece] = true
			}
		}
		offset += file.Length
	}
	return wanted
}

func fileOverlapsWantedPiece(offset, length, pieceLen int64, wanted []bool) bool {
	if len(wanted) == 0 || length <= 0 || pieceLen <= 0 {
		return false
	}
	startPiece := offset / pieceLen
	endPiece := (offset + length - 1) / pieceLen
	for piece := startPiece; piece <= endPiece && piece < int64(len(wanted)); piece++ {
		if wanted[piece] {
			return true
		}
	}
	return false
}
