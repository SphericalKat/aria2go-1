package aria2c

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smartass08/aria2go/internal/bencode"
	"github.com/smartass08/aria2go/internal/core"
	magnetpkg "github.com/smartass08/aria2go/internal/magnet"
	btpeer "github.com/smartass08/aria2go/internal/protocol/bittorrent/peer"
)

// btFixture is an offline BitTorrent swarm: an HTTP tracker and a seed peer
// that serves metadata over ut_metadata and payload pieces. It backs the
// public magnet, torrent-file, and followed-torrent tests.
type btFixture struct {
	TorrentData []byte
	InfoRaw     []byte
	InfoHash    [20]byte
	Name        string

	payload []byte
	piece   int
	peerLn  net.Listener
	tracker *httptest.Server
	cancel  context.CancelFunc
}

func startBTFixture(t *testing.T, name string, payload []byte, pieceLength int) *btFixture {
	t.Helper()

	peerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bt peer listen: %v", err)
	}
	peerPort := peerLn.Addr().(*net.TCPAddr).Port

	tracker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/announce" {
			http.NotFound(w, r)
			return
		}
		resp, err := fixtureTrackerResponse(peerPort)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(resp)
	}))

	torrentData, infoRaw, infoHash, err := buildFixtureTorrent(tracker.URL+"/announce", name, payload, pieceLength)
	if err != nil {
		tracker.Close()
		_ = peerLn.Close()
		t.Fatalf("build torrent fixture: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	f := &btFixture{
		TorrentData: append([]byte(nil), torrentData...),
		InfoRaw:     append([]byte(nil), infoRaw...),
		InfoHash:    infoHash,
		Name:        name,
		payload:     append([]byte(nil), payload...),
		piece:       pieceLength,
		peerLn:      peerLn,
		tracker:     tracker,
		cancel:      cancel,
	}
	go f.servePeer(ctx)
	t.Cleanup(f.Close)
	return f
}

func (f *btFixture) Close() {
	f.cancel()
	_ = f.peerLn.Close()
	f.tracker.Close()
}

// MagnetURI returns a magnet link with the fixture info hash and tracker.
func (f *btFixture) MagnetURI(t *testing.T) string {
	t.Helper()
	var infoHash core.InfoHashV1
	copy(infoHash[:], f.InfoHash[:])
	m := &magnetpkg.Magnet{
		InfoHashV1:  &infoHash,
		DisplayName: f.Name,
		Trackers:    []string{f.tracker.URL + "/announce"},
	}
	return m.String()
}

func buildFixtureTorrent(announce, name string, data []byte, pieceLength int) ([]byte, []byte, [20]byte, error) {
	if pieceLength <= 0 {
		return nil, nil, [20]byte{}, fmt.Errorf("piece length must be positive")
	}
	var pieces []byte
	for off := 0; off < len(data); off += pieceLength {
		end := off + pieceLength
		if end > len(data) {
			end = len(data)
		}
		sum := sha1.Sum(data[off:end])
		pieces = append(pieces, sum[:]...)
	}

	info := bencode.NewDict()
	info.Set("length", bencode.NewInt(int64(len(data))))
	info.Set("name", bencode.NewString(name))
	info.Set("piece length", bencode.NewInt(int64(pieceLength)))
	info.Set("pieces", bencode.NewString(string(pieces)))

	top := bencode.NewDict()
	top.Set("announce", bencode.NewString(announce))
	top.Set("info", info)

	torrentData, err := bencode.Marshal(top)
	if err != nil {
		return nil, nil, [20]byte{}, err
	}
	infoRaw, err := bencode.Marshal(info)
	if err != nil {
		return nil, nil, [20]byte{}, err
	}
	return torrentData, infoRaw, sha1.Sum(infoRaw), nil
}

func fixtureTrackerResponse(peerPort int) ([]byte, error) {
	ip := net.ParseIP("127.0.0.1").To4()
	if ip == nil {
		return nil, fmt.Errorf("cannot encode loopback peer")
	}
	var compact [6]byte
	copy(compact[:4], ip)
	binary.BigEndian.PutUint16(compact[4:], uint16(peerPort))

	resp := bencode.NewDict()
	resp.Set("interval", bencode.NewInt(1800))
	resp.Set("peers", bencode.NewString(string(compact[:])))
	return bencode.Marshal(resp)
}

func (f *btFixture) servePeer(ctx context.Context) {
	for {
		conn, err := f.peerLn.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go f.handlePeer(ctx, conn)
	}
}

func (f *btFixture) handlePeer(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var hs [68]byte
	if _, err := io.ReadFull(conn, hs[:]); err != nil {
		return
	}
	if hs[0] != 19 || string(hs[1:20]) != "BitTorrent protocol" {
		return
	}
	if !bytes.Equal(hs[28:48], f.InfoHash[:]) {
		return
	}

	var resp [68]byte
	resp[0] = 19
	copy(resp[1:20], "BitTorrent protocol")
	reserved := btpeer.MakeReserved(false, true, false)
	copy(resp[20:28], reserved[:])
	copy(resp[28:48], f.InfoHash[:])
	copy(resp[48:68], []byte("-AG0001-pkgfixtureXX"))
	if _, err := conn.Write(resp[:]); err != nil {
		return
	}

	extHandshake, err := btpeer.EncodeExtendedHandshakeKeys("pkg-fixture", 0, len(f.InfoRaw), map[int]uint8{
		btpeer.ExtensionUTMetadata: 3,
	})
	if err != nil {
		return
	}
	if _, err := conn.Write(btpeer.MarshalExtended(btpeer.ExtensionHandshakeID, extHandshake)); err != nil {
		return
	}

	bitfieldSent := false
	clientMetadataID := uint8(0)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		if msgLen == 0 {
			continue
		}
		payload := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		if len(payload) == 0 {
			continue
		}

		switch payload[0] {
		case byte(btpeer.MsgBitfield), byte(btpeer.MsgInterested):
			if bitfieldSent {
				continue
			}
			if _, err := conn.Write([]byte{0, 0, 0, 1, 1}); err != nil {
				return
			}
			if err := f.writeBitfield(conn); err != nil {
				return
			}
			bitfieldSent = true
		case byte(btpeer.MsgExtended):
			if len(payload) < 2 {
				continue
			}
			if payload[1] == 0 {
				hs, err := btpeer.ParseExtendedHandshake(payload[2:])
				if err != nil {
					return
				}
				clientMetadataID = hs.Extensions[btpeer.ExtensionNameUTMetadata]
				continue
			}
			if payload[1] != 3 {
				continue
			}
			msg, err := btpeer.ParseUTMetadata(payload[2:])
			if err != nil {
				return
			}
			if msg.MessageType != btpeer.UTMetadataRequest {
				continue
			}
			if clientMetadataID == 0 {
				return
			}
			if err := f.writeMetadataPiece(conn, clientMetadataID, msg.Piece); err != nil {
				return
			}
		case byte(btpeer.MsgRequest):
			if len(payload) < 13 {
				return
			}
			index := binary.BigEndian.Uint32(payload[1:5])
			begin := binary.BigEndian.Uint32(payload[5:9])
			length := binary.BigEndian.Uint32(payload[9:13])
			if err := f.writePiece(conn, index, begin, length); err != nil {
				return
			}
		}
	}
}

func (f *btFixture) writeMetadataPiece(w io.Writer, extID uint8, piece int) error {
	start := piece * btpeer.MetadataPieceSize
	if start < 0 || start >= len(f.InfoRaw) {
		return nil
	}
	end := start + btpeer.MetadataPieceSize
	if end > len(f.InfoRaw) {
		end = len(f.InfoRaw)
	}
	payload, err := btpeer.EncodeUTMetadataData(piece, len(f.InfoRaw), f.InfoRaw[start:end])
	if err != nil {
		return err
	}
	_, err = w.Write(btpeer.MarshalExtended(extID, payload))
	return err
}

func (f *btFixture) writeBitfield(w io.Writer) error {
	numPieces := (len(f.payload) + f.piece - 1) / f.piece
	bitfield := make([]byte, (numPieces+7)/8)
	for i := 0; i < numPieces; i++ {
		bitfield[i/8] |= 1 << (7 - (i % 8))
	}
	msg := make([]byte, 4+1+len(bitfield))
	binary.BigEndian.PutUint32(msg[:4], uint32(1+len(bitfield)))
	msg[4] = byte(btpeer.MsgBitfield)
	copy(msg[5:], bitfield)
	_, err := w.Write(msg)
	return err
}

func (f *btFixture) writePiece(w io.Writer, index, begin, length uint32) error {
	offset := int64(index)*int64(f.piece) + int64(begin)
	if offset < 0 || offset >= int64(len(f.payload)) {
		return nil
	}
	end := offset + int64(length)
	if end > int64(len(f.payload)) {
		end = int64(len(f.payload))
	}
	block := f.payload[offset:end]
	msg := make([]byte, 4+1+8+len(block))
	binary.BigEndian.PutUint32(msg[:4], uint32(9+len(block)))
	msg[4] = byte(btpeer.MsgPiece)
	binary.BigEndian.PutUint32(msg[5:9], index)
	binary.BigEndian.PutUint32(msg[9:13], begin)
	copy(msg[13:], block)
	_, err := w.Write(msg)
	return err
}
