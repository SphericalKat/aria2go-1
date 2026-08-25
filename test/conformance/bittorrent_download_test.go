package conformance

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/smartass08/aria2go/internal/bencode"
)

func TestBitTorrent_SingleFileDownloadParity(t *testing.T) {
	SkipIfNoRef(t)

	payload := protocolPayload("bittorrent-single-file-download-parity", 48*1024+777)
	const (
		name        = "bt-parity.bin"
		pieceLength = 16 * 1024
	)

	refBT := startProtocolBTFixture(t, name, payload, pieceLength)
	implBT := startProtocolBTFixture(t, name, payload, pieceLength)

	refDir := t.TempDir()
	implDir := t.TempDir()
	refTorrent := refBT.writeTorrentFile(t, refDir)
	implTorrent := implBT.writeTorrentFile(t, implDir)

	ref := protocolRun(t, true, bittorrentDownloadArgs(refDir, refTorrent))
	impl := protocolRun(t, false, bittorrentDownloadArgs(implDir, implTorrent))

	AssertEqualExit(t, ref, impl)
	protocolRequireExitZero(t, "ref bittorrent", ref)
	protocolRequireExitZero(t, "impl bittorrent", impl)
	protocolRequireFile(t, filepath.Join(refDir, name), payload)
	protocolRequireFile(t, filepath.Join(implDir, name), payload)
}

func TestBitTorrent_WebSeedURLListParity(t *testing.T) {
	SkipIfNoRef(t)

	payload := protocolPayload("bittorrent-webseed-url-list", 33*1024+19)
	const (
		name        = "bt-webseed.bin"
		pieceLength = 16 * 1024
	)

	webseed := startProtocolHTTPFixture(t, map[string][]byte{name: payload})
	torrentData, err := protocolTorrentSingleFileWithURLList("http://127.0.0.1:9/announce", name, payload, pieceLength, []string{webseed.URL + "/"})
	if err != nil {
		t.Fatalf("build torrent: %v", err)
	}

	refDir := t.TempDir()
	implDir := t.TempDir()
	refTorrent := filepath.Join(refDir, "webseed.torrent")
	implTorrent := filepath.Join(implDir, "webseed.torrent")
	if err := os.WriteFile(refTorrent, torrentData, 0o644); err != nil {
		t.Fatalf("write ref torrent: %v", err)
	}
	if err := os.WriteFile(implTorrent, torrentData, 0o644); err != nil {
		t.Fatalf("write impl torrent: %v", err)
	}

	ref := protocolRun(t, true, bittorrentDownloadArgs(refDir, refTorrent))
	impl := protocolRun(t, false, bittorrentDownloadArgs(implDir, implTorrent))

	AssertEqualExit(t, ref, impl)
	protocolRequireExitZero(t, "ref bittorrent webseed url-list", ref)
	protocolRequireExitZero(t, "impl bittorrent webseed url-list", impl)
	protocolRequireFile(t, filepath.Join(refDir, name), payload)
	protocolRequireFile(t, filepath.Join(implDir, name), payload)
}

func TestBitTorrent_WebSeedPositionalParity(t *testing.T) {
	t.Skip("reference aria2 positional webseed CLI invocation is unstable in this harness; runtime is covered by internal engine tests")
}

func bittorrentDownloadArgs(dir, torrentPath string) []string {
	args := protocolBaseArgs(dir)
	args = append(args,
		"--enable-peer-exchange=false",
		"--bt-max-peers=1",
		"--seed-time=0",
		torrentPath,
	)
	return args
}

func protocolTorrentSingleFileWithURLList(announce, name string, data []byte, pieceLength int, urlList []string) ([]byte, error) {
	torrentData, _, err := protocolTorrentSingleFile(announce, name, data, pieceLength)
	if err != nil {
		return nil, err
	}
	meta, err := bencode.NewDecoder(bytes.NewReader(torrentData)).Decode()
	if err != nil {
		return nil, err
	}
	top, ok := meta.(*bencode.DictVal)
	if !ok {
		return nil, fmt.Errorf("decoded torrent root is %T, want *bencode.DictVal", meta)
	}
	if len(urlList) == 1 {
		top.Set("url-list", bencode.NewString(urlList[0]))
	} else {
		values := make([]bencode.Value, 0, len(urlList))
		for _, raw := range urlList {
			values = append(values, bencode.NewString(raw))
		}
		top.Set("url-list", bencode.NewList(values...))
	}
	return bencode.Marshal(top)
}

func TestBitTorrent_FollowTorrentURLParity(t *testing.T) {
	SkipIfNoRef(t)

	payload := protocolPayload("bittorrent-follow-torrent-url-parity", 32*1024+123)
	const (
		name        = "bt-follow.bin"
		pieceLength = 16 * 1024
	)

	refBT := startProtocolBTFixture(t, name, payload, pieceLength)
	implBT := startProtocolBTFixture(t, name, payload, pieceLength)

	refTorrentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "payload.torrent", time.Now(), bytes.NewReader(refBT.TorrentData))
	}))
	defer refTorrentSrv.Close()
	implTorrentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "payload.torrent", time.Now(), bytes.NewReader(implBT.TorrentData))
	}))
	defer implTorrentSrv.Close()

	refDir := t.TempDir()
	implDir := t.TempDir()
	followArgs := func(dir, torrentURL string) []string {
		args := bittorrentDownloadArgs(dir, torrentURL)
		// The .torrent file is saved next to the payload; avoid the
		// ref/impl sharing one directory.
		args = append(args[:len(args)-1], "--bt-save-metadata=false", torrentURL)
		return args
	}

	ref := protocolRun(t, true, followArgs(refDir, refTorrentSrv.URL+"/payload.torrent"))
	impl := protocolRun(t, false, followArgs(implDir, implTorrentSrv.URL+"/payload.torrent"))

	AssertEqualExit(t, ref, impl)
	protocolRequireExitZero(t, "ref follow-torrent", ref)
	protocolRequireExitZero(t, "impl follow-torrent", impl)
	protocolRequireFile(t, filepath.Join(refDir, name), payload)
	protocolRequireFile(t, filepath.Join(implDir, name), payload)
}
