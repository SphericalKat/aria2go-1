package aria2c

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func waitForEvent(t *testing.T, ch <-chan Event, gid GID, kind EventKind, timeout time.Duration) Event {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-ch:
			if ev.GID == gid && ev.Kind == kind {
				return ev
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s event for GID %s", kind, gid)
			return Event{}
		}
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func TestEmbed_HTTPDownload(t *testing.T) {
	payload := []byte("http-download-payload-0123456789")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "file.bin", time.Now(), bytes.NewReader(payload))
	}))
	defer srv.Close()

	d, _ := runDaemon(t, &EngineOptions{Dir: t.TempDir(), MaxConcurrentDownloads: 2})
	events, _ := d.Subscribe()

	gid, err := d.AddURI(srv.URL+"/file.bin", nil)
	if err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}

	waitForEvent(t, events, gid, EventComplete, 15*time.Second)

	st, err := d.TellStatus(gid)
	if err != nil {
		t.Fatalf("TellStatus() error = %v", err)
	}
	if st.Status != "complete" {
		t.Errorf("Status = %q, want complete", st.Status)
	}
	if st.TotalLength != int64(len(payload)) || st.CompletedLength != int64(len(payload)) {
		t.Errorf("lengths = %d/%d, want %d/%d", st.TotalLength, st.CompletedLength, len(payload), len(payload))
	}
	if st.ErrorCode != 0 || st.ErrorMessage != "" {
		t.Errorf("error = %d %q, want none", st.ErrorCode, st.ErrorMessage)
	}

	files, err := d.Files(gid)
	if err != nil {
		t.Fatalf("Files() error = %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("len(Files) = %d, want 1", len(files))
	}
	if files[0].Length != int64(len(payload)) || !files[0].Selected {
		t.Errorf("file[0] = %+v, want length %d selected", files[0], len(payload))
	}
	if got := readFile(t, files[0].Path); !bytes.Equal(got, payload) {
		t.Errorf("downloaded content mismatch: %q", got)
	}
}

func TestEmbed_HTTPSDownload(t *testing.T) {
	payload := []byte("https-download-payload")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "secure.bin", time.Now(), bytes.NewReader(payload))
	}))
	defer srv.Close()

	var caPEM bytes.Buffer
	if err := pem.Encode(&caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}); err != nil {
		t.Fatalf("encode CA PEM: %v", err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, caPEM.Bytes(), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	d, _ := runDaemon(t, &EngineOptions{
		Dir:           t.TempDir(),
		CACertificate: caPath,
	})
	events, _ := d.Subscribe()

	gid, err := d.AddURI(srv.URL+"/secure.bin", nil)
	if err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}
	waitForEvent(t, events, gid, EventComplete, 15*time.Second)

	st, err := d.TellStatus(gid)
	if err != nil {
		t.Fatalf("TellStatus() error = %v", err)
	}
	if st.Status != "complete" {
		t.Fatalf("Status = %q, errMsg = %q", st.Status, st.ErrorMessage)
	}
}

func TestEmbed_PerDownloadDirAndOut(t *testing.T) {
	payload := []byte("per-download-dir-payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "original.bin", time.Now(), bytes.NewReader(payload))
	}))
	defer srv.Close()

	base := t.TempDir()
	d, _ := runDaemon(t, &EngineOptions{Dir: base})
	events, _ := d.Subscribe()

	subdir := filepath.Join(base, "uuid-dir")
	gid, err := d.AddURI(srv.URL+"/original.bin", &DownloadOptions{Dir: subdir, Out: "renamed.bin"})
	if err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}
	waitForEvent(t, events, gid, EventComplete, 15*time.Second)

	if got := readFile(t, filepath.Join(subdir, "renamed.bin")); !bytes.Equal(got, payload) {
		t.Errorf("renamed file content mismatch: %q", got)
	}
}

func TestEmbed_MagnetDownload(t *testing.T) {
	payload := []byte("magnet-download-payload-abcdefgh")
	fixture := startBTFixture(t, "magnet.bin", payload, 16*1024)

	d, _ := runDaemon(t, &EngineOptions{Dir: t.TempDir(), MaxConcurrentDownloads: 2, SeedTime: "0"})
	events, _ := d.Subscribe()

	gid, err := d.AddURI(fixture.MagnetURI(t), nil)
	if err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}

	waitForEvent(t, events, gid, EventComplete, 30*time.Second)

	st, err := d.TellStatus(gid)
	if err != nil {
		t.Fatalf("TellStatus(metadata) error = %v", err)
	}
	if st.Status != "complete" {
		t.Fatalf("metadata status = %q, errMsg = %q", st.Status, st.ErrorMessage)
	}
	if len(st.FollowedBy) != 1 {
		t.Fatalf("FollowedBy = %v, want one child GID", st.FollowedBy)
	}
	child := st.FollowedBy[0]

	waitForEvent(t, events, child, EventComplete, 30*time.Second)

	childStatus, err := d.TellStatus(child)
	if err != nil {
		t.Fatalf("TellStatus(child) error = %v", err)
	}
	if childStatus.Status != "complete" {
		t.Fatalf("child status = %q, errMsg = %q", childStatus.Status, childStatus.ErrorMessage)
	}
	if childStatus.Following != gid {
		t.Errorf("child Following = %s, want %s", childStatus.Following, gid)
	}
	if childStatus.TotalLength != int64(len(payload)) {
		t.Errorf("child TotalLength = %d, want %d", childStatus.TotalLength, len(payload))
	}

	childFiles, err := d.Files(child)
	if err != nil {
		t.Fatalf("Files(child) error = %v", err)
	}
	if len(childFiles) != 1 {
		t.Fatalf("len(child Files) = %d, want 1", len(childFiles))
	}
	if got := readFile(t, childFiles[0].Path); !bytes.Equal(got, payload) {
		t.Errorf("magnet payload mismatch: %q", got)
	}
}

func TestEmbed_TorrentFileBytes(t *testing.T) {
	payload := []byte("torrent-bytes-payload-0123456789")
	fixture := startBTFixture(t, "bytes.bin", payload, 16*1024)

	d, _ := runDaemon(t, &EngineOptions{Dir: t.TempDir(), SeedTime: "0"})
	events, _ := d.Subscribe()

	gid, err := d.AddTorrent(fixture.TorrentData, nil)
	if err != nil {
		t.Fatalf("AddTorrent() error = %v", err)
	}
	waitForEvent(t, events, gid, EventComplete, 30*time.Second)

	st, err := d.TellStatus(gid)
	if err != nil {
		t.Fatalf("TellStatus() error = %v", err)
	}
	if st.Status != "complete" {
		t.Fatalf("status = %q, errMsg = %q", st.Status, st.ErrorMessage)
	}

	files, err := d.Files(gid)
	if err != nil {
		t.Fatalf("Files() error = %v", err)
	}
	if len(files) != 1 || filepath.Base(files[0].Path) != "bytes.bin" {
		t.Fatalf("files = %+v, want one file named bytes.bin", files)
	}
	if got := readFile(t, files[0].Path); !bytes.Equal(got, payload) {
		t.Errorf("torrent payload mismatch: %q", got)
	}
}

func TestEmbed_FollowTorrentURL(t *testing.T) {
	payload := []byte("follow-torrent-payload-ABCDEFGHIJ")
	fixture := startBTFixture(t, "followed.bin", payload, 16*1024)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-bittorrent")
		http.ServeContent(w, r, "payload.torrent", time.Now(), bytes.NewReader(fixture.TorrentData))
	}))
	defer srv.Close()

	d, _ := runDaemon(t, &EngineOptions{Dir: t.TempDir(), SeedTime: "0"})
	events, _ := d.Subscribe()

	gid, err := d.AddURI(srv.URL+"/payload.torrent", nil)
	if err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}

	waitForEvent(t, events, gid, EventComplete, 30*time.Second)

	st, err := d.TellStatus(gid)
	if err != nil {
		t.Fatalf("TellStatus(metadata) error = %v", err)
	}
	if st.Status != "complete" {
		t.Fatalf("metadata status = %q, errMsg = %q", st.Status, st.ErrorMessage)
	}
	if len(st.FollowedBy) != 1 {
		t.Fatalf("FollowedBy = %v, want one child GID", st.FollowedBy)
	}
	child := st.FollowedBy[0]

	waitForEvent(t, events, child, EventComplete, 30*time.Second)

	childStatus, err := d.TellStatus(child)
	if err != nil {
		t.Fatalf("TellStatus(child) error = %v", err)
	}
	if childStatus.Status != "complete" {
		t.Fatalf("child status = %q, errMsg = %q", childStatus.Status, childStatus.ErrorMessage)
	}
	if got := readFile(t, filepath.Join(st.Dir, "followed.bin")); !bytes.Equal(got, payload) {
		t.Errorf("followed payload mismatch: %q", got)
	}
	if got := readFile(t, filepath.Join(st.Dir, "payload.torrent")); !bytes.Equal(got, fixture.TorrentData) {
		t.Errorf("saved .torrent mismatch: %d bytes", len(got))
	}
}

func TestEmbed_CancelQueued(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseNow := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseNow()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/block.bin" {
			select {
			case <-release:
				http.ServeContent(w, r, "block.bin", time.Now(), bytes.NewReader([]byte("blocked-payload")))
			case <-r.Context().Done():
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	d, _ := runDaemon(t, &EngineOptions{Dir: t.TempDir(), MaxConcurrentDownloads: 1})
	events, _ := d.Subscribe()

	first, err := d.AddURI(srv.URL+"/block.bin", nil)
	if err != nil {
		t.Fatalf("AddURI(first) error = %v", err)
	}
	waitForEvent(t, events, first, EventStart, 15*time.Second)

	second, err := d.AddURI(srv.URL+"/missing-after-cancel.bin", nil)
	if err != nil {
		t.Fatalf("AddURI(second) error = %v", err)
	}

	secondStatus, err := d.TellStatus(second)
	if err != nil {
		t.Fatalf("TellStatus(second) error = %v", err)
	}
	if secondStatus.Status != "waiting" {
		t.Fatalf("second status = %q, want waiting while first is active", secondStatus.Status)
	}

	if err := d.Cancel(second); err != nil {
		t.Fatalf("Cancel(queued) error = %v", err)
	}

	if _, err := d.TellStatus(second); err == nil {
		t.Error("expected TellStatus error after cancelling a queued download")
	}
	if err := d.Cancel(second); err == nil {
		t.Error("expected Cancel error for unknown GID")
	}

	releaseNow()
	waitForEvent(t, events, first, EventComplete, 15*time.Second)
}

func TestEmbed_CancelActive(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
			http.ServeContent(w, r, "block.bin", time.Now(), bytes.NewReader([]byte("blocked-payload")))
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	d, _ := runDaemon(t, &EngineOptions{Dir: t.TempDir(), MaxConcurrentDownloads: 1})
	events, _ := d.Subscribe()

	gid, err := d.AddURI(srv.URL+"/block.bin", nil)
	if err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}
	waitForEvent(t, events, gid, EventStart, 15*time.Second)

	if err := d.Cancel(gid); err != nil {
		t.Fatalf("Cancel(active) error = %v", err)
	}
	waitForEvent(t, events, gid, EventStop, 15*time.Second)

	st, err := d.TellStatus(gid)
	if err != nil {
		t.Fatalf("TellStatus() error = %v", err)
	}
	if st.Status != "removed" {
		t.Errorf("Status = %q, want removed", st.Status)
	}
	if st.ErrorCode == 0 {
		t.Error("ErrorCode = 0, want the aria2 removed code")
	}
}

func TestEmbed_ErrorStatus(t *testing.T) {
	d, _ := runDaemon(t, &EngineOptions{Dir: t.TempDir(), MaxConcurrentDownloads: 1})
	events, _ := d.Subscribe()

	gid, err := d.AddURI("http://127.0.0.1:1/unreachable.bin", nil)
	if err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}
	waitForEvent(t, events, gid, EventError, 30*time.Second)

	st, err := d.TellStatus(gid)
	if err != nil {
		t.Fatalf("TellStatus() error = %v", err)
	}
	if st.Status != "error" {
		t.Errorf("Status = %q, want error", st.Status)
	}
	if st.ErrorCode == 0 {
		t.Error("ErrorCode = 0, want a non-zero aria2 error code")
	}
	if st.ErrorMessage == "" {
		t.Error("ErrorMessage empty, want details")
	}
}

func TestEmbed_KeepRunning(t *testing.T) {
	d, err := New(Config{Engine: &EngineOptions{Dir: t.TempDir(), KeepRunning: true}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- d.Run(ctx)
	}()

	select {
	case err := <-done:
		t.Fatalf("Run returned while idle without KeepRunning effect: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	st := d.Status()
	if st.Active != 0 || st.Waiting != 0 {
		t.Fatalf("Status() = %+v, want idle engine", st)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

func TestEmbed_EventsIncludeStart(t *testing.T) {
	payload := []byte("start-event-payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "file.bin", time.Now(), bytes.NewReader(payload))
	}))
	defer srv.Close()

	d, _ := runDaemon(t, &EngineOptions{Dir: t.TempDir()})
	events, unsubscribe := d.Subscribe()
	defer unsubscribe()

	gid, err := d.AddURI(srv.URL+"/file.bin", nil)
	if err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}

	waitForEvent(t, events, gid, EventStart, 15*time.Second)
	waitForEvent(t, events, gid, EventComplete, 15*time.Second)

	unsubscribe()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return // channel closed, as documented
			}
		case <-deadline:
			t.Error("events channel not closed after unsubscribe")
			return
		}
	}
}

func TestEmbed_SubscribeBeforeRun(t *testing.T) {
	d, err := New(Config{Engine: &EngineOptions{Dir: t.TempDir(), DryRun: true}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	events, _ := d.Subscribe()

	gid, err := d.AddURI("http://example.com/queued.bin", nil)
	if err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = d.Run(ctx)
		close(done)
	}()

	waitForEvent(t, events, gid, EventComplete, 15*time.Second)
	cancel()
	<-done
}
