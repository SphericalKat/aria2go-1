package engine

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/smartass08/aria2go/internal/config"
	"github.com/smartass08/aria2go/internal/core"
)

// runFollowTorrentEngine runs a full engine lifecycle for the follow-torrent
// tests and waits until gid reaches the given state.
func runFollowTorrentEngine(t *testing.T, opts *config.Options, add func(e *Engine) core.GID, want core.Status) (*Engine, <-chan error, core.GID) {
	t.Helper()

	e, err := New(opts, testLogger(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	e.KeepRunning()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- e.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("engine Run did not return after cancel")
		}
	})

	target := add(e)
	waitForStatus(t, e, done, target, want)
	return e, done, target
}

func waitForStatus(t *testing.T, e *Engine, done <-chan error, gid core.GID, want core.Status) *Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		st, err := e.TellStatus(gid)
		if err == nil && st.Status == want {
			return st
		}
		select {
		case err := <-done:
			t.Fatalf("engine exited early: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			st, _ := e.TellStatus(gid)
			t.Fatalf("timed out waiting for %s; last status = %+v", want, st)
		}
	}
}

func followTestOpts(t *testing.T) *config.Options {
	t.Helper()
	opts := testOpts()
	opts.Dir = t.TempDir()
	opts.MaxConcurrentDownloads = 1
	opts.EnableDHT = false
	opts.BTMaxPeers = 1
	opts.SeedTime = "0"
	return opts
}

func TestFollowTorrent_URISuffixEnqueuesChild(t *testing.T) {
	payload := []byte("follow-torrent-uri-suffix-payload")
	fixture := startTestMagnetFixture(t, "followed.bin", payload, 16*1024)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "payload.torrent", time.Now(), bytes.NewReader(fixture.TorrentData))
	}))
	defer srv.Close()

	opts := followTestOpts(t)
	e, done, metaGID := runFollowTorrentEngine(t, opts, func(e *Engine) core.GID {
		gid, err := e.Add(AddSpec{URIs: []string{srv.URL + "/payload.torrent"}, Options: opts})
		if err != nil {
			t.Fatalf("Add() error = %v", err)
		}
		return gid
	}, core.StatusComplete)

	st, err := e.TellStatus(metaGID)
	if err != nil {
		t.Fatalf("TellStatus(metadata) error = %v", err)
	}
	if len(st.FollowedBy) != 1 {
		t.Fatalf("FollowedBy = %v, want one child", st.FollowedBy)
	}
	child := st.FollowedBy[0]

	childSt := waitForStatus(t, e, done, child, core.StatusComplete)
	if childSt.Following != metaGID {
		t.Errorf("child Following = %s, want %s", childSt.Following, metaGID)
	}

	if got, err := os.ReadFile(filepath.Join(opts.Dir, "followed.bin")); err != nil || !bytes.Equal(got, payload) {
		t.Errorf("payload file mismatch: err = %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(opts.Dir, "payload.torrent")); err != nil || !bytes.Equal(got, fixture.TorrentData) {
		t.Errorf("saved .torrent mismatch: err = %v", err)
	}
}

func TestFollowTorrent_ContentTypeWithoutSuffix(t *testing.T) {
	payload := []byte("follow-torrent-content-type-payload")
	fixture := startTestMagnetFixture(t, "ct-followed.bin", payload, 16*1024)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-bittorrent")
		http.ServeContent(w, r, "download", time.Now(), bytes.NewReader(fixture.TorrentData))
	}))
	defer srv.Close()

	opts := followTestOpts(t)
	e, _, metaGID := runFollowTorrentEngine(t, opts, func(e *Engine) core.GID {
		gid, err := e.Add(AddSpec{URIs: []string{srv.URL + "/download"}, Options: opts})
		if err != nil {
			t.Fatalf("Add() error = %v", err)
		}
		return gid
	}, core.StatusComplete)

	st, err := e.TellStatus(metaGID)
	if err != nil {
		t.Fatalf("TellStatus(metadata) error = %v", err)
	}
	if len(st.FollowedBy) != 1 {
		t.Fatalf("FollowedBy = %v, want one child for content-type trigger", st.FollowedBy)
	}
}

func TestFollowTorrent_MemDoesNotSaveTorrentFile(t *testing.T) {
	payload := []byte("follow-torrent-mem-payload")
	fixture := startTestMagnetFixture(t, "mem-followed.bin", payload, 16*1024)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "payload.torrent", time.Now(), bytes.NewReader(fixture.TorrentData))
	}))
	defer srv.Close()

	opts := followTestOpts(t)
	opts.FollowTorrent = "mem"

	e, _, metaGID := runFollowTorrentEngine(t, opts, func(e *Engine) core.GID {
		gid, err := e.Add(AddSpec{URIs: []string{srv.URL + "/payload.torrent"}, Options: opts})
		if err != nil {
			t.Fatalf("Add() error = %v", err)
		}
		return gid
	}, core.StatusComplete)

	st, err := e.TellStatus(metaGID)
	if err != nil {
		t.Fatalf("TellStatus(metadata) error = %v", err)
	}
	if len(st.FollowedBy) != 1 {
		t.Fatalf("FollowedBy = %v, want one child", st.FollowedBy)
	}
	if _, err := os.Stat(filepath.Join(opts.Dir, "payload.torrent")); !os.IsNotExist(err) {
		t.Errorf("mem mode saved the .torrent file; stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(opts.Dir, "mem-followed.bin")); err != nil {
		t.Errorf("payload file missing: %v", err)
	}
}

func TestFollowTorrent_DisabledDownloadsPlainFile(t *testing.T) {
	payload := []byte("follow-torrent-disabled-payload")
	fixture := startTestMagnetFixture(t, "disabled.bin", payload, 16*1024)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "payload.torrent", time.Now(), bytes.NewReader(fixture.TorrentData))
	}))
	defer srv.Close()

	opts := followTestOpts(t)
	opts.FollowTorrent = "false"

	e, _, _ := runFollowTorrentEngine(t, opts, func(e *Engine) core.GID {
		gid, err := e.Add(AddSpec{URIs: []string{srv.URL + "/payload.torrent"}, Options: opts})
		if err != nil {
			t.Fatalf("Add() error = %v", err)
		}
		return gid
	}, core.StatusComplete)

	statuses := e.TellStopped(0, 10)
	if len(statuses) != 1 {
		t.Fatalf("stopped results = %d, want 1 (no child)", len(statuses))
	}
	got, err := os.ReadFile(filepath.Join(opts.Dir, "payload.torrent"))
	if err != nil || !bytes.Equal(got, fixture.TorrentData) {
		t.Errorf("plain .torrent file mismatch: err = %v", err)
	}
}
