package aria2c

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testMetalinkV4 = `<?xml version="1.0" encoding="UTF-8"?>
<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <file name="example.iso">
    <url>http://example.com/example.iso</url>
    <url>http://mirror.example.com/example.iso</url>
  </file>
</metalink>`

const testMetalinkMultiFile = `<?xml version="1.0" encoding="UTF-8"?>
<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <file name="a.bin">
    <url>http://example.com/a.bin</url>
  </file>
  <file name="b.bin">
    <url>http://example.com/b.bin</url>
  </file>
</metalink>`

func testEngineOptions(t *testing.T) *EngineOptions {
	t.Helper()
	return &EngineOptions{
		Dir:                    t.TempDir(),
		MaxConcurrentDownloads: 5,
		DryRun:                 true,
	}
}

func runDaemon(t *testing.T, opts *EngineOptions) (*Daemon, context.CancelFunc) {
	t.Helper()
	d, err := New(Config{Engine: opts})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = d.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("Run did not return after context cancel")
		}
	})
	return d, cancel
}

func TestNew(t *testing.T) {
	d, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if d == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNew_WithEngineOptions(t *testing.T) {
	opts := &EngineOptions{Dir: "/tmp/aria2go-engine-test", MaxConcurrentDownloads: 3}
	d, err := New(Config{Engine: opts})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if d == nil {
		t.Fatal("New() returned nil")
	}
}

func TestAddURI(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	gid, err := d.AddURI("http://example.com/file.iso", nil)
	if err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}
	if gid == 0 {
		t.Error("AddURI() returned zero GID")
	}

	st := d.Status()
	if st.Waiting != 1 {
		t.Errorf("Waiting = %d, want 1", st.Waiting)
	}
}

func TestAddTorrent(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	gid, err := d.AddTorrent([]byte("dummy torrent data"), nil)
	if err != nil {
		t.Fatalf("AddTorrent() error = %v", err)
	}
	if gid == 0 {
		t.Error("AddTorrent() returned zero GID")
	}
}

func TestAddMetalink(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	gids, err := d.AddMetalink([]byte(testMetalinkV4), nil)
	if err != nil {
		t.Fatalf("AddMetalink() error = %v", err)
	}
	if len(gids) != 1 {
		t.Fatalf("len(gids) = %d, want 1", len(gids))
	}
	if gids[0] == 0 {
		t.Error("AddMetalink() returned zero GID")
	}
}

func TestAddMetalink_MultiFileReturnsMultipleGIDs(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	gids, err := d.AddMetalink([]byte(testMetalinkMultiFile), nil)
	if err != nil {
		t.Fatalf("AddMetalink() error = %v", err)
	}
	if len(gids) != 2 {
		t.Fatalf("len(gids) = %d, want 2", len(gids))
	}
	if gids[0] == 0 || gids[1] == 0 {
		t.Fatalf("AddMetalink() returned zero gid(s): %v", gids)
	}
	if gids[0] == gids[1] {
		t.Fatalf("AddMetalink() returned duplicate gids: %v", gids)
	}
}

func TestAddMetalink_InvalidXML(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = d.AddMetalink([]byte("not xml"), nil)
	if err == nil {
		t.Error("expected error for invalid metalink XML")
	}
}

func TestRPCAddr_Disabled(t *testing.T) {
	d, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if addr := d.RPCAddr(); addr != "" {
		t.Errorf("RPCAddr() = %q, want empty", addr)
	}
}

func TestTellStatus_UnknownGID(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := d.TellStatus(GID(1)); err == nil {
		t.Error("expected error for unknown GID")
	}
}

func TestShutdown(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- d.Run(ctx)
	}()

	time.Sleep(10 * time.Millisecond)

	if err := d.Shutdown(false); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after Shutdown")
	}
}

func TestShutdown_Force(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.Run(ctx)
	time.Sleep(10 * time.Millisecond)

	if err := d.Shutdown(true); err != nil {
		t.Fatalf("Shutdown(true) error = %v", err)
	}
}

func TestShutdown_DoubleCall(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.Run(ctx)
	time.Sleep(10 * time.Millisecond)

	d.Shutdown(false)
	if err := d.Shutdown(false); err == nil {
		t.Error("expected error on second shutdown call")
	}
}

func TestShutdown_Concurrent(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.Run(ctx)
	time.Sleep(10 * time.Millisecond)

	for i := 0; i < 10; i++ {
		if _, err := d.AddURI("http://example.com/"+string(rune('a'+i%26)), nil); err != nil {
			t.Fatalf("AddURI() error = %v", err)
		}
	}

	var wg sync.WaitGroup

	var shutdownErrors int32
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := d.Shutdown(false); err != nil {
				atomic.AddInt32(&shutdownErrors, 1)
			}
		}()
	}

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Status()
		}()
	}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = d.AddURI("http://example.com/new-"+string(rune('a'+i%26)), nil)
		}(i)
	}

	wg.Wait()

	if shutdownErrors < 3 {
		t.Errorf("expected most concurrent shutdowns to fail, got %d failures out of 5", shutdownErrors)
	}
}

func TestStatus(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	st := d.Status()
	if st.Active != 0 || st.Waiting != 0 || st.Stopped != 0 || st.Speed != 0 {
		t.Errorf("Status() = %+v, want all zero", st)
	}
}

func TestStatus_WithDownloads(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, name := range []string{"a", "b", "c"} {
		if _, err := d.AddURI("http://example.com/"+name, nil); err != nil {
			t.Fatalf("AddURI() error = %v", err)
		}
	}

	st := d.Status()
	if st.Waiting != 3 {
		t.Errorf("Waiting = %d, want 3", st.Waiting)
	}
	if st.Active != 0 {
		t.Errorf("Active = %d, want 0 (no Run called)", st.Active)
	}
}

func TestStatus_Concurrent(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := d.AddURI("http://example.com/file.iso", nil); err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Status()
		}()
	}
	wg.Wait()
}

func TestAddURI_Concurrent(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := d.AddURI("http://example.com/"+string(rune('a'+i%26)), nil); err != nil {
				t.Errorf("AddURI concurrent error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	d.Shutdown(true)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after Shutdown")
	}

	st := d.Status()
	if st.Stopped != 20 {
		t.Errorf("Stopped = %d, want 20 (dry-run completes)", st.Stopped)
	}
}

func TestAddMetalink_Concurrent(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.AddMetalink([]byte(testMetalinkV4), nil); err != nil {
				t.Errorf("AddMetalink concurrent error: %v", err)
			}
		}()
	}
	wg.Wait()

	st := d.Status()
	if st.Waiting != 10 {
		t.Errorf("Waiting = %d, want 10", st.Waiting)
	}
}

func TestParseGID(t *testing.T) {
	gid, err := ParseGID("0000000000000001")
	if err != nil {
		t.Fatalf("ParseGID(hex) error = %v", err)
	}
	if gid != 1 {
		t.Errorf("ParseGID(hex) = %d, want 1", gid)
	}

	gid, err = ParseGID("42")
	if err != nil {
		t.Fatalf("ParseGID(decimal) error = %v", err)
	}
	if gid != 42 {
		t.Errorf("ParseGID(decimal) = %d, want 42", gid)
	}

	if _, err := ParseGID("zz"); err == nil {
		t.Error("expected error for invalid GID")
	}
}

func TestGIDRoundTrip(t *testing.T) {
	d, err := New(Config{Engine: testEngineOptions(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	gid, err := d.AddURI("http://example.com/file.iso", nil)
	if err != nil {
		t.Fatalf("AddURI() error = %v", err)
	}
	parsed, err := ParseGID(gid.Hex())
	if err != nil {
		t.Fatalf("ParseGID(Hex()) error = %v", err)
	}
	if parsed != gid {
		t.Errorf("round trip = %s, want %s", parsed, gid)
	}
	st, err := d.TellStatus(parsed)
	if err != nil {
		t.Fatalf("TellStatus(parsed) error = %v", err)
	}
	if st.GID != gid {
		t.Errorf("status GID = %s, want %s", st.GID, gid)
	}
}
