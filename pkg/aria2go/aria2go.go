// Package aria2c is the frozen public API for the aria2go download daemon.
// It is the only package consumers import; everything else is internal/.
//
// The Daemon type provides a concurrency-safe interface for adding URI
// (HTTP(S), FTP, SFTP, magnet), torrent, and metalink downloads, querying
// per-download status, cancelling downloads, receiving lifecycle events,
// and controlling the daemon lifecycle.
package aria2c

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/smartass08/aria2go/internal/config"
	"github.com/smartass08/aria2go/internal/core"
	"github.com/smartass08/aria2go/internal/engine"
)

// GID identifies a download. It matches aria2's GID: the zero value is
// invalid and every valid GID is greater than zero.
type GID = core.GID

// ErrDownloadNotFound reports a GID the engine no longer knows, e.g. after
// a queued download is cancelled or its stopped-result entry is evicted.
var ErrDownloadNotFound = engine.ErrDownloadNotFound

// eventBufferSize is the subscriber channel size used between the engine
// event bus and Daemon event subscribers. The engine drops events for
// subscribers whose channel is full, so consumers must drain their channel.
const eventBufferSize = 1024

// EngineOptions configures a Daemon at construction time. The zero value
// gives an offline engine: no DHT, no RPC, downloads in the current
// directory.
type EngineOptions struct {
	// Dir is the base output directory for downloads that do not carry a
	// per-download directory. Empty means the current directory.
	Dir string

	// MaxConcurrentDownloads caps simultaneously active downloads.
	// Zero or negative selects the aria2 default (5).
	MaxConcurrentDownloads int

	// EnableDHT enables BitTorrent DHT peer discovery. The zero value
	// disables DHT so embedded engines stay offline unless explicitly
	// enabled.
	EnableDHT bool

	// DryRun probes every download and completes it without writing payload
	// data.
	DryRun bool

	// SeedTime controls BitTorrent seeding after a download completes,
	// in aria2 minutes semantics: empty seeds indefinitely (the aria2
	// default) and "0" stops the download as soon as it completes.
	SeedTime string

	// CACertificate is a path to a PEM file added to the TLS root set for
	// HTTPS downloads.
	CACertificate string

	// KeepRunning stops the engine from exiting when the download queues
	// empty. Run then blocks until its context is cancelled or Shutdown is
	// called. Embeddings that own the lifecycle through a context set this.
	KeepRunning bool
}

// DownloadOptions carries per-download overrides. Nil fields mean "use the
// engine defaults".
type DownloadOptions struct {
	// Dir is the output directory for this download. It overrides
	// EngineOptions.Dir.
	Dir string

	// Out is the output file name for single-file downloads. It overrides
	// the name derived from the URI.
	Out string

	// Pause adds the download in the paused state. It requires an engine
	// started with KeepRunning, matching aria2's pause behavior.
	Pause bool
}

// Config holds configuration for creating a Daemon.
type Config struct {
	// Engine carries the engine-level options. If nil, defaults are used.
	Engine *EngineOptions
}

// New creates a new Daemon with the given configuration.
// Call Run to start the daemon; until then, downloads can be added to the
// waiting queue but will not begin.
func New(cfg Config) (*Daemon, error) {
	opts := config.Default()
	if cfg.Engine != nil {
		if cfg.Engine.Dir != "" {
			opts.Dir = cfg.Engine.Dir
		}
		if cfg.Engine.MaxConcurrentDownloads > 0 {
			opts.MaxConcurrentDownloads = cfg.Engine.MaxConcurrentDownloads
		}
		opts.EnableDHT = cfg.Engine.EnableDHT
		opts.DryRun = cfg.Engine.DryRun
		opts.SeedTime = cfg.Engine.SeedTime
		if cfg.Engine.CACertificate != "" {
			opts.CACertificate = cfg.Engine.CACertificate
		}
	}

	log := slog.Default()
	eng, err := engine.New(opts, log)
	if err != nil {
		return nil, fmt.Errorf("aria2c: %w", err)
	}
	if cfg.Engine != nil && cfg.Engine.KeepRunning {
		eng.KeepRunning()
	}

	return &Daemon{
		eng:     eng,
		cfg:     opts,
		rpcAddr: "",
	}, nil
}

// Daemon encapsulates the download engine and provides a frozen,
// concurrency-safe public API for managing downloads.
type Daemon struct {
	eng     *engine.Engine
	cfg     *config.Options
	rpcAddr string
}

// Run starts the daemon and blocks until ctx is cancelled or Shutdown is
// called. It must be running for downloads to progress.
func (d *Daemon) Run(ctx context.Context) error {
	return d.eng.Run(ctx)
}

func (d *Daemon) downloadConfig(opts *DownloadOptions) *config.Options {
	if opts == nil {
		return nil
	}
	cfg := &config.Options{}
	if opts.Dir != "" {
		cfg.Dir = opts.Dir
	}
	if opts.Out != "" {
		cfg.Out = opts.Out
	}
	if opts.Pause {
		cfg.Pause = true
	}
	return cfg
}

// AddURI adds a download for the given URI and returns the assigned GID.
// The URI may be HTTP(S), FTP, SFTP, or a magnet link. HTTP(S) URIs that
// name a .torrent file or answer with the bittorrent content type enqueue
// the described torrent as a followed child download, matching aria2's
// follow-torrent behavior.
func (d *Daemon) AddURI(uri string, opts *DownloadOptions) (GID, error) {
	return d.eng.Add(engine.AddSpec{
		URIs:    []string{uri},
		Options: d.downloadConfig(opts),
	})
}

// AddTorrent adds a .torrent file download. data is the raw bencoded
// torrent.
func (d *Daemon) AddTorrent(data []byte, opts *DownloadOptions) (GID, error) {
	return d.eng.Add(engine.AddSpec{
		Torrent: data,
		Options: d.downloadConfig(opts),
	})
}

// AddMetalink adds a metalink download. data is the raw metalink XML.
// It returns one GID per selected metalink file, matching aria2's multi-GID
// metalink behavior.
func (d *Daemon) AddMetalink(data []byte, opts *DownloadOptions) ([]GID, error) {
	gids, err := d.eng.AddMetalink(data, d.downloadConfig(opts), 0, false)
	if err != nil {
		return nil, fmt.Errorf("aria2c: add metalink: %w", err)
	}
	return gids, nil
}

// Cancel removes a queued or active download. A queued download disappears
// without leaving a result entry, matching aria2.remove on a waiting
// download. An active download is halted and recorded with the removed
// status. Cancelling a download that already finished returns an error.
func (d *Daemon) Cancel(gid GID) error {
	return d.eng.Remove(gid, false)
}

// FileInfo describes one file that belongs to a download.
type FileInfo struct {
	Index           int
	Path            string
	Length          int64
	CompletedLength int64
	Selected        bool
}

// DownloadStatus is a per-download snapshot.
type DownloadStatus struct {
	GID GID
	// Status is one of "waiting", "active", "paused", "complete", "error",
	// or "removed".
	Status          string
	TotalLength     int64
	CompletedLength int64
	UploadLength    int64
	DownloadSpeed   int64
	UploadSpeed     int64
	// ErrorCode is the aria2 exit code; zero means success.
	ErrorCode    int
	ErrorMessage string
	Dir          string
	Files        []FileInfo
	// FollowedBy lists child downloads created by this download, e.g. the
	// torrent payload download behind a magnet or followed .torrent URI.
	FollowedBy []GID
	// Following is the parent metadata download for followed children.
	Following GID
	// BelongsTo is the metadata GID that created this download, when any.
	BelongsTo GID
	InfoHash  string
	// NumSeeders and Connections report BitTorrent peer activity.
	NumSeeders  int64
	Connections int
}

// TellStatus returns the current snapshot for gid. It reports an error when
// the engine no longer knows the GID, e.g. after a queued download is
// cancelled or the stopped-result entry is evicted. Use errors.Is with
// ErrDownloadNotFound to detect that case.
func (d *Daemon) TellStatus(gid GID) (DownloadStatus, error) {
	st, err := d.eng.TellStatus(gid)
	if err != nil {
		return DownloadStatus{}, fmt.Errorf("aria2c: %w", err)
	}
	return newDownloadStatus(st), nil
}

// Files returns the file list for gid. It is a convenience wrapper around
// TellStatus.
func (d *Daemon) Files(gid GID) ([]FileInfo, error) {
	st, err := d.TellStatus(gid)
	if err != nil {
		return nil, err
	}
	return st.Files, nil
}

func newDownloadStatus(st *engine.Status) DownloadStatus {
	if st == nil {
		return DownloadStatus{}
	}
	files := make([]FileInfo, 0, len(st.Files))
	for _, f := range st.Files {
		files = append(files, FileInfo{
			Index:           f.Index,
			Path:            f.Path,
			Length:          f.Length,
			CompletedLength: f.CompletedLength,
			Selected:        f.Selected,
		})
	}
	return DownloadStatus{
		GID:             st.GID,
		Status:          st.Status.String(),
		TotalLength:     st.TotalLength,
		CompletedLength: st.CompletedLength,
		UploadLength:    st.UploadLength,
		DownloadSpeed:   st.DownloadSpeed,
		UploadSpeed:     st.UploadSpeed,
		ErrorCode:       int(st.ErrorCode),
		ErrorMessage:    st.ErrorMessage,
		Dir:             st.Dir,
		Files:           files,
		FollowedBy:      append([]GID(nil), st.FollowedBy...),
		Following:       st.Following,
		BelongsTo:       st.BelongsTo,
		InfoHash:        st.InfoHash,
		NumSeeders:      st.NumSeeders,
		Connections:     st.Connections,
	}
}

// EventKind identifies a download lifecycle event.
type EventKind string

// Download lifecycle event kinds, matching aria2's RPC notifications.
const (
	EventStart      EventKind = "start"
	EventPause      EventKind = "pause"
	EventStop       EventKind = "stop"
	EventComplete   EventKind = "complete"
	EventError      EventKind = "error"
	EventBTComplete EventKind = "btcomplete"
)

// Event is a lifecycle notification for a single download.
type Event struct {
	GID  GID
	Kind EventKind
	Time time.Time
}

// Subscribe returns a channel that receives download lifecycle events for
// every download in the daemon. The returned function unsubscribes and
// closes the channel; it is safe to call more than once. Events still
// queued at unsubscribe time are dropped.
//
// The engine drops events when a subscriber stops draining its channel, so
// consumers must keep reading the channel while downloads progress.
func (d *Daemon) Subscribe() (<-chan Event, func()) {
	src := make(chan core.Event, eventBufferSize)
	unsubscribe := d.eng.Subscribe(src).Unsubscribe

	dst := make(chan Event, eventBufferSize)
	done := make(chan struct{})
	go func() {
		defer close(dst)
		for {
			select {
			case ev := <-src:
				select {
				case dst <- Event{GID: ev.GID, Kind: EventKind(ev.Kind.String()), Time: ev.Time}:
				case <-done:
					return
				}
			case <-done:
				return
			}
		}
	}()

	var once sync.Once
	return dst, func() {
		once.Do(func() {
			unsubscribe()
			close(done)
		})
	}
}

// Shutdown stops the daemon gracefully. If force is true, active downloads
// are halted immediately; otherwise they receive a pause request and the
// engine waits for clean teardown.
func (d *Daemon) Shutdown(force bool) error {
	return d.eng.Shutdown(force)
}

// RPCAddr returns the RPC listen address if RPC is enabled, or an empty
// string otherwise. Engines created through Config never enable RPC.
func (d *Daemon) RPCAddr() string {
	return d.rpcAddr
}

// DaemonStatus is an aggregate snapshot of daemon state.
type DaemonStatus struct {
	Active  int   // number of active downloads
	Waiting int   // number of waiting (including paused) downloads
	Stopped int   // number of stopped (complete/error/removed) downloads
	Speed   int64 // total download speed in bytes/sec across all active downloads
}

// Status returns the current aggregate daemon status. All counters are
// point-in-time snapshots taken under the engine's internal mutex.
func (d *Daemon) Status() DaemonStatus {
	active := d.eng.TellActive()

	var speed int64
	for _, s := range active {
		speed += s.DownloadSpeed
	}

	return DaemonStatus{
		Active:  len(active),
		Waiting: len(d.eng.TellWaiting(0, math.MaxInt)),
		Stopped: len(d.eng.TellStopped(0, math.MaxInt)),
		Speed:   speed,
	}
}
