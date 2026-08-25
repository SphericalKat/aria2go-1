package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/smartass08/aria2go/internal/config"
	"github.com/smartass08/aria2go/internal/console"
	"github.com/smartass08/aria2go/internal/cookies"
	"github.com/smartass08/aria2go/internal/core"
	"github.com/smartass08/aria2go/internal/dht"
	"github.com/smartass08/aria2go/internal/disk"
	"github.com/smartass08/aria2go/internal/hash"
	"github.com/smartass08/aria2go/internal/hookrunner"
	"github.com/smartass08/aria2go/internal/lpd"
	"github.com/smartass08/aria2go/internal/magnet"
	"github.com/smartass08/aria2go/internal/netrc"
	"github.com/smartass08/aria2go/internal/netx"
	"github.com/smartass08/aria2go/internal/portmap"
	btprogress "github.com/smartass08/aria2go/internal/protocol/bittorrent/progress"
	ftpproto "github.com/smartass08/aria2go/internal/protocol/ftp"
	httpproto "github.com/smartass08/aria2go/internal/protocol/http"
	"github.com/smartass08/aria2go/internal/protocol/metalink"
	sftpproto "github.com/smartass08/aria2go/internal/protocol/sftp"
	rpc_transport "github.com/smartass08/aria2go/internal/rpc/transport"
	"github.com/smartass08/aria2go/internal/sessionfile"
	"github.com/smartass08/aria2go/internal/tlsx"
	"github.com/smartass08/aria2go/internal/torrent"
)

// ShutdownDelay is the delay before shutdown actually executes, matching
// aria2's TimedHaltCommand 3-second delay to give clients time to receive
// the RPC response.
const ShutdownDelay = 3 * time.Second

// numGIDShards is the number of shards for the GID → requestGroup map.
// Must be a power of two for fast modulo.
const numGIDShards = 64

// requestGroup represents a single download in the engine's lifecycle.
// It mirrors aria2's RequestGroup class state machine but uses Go contexts
// for cancellation instead of the command/event-poll pattern.
type haltReason uint8

const (
	haltReasonNone haltReason = iota
	haltReasonUserRequest
	haltReasonShutdown
)

type requestGroup struct {
	gid          core.GID
	opts         *config.Options
	localOpts    *config.Options
	uris         []string
	torrent      []byte
	metalinkData []byte
	metadataURI  string
	state        core.Status

	created       time.Time
	errCode       core.ErrorCode
	errMsg        string
	pauseReq      bool
	restartReq    bool
	forceHaltReq  bool
	haltRequested bool
	haltReason    haltReason

	belongsTo  core.GID
	following  core.GID
	followedBy []core.GID

	seeder bool

	pendingOpts *config.Options

	filePath          string
	fileEntries       []disk.FileEntry
	inMemory          bool
	controlPath       string
	controlLoaded     bool
	controlInfo       *btprogress.Info
	controlPieceBytes []int64
	adaptor           disk.Adaptor
	controlMu         sync.Mutex
	// statusMu guards completion fields that worker goroutines write
	// without the group lock and makeStatus reads: errCode, errMsg,
	// followedBy, following, seeder.
	statusMu         sync.Mutex
	probed           bool
	probedSize       int64
	acceptsRanges    bool
	inflatedResponse bool
	cdFilename       string
	lastModified     time.Time
	contentType      string

	completedLength    int64
	totalLength        int64
	numConnections     atomic.Int64
	numSeeders         atomic.Int64
	fileName           string
	resumeFailureCount int
	bytesDownloaded    int64
	bytesUploaded      int64
	sessionUploaded    int64
	lastSpeedSample    time.Time

	downloadLimit *Throttle
	uploadLimit   *Throttle
	btSwarm       atomic.Pointer[btSwarm]

	filePathFromURI bool
	btInfoHash      string
	btUnselected    []string
	uriUsed         bool
	activeURI       string
	activeHosts     map[string]int
	integrity       downloadIntegrity
	integrityRetry  int
	integrityMu     sync.Mutex

	resumeBlockedURIs map[string]struct{}

	ctx    context.Context
	cancel context.CancelFunc

	downloadSpeed int64
	uploadSpeed   int64
}

// gidShard holds a portion of the GID → requestGroup map with its own mutex.
type gidShard struct {
	mu     sync.Mutex
	groups map[core.GID]*requestGroup
}

// gidShardMap provides sharded access to requestGroup lookups by GID.
type gidShardMap struct {
	shards [numGIDShards]gidShard
}

func newGIDShardMap(capacity int) *gidShardMap {
	m := &gidShardMap{}
	perShard := capacity / numGIDShards
	if perShard < 1 {
		perShard = 1
	}
	for i := range m.shards {
		m.shards[i].groups = make(map[core.GID]*requestGroup, perShard)
	}
	return m
}

func (m *gidShardMap) shard(gid core.GID) *gidShard {
	return &m.shards[uint64(gid)&(numGIDShards-1)]
}

func (m *gidShardMap) get(gid core.GID) (*requestGroup, bool) {
	s := m.shard(gid)
	s.mu.Lock()
	rg, ok := s.groups[gid]
	s.mu.Unlock()
	return rg, ok
}

func (m *gidShardMap) set(gid core.GID, rg *requestGroup) {
	s := m.shard(gid)
	s.mu.Lock()
	s.groups[gid] = rg
	s.mu.Unlock()
}

func (m *gidShardMap) delete(gid core.GID) {
	s := m.shard(gid)
	s.mu.Lock()
	delete(s.groups, gid)
	s.mu.Unlock()
}

func (m *gidShardMap) deleteLocked(gid core.GID) {
	delete(m.shard(gid).groups, gid)
}

func (m *gidShardMap) getLocked(gid core.GID) (*requestGroup, bool) {
	s := m.shard(gid)
	s.mu.Lock()
	rg, ok := s.groups[gid]
	if !ok {
		s.mu.Unlock()
	}
	return rg, ok
}

func (m *gidShardMap) unlock(gid core.GID) {
	m.shard(gid).mu.Unlock()
}

// Subscriber receives engine lifecycle events. Implementations must not block.
type Subscriber interface {
	OnEvent(ev core.Event)
}

// drPool reuses downloadResult allocations to reduce GC pressure.
var drPool = sync.Pool{
	New: func() any {
		return &downloadResult{}
	},
}

// Engine is the central download orchestrator, matching aria2's DownloadEngine
// architecture. It manages the lifecycle of all downloads (RequestGroups),
// assigns GIDs via random generation (matching aria2's GroupId::create),
// and dispatches lifecycle events via a pub/sub event bus.
//
// In aria2's C++ implementation the engine uses an event-poll + command
// pattern. In Go the same semantics are achieved with goroutines + context
// cancellation: each active download runs in a goroutine that watches its
// context for cancellation, and the engine's queue management goroutine
// moves downloads between waiting/active/stopped queues.
type Engine struct {
	cfg *config.Options
	log *slog.Logger

	startupTemplate *config.Options

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	groups *gidShardMap

	queuesMu  sync.Mutex
	active    []core.GID
	waiting   []core.GID
	queueWake chan struct{}

	usedGIDsMu sync.Mutex
	usedGIDs   map[core.GID]struct{}

	stoppedRing  *stoppedRing
	stoppedTotal atomic.Int64

	removedErrors  atomic.Int64
	removedLastErr atomic.Int64

	bus *EventBus

	subMu      sync.RWMutex
	subs       map[any]Subscriber
	dispatcher Subscriber

	sessionID string
	created   time.Time

	running      atomic.Bool
	shuttingDown atomic.Bool
	haltReq      atomic.Bool
	keepRunning  bool

	httpDriver  *httpproto.Driver
	netDialer   *netx.Dialer
	cookieJar   *cookies.Jar
	authFactory *AuthConfigFactory

	rpcServer   *rpc_transport.Server
	RPCBackend  RPCBackend
	dhtServer   *dht.Server
	portMapper  *portmap.Mapper
	console     *console.Console
	lpdListener *lpd.Listener
	btSession   *BtSession
	serverStats *ServerStatMan

	rateGlobal   *Throttle
	rateGlobalUp *Throttle

	saveInterval        time.Duration
	saveSessionInterval time.Duration
	inputParser         *sessionfile.Parser
	shutdownSession     []sessionfile.Entry
	shutdownExitPending atomic.Bool
	shutdownExitLastErr atomic.Int64
	shutdownHadActive   atomic.Bool
	lastSessionHash     [20]byte
	hasSessionHash      bool

	downloadSpeed atomic.Int64
	uploadSpeed   atomic.Int64

	newDispatcher func(e *Engine, secret string) RPCBackend
}

// AddSpec describes a download to be added to the engine.
type AddSpec struct {
	URIs        []string
	Options     *config.Options
	Torrent     []byte
	Metalink    []byte
	MetadataURI string
	OutputName  string
	Position    int
	PositionSet bool
	BelongsTo   core.GID
}

// SubscribeResult holds the result of subscribing to engine events.
type SubscribeResult struct {
	C           <-chan core.Event
	Unsubscribe func()
}

// Status is the public status snapshot of a single download, matching
// aria2's aria2.tellStatus RPC response shape.
type Status struct {
	GID                    core.GID       `json:"gid"`
	Status                 core.Status    `json:"status"`
	TotalLength            int64          `json:"totalLength"`
	CompletedLength        int64          `json:"completedLength"`
	UploadLength           int64          `json:"uploadLength"`
	DownloadSpeed          int64          `json:"downloadSpeed"`
	UploadSpeed            int64          `json:"uploadSpeed"`
	InfoHash               string         `json:"infoHash,omitempty"`
	NumSeeders             int64          `json:"numSeeders,string"`
	Connections            int            `json:"connections"`
	ErrorCode              core.ErrorCode `json:"errorCode,string"`
	ErrorMessage           string         `json:"errorMessage,omitempty"`
	FollowedBy             []core.GID     `json:"followedBy,omitempty"`
	BelongsTo              core.GID       `json:"belongsTo,omitempty"`
	Following              core.GID       `json:"following,omitempty"`
	Dir                    string         `json:"dir"`
	Files                  []FileStatus   `json:"files"`
	Seeder                 bool           `json:"seeder,string"`
	Bittorrent             map[string]any `json:"bittorrent,omitempty"`
	VerifiedLength         int64          `json:"verifiedLength"`
	VerifyIntegrityPending bool           `json:"verifyIntegrityPending,string"`
	Bitfield               string         `json:"bitfield,omitempty"`
	PieceLength            int64          `json:"pieceLength"`
	NumPieces              int64          `json:"numPieces"`
}

// FileStatus describes a file within a multi-file download.
type FileStatus struct {
	Index           int         `json:"index,string"`
	Path            string      `json:"path"`
	Length          int64       `json:"length,string"`
	CompletedLength int64       `json:"completedLength,string"`
	Selected        bool        `json:"selected,string"`
	URIs            []URIStatus `json:"uris"`
}

// URIStatus describes the status of a single URI for a file.
type URIStatus struct {
	URI    string `json:"uri"`
	Status string `json:"status"`
}

type PeerStatus struct {
	PeerID        string
	IP            string
	Port          string
	Bitfield      string
	AmChoking     bool
	PeerChoking   bool
	DownloadSpeed int64
	UploadSpeed   int64
	Seeder        bool
}

// downloadResult holds the final state of a completed/error/removed download,
// mirroring aria2's DownloadResult / downloadResults_ queue.
type downloadResult struct {
	gid         core.GID
	state       core.Status
	errCode     core.ErrorCode
	errMsg      string
	belongsTo   core.GID
	following   core.GID
	followedBy  []core.GID
	opts        *config.Options
	localOpts   *config.Options
	metadataURI string

	filePath              string
	statusSnapshot        Status
	totalLength           int64
	completedLength       int64
	sessionDownloadLength int64
	sessionTime           time.Duration
}

// New creates a new Engine with the given configuration and logger.
// The engine does not start any goroutines until Run is called.
func New(cfg *config.Options, log *slog.Logger) (*Engine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("engine: config is nil")
	}
	if log == nil {
		return nil, fmt.Errorf("engine: logger is nil")
	}

	maxDownloads := cfg.MaxConcurrentDownloads
	if maxDownloads <= 0 {
		maxDownloads = 5
	}
	maxResults := cfg.MaxDownloadResult
	if maxResults <= 0 {
		maxResults = 1000
	}

	dialer, err := netx.NewDialer(engineDialerConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("engine: dialer: %w", err)
	}

	httpTLS, err := httpClientTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("engine: http tls: %w", err)
	}

	cookieJar := newHTTPCookieJar(cfg, log)
	acceptEncoding := ""
	if cfg.HTTPAcceptGzip {
		acceptEncoding = "deflate, gzip"
	}

	httpDriver := httpproto.NewDriver(httpproto.Opts{
		Dialer:            dialer,
		TLS:               httpTLS,
		Jar:               httpCookieJar(cookieJar),
		Timeout:           time.Duration(parseInt(cfg.Timeout)) * time.Second,
		UserAgent:         cfg.UserAgent,
		Header:            cfg.Header,
		CheckCertificate:  &cfg.CheckCertificate,
		MaxRedirs:         20,
		AcceptEncoding:    acceptEncoding,
		Referer:           cfg.Referer,
		HTTPUser:          cfg.HTTPUser,
		HTTPPasswd:        cfg.HTTPPasswd,
		HTTPAuthChallenge: cfg.HTTPAuthChallenge,
		DisableKeepAlive:  !cfg.EnableHTTPKeepAlive,
		NoCache:           &cfg.HTTPNoCache,
		EnableWantDigest:  boolPtr(!cfg.NoWantDigestHeader),
		UseHead:           cfg.UseHead,
		DryRun:            cfg.DryRun,
	})
	authFactory := NewAuthConfigFactory()
	if !cfg.NoNetrc {
		entries, defaultEntry := loadNetrcForConfig(cfg, log)
		authFactory.SetNetrc(entries, defaultEntry)
	}

	e := &Engine{
		cfg:             cfg,
		log:             log,
		startupTemplate: config.Merge(cfg),
		groups:          newGIDShardMap(maxDownloads * 2),
		active:          make([]core.GID, 0, maxDownloads),
		waiting:         make([]core.GID, 0, maxDownloads),
		queueWake:       make(chan struct{}, 1),
		usedGIDs:        make(map[core.GID]struct{}),
		stoppedRing:     newStoppedRing(maxResults),
		bus:             NewEventBus(),
		sessionID:       newSessionID(),
		created:         time.Now(),
		keepRunning:     cfg.EnableRPC,
		httpDriver:      httpDriver,
		netDialer:       dialer,
		cookieJar:       cookieJar,
		authFactory:     authFactory,
		serverStats:     NewServerStatMan(),
		rateGlobal:      NewThrottle(parseSize(cfg.MaxOverallDownloadLimit)),
		rateGlobalUp:    NewThrottle(parseSize(cfg.MaxOverallUploadLimit)),
		btSession:       NewBtSession(cfg),
	}
	if err := e.loadServerStats(cfg); err != nil {
		log.Warn("failed to load server stats", "error", err)
	}

	if cfg.BTEnableLPD {
		lpdL, lpdErr := lpd.NewListener()
		if lpdErr != nil {
			log.Warn("lpd init failed, continuing without LPD", "error", lpdErr)
		} else {
			e.lpdListener = lpdL
		}
	}

	if cfg.AutoSaveInterval != "" {
		e.saveInterval = time.Duration(parseInt(cfg.AutoSaveInterval)) * time.Second
	}
	if e.saveInterval <= 0 {
		e.saveInterval = 0
	}

	if interval := cfg.SaveSessionInterval; interval != "" {
		e.saveSessionInterval = time.Duration(parseInt(interval)) * time.Second
	}
	if e.saveSessionInterval <= 0 {
		e.saveSessionInterval = 0
	}

	dhtPort := parseDHTPort(cfg.DHTListenPort)
	listenPort := parseListenPort(cfg.ListenPort)

	if cfg.EnableDHT {
		dhtSrv, err := dht.NewServer(engineDHTConfig(dhtPort, cfg))
		if err != nil {
			return nil, fmt.Errorf("engine: dht server: %w", err)
		}
		e.dhtServer = dhtSrv
	}

	pm, err := portmap.New(portmap.Config{
		InternalPort: listenPort,
		ExternalPort: listenPort,
		Protocols:    []string{"tcp"},
	})
	if err != nil {
		log.Warn("portmap init failed, continuing without port mapping", "error", err)
	} else {
		e.portMapper = pm
	}

	e.console = console.New(engineConsoleOptions(cfg))

	e.removedLastErr.Store(int64(core.ExitSuccess))
	return e, nil
}

func engineConsoleOptions(cfg *config.Options) console.Options {
	summaryInterval := time.Duration(parseInt(cfg.SummaryInterval)) * time.Second
	if summaryInterval < 0 {
		summaryInterval = 0
	}
	return console.Options{
		Quiet:           cfg.Quiet,
		SummaryInterval: summaryInterval,
		Interactive:     !cfg.Quiet,
		Stderr:          cfg.Stderr,
		ShowReadout:     cfg.ShowConsoleReadout,
		ShowReadoutSet:  true,
		Truncate:        cfg.TruncateConsoleReadout,
		TruncateSet:     true,
	}
}

func engineDialerConfig(cfg *config.Options) netx.DialerConfig {
	return netx.DialerConfig{
		Timeout:              time.Duration(parseInt(cfg.ConnectTimeout)) * time.Second,
		KeepAlive:            30 * time.Second,
		Interface:            cfg.Interface,
		PreferIPv4:           cfg.DisableIPv6,
		DisableIPv6:          cfg.DisableIPv6,
		AsyncDNS:             cfg.AsyncDNS,
		EnableAsyncDNS6:      cfg.EnableAsyncDNS6,
		AsyncDNSServer:       cfg.AsyncDNSServer,
		SocketRecvBufferSize: parseInt(cfg.SocketRecvBufferSize),
		DSCP:                 parseInt(cfg.DSCP),
		Interfaces:           cfg.MultipleInterface,
		NoProxy:              cfg.NoProxy,
	}
}

func engineDialerConfigWithoutProxy(cfg *config.Options) netx.DialerConfig {
	dialerCfg := engineDialerConfig(cfg)
	dialerCfg.ProxyURL = ""
	return dialerCfg
}

func httpClientTLSConfig(cfg *config.Options) (*tls.Config, error) {
	minVersion, err := tlsx.TLSVersion(cfg.MinTLSVersion)
	if err != nil {
		return nil, err
	}
	var caCerts [][]byte
	if cfg.CACertificate != "" {
		ca, err := os.ReadFile(cfg.CACertificate)
		if err != nil {
			return nil, fmt.Errorf("read ca-certificate: %w", err)
		}
		caCerts = append(caCerts, ca)
	}
	var clientCert []byte
	if cfg.Certificate != "" {
		clientCert, err = os.ReadFile(cfg.Certificate)
		if err != nil {
			return nil, fmt.Errorf("read certificate: %w", err)
		}
	}
	var clientKey []byte
	if cfg.Certificate != "" && cfg.PrivateKey != "" {
		clientKey, err = os.ReadFile(cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("read private-key: %w", err)
		}
	}
	return tlsx.ClientConfig(tlsx.ClientOpts{
		CACerts:    caCerts,
		ClientCert: clientCert,
		ClientKey:  clientKey,
		MinVersion: minVersion,
	})
}

func newHTTPCookieJar(cfg *config.Options, log *slog.Logger) *cookies.Jar {
	if cfg.LoadCookies == "" && cfg.SaveCookies == "" {
		return nil
	}
	jar := cookies.New()
	if cfg.LoadCookies == "" {
		return jar
	}
	if err := jar.LoadFile(cfg.LoadCookies); err != nil {
		log.Error("failed to load cookies", "path", cfg.LoadCookies, "error", err)
		return jar
	}
	log.Info("loaded cookies", "path", cfg.LoadCookies)
	return jar
}

func httpCookieJar(jar *cookies.Jar) http.CookieJar {
	if jar == nil {
		return nil
	}
	return jar
}

func loadNetrcForConfig(cfg *config.Options, log *slog.Logger) ([]netrc.Entry, *netrc.DefaultEntry) {
	path := expandHomePath(cfg.NetrcPath)
	if path == "" {
		return nil, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn("netrc stat failed", "path", path, "error", err)
		}
		return nil, nil
	}
	if !st.Mode().IsRegular() {
		return nil, nil
	}
	if st.Mode().Perm()&0o077 != 0 {
		log.Warn("netrc ignored due to permissions", "path", path)
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		log.Warn("netrc open failed", "path", path, "error", err)
		return nil, nil
	}
	defer f.Close()
	entries, def, err := netrc.Parse(f)
	if err != nil {
		log.Warn("netrc parse failed", "path", path, "error", err)
		return nil, nil
	}
	return entries, def
}

func expandHomePath(path string) string {
	if path == "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	switch {
	case path == "$(HOME)":
		return home
	case strings.HasPrefix(path, "$(HOME)/"), strings.HasPrefix(path, "$(HOME)\\"):
		return filepath.Join(home, path[len("$(HOME)/"):])
	default:
		return path
	}
}

func engineDHTConfig(port int, cfg *config.Options) dht.Config {
	return dht.Config{
		Addr:      fmt.Sprintf(":%d", port),
		Bootstrap: dhtBootstrapAddrs(cfg),
		PersistTo: cfg.DHTFilePath,
	}
}

func dhtBootstrapAddrs(cfg *config.Options) []string {
	if cfg == nil {
		return nil
	}
	host, port := cfg.DHTEntryPointHost, cfg.DHTEntryPointPort
	if host != "" {
		if port == "" {
			port = "6881"
		}
		return []string{net.JoinHostPort(host, port)}
	}
	if len(cfg.DHTEntryPoint) == 0 {
		return nil
	}
	return append([]string(nil), cfg.DHTEntryPoint...)
}

// SetDispatcherFactory sets the factory function used to create an RPC dispatcher
// backend when EnableRPC is true. Must be called before Run().
// The factory receives the engine and RPC secret, and returns an RPCBackend
// which bridges to the transport layer. This indirection avoids an import cycle
// between engine and rpc/dispatcher.
func (e *Engine) SetDispatcherFactory(fn func(e *Engine, secret string) RPCBackend) {
	e.newDispatcher = fn
}

// newSessionID generates a random 20-byte session identifier (matching
// aria2's DownloadEngine constructor which calls generateRandomKey for 20 bytes).
func newSessionID() string {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("engine: failed to generate session ID: %v", err))
	}
	return fmt.Sprintf("%x", b[:])
}

// nextGID generates a random uint64 GID, retrying if zero or already used.
// Matches aria2's GroupId::create() behavior exactly — GIDs are random,
// not monotonic. Used GIDs are tracked in e.usedGIDs (cleared via ClearGIDs
// for tests, or retained for session-scoped uniqueness).
func (e *Engine) nextGID() core.GID {
	e.usedGIDsMu.Lock()
	defer e.usedGIDsMu.Unlock()
	return e.nextGIDLocked()
}

func (e *Engine) nextGIDLocked() core.GID {
	var buf [8]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			panic(fmt.Sprintf("engine: failed to generate GID: %v", err))
		}
		n := core.GID(binary.BigEndian.Uint64(buf[:]))
		if n == 0 {
			continue
		}
		if _, used := e.usedGIDs[n]; !used {
			e.usedGIDs[n] = struct{}{}
			return n
		}
	}
}

// ClearGIDs resets the used GID set. Only for testing.
func (e *Engine) ClearGIDs() {
	e.usedGIDsMu.Lock()
	defer e.usedGIDsMu.Unlock()
	e.usedGIDs = make(map[core.GID]struct{})
}

// SessionID returns the engine's session identifier, used by the RPC layer
// for session-scoped state.
func (e *Engine) SessionID() string {
	return e.sessionID
}

// Created returns the time the engine was created.
func (e *Engine) Created() time.Time {
	return e.created
}

// emit sends a lifecycle event to all registered subscribers via the EventBus.
func (e *Engine) emit(kind core.EventKind, gid core.GID) {
	e.bus.Emit(core.Event{
		Kind: kind,
		GID:  gid,
		Time: time.Now(),
	})
}

// emitBatch sends multiple lifecycle events to all registered subscribers
// in a single notification pass via the EventBus.
func (e *Engine) emitBatch(evs []core.Event) {
	if len(evs) == 0 {
		return
	}
	for i := range evs {
		e.bus.Emit(evs[i])
	}
}

// Run starts the engine's main goroutines and blocks until the context is
// cancelled or all downloads complete. The engine exits cleanly when ctx
// is done; call Shutdown for graceful shutdown.
//
// When keepRunning is true (set via PREF_ENABLE_RPC), the engine continues
// running even when there are no active downloads, matching aria2's
// keepRunning_ flag.
func (e *Engine) Run(ctx context.Context) error {
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.running.Store(true)
	defer e.running.Store(false)
	if e.btSession != nil {
		defer e.btSession.Close()
	}
	defer func() {
		if e.inputParser != nil {
			_ = e.inputParser.Close()
			e.inputParser = nil
		}
	}()

	e.log.Info("engine started", "session", e.sessionID)

	startupInput := ""
	startupDeferred := false
	if e.startupTemplate != nil {
		startupInput = e.startupTemplate.InputFile
		startupDeferred = e.startupTemplate.DeferredInput
	}

	if startupInput != "" {
		if startupDeferred {
			parser, err := sessionfile.OpenParser(startupInput)
			if err != nil {
				return fmt.Errorf("engine: input file: %w", err)
			}
			e.inputParser = parser
		} else {
			runtimeCfg := e.cfg
			e.cfg = e.startupTemplate
			err := e.loadInputFile(startupInput)
			e.cfg = runtimeCfg
			if err != nil {
				return err
			}
		}
	}

	// 1. Load session if path exists. If input-file and save-session point to
	// the same path, load it once through the input-file path.
	if e.cfg.SaveSession != "" && e.cfg.SaveSession != startupInput {
		if err := e.LoadSession(e.cfg.SaveSession); err != nil {
			e.log.Warn("failed to load session", "error", err)
		}
	}

	// Initialize RPC transport if dispatcher factory is set.
	if e.newDispatcher != nil {
		backend := e.newDispatcher(e, e.cfg.RPCSecret)
		tsCfg, err := e.rpcTransportConfig(backend)
		if err != nil {
			return err
		}
		ts, err := rpc_transport.New(tsCfg)
		if err != nil {
			return fmt.Errorf("engine: rpc transport: %w", err)
		}
		e.rpcServer = ts
	}

	// 2. Start queue manager (scheduler)
	e.startLifecycleWatchers()

	// 2. Start queue manager (scheduler)
	e.wg.Add(1)
	go e.queueManager()

	// 3. Start ticker (periodic stats, console, auto-save)
	e.wg.Add(1)
	go e.ticker()

	// 3. Start RPC if enabled
	if e.rpcServer != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := e.rpcServer.Run(e.ctx); err != nil {
				e.log.Error("rpc transport error", "error", err)
			}
		}()
	}

	// 4. Start DHT if enabled
	if e.dhtServer != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := e.dhtServer.Run(e.ctx); err != nil && err != context.Canceled {
				e.log.Error("dht server error", "error", err)
			}
		}()
	}

	// 5. Start portmap (only when DHT/BT features are enabled)
	if e.cfg.EnableDHT && e.portMapper != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := e.portMapper.Run(e.ctx); err != nil && err != context.Canceled {
				e.log.Error("portmap error", "error", err)
			}
		}()
	}

	// 6. Start LPD if enabled
	if e.lpdListener != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := e.lpdListener.Run(e.ctx); err != nil && err != context.Canceled {
				e.log.Error("lpd listener error", "error", err)
			}
		}()
	}

	<-e.ctx.Done()

	e.log.Info("engine stopping")
	e.wg.Wait()
	e.log.Info("engine stopped")

	e.showDownloadResults()
	e.saveHTTPCookies()
	if err := e.saveServerStats(); err != nil {
		e.log.Warn("failed to save server stats", "error", err)
	}

	// Save session on exit (only if path configured)
	if e.cfg.SaveSession != "" {
		if err := e.SaveSession(); err != nil {
			e.log.Error("failed to save session on exit", "error", err)
		}
	}

	return nil
}

func (e *Engine) rpcTransportConfig(backend RPCBackend) (rpc_transport.Config, error) {
	rpcPort := e.cfg.RPCListenPort
	if rpcPort <= 0 {
		rpcPort = 6800
	}
	rpcListen := fmt.Sprintf(":%d", rpcPort)
	var origins []string
	if e.cfg.RPCAllowOriginAll {
		origins = []string{"*"}
	}
	tsCfg := rpc_transport.Config{
		Listen:         rpcListen,
		ListenAll:      e.cfg.RPCListenAll,
		AllowedOrigins: origins,
		Dispatcher:     &rpcAdapter{b: backend},
		Secret:         e.cfg.RPCSecret,
		RPCUser:        e.cfg.RPCUser,
		RPCPasswd:      e.cfg.RPCPasswd,
		MaxRequestSize: parseSize(e.cfg.RPCMaxRequestSize),
	}
	if e.cfg.RPCSecure {
		tlsCfg, err := loadRPCServerTLSConfig(e.cfg.RPCCertificate, e.cfg.RPCPrivateKey)
		if err != nil {
			return rpc_transport.Config{}, fmt.Errorf("engine: rpc tls: %w", err)
		}
		tsCfg.TLS = tlsCfg
	}
	return tsCfg, nil
}

func loadRPCServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	return tlsx.ServerConfig(tlsx.ServerOpts{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
}

func (e *Engine) saveHTTPCookies() {
	if e.cookieJar == nil || e.cfg.SaveCookies == "" {
		return
	}
	f, err := os.Create(e.cfg.SaveCookies)
	if err != nil {
		e.log.Error("failed to save cookies", "path", e.cfg.SaveCookies, "error", err)
		return
	}
	defer f.Close()
	if err := e.cookieJar.SaveNetscape(f); err != nil {
		e.log.Error("failed to write cookies", "path", e.cfg.SaveCookies, "error", err)
		return
	}
	e.log.Info("saved cookies", "path", e.cfg.SaveCookies)
}

func (e *Engine) startLifecycleWatchers() {
	if stopAfter := time.Duration(parseInt(e.cfg.Stop)) * time.Second; stopAfter > 0 {
		e.wg.Add(1)
		go e.runStopTimer(stopAfter)
	}
	if pid := e.cfg.StopWithProcess; pid > 0 {
		e.wg.Add(1)
		go e.runProcessWatch(pid)
	}
}

func (e *Engine) runStopTimer(stopAfter time.Duration) {
	defer e.wg.Done()

	timer := time.NewTimer(stopAfter)
	defer timer.Stop()

	select {
	case <-e.ctx.Done():
		return
	case <-timer.C:
		if e.shuttingDown.Load() || e.ctx.Err() != nil {
			return
		}
		e.log.Info("stop timer elapsed", "after", stopAfter)
		_ = e.Shutdown(false)
	}
}

func (e *Engine) runProcessWatch(pid int) {
	defer e.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			if e.shuttingDown.Load() {
				return
			}
			if processRunning(pid) {
				continue
			}
			e.log.Info("watched process exited; commencing shutdown", "pid", pid)
			_ = e.Shutdown(false)
			return
		}
	}
}

func processRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrProcessDone) {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "access is denied")
}

// Shutdown initiates an orderly shutdown. If force is true, the shutdown
// is immediate (matching aria2's requestForceHalt). Otherwise, active
// downloads are requested to halt gracefully (requestHalt).
func (e *Engine) Shutdown(force bool) error {
	if !e.shuttingDown.CompareAndSwap(false, true) {
		if force {
			e.log.Info("shutdown escalation requested", "force", true)
			e.markActiveShutdown(force)
			e.haltReq.Store(true)
			if e.cancel != nil {
				e.cancel()
			}
			return nil
		}
		return fmt.Errorf("engine: already shutting down")
	}
	e.log.Info("shutdown requested", "force", force)
	e.markActiveShutdown(force)

	e.haltReq.Store(true)
	if e.cancel != nil {
		e.cancel()
	}
	return nil
}

// KeepRunning configures the engine to keep running when no downloads remain,
// matching aria2's keepRunning_ behavior with --enable-rpc. Library embeddings
// that manage the engine lifecycle through Run's context call this before Run.
func (e *Engine) KeepRunning() {
	e.keepRunning = true
}

func (e *Engine) markActiveShutdown(force bool) {
	e.queuesMu.Lock()
	for _, gid := range e.active {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}
		rg.haltRequested = true
		rg.haltReason = haltReasonShutdown
		if force {
			rg.forceHaltReq = true
		}
		e.groups.unlock(gid)
	}
	e.queuesMu.Unlock()
}

// ShutdownDelayed schedules a shutdown after ShutdownDelay, matching
// aria2's TimedHaltCommand pattern. This gives the RPC client time to
// receive the response before the server exits.
func (e *Engine) ShutdownDelayed(force bool) {
	e.log.Info("scheduling delayed shutdown", "force", force, "delay", ShutdownDelay)
	time.AfterFunc(ShutdownDelay, func() {
		_ = e.Shutdown(force)
	})
}

// Add creates a new download from the given specification and assigns either
// the supplied valid GID or a random GID (matching aria2's GroupId::create).
// The download is placed in the waiting queue. If there are available active
// slots (respecting max-concurrent-downloads), the queue manager will promote
// it to active.
//
// Returns the assigned GID on success.
func (e *Engine) Add(spec AddSpec) (core.GID, error) {
	if len(spec.URIs) == 0 && len(spec.Torrent) == 0 && len(spec.Metalink) == 0 {
		return 0, fmt.Errorf("engine: Add requires URIs, Torrent, or Metalink")
	}

	if e.shuttingDown.Load() {
		return 0, fmt.Errorf("engine: cannot add download during shutdown")
	}

	opts := spec.Options
	if opts == nil {
		opts = &config.Options{}
	}
	localOpts := config.CloneExplicitOptions(opts)
	opts = config.Merge(e.cfg, opts)

	gid, err := e.gidForOptions(opts)
	if err != nil {
		return 0, err
	}
	filePath := ""
	filePathFromURI := false
	if opts.Out != "" {
		filePath = filepath.Join(opts.Dir, opts.Out)
	} else if spec.OutputName != "" {
		filePath = filepath.Join(opts.Dir, spec.OutputName)
	} else if len(spec.URIs) > 0 {
		filePath = defaultOutputPathFromURI(spec.URIs[0])
		filePathFromURI = true
	}
	rg := &requestGroup{
		gid:             gid,
		opts:            opts,
		localOpts:       localOpts,
		uris:            spec.URIs,
		torrent:         spec.Torrent,
		metalinkData:    spec.Metalink,
		metadataURI:     spec.MetadataURI,
		state:           core.StatusWaiting,
		created:         time.Now(),
		pauseReq:        opts.Pause && e.keepRunning,
		belongsTo:       spec.BelongsTo,
		filePath:        filePath,
		filePathFromURI: filePathFromURI,
	}
	if err := e.applyRequestGroupRuntimeOptions(rg, opts); err != nil {
		return 0, err
	}

	e.groups.set(gid, rg)

	e.queuesMu.Lock()
	pos := len(e.waiting)
	if spec.PositionSet {
		pos = spec.Position
		if pos < 0 || pos > len(e.waiting) {
			pos = len(e.waiting)
		}
	}
	e.waiting = append(e.waiting, 0)
	copy(e.waiting[pos+1:], e.waiting[pos:])
	e.waiting[pos] = gid
	e.queuesMu.Unlock()

	// Wake queue manager so it can immediately try to promote this download.
	select {
	case e.queueWake <- struct{}{}:
	default:
	}

	e.log.Info("download added", "gid", gid, "uris", len(spec.URIs), "position", pos)
	return gid, nil
}

func (e *Engine) AddMetalink(data []byte, opts *config.Options, pos int, posSet bool) ([]core.GID, error) {
	specs, err := metalinkAddSpecs(data, opts)
	if err != nil {
		return nil, err
	}
	gids := make([]core.GID, 0, len(specs))
	for i, spec := range specs {
		if posSet {
			spec.PositionSet = true
			spec.Position = pos + i
		}
		gid, err := e.Add(spec)
		if err != nil {
			return nil, err
		}
		gids = append(gids, gid)
	}
	return gids, nil
}

func metalinkAddSpecs(data []byte, opts *config.Options) ([]AddSpec, error) {
	parseOpts, queryOpts := metalinkOptions(opts)
	doc, err := metalink.ParseWithOptions(bytes.NewReader(data), parseOpts)
	if err != nil {
		return nil, err
	}
	doc = metalink.Query(doc, queryOpts)

	var selected []bool
	if opts != nil && opts.SelectFile != "" {
		selected, err = parseBTSelectedFiles(opts.SelectFile, len(doc.Files))
		if err != nil {
			return nil, err
		}
	}

	specs := make([]AddSpec, 0, len(doc.Files))
	for fileIndex, file := range doc.Files {
		if len(selected) > 0 && !selected[fileIndex] {
			continue
		}

		urls := metalink.OrderURLs(file.URLs, queryOpts)

		uris := make([]string, 0, len(urls))
		for _, u := range urls {
			if u.URL != "" {
				uris = append(uris, u.URL)
			}
		}
		if len(uris) == 0 {
			continue
		}

		specOpts := config.Merge(opts)
		specOpts.Out = ""
		specOpts.ClearExplicit("out")
		specOpts.GID = ""
		specOpts.ClearExplicit("gid")

		specs = append(specs, AddSpec{
			URIs:        uris,
			Options:     specOpts,
			MetadataURI: specOpts.MetalinkFile,
			OutputName:  file.Name,
		})
	}

	return specs, nil
}

func (e *Engine) gidForOptions(opts *config.Options) (core.GID, error) {
	if opts.GID == "" {
		return e.nextGID(), nil
	}
	gid, err := core.ParseGID(opts.GID)
	if err != nil || gid == 0 {
		if err == nil {
			err = fmt.Errorf("zero GID")
		}
		return 0, fmt.Errorf("engine: invalid GID %q: %w", opts.GID, err)
	}
	if _, exists := e.groups.get(gid); exists {
		return 0, fmt.Errorf("engine: duplicate GID %s", gid.Hex())
	}
	e.usedGIDsMu.Lock()
	defer e.usedGIDsMu.Unlock()
	if _, used := e.usedGIDs[gid]; used {
		return 0, fmt.Errorf("engine: duplicate GID %s", gid.Hex())
	}
	e.usedGIDs[gid] = struct{}{}
	return gid, nil
}

// Pause pauses an active or waiting download. For an active download, this
// mirrors aria2's pauseRequestGroup(): it marks the group paused, requests the
// active worker to halt, and lets removeStoppedGroup finalize the transition to
// the waiting queue and fire pause hooks once the worker stops.
//
// If force is true, the active worker is force-halted.
func (e *Engine) Pause(gid core.GID, force bool) error {
	rg, ok := e.groups.getLocked(gid)
	if !ok {
		return fmt.Errorf("engine: download GID#%s not found", gid)
	}
	defer e.groups.unlock(gid)

	if rg.pauseReq {
		return fmt.Errorf("engine: download GID#%s is already paused", gid)
	}

	switch rg.state {
	case core.StatusActive:
		rg.pauseReq = true
		if force {
			rg.forceHaltReq = true
		} else {
			rg.haltRequested = true
		}
		if rg.cancel != nil {
			rg.cancel()
			e.log.Info("download pause requested", "gid", gid, "force", force)
		} else {
			// Tests can synthesize an active group without a running worker.
			// Finalize the pause inline so the group does not remain stuck active.
			e.queuesMu.Lock()
			e.moveFromActiveLocked(gid)
			e.waiting = append([]core.GID{gid}, e.waiting...)
			e.queuesMu.Unlock()
			rg.state = core.StatusWaiting
			rg.haltRequested = false
			rg.forceHaltReq = false
			e.runHookByName(rg, 1, "on-download-pause")
			e.emit(core.EvPause, gid)
			e.log.Info("download paused", "gid", gid, "force", force)
		}

	case core.StatusWaiting:
		rg.pauseReq = true
		// aria2 keeps the group in the reserved queue with pauseRequested;
		// state remains STATUS_WAITING + pauseRequested.
		e.log.Info("download pause requested", "gid", gid)

	case core.StatusComplete, core.StatusError, core.StatusRemoved:
		return fmt.Errorf("engine: cannot pause download GID#%s in state %s", gid, rg.state)
	}

	select {
	case e.queueWake <- struct{}{}:
	default:
	}

	return nil
}

// Resume restarts a paused download after it has reached the waiting queue.
// The queue manager will promote it to active when a slot becomes available,
// matching aria2's unpause -> waiting -> active flow.
func (e *Engine) Resume(gid core.GID) error {
	rg, ok := e.groups.getLocked(gid)
	if !ok {
		return fmt.Errorf("engine: download GID#%s not found", gid)
	}
	defer e.groups.unlock(gid)

	if rg.state != core.StatusWaiting || !rg.pauseReq {
		return fmt.Errorf("engine: download GID#%s is not paused (state=%s)", gid, rg.state)
	}

	rg.pauseReq = false
	// Download is already in waiting queue (aria2 places paused groups
	// in reservedGroups_ which is the waiting queue). State stays Waiting.
	e.log.Info("download resumed", "gid", gid)
	select {
	case e.queueWake <- struct{}{}:
	default:
	}
	return nil
}

// Remove removes a download. Active downloads are force-halted first.
// Waiting downloads are dropped from the reserved queue without producing a
// stopped result, matching aria2's removeReservedGroup path.
//
// If force is true, the removal is immediate even if the download is
// mid-transfer.
func (e *Engine) Remove(gid core.GID, force bool) error {
	e.queuesMu.Lock()
	rg, ok := e.groups.getLocked(gid)
	if !ok {
		e.queuesMu.Unlock()
		return fmt.Errorf("%w: GID#%s", ErrDownloadNotFound, gid)
	}

	rg.haltRequested = true
	rg.forceHaltReq = force
	rg.haltReason = haltReasonUserRequest

	switch rg.state {
	case core.StatusActive:
		rg.pauseReq = false
		rg.restartReq = false
		if rg.cancel == nil {
			e.moveFromActiveLocked(gid)
			e.queuesMu.Unlock()
			e.addStoppedLocked(rg, core.StatusRemoved, core.ExitRemoved, "")
			e.groups.deleteLocked(gid)
			e.groups.unlock(gid)
			e.log.Info("download removed", "gid", gid, "force", force)
			return nil
		}
		rg.cancel()
		e.groups.unlock(gid)
		e.queuesMu.Unlock()
		e.log.Info("download remove requested", "gid", gid, "force", force)
		return nil
	case core.StatusWaiting:
		e.moveFromWaitingLocked(gid)
		e.queuesMu.Unlock()
		e.groups.deleteLocked(gid)
		e.groups.unlock(gid)
		e.log.Info("download removed", "gid", gid, "force", force)
		return nil
	case core.StatusComplete, core.StatusError, core.StatusRemoved:
		e.queuesMu.Unlock()
		e.groups.unlock(gid)
		return fmt.Errorf("engine: cannot remove download GID#%s in state %s", gid, rg.state)
	default:
		e.queuesMu.Unlock()
		e.groups.unlock(gid)
		return fmt.Errorf("engine: cannot remove download GID#%s in state %s", gid, rg.state)
	}
}

// PurgeDownloadResult clears the stopped/results queue and returns the
// number of entries purged. This matches aria2's purgeDownloadResult.
func (e *Engine) PurgeDownloadResult() int {
	e.stoppedRing.mu.Lock()
	n := e.stoppedRing.size
	e.stoppedRing.mu.Unlock()
	e.stoppedRing.purge()
	return n
}

// RemoveDownloadResult removes a completed/error/removed result from the
// stopped-results queue.
func (e *Engine) RemoveDownloadResult(gid core.GID) error {
	if _, ok := e.groups.get(gid); ok {
		return fmt.Errorf("engine: download GID#%s is still active or waiting", gid)
	}
	if !e.stoppedRing.removeByGID(gid) {
		return fmt.Errorf("engine: download result GID#%s not found", gid)
	}
	return nil
}

// NumStopped returns the total number of downloads that have ever been stopped
// (mirrors aria2's RequestGroupMan::getNumStoppedTotal).
func (e *Engine) NumStopped() int64 {
	return e.stoppedTotal.Load()
}

// RemovedErrorResult returns the count and last error code of error results
// evicted from the stopped queue due to max-download-result limits.
func (e *Engine) RemovedErrorResult() (count int, lastErr core.ErrorCode) {
	return int(e.removedErrors.Load()), core.ErrorCode(e.removedLastErr.Load())
}

// GetDownloadStat returns aggregate statistics for completed/error/in-progress/waiting
// downloads, matching aria2's RequestGroupMan::getDownloadStat.
func (e *Engine) GetDownloadStat() (completed, errors, inProgress, waiting int) {
	e.queuesMu.Lock()
	inProgress = len(e.active)
	waiting = len(e.waiting)
	e.queuesMu.Unlock()

	e.stoppedRing.mu.Lock()
	defer e.stoppedRing.mu.Unlock()
	capacity := len(e.stoppedRing.buf)
	for i := 0; i < e.stoppedRing.size; i++ {
		pos := (e.stoppedRing.head + i) % capacity
		dr := e.stoppedRing.buf[pos]
		if dr.belongsTo != 0 {
			continue
		}
		switch dr.errCode {
		case core.ExitSuccess:
			completed++
		case core.ExitInProgress:
			inProgress++
		case core.ExitRemoved:
			// removed — don't count
		default:
			errors++
		}
	}
	errors += int(e.removedErrors.Load())
	return
}

// ExitCode returns the CLI session result code after Run has drained.
func (e *Engine) ExitCode() core.ErrorCode {
	_, errorsCount, inProgress, waiting := e.GetDownloadStat()
	lastErr := core.ErrorCode(e.removedLastErr.Load())

	e.stoppedRing.mu.Lock()
	capacity := len(e.stoppedRing.buf)
	for i := 0; i < e.stoppedRing.size; i++ {
		pos := (e.stoppedRing.head + i) % capacity
		dr := e.stoppedRing.buf[pos]
		if dr.belongsTo != 0 {
			continue
		}
		switch dr.errCode {
		case core.ExitSuccess:
		case core.ExitRemoved:
		case core.ExitInProgress:
			inProgress++
		default:
			lastErr = dr.errCode
		}
	}
	e.stoppedRing.mu.Unlock()

	if errorsCount == 0 && inProgress == 0 && waiting == 0 {
		if e.shuttingDown.Load() && e.shutdownHadActive.Load() {
			shutdownLastErr := core.ErrorCode(e.shutdownExitLastErr.Load())
			if shutdownLastErr != core.ExitSuccess {
				return shutdownLastErr
			}
			if e.shutdownExitPending.Load() {
				return core.ExitUnfinishedDownloads
			}
		}
		return core.ExitSuccess
	}
	if lastErr == core.ExitSuccess && inProgress > 0 {
		return core.ExitUnfinishedDownloads
	}
	if lastErr != core.ExitSuccess {
		return lastErr
	}
	return core.ExitUnknownError
}

// TellStatus returns the current status of a single download.
// ErrDownloadNotFound reports an unknown GID passed to TellStatus or Remove.
var ErrDownloadNotFound = errors.New("engine: download not found")

func (e *Engine) TellStatus(gid core.GID) (*Status, error) {
	rg, ok := e.groups.getLocked(gid)
	if ok {
		status := e.makeStatus(rg)
		e.groups.unlock(gid)
		return status, nil
	}

	dr, found := e.stoppedRing.getByGID(gid)
	if !found {
		return nil, fmt.Errorf("%w: GID#%s", ErrDownloadNotFound, gid)
	}
	status := cloneStatusSnapshot(dr.statusSnapshot)
	return &status, nil
}

// TellActive returns status snapshots of all active downloads.
func (e *Engine) TellActive() []Status {
	e.queuesMu.Lock()
	activeCopy := make([]core.GID, len(e.active))
	copy(activeCopy, e.active)
	e.queuesMu.Unlock()

	result := make([]Status, 0, len(activeCopy))
	for _, gid := range activeCopy {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}
		result = append(result, *e.makeStatus(rg))
		e.groups.unlock(gid)
	}
	return result
}

// TellWaiting returns status snapshots of waiting/paused downloads,
// starting at offset, up to num entries.
func (e *Engine) TellWaiting(offset, num int) []Status {
	e.queuesMu.Lock()
	waitingCopy := make([]core.GID, len(e.waiting))
	copy(waitingCopy, e.waiting)
	e.queuesMu.Unlock()

	if offset >= len(waitingCopy) {
		return nil
	}
	end := offset + num
	if end > len(waitingCopy) {
		end = len(waitingCopy)
	}

	result := make([]Status, 0, end-offset)
	for _, gid := range waitingCopy[offset:end] {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}
		result = append(result, *e.makeStatus(rg))
		e.groups.unlock(gid)
	}
	return result
}

// TellStopped returns status snapshots of completed/error/removed downloads,
// starting at offset, up to num entries.
func (e *Engine) TellStopped(offset, num int) []Status {
	return e.stoppedRing.snapshotStatuses(offset, num)
}

// ChangeOption applies per-download option changes. For active downloads,
// the options are stored as pending and take effect on restart (pause+resume),
// matching aria2's pendingOption_ pattern (RequestGroupMan.cc:440-443).
// For waiting downloads, the options are applied immediately since the
// download has not yet started.
func (e *Engine) ChangeOption(gid core.GID, opts *config.Options) error {
	if opts == nil {
		return fmt.Errorf("engine: options is nil")
	}

	rg, ok := e.groups.getLocked(gid)
	if !ok {
		if e.stoppedRing.mergeOptions(gid, opts) {
			return nil
		}
		return fmt.Errorf("engine: download GID#%s not found", gid)
	}
	defer e.groups.unlock(gid)

	rg.localOpts = config.Merge(rg.localOpts, opts)
	if rg.state == core.StatusActive {
		if rg.pendingOpts == nil {
			rg.pendingOpts = &config.Options{}
		}
		rg.pendingOpts = config.Merge(rg.pendingOpts, opts)
		e.applyRequestGroupRuntimeOptionPatch(rg, opts)
		rg.restartReq = true
		rg.pauseReq = true
		if rg.cancel != nil {
			rg.cancel()
		}
	} else {
		rg.opts = config.Merge(rg.opts, opts)
		if err := e.applyRequestGroupRuntimeOptions(rg, rg.opts); err != nil {
			return err
		}
	}
	return nil
}

// GetOption returns a copy of the current per-download options for gid.
func (e *Engine) GetOption(gid core.GID) (*config.Options, error) {
	rg, ok := e.groups.getLocked(gid)
	if !ok {
		if opts, found := e.stoppedRing.optionsByGID(gid); found {
			return opts, nil
		}
		return nil, fmt.Errorf("engine: download GID#%s not found", gid)
	}
	defer e.groups.unlock(gid)

	if rg.opts == nil {
		return &config.Options{}, nil
	}
	cp := *rg.opts
	return &cp, nil
}

// ChangePosition moves a download within the waiting queue. how must be
// one of "POS_SET", "POS_CUR", or "POS_END". Returns the new absolute
// position (0-indexed) matching aria2's ChangePositionRpcMethod.
func (e *Engine) ChangePosition(gid core.GID, pos int, how string) (int64, error) {
	e.queuesMu.Lock()
	rg, ok := e.groups.getLocked(gid)
	if !ok {
		e.queuesMu.Unlock()
		return 0, fmt.Errorf("engine: download GID#%s not found", gid)
	}

	if rg.state != core.StatusWaiting {
		e.groups.unlock(gid)
		e.queuesMu.Unlock()
		return 0, fmt.Errorf("engine: download GID#%s is not in waiting state", gid)
	}

	n := len(e.waiting)
	curIdx := -1
	for i, g := range e.waiting {
		if g == gid {
			curIdx = i
			break
		}
	}
	if curIdx < 0 {
		e.groups.unlock(gid)
		e.queuesMu.Unlock()
		return 0, fmt.Errorf("engine: download GID#%s not found in waiting queue", gid)
	}

	var dest int
	switch how {
	case "POS_SET":
		dest = pos
	case "POS_CUR":
		dest = curIdx + pos
	case "POS_END":
		dest = n + pos // pos is typically negative for POS_END
	default:
		e.groups.unlock(gid)
		e.queuesMu.Unlock()
		return 0, fmt.Errorf("engine: invalid how parameter: %q", how)
	}
	if dest < 0 {
		dest = 0
	}
	if dest >= n {
		dest = n - 1
	}

	// Remove from current position.
	e.waiting = append(e.waiting[:curIdx], e.waiting[curIdx+1:]...)
	if dest > curIdx {
		dest--
	}
	// Insert at new position.
	e.waiting = append(e.waiting, 0)
	copy(e.waiting[dest+1:], e.waiting[dest:])
	e.waiting[dest] = gid

	e.groups.unlock(gid)
	e.queuesMu.Unlock()
	return int64(dest), nil
}

// ChangeURI mutates the URI list for a single-file download and returns the
// number of removed and added URIs.
func (e *Engine) ChangeURI(gid core.GID, fileIndex int, delURIs, addURIs []string, pos int) (int64, int64, error) {
	return e.ChangeURIWithPosition(gid, fileIndex, delURIs, addURIs, pos, true)
}

// ChangeURIWithPosition mutates the URI list for a single-file download. When
// positionSet is false, new URIs are appended; when true, pos is clamped to the
// current URI list length, matching aria2.changeUri's optional position.
func (e *Engine) ChangeURIWithPosition(gid core.GID, fileIndex int, delURIs, addURIs []string, pos int, positionSet bool) (int64, int64, error) {
	if fileIndex < 1 {
		return 0, 0, fmt.Errorf("engine: fileIndex must be >= 1")
	}
	if fileIndex != 1 {
		return 0, 0, fmt.Errorf("engine: fileIndex is out of range")
	}
	if positionSet && pos < 0 {
		return 0, 0, fmt.Errorf("engine: position must be >= 0")
	}
	rg, ok := e.groups.getLocked(gid)
	if !ok {
		return 0, 0, fmt.Errorf("engine: download GID#%s not found", gid)
	}
	defer e.groups.unlock(gid)

	removed := 0
	for _, target := range delURIs {
		for i, uri := range rg.uris {
			if uri == target {
				rg.uris = append(rg.uris[:i], rg.uris[i+1:]...)
				removed++
				break
			}
		}
	}

	if !positionSet || pos > len(rg.uris) {
		pos = len(rg.uris)
	}
	added := 0
	for _, rawURI := range addURIs {
		uri, valid := normalizeChangeURI(rawURI)
		if !valid {
			continue
		}
		rg.uris = append(rg.uris, "")
		copy(rg.uris[pos+1:], rg.uris[pos:])
		rg.uris[pos] = uri
		pos++
		added++
	}
	if rg.filePath == "" && len(rg.uris) > 0 {
		rg.filePath = filepath.Base(rg.uris[0])
	}
	return int64(removed), int64(added), nil
}

func normalizeChangeURI(rawURI string) (string, bool) {
	uri := strings.ReplaceAll(rawURI, " ", "%20")
	parsed, err := url.Parse(uri)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" {
		return "", false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ftp", "sftp":
		if parsed.Host == "" {
			return "", false
		}
	}
	return uri, true
}

// ChangeGlobalOption updates the global engine options. These apply to
// all new downloads created after the change.
func (e *Engine) ChangeGlobalOption(opts *config.Options) error {
	if opts == nil {
		return fmt.Errorf("engine: options is nil")
	}

	explicit := optionExplicitSet(opts)

	e.queuesMu.Lock()
	e.cfg = config.Merge(e.cfg, opts)
	if optionChangeRequested(explicit, "auto-save-interval", opts.AutoSaveInterval != "") {
		e.saveInterval = time.Duration(parseInt(e.cfg.AutoSaveInterval)) * time.Second
		if e.saveInterval <= 0 {
			e.saveInterval = 0
		}
	}
	if optionChangeRequested(explicit, "save-session-interval", opts.SaveSessionInterval != "") {
		e.saveSessionInterval = time.Duration(parseInt(e.cfg.SaveSessionInterval)) * time.Second
		if e.saveSessionInterval <= 0 {
			e.saveSessionInterval = 0
		}
	}
	e.queuesMu.Unlock()

	if optionChangeRequested(explicit, "max-overall-download-limit", opts.MaxOverallDownloadLimit != "") {
		e.rateGlobal.SetRate(parseSize(e.cfg.MaxOverallDownloadLimit))
	}
	if optionChangeRequested(explicit, "max-overall-upload-limit", opts.MaxOverallUploadLimit != "") {
		e.rateGlobalUp.SetRate(parseSize(e.cfg.MaxOverallUploadLimit))
	}
	if optionChangeRequested(explicit, "max-download-result", opts.MaxDownloadResult != 0) {
		e.stoppedRing.resize(e.cfg.MaxDownloadResult)
		_, errors, lastErr := e.stoppedRing.evictionInfo()
		e.removedErrors.Store(int64(errors))
		e.removedLastErr.Store(int64(lastErr))
	}
	if optionChangeRequested(explicit, "max-concurrent-downloads", opts.MaxConcurrentDownloads != 0) ||
		optionChangeRequested(explicit, "optimize-concurrent-downloads", opts.OptimizeConcurrentDownloads != "") {
		select {
		case e.queueWake <- struct{}{}:
		default:
		}
	}
	return nil
}

// GetGlobalOption returns a copy of the current global options.
func (e *Engine) GetGlobalOption() *config.Options {
	e.queuesMu.Lock()
	defer e.queuesMu.Unlock()
	cp := *e.cfg
	return &cp
}

func optionExplicitSet(opts *config.Options) map[string]bool {
	names := opts.ExplicitNames()
	if len(names) == 0 {
		return nil
	}
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

func optionChangeRequested(explicit map[string]bool, name string, fallback bool) bool {
	if explicit != nil {
		return explicit[name]
	}
	return fallback
}

func (e *Engine) GetPeers(gid core.GID) ([]PeerStatus, error) {
	rg, ok := e.groups.get(gid)
	if !ok {
		return nil, fmt.Errorf("engine: download GID#%s not found", gid)
	}
	swarm := rg.btSwarm.Load()
	if swarm == nil {
		return []PeerStatus{}, nil
	}
	return swarm.snapshotPeers(), nil
}

// SaveSession serializes the current engine state (all active and waiting
// downloads) to the save-session file path specified in configuration.
// The output is aria2-compatible session file format using the sessionfile
// package. If no save session path is configured, this is a no-op.
func (e *Engine) SaveSession() error {
	path := e.cfg.SaveSession
	if path == "" {
		return fmt.Errorf("engine: Filename is not given.")
	}

	entries := e.sessionEntriesForSave()

	hash, err := sessionfile.SerializedHash(entries)
	if err != nil {
		return err
	}
	e.queuesMu.Lock()
	if e.hasSessionHash && e.lastSessionHash == hash {
		e.queuesMu.Unlock()
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		e.queuesMu.Lock()
	}
	e.lastSessionHash = hash
	e.hasSessionHash = true
	e.queuesMu.Unlock()

	return sessionfile.AtomicSave(path, entries, false)
}

func (e *Engine) sessionEntriesForSave() []sessionfile.Entry {
	e.queuesMu.Lock()
	waitingCopy := append([]core.GID(nil), e.waiting...)
	activeCopy := append([]core.GID(nil), e.active...)
	shutdownCopy := append([]sessionfile.Entry(nil), e.shutdownSession...)
	useShutdownSnapshot := e.shuttingDown.Load() && len(waitingCopy) == 0 && len(activeCopy) == 0 && len(shutdownCopy) > 0
	e.queuesMu.Unlock()

	if useShutdownSnapshot {
		return shutdownCopy
	}
	return e.sessionEntriesFromQueues(activeCopy, waitingCopy)
}

func (e *Engine) sessionEntriesFromQueues(activeCopy, waitingCopy []core.GID) []sessionfile.Entry {
	entries := make([]sessionfile.Entry, 0, len(waitingCopy)+len(activeCopy))
	for _, gid := range activeCopy {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}
		entries = append(entries, e.toSessionEntry(rg))
		e.groups.unlock(gid)
	}
	for _, gid := range waitingCopy {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}
		entries = append(entries, e.toSessionEntry(rg))
		e.groups.unlock(gid)
	}
	return entries
}

func (e *Engine) toSessionEntry(rg *requestGroup) sessionfile.Entry {
	uris := append([]string(nil), rg.uris...)
	if (len(rg.torrent) > 0 || len(rg.metalinkData) > 0) && rg.metadataURI == "" {
		uris = nil
	} else if rg.metadataURI != "" {
		uris = []string{rg.metadataURI}
	}
	entry := sessionfile.Entry{
		URIs:    uris,
		GID:     rg.gid,
		Options: config.SessionOptionMap(rg.localOpts),
	}
	if rg.pauseReq {
		entry.Status = core.StatusPaused
	} else {
		entry.Status = core.StatusWaiting
	}
	return entry
}

// LoadSession restores downloads from an aria2 session file at the given path.
// Each entry in the session file is added to the engine as a waiting download.
// Entries with the pause flag set are added in paused state.
func (e *Engine) LoadSession(path string) error {
	parser, err := sessionfile.OpenParser(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("engine: load session: %w", err)
	}
	defer parser.Close()

	loaded := 0
	for {
		entry, ok, err := parser.Next()
		if err != nil {
			return fmt.Errorf("engine: load session: %w", err)
		}
		if !ok {
			break
		}
		if len(entry.URIs) == 0 {
			continue
		}
		opts, optErr := optionsFromSessionEntry(entry)
		if optErr != nil {
			e.log.Warn("session load: failed to parse entry options", "gid", entry.GID, "error", optErr)
			continue
		}
		added, addErr := e.addURIEntry(entry.URIs, opts)
		if addErr != nil {
			e.log.Warn("session load: failed to add entry", "gid", entry.GID, "error", addErr)
			continue
		}
		loaded += added
	}

	e.log.Info("session loaded", "entries", loaded)
	return nil
}

// loadInputFile reads aria2 input/session entries and adds them to the engine.
// Option lines following each URI entry are parsed with the normal config parser.
func (e *Engine) loadInputFile(path string) error {
	parser, err := sessionfile.OpenParser(path)
	if err != nil {
		return fmt.Errorf("engine: input file: %w", err)
	}
	defer parser.Close()

	loaded := 0
	for {
		entry, ok, err := parser.Next()
		if err != nil {
			return fmt.Errorf("engine: input file read: %w", err)
		}
		if !ok {
			break
		}
		if len(entry.URIs) == 0 {
			continue
		}
		opts, optErr := optionsFromSessionEntry(entry)
		if optErr != nil {
			return fmt.Errorf("engine: input file options: %w", optErr)
		}
		added, err := e.addURIEntry(entry.URIs, opts)
		if err != nil {
			return fmt.Errorf("engine: input file add: %w", err)
		}
		loaded += added
	}

	e.log.Info("input file loaded", "path", path, "entries", loaded)
	return nil
}

func (e *Engine) addURIEntry(uris []string, opts *config.Options) (int, error) {
	effective := config.Merge(e.cfg, opts)
	if effective.ParameterizedURI {
		expanded, err := config.ExpandParameterizedURIs(uris)
		if err != nil {
			return 0, err
		}
		uris = expanded
	}
	if len(uris) == 0 {
		return 0, nil
	}
	if effective.ForceSequential {
		added := 0
		for _, uri := range uris {
			ok, err := e.addInputSource(uri, opts)
			if err != nil {
				return 0, err
			}
			if ok {
				added++
			}
		}
		return added, nil
	}

	streamURIs := make([]string, 0, len(uris))
	added := 0
	for _, uri := range uris {
		if isStreamURI(uri) {
			streamURIs = append(streamURIs, uri)
			continue
		}
		ok, err := e.addInputSource(uri, opts)
		if err != nil {
			return 0, err
		}
		if ok {
			added++
		}
	}

	if len(streamURIs) > 0 {
		if _, err := e.Add(AddSpec{URIs: streamURIs, Options: opts}); err != nil {
			return 0, err
		}
		added++
	}
	return added, nil
}

func (e *Engine) addInputSource(source string, opts *config.Options) (bool, error) {
	switch {
	case guessLocalTorrentFile(source):
		data, err := os.ReadFile(source)
		if err != nil {
			e.log.Warn("input source: cannot read torrent file", "path", source, "error", err)
			return false, nil
		}
		if _, err := torrent.Load(data); err != nil {
			e.log.Warn("input source: cannot parse torrent file", "path", source, "error", err)
			return false, nil
		}
		if _, err := e.Add(AddSpec{Torrent: data, Options: opts, MetadataURI: source}); err != nil {
			return false, err
		}
		return true, nil
	case guessLocalMetalinkFile(source):
		data, err := os.ReadFile(source)
		if err != nil {
			e.log.Warn("input source: cannot read metalink file", "path", source, "error", err)
			return false, nil
		}
		if _, err := metalink.Parse(bytes.NewReader(data)); err != nil {
			e.log.Warn("input source: cannot parse metalink file", "path", source, "error", err)
			return false, nil
		}
		if _, err := e.Add(AddSpec{Metalink: data, Options: opts, MetadataURI: source}); err != nil {
			return false, err
		}
		return true, nil
	default:
		if !isAddableURI(source) {
			e.log.Warn("input source: unrecognized URI", "value", source)
			return false, nil
		}
		if _, err := e.Add(AddSpec{URIs: []string{source}, Options: opts}); err != nil {
			return false, err
		}
		return true, nil
	}
}

func isStreamURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Scheme == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ftp", "sftp":
		return u.Host != ""
	default:
		return false
	}
}

func isAddableURI(raw string) bool {
	if isStreamURI(raw) {
		return true
	}
	if _, err := magnet.Parse(raw); err == nil {
		return true
	}
	return false
}

func guessLocalTorrentFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var head [1]byte
	n, err := f.Read(head[:])
	return err == nil && n == 1 && head[0] == 'd'
}

func guessLocalMetalinkFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var head [5]byte
	n, err := f.Read(head[:])
	return err == nil && n == len(head) && string(head[:]) == "<?xml"
}

func optionsFromSessionEntry(entry sessionfile.Entry) (*config.Options, error) {
	opts := &config.Options{}
	if len(entry.Options) > 0 {
		var b strings.Builder
		for key, val := range entry.Options {
			for _, line := range strings.Split(val, "\n") {
				b.WriteString(key)
				b.WriteByte('=')
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
		if err := config.ParseConf(strings.NewReader(b.String()), opts); err != nil {
			return nil, err
		}
	}
	if entry.Status == core.StatusPaused {
		opts.Pause = true
	}
	return opts, nil
}

// SubscribeChannel registers a channel to receive engine lifecycle events.
// Returns a result containing the read-only channel and an unsubscribe function.
//
// Callers should use a buffered channel (e.g. make(chan core.Event, 64))
// to avoid missing events during bursts. If the channel is full, events
// are dropped — matching aria2's Notifier behavior where missed events
// are not retried.
func (e *Engine) Subscribe(ch chan core.Event) SubscribeResult {
	unsub := e.bus.Subscribe(ch)
	return SubscribeResult{
		C:           ch,
		Unsubscribe: unsub,
	}
}

// SubscribeChannel registers a channel to receive engine lifecycle events.
// Identical to Subscribe; provided for API compatibility with tests that
// prefer the explicit channel-oriented name.
func (e *Engine) SubscribeChannel(ch chan core.Event) SubscribeResult {
	return e.Subscribe(ch)
}

// SubscribeLegacy registers a Subscriber-compatible interface for engines
// that use the older synchronous pattern. Returns an unsubscribe function.
func (e *Engine) SubscribeLegacy(s Subscriber) (unsubscribe func()) {
	ch := make(chan core.Event, 64)
	unsub := e.bus.Subscribe(ch)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range ch {
			s.OnEvent(ev)
		}
	}()
	return func() {
		unsub()
		close(ch)
		<-done
	}
}

// ticker performs periodic background tasks: auto-save and stat aggregation.
// It runs every 1 second, matching aria2's DEFAULT_REFRESH_INTERVAL.
func (e *Engine) ticker() {
	defer e.wg.Done()

	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	var lastControlSave time.Time
	var lastSessionSave time.Time

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
			e.refreshStats()

			if e.console != nil && !e.cfg.Quiet && (e.cfg.ShowConsoleReadout || parseInt(e.cfg.SummaryInterval) > 0) {
				e.console.Render(e.collectDownloadStats())
			}

			if e.saveInterval > 0 && time.Since(lastControlSave) >= e.saveInterval {
				e.saveControlFiles()
				lastControlSave = time.Now()
			}
			if e.saveSessionInterval > 0 && time.Since(lastSessionSave) >= e.saveSessionInterval {
				if err := e.SaveSession(); err != nil && e.cfg.SaveSession != "" {
					e.log.Warn("failed to save session", "error", err)
				}
				lastSessionSave = time.Now()
			}
		}
	}
}

func (e *Engine) saveControlFiles() {
	e.queuesMu.Lock()
	gids := make([]core.GID, 0, len(e.active)+len(e.waiting))
	gids = append(gids, e.active...)
	gids = append(gids, e.waiting...)
	e.queuesMu.Unlock()

	for _, gid := range gids {
		rg, ok := e.groups.get(gid)
		if !ok {
			continue
		}
		e.saveControlFile(rg)
	}
}

func (e *Engine) controlFileAllowsResume(path string, opts *config.Options, expectedTotal, expectedPieceLen int64, infoHash []byte) bool {
	if path == "" {
		return false
	}
	controlPath := path + btprogress.Suffix
	if opts != nil && opts.RemoveControlFile {
		if err := os.Remove(controlPath); err != nil && !os.IsNotExist(err) {
			e.log.Warn("failed to remove requested control file", "path", controlPath, "error", err)
		}
		return false
	}
	if _, statErr := os.Stat(controlPath); statErr != nil {
		return false
	}
	info, err := btprogress.Load(path)
	if err != nil {
		if !os.IsNotExist(err) {
			e.removeInvalidControlFile(controlPath, "load failed", err)
		}
		return false
	}
	if !controlInfoMatchesRequest(info, expectedTotal, expectedPieceLen, infoHash) {
		e.removeInvalidControlFile(controlPath, "metadata mismatch", nil)
		return false
	}
	if _, err := os.Stat(path); err == nil {
		return true
	} else if os.IsNotExist(err) {
		if rmErr := os.Remove(controlPath); rmErr != nil && !os.IsNotExist(rmErr) {
			e.log.Warn("failed to remove defunct control file", "path", controlPath, "error", rmErr)
		}
		return false
	} else {
		e.log.Warn("failed to stat payload for control file", "path", path, "error", err)
		return false
	}
}

func controlInfoMatchesRequest(info *btprogress.Info, expectedTotal, expectedPieceLen int64, infoHash []byte) bool {
	if info == nil || info.PieceLength <= 0 || info.TotalLength < 0 {
		return false
	}
	if expectedTotal >= 0 && info.TotalLength != expectedTotal {
		return false
	}
	if expectedPieceLen > 0 && info.PieceLength != expectedPieceLen {
		return false
	}
	if len(infoHash) == 0 {
		if len(info.InfoHash) != 0 {
			return false
		}
	} else if !bytes.Equal(info.InfoHash, infoHash) {
		return false
	}
	expectedBitfieldLen := controlBitfieldLen(controlNumPieces(info.TotalLength, info.PieceLength))
	return len(info.Bitfield) == expectedBitfieldLen
}

func (e *Engine) removeInvalidControlFile(controlPath, reason string, cause error) {
	args := []any{"path", controlPath, "reason", reason}
	if cause != nil {
		args = append(args, "error", cause)
	}
	e.log.Warn("removing invalid control file", args...)
	if err := os.Remove(controlPath); err != nil && !os.IsNotExist(err) {
		e.log.Warn("failed to remove invalid control file", "path", controlPath, "error", err)
	}
}

func (e *Engine) initControlInfo(rg *requestGroup, path string, total int64, pieceLen int64, infoHash []byte) {
	if total < 0 {
		total = 0
	}
	if pieceLen <= 0 {
		pieceLen = controlPieceLength(rg.opts)
	}
	info := newControlInfo(total, pieceLen, infoHash)
	loaded := false
	controlPath := path + btprogress.Suffix
	if _, statErr := os.Stat(controlPath); statErr == nil {
		if loadedInfo, err := btprogress.Load(path); err == nil {
			if normalized, ok := normalizeControlInfo(loadedInfo, total, pieceLen, infoHash, rg.opts); ok {
				info = normalized
				loaded = true
			} else {
				e.log.Warn("ignoring incompatible control file", "gid", rg.gid, "path", controlPath)
				e.removeInvalidControlFile(controlPath, "metadata mismatch", nil)
			}
		} else {
			e.log.Warn("failed to load control file", "gid", rg.gid, "path", controlPath, "error", err)
			e.removeInvalidControlFile(controlPath, "load failed", err)
		}
	}

	rg.controlMu.Lock()
	rg.controlPath = path
	rg.controlInfo = info
	rg.controlLoaded = loaded
	rg.controlPieceBytes = seedControlPieceBytes(info)
	rg.controlMu.Unlock()

	e.saveControlFile(rg)
}

func newControlInfo(total, pieceLen int64, infoHash []byte) *btprogress.Info {
	pieces := controlNumPieces(total, pieceLen)
	return &btprogress.Info{
		InfoHash:    append([]byte(nil), infoHash...),
		PieceLength: pieceLen,
		TotalLength: total,
		Bitfield:    make([]byte, controlBitfieldLen(pieces)),
	}
}

func normalizeControlInfo(info *btprogress.Info, total, pieceLen int64, infoHash []byte, opts *config.Options) (*btprogress.Info, bool) {
	if info == nil || info.TotalLength != total || info.PieceLength <= 0 {
		return nil, false
	}
	if len(infoHash) == 0 {
		if len(info.InfoHash) != 0 {
			return nil, false
		}
	} else if !bytes.Equal(info.InfoHash, infoHash) {
		return nil, false
	}

	if info.PieceLength != pieceLen {
		if opts == nil || !opts.AllowPieceLengthChange {
			return nil, false
		}
		return &btprogress.Info{
			InfoHash:    append([]byte(nil), infoHash...),
			PieceLength: pieceLen,
			TotalLength: total,
			Bitfield:    convertControlBitfield(info.Bitfield, total, info.PieceLength, pieceLen),
		}, true
	}

	expectedLen := controlBitfieldLen(controlNumPieces(total, pieceLen))
	if len(info.Bitfield) != expectedLen {
		return nil, false
	}
	return cloneControlInfo(info), true
}

func cloneControlInfo(info *btprogress.Info) *btprogress.Info {
	if info == nil {
		return nil
	}
	clone := &btprogress.Info{
		InfoHash:     append([]byte(nil), info.InfoHash...),
		PieceLength:  info.PieceLength,
		TotalLength:  info.TotalLength,
		UploadLength: info.UploadLength,
		Bitfield:     append([]byte(nil), info.Bitfield...),
	}
	if len(info.InFlight) > 0 {
		clone.InFlight = make([]btprogress.InFlightPiece, len(info.InFlight))
		for i, piece := range info.InFlight {
			clone.InFlight[i] = btprogress.InFlightPiece{
				Index:    piece.Index,
				Length:   piece.Length,
				Bitfield: append([]byte(nil), piece.Bitfield...),
			}
		}
	}
	return clone
}

func seedControlPieceBytes(info *btprogress.Info) []int64 {
	pieces := controlNumPieces(info.TotalLength, info.PieceLength)
	pieceBytes := make([]int64, pieces)
	for i := 0; i < pieces; i++ {
		if controlBit(info.Bitfield, i) {
			pieceBytes[i] = controlPieceSize(info.TotalLength, info.PieceLength, i)
		}
	}
	return pieceBytes
}

func (e *Engine) saveControlFile(rg *requestGroup) {
	rg.controlMu.Lock()
	path := rg.controlPath
	info := cloneControlInfo(rg.controlInfo)
	adaptor := rg.adaptor
	rg.controlMu.Unlock()
	if path == "" || info == nil {
		return
	}
	if adaptor != nil {
		if err := adaptor.Sync(); err != nil && !errors.Is(err, disk.ErrFileClosed) {
			e.log.Warn("failed to sync payload before saving control file", "gid", rg.gid, "path", path, "error", err)
		}
	}
	if err := btprogress.Save(path, info); err != nil {
		e.log.Warn("failed to save control file", "gid", rg.gid, "path", path+btprogress.Suffix, "error", err)
	}
}

func (e *Engine) setControlAdaptor(rg *requestGroup, adaptor disk.Adaptor) {
	rg.controlMu.Lock()
	rg.adaptor = adaptor
	rg.controlMu.Unlock()
}

func (e *Engine) addBTUploadLength(rg *requestGroup, delta int64) {
	if delta <= 0 {
		return
	}
	rg.controlMu.Lock()
	if rg.controlInfo != nil {
		rg.controlInfo.UploadLength += delta
	}
	rg.controlMu.Unlock()
}

func (e *Engine) syncControlAdaptor(rg *requestGroup) {
	rg.controlMu.Lock()
	adaptor := rg.adaptor
	rg.controlMu.Unlock()
	if adaptor == nil {
		return
	}
	if err := adaptor.Sync(); err != nil && !errors.Is(err, disk.ErrFileClosed) {
		e.log.Warn("failed to sync payload", "gid", rg.gid, "error", err)
	}
}

func (e *Engine) removeControlFile(rg *requestGroup) {
	rg.controlMu.Lock()
	path := rg.controlPath
	rg.controlMu.Unlock()
	if path == "" {
		path = rg.filePath
	}
	if path == "" {
		return
	}
	if err := os.Remove(path + btprogress.Suffix); err != nil && !os.IsNotExist(err) {
		e.log.Warn("failed to remove control file", "gid", rg.gid, "path", path+btprogress.Suffix, "error", err)
	}
}

func (e *Engine) finishControlFile(rg *requestGroup) {
	locked, ok := e.groups.getLocked(rg.gid)
	if !ok {
		return
	}
	errCode := locked.errCode
	e.groups.unlock(rg.gid)

	if errCode == core.ExitSuccess {
		if rg.opts != nil && rg.opts.ForceSave {
			e.saveControlFile(rg)
		} else {
			e.removeControlFile(rg)
		}
		return
	}
	e.saveControlFile(rg)
}

func (e *Engine) applyControlBitfield(rg *requestGroup, adaptor disk.Adaptor) {
	rg.controlMu.Lock()
	info := cloneControlInfo(rg.controlInfo)
	rg.controlMu.Unlock()
	if info == nil {
		return
	}
	pieces := controlNumPieces(info.TotalLength, info.PieceLength)
	adaptor.SetPieceCount(pieces)
	for i := 0; i < pieces; i++ {
		if controlBit(info.Bitfield, i) {
			adaptor.MarkPiece(i, true)
		}
	}
}

func (e *Engine) markControlWritten(rg *requestGroup, start, length int64) []int {
	if length <= 0 {
		return nil
	}
	rg.controlMu.Lock()
	defer rg.controlMu.Unlock()
	info := rg.controlInfo
	if info == nil || info.PieceLength <= 0 || info.TotalLength <= 0 {
		return nil
	}
	end := start + length
	if end > info.TotalLength {
		end = info.TotalLength
	}
	if start < 0 || start >= end {
		return nil
	}
	pieces := controlNumPieces(info.TotalLength, info.PieceLength)
	if len(rg.controlPieceBytes) != pieces {
		rg.controlPieceBytes = seedControlPieceBytes(info)
	}
	first := int(start / info.PieceLength)
	last := int((end - 1) / info.PieceLength)
	var completed []int
	for i := first; i <= last && i < pieces; i++ {
		if controlBit(info.Bitfield, i) {
			continue
		}
		pieceStart := int64(i) * info.PieceLength
		pieceEnd := pieceStart + controlPieceSize(info.TotalLength, info.PieceLength, i)
		overlapStart := max64(start, pieceStart)
		overlapEnd := min64(end, pieceEnd)
		if overlapEnd <= overlapStart {
			continue
		}
		rg.controlPieceBytes[i] += overlapEnd - overlapStart
		if rg.controlPieceBytes[i] >= pieceEnd-pieceStart {
			rg.controlPieceBytes[i] = pieceEnd - pieceStart
			setControlBit(info.Bitfield, i, true)
			completed = append(completed, i)
		}
	}
	return completed
}

func (e *Engine) markControlPiece(rg *requestGroup, index int, ok bool) {
	rg.controlMu.Lock()
	defer rg.controlMu.Unlock()
	info := rg.controlInfo
	if info == nil {
		return
	}
	pieces := controlNumPieces(info.TotalLength, info.PieceLength)
	if index < 0 || index >= pieces {
		return
	}
	setControlBit(info.Bitfield, index, ok)
	if len(rg.controlPieceBytes) != pieces {
		rg.controlPieceBytes = seedControlPieceBytes(info)
	}
	if ok {
		rg.controlPieceBytes[index] = controlPieceSize(info.TotalLength, info.PieceLength, index)
	} else {
		rg.controlPieceBytes[index] = 0
	}
}

func (e *Engine) controlResumeOffset(rg *requestGroup, path string) int64 {
	rg.controlMu.Lock()
	loaded := rg.controlLoaded
	info := cloneControlInfo(rg.controlInfo)
	rg.controlMu.Unlock()
	if !loaded || info == nil {
		return 0
	}
	offset := controlContiguousLength(info)
	if st, err := os.Stat(path); err == nil && !st.IsDir() && st.Size() < offset {
		offset = st.Size()
	}
	return offset
}

func (e *Engine) controlCompletedLength(rg *requestGroup) int64 {
	rg.controlMu.Lock()
	info := cloneControlInfo(rg.controlInfo)
	rg.controlMu.Unlock()
	if info == nil {
		return 0
	}
	return controlCompletedLength(info)
}

func (e *Engine) controlLoaded(rg *requestGroup) bool {
	rg.controlMu.Lock()
	defer rg.controlMu.Unlock()
	return rg.controlLoaded
}

func (e *Engine) controlSegmentMan(rg *requestGroup) *SegmentMan {
	rg.controlMu.Lock()
	loaded := rg.controlLoaded
	info := cloneControlInfo(rg.controlInfo)
	rg.controlMu.Unlock()
	if !loaded || info == nil {
		return nil
	}
	return newControlSegmentMan(info.TotalLength, info.PieceLength, info.Bitfield)
}

func controlPieceLength(opts *config.Options) int64 {
	if opts != nil && opts.PieceLength != "" {
		if n := parseSize(opts.PieceLength); n > 0 {
			return n
		}
	}
	return 1 << 20
}

func controlNumPieces(total, pieceLen int64) int {
	if total <= 0 || pieceLen <= 0 {
		return 0
	}
	return int((total + pieceLen - 1) / pieceLen)
}

func controlBitfieldLen(pieces int) int {
	if pieces <= 0 {
		return 0
	}
	return (pieces + 7) / 8
}

func controlPieceSize(total, pieceLen int64, index int) int64 {
	start := int64(index) * pieceLen
	if start >= total {
		return 0
	}
	end := start + pieceLen
	if end > total {
		end = total
	}
	return end - start
}

func controlBit(bitfield []byte, index int) bool {
	if index < 0 || index/8 >= len(bitfield) {
		return false
	}
	return bitfield[index/8]&(1<<uint(7-index%8)) != 0
}

func setControlBit(bitfield []byte, index int, ok bool) {
	if index < 0 || index/8 >= len(bitfield) {
		return
	}
	mask := byte(1 << uint(7-index%8))
	if ok {
		bitfield[index/8] |= mask
		return
	}
	bitfield[index/8] &^= mask
}

func controlContiguousLength(info *btprogress.Info) int64 {
	pieces := controlNumPieces(info.TotalLength, info.PieceLength)
	var completed int64
	for i := 0; i < pieces; i++ {
		if !controlBit(info.Bitfield, i) {
			break
		}
		completed += controlPieceSize(info.TotalLength, info.PieceLength, i)
	}
	return completed
}

func controlCompletedLength(info *btprogress.Info) int64 {
	pieces := controlNumPieces(info.TotalLength, info.PieceLength)
	var completed int64
	for i := 0; i < pieces; i++ {
		if controlBit(info.Bitfield, i) {
			completed += controlPieceSize(info.TotalLength, info.PieceLength, i)
		}
	}
	return completed
}

func convertControlBitfield(src []byte, total, srcPieceLen, dstPieceLen int64) []byte {
	dstPieces := controlNumPieces(total, dstPieceLen)
	dst := make([]byte, controlBitfieldLen(dstPieces))
	for i := 0; i < dstPieces; i++ {
		start := int64(i) * dstPieceLen
		end := start + controlPieceSize(total, dstPieceLen, i)
		complete := true
		for pos := start; pos < end; {
			srcIdx := int(pos / srcPieceLen)
			if !controlBit(src, srcIdx) {
				complete = false
				break
			}
			next := int64(srcIdx+1) * srcPieceLen
			if next > end {
				next = end
			}
			pos = next
		}
		if complete {
			setControlBit(dst, i, true)
		}
	}
	return dst
}

func newControlSegmentMan(total, pieceLen int64, bitfield []byte) *SegmentMan {
	pieces := controlNumPieces(total, pieceLen)
	segments := make([]*Segment, 0)
	for i := 0; i < pieces; {
		if controlBit(bitfield, i) {
			i++
			continue
		}
		startPiece := i
		for i < pieces && !controlBit(bitfield, i) {
			i++
		}
		start := int64(startPiece) * pieceLen
		endPiece := i - 1
		end := int64(endPiece)*pieceLen + controlPieceSize(total, pieceLen, endPiece)
		segments = append(segments, &Segment{Index: len(segments), Start: start, End: end})
	}
	return &SegmentMan{segments: segments, totalSize: total}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// collectDownloadStats gathers download stat snapshots from all active
// downloads for console rendering.
func (e *Engine) collectDownloadStats() []console.DownloadStat {
	active := e.TellActive()
	snapshots := make([]console.DownloadStat, 0, len(active))
	for _, s := range active {
		fn := ""
		if len(s.Files) > 0 {
			fn = filepath.Base(s.Files[0].Path)
		}
		sessionUploaded := int64(0)
		if rg, ok := e.groups.get(s.GID); ok {
			sessionUploaded = rg.sessionUploaded
		}
		snapshots = append(snapshots, console.DownloadStat{
			GID:                 s.GID.Hex(),
			Status:              s.Status.String(),
			TotalSize:           s.TotalLength,
			CompletedSize:       s.CompletedLength,
			Speed:               s.DownloadSpeed,
			UploadSpeed:         s.UploadSpeed,
			AllTimeUploadLength: s.UploadLength,
			SessionUploadLength: sessionUploaded,
			Connections:         s.Connections,
			ErrorCode:           int(s.ErrorCode),
			NumSeeders:          int(s.NumSeeders),
			Filename:            fn,
			Seeder:              s.Seeder,
		})
	}
	return snapshots
}

func (e *Engine) showDownloadResults() {
	if e.console == nil || e.cfg == nil || e.cfg.Quiet || e.cfg.DownloadResult == "hide" {
		return
	}
	e.console.PrintDownloadResults(e.collectDownloadResults(), e.cfg.DownloadResult == "full")
}

func (e *Engine) collectDownloadResults() []console.ResultStat {
	e.stoppedRing.mu.Lock()
	defer e.stoppedRing.mu.Unlock()

	results := make([]console.ResultStat, 0, e.stoppedRing.size)
	capacity := len(e.stoppedRing.buf)
	for i := 0; i < e.stoppedRing.size; i++ {
		pos := (e.stoppedRing.head + i) % capacity
		dr := e.stoppedRing.buf[pos]
		if dr == nil || dr.belongsTo != 0 {
			continue
		}
		results = append(results, console.ResultStat{
			GID:          dr.gid.Hex(),
			Status:       downloadResultStatus(dr),
			AverageSpeed: downloadResultAverageSpeed(dr),
			Path:         dr.filePath,
			Percent:      downloadResultPercent(dr),
		})
	}
	return results
}

func downloadResultStatus(dr *downloadResult) string {
	if dr.errCode == core.ExitSuccess && dr.state == core.StatusComplete {
		return "OK"
	}
	if dr.errCode == core.ExitInProgress || (dr.state == core.StatusError && dr.errMsg == "shutdown") {
		return "INPR"
	}
	if dr.state == core.StatusRemoved {
		return "RM"
	}
	return "ERR"
}

func downloadResultAverageSpeed(dr *downloadResult) int64 {
	if dr.sessionTime <= 0 {
		return -1
	}
	return int64(float64(dr.sessionDownloadLength) / dr.sessionTime.Seconds())
}

func downloadResultPercent(dr *downloadResult) int {
	if dr.totalLength <= 0 {
		return -1
	}
	percent := int(100 * dr.completedLength / dr.totalLength)
	if percent > 100 {
		return 100
	}
	if percent < 0 {
		return 0
	}
	return percent
}

// emaAlpha is the EMA smoothing factor for speed calculation.
// aria2's SpeedCalc uses window-based calculation with equivalent smoothing;
// 0.25 matches aria2's default behavior for stable speed reporting.
const emaAlpha = 0.25

// refreshStats updates the download/upload speed stats using an exponential
// moving average. It mirrors aria2's RequestGroupMan::calculateStat() which
// aggregates per-request-group TransferStat, and StatCalc which applies EMA.
//
// For each active download, the instantaneous speed is computed as
// bytesDownloaded / elapsed, then smoothed with EMA:
//
//	speed = emaAlpha * current + (1 - emaAlpha) * previous
func (e *Engine) refreshStats() {
	e.queuesMu.Lock()
	activeCopy := make([]core.GID, len(e.active))
	copy(activeCopy, e.active)
	e.queuesMu.Unlock()

	var totalDL, totalUL int64

	for _, gid := range activeCopy {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}

		now := time.Now()
		elapsed := now.Sub(rg.lastSpeedSample)

		// A worker that already cancelled its transfer context has
		// assigned the final completed/uploaded lengths. Counting its
		// remaining byte counters again would double-report the final
		// sample, so drop it instead. The group stays in the active
		// queue until removeStoppedGroup reaps it.
		transferDone := rg.ctx != nil && rg.ctx.Err() != nil

		if elapsed > 0 {
			// Download Speed EMA
			dlInstant := int64(0)
			if rg.bytesDownloaded > 0 {
				dlInstant = int64(float64(rg.bytesDownloaded) / elapsed.Seconds())
				if transferDone {
					rg.bytesDownloaded = 0
				} else {
					rg.statusMu.Lock()
					rg.completedLength += rg.bytesDownloaded
					rg.statusMu.Unlock()
					rg.bytesDownloaded = 0
				}
			}
			prevDL := rg.downloadSpeed
			smoothedDL := int64(emaAlpha*float64(dlInstant) + (1-emaAlpha)*float64(prevDL))
			if dlInstant == 0 && prevDL == 0 {
				smoothedDL = 0
			}
			rg.downloadSpeed = smoothedDL
			totalDL += smoothedDL

			// Upload Speed EMA
			ulInstant := int64(0)
			if rg.bytesUploaded > 0 {
				ulInstant = int64(float64(rg.bytesUploaded) / elapsed.Seconds())
				rg.bytesUploaded = 0
			}
			prevUL := rg.uploadSpeed
			smoothedUL := int64(emaAlpha*float64(ulInstant) + (1-emaAlpha)*float64(prevUL))
			if ulInstant == 0 && prevUL == 0 {
				smoothedUL = 0
			}
			rg.uploadSpeed = smoothedUL
			totalUL += smoothedUL
		}

		rg.statusMu.Lock()
		rg.lastSpeedSample = now
		rg.statusMu.Unlock()
		e.groups.unlock(gid)
	}

	e.downloadSpeed.Store(totalDL)
	e.uploadSpeed.Store(totalUL)
}

// queueManager is the main scheduling goroutine. It periodically:
// 1. Processes stopped active downloads (removeStoppedGroup equivalent)
// 2. Promotes waiting downloads to active (fillRequestGroupFromReserver)
// 3. On shutdown, performs onEndOfRun cleanup
//
// The tick interval matches aria2's DEFAULT_REFRESH_INTERVAL = 1 second.
func (e *Engine) queueManager() {
	defer e.wg.Done()

	e.log.Debug("queue manager started")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			e.log.Debug("queue manager draining")
			e.onEndOfRun()
			e.log.Debug("queue manager stopped")
			return
		case <-e.queueWake:
			e.removeStoppedGroup()
			e.fillRequestGroupFromReserver()
			e.cancelIfIdle()
		case <-ticker.C:
			e.removeStoppedGroup()
			e.fillRequestGroupFromReserver()
			e.cancelIfIdle()
		}
	}
}

func (e *Engine) cancelIfIdle() {
	e.queuesMu.Lock()
	isEmpty := len(e.active) == 0 && len(e.waiting) == 0
	e.queuesMu.Unlock()
	if isEmpty && e.inputParser != nil {
		return
	}
	if isEmpty && !e.keepRunning && e.cancel != nil {
		e.cancel()
	}
}

// removeStoppedGroup processes active downloads that have been cancelled
// (context done). For paused downloads, it applies pendingOption and moves
// the stopped results queue. Matches aria2's ProcessStoppedRequestGroup +
// removeStoppedGroup flow (RequestGroupMan.cc:290-483).
func (e *Engine) removeStoppedGroup() {
	e.queuesMu.Lock()
	activeCopy := make([]core.GID, len(e.active))
	copy(activeCopy, e.active)
	e.queuesMu.Unlock()

	var stoppedGIDs []core.GID
	for _, gid := range activeCopy {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}
		// Check if the download's context has been cancelled (stopped).
		isDone := false
		if rg.ctx != nil {
			select {
			case <-rg.ctx.Done():
				isDone = true
			default:
			}
		}
		if isDone {
			stoppedGIDs = append(stoppedGIDs, gid)
		}
		e.groups.unlock(gid)
	}

	if len(stoppedGIDs) == 0 {
		return
	}

	e.queuesMu.Lock()
	for _, gid := range stoppedGIDs {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}
		e.moveFromActiveLocked(gid)

		if rg.pauseReq {
			rg.state = core.StatusWaiting
			e.waiting = append([]core.GID{gid}, e.waiting...)

			if rg.pendingOpts != nil {
				rg.opts = config.Merge(rg.opts, rg.pendingOpts)
				_ = e.applyRequestGroupRuntimeOptions(rg, rg.opts)
				rg.pendingOpts = nil
			}

			if rg.restartReq {
				rg.pauseReq = false
			} else {
				e.log.Info("download paused", "gid", gid)
				e.runHookByName(rg, 1, "on-download-pause")
				e.emit(core.EvPause, gid)
			}

			rg.restartReq = false
			rg.forceHaltReq = false
			rg.haltRequested = false
			rg.haltReason = haltReasonNone
		} else if rg.haltRequested {
			switch rg.haltReason {
			case haltReasonUserRequest:
				e.addStoppedLocked(rg, core.StatusRemoved, core.ExitRemoved, "")
			default:
				errCode := core.ExitInProgress
				if code, _ := rg.errorStatus(); code != 0 && code != core.ExitSuccess {
					errCode = code
				}
				errMsg := ""
				if errCode != core.ExitInProgress {
					_, errMsg = rg.errorStatus()
				}
				e.addStoppedLocked(rg, core.StatusError, errCode, errMsg)
			}
			e.groups.unlock(gid)
			e.groups.delete(gid)
			continue
		} else {
			// Completed or error — add to stopped results.
			code, msg := rg.errorStatus()
			errCode := core.ExitSuccess
			if code != 0 {
				errCode = code
			}
			finalState := core.StatusComplete
			if errCode != core.ExitSuccess {
				finalState = core.StatusError
			}
			e.addStoppedLocked(rg, finalState, errCode, msg)
			e.groups.unlock(gid)
			e.groups.delete(gid)
			continue
		}
		e.groups.unlock(gid)
	}
	e.queuesMu.Unlock()
}

// fillRequestGroupFromReserver promotes waiting downloads to active up to
// maxConcurrentDownloads, skipping paused and dependency-unresolved groups,
// and launches a download goroutine for each newly promoted group.
// Matches aria2's RequestGroupMan::fillRequestGroupFromReserver
// (RequestGroupMan.cc:515-593).
func (e *Engine) fillRequestGroupFromReserver() {
	for {
		e.queuesMu.Lock()

		max := e.cfg.MaxConcurrentDownloads
		if max <= 0 {
			max = 1
		}

		if len(e.active) >= max {
			e.queuesMu.Unlock()
			return
		}

		if len(e.waiting) == 0 && e.inputParser != nil {
			e.queuesMu.Unlock()
			added, err := e.loadNextDeferredInputEntry()
			if err != nil {
				e.log.Warn("deferred input load failed", "error", err)
			}
			if added == 0 {
				return
			}
			continue
		}

		num := max - len(e.active)
		promoted := 0
		var pending []core.GID
		var promotedGIDs []core.GID

		batchSize := num
		if batchSize < 1 {
			batchSize = 1
		}
		startEvents := make([]core.Event, 0, batchSize)

		for promoted < num && len(e.waiting) > 0 {
			gid := e.waiting[0]
			e.waiting = e.waiting[1:]

			rg, ok := e.groups.getLocked(gid)
			if !ok {
				continue
			}

			if rg.pauseReq {
				pending = append(pending, gid)
				e.groups.unlock(gid)
				continue
			}

			rg.state = core.StatusActive
			e.active = append(e.active, gid)
			promoted++
			promotedGIDs = append(promotedGIDs, gid)
			startEvents = append(startEvents, core.Event{
				Kind: core.EvStart,
				GID:  gid,
				Time: time.Now(),
			})
			e.log.Info("download started", "gid", gid)
			e.groups.unlock(gid)
		}

		if len(pending) > 0 {
			e.waiting = append(pending, e.waiting...)
		}

		e.emitBatch(startEvents)
		e.queuesMu.Unlock()

		if !e.running.Load() {
			return
		}

		for _, gid := range promotedGIDs {
			rg, ok := e.groups.getLocked(gid)
			if !ok {
				continue
			}
			e.runHookByName(rg, 1, "on-download-start")
			rg.ctx, rg.cancel = context.WithCancel(e.ctx)
			e.wg.Add(1)
			go e.runDownload(rg)
			e.groups.unlock(gid)
		}
		return
	}
}

func (e *Engine) loadNextDeferredInputEntry() (int, error) {
	for e.inputParser != nil {
		entry, ok, err := e.inputParser.Next()
		if err != nil {
			_ = e.inputParser.Close()
			e.inputParser = nil
			return 0, fmt.Errorf("engine: deferred input read: %w", err)
		}
		if !ok {
			_ = e.inputParser.Close()
			e.inputParser = nil
			return 0, nil
		}
		if len(entry.URIs) == 0 {
			continue
		}
		opts, optErr := optionsFromSessionEntry(entry)
		if optErr != nil {
			_ = e.inputParser.Close()
			e.inputParser = nil
			return 0, fmt.Errorf("engine: deferred input options: %w", optErr)
		}
		added, addErr := e.addURIEntry(entry.URIs, opts)
		if addErr != nil {
			_ = e.inputParser.Close()
			e.inputParser = nil
			return 0, fmt.Errorf("engine: deferred input add: %w", addErr)
		}
		if added > 0 {
			return added, nil
		}
	}
	return 0, nil
}

// onEndOfRun performs cleanup when the engine stops, matching aria2's
// DownloadEngine::onEndOfRun (DownloadEngine.cc:237-242):
//
//	requestGroupMan_->removeStoppedGroup(this);
//	requestGroupMan_->closeFile();
//	requestGroupMan_->save();
func (e *Engine) onEndOfRun() {
	// 1. Process stopped groups (removeStoppedGroup).
	e.queuesMu.Lock()
	activeCopy := make([]core.GID, len(e.active))
	copy(activeCopy, e.active)
	waitingCopy := make([]core.GID, len(e.waiting))
	copy(waitingCopy, e.waiting)
	e.queuesMu.Unlock()

	shutdownEntries := e.sessionEntriesFromQueues(activeCopy, waitingCopy)
	e.queuesMu.Lock()
	e.shutdownSession = append(e.shutdownSession[:0], shutdownEntries...)
	e.queuesMu.Unlock()
	e.shutdownHadActive.Store(len(activeCopy) > 0)
	e.shutdownExitPending.Store(false)
	e.shutdownExitLastErr.Store(int64(core.ExitSuccess))

	for _, gid := range activeCopy {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}
		if rg.state == core.StatusActive {
			e.queuesMu.Lock()
			e.moveFromActiveLocked(gid)
			e.queuesMu.Unlock()
			// Graceful shutdown: mark as IN_PROGRESS so they can be
			// resumed on restart (matches aria2's SHUTDOWN_SIGNAL halt reason).
			errCode := core.ExitInProgress
			errMsg := ""
			if code, msg := rg.errorStatus(); code != 0 && code != core.ExitSuccess {
				errCode = code
				errMsg = msg
			}
			if errCode == core.ExitInProgress {
				errMsg = ""
				e.shutdownExitPending.Store(true)
			} else if errCode != core.ExitSuccess && errCode != core.ExitRemoved {
				e.shutdownExitLastErr.Store(int64(errCode))
			}
			e.addStoppedLocked(rg, core.StatusError, errCode, errMsg)
			e.groups.unlock(gid)
			e.groups.delete(gid)
			continue
		}
		e.groups.unlock(gid)
	}

	for _, gid := range waitingCopy {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}
		e.queuesMu.Lock()
		e.moveFromWaitingLocked(gid)
		e.queuesMu.Unlock()
		// If paused, mark for resume; otherwise just removed.
		if rg.pauseReq {
			e.addStoppedLocked(rg, core.StatusError, core.ExitRemoved, "shutdown")
		} else {
			e.addStoppedLocked(rg, core.StatusRemoved, core.ExitRemoved, "shutdown")
		}
		e.groups.unlock(gid)
		e.groups.delete(gid)
	}

	e.log.Debug("engine files closed and state saved for shutdown")
}

// moveFromActiveLocked removes gid from the active queue. Caller must hold e.queuesMu.
func (e *Engine) moveFromActiveLocked(gid core.GID) {
	for i, g := range e.active {
		if g == gid {
			e.active = append(e.active[:i], e.active[i+1:]...)
			return
		}
	}
}

// moveFromWaitingLocked removes gid from the waiting queue. Caller must hold e.queuesMu.
func (e *Engine) moveFromWaitingLocked(gid core.GID) {
	for i, g := range e.waiting {
		if g == gid {
			e.waiting = append(e.waiting[:i], e.waiting[i+1:]...)
			return
		}
	}
}

// addStoppedLocked adds a download to the results/stopped queue.
// Caller must hold the shard lock for rg.gid.
func (e *Engine) addStoppedLocked(rg *requestGroup, state core.Status, errCode core.ErrorCode, errMsg string) {
	rg.state = state
	rg.setError(errCode, errMsg)

	dr := drPool.Get().(*downloadResult)
	dr.gid = rg.gid
	dr.state = state
	dr.errCode = errCode
	dr.errMsg = errMsg
	dr.belongsTo = rg.belongsTo
	dr.following = rg.following
	dr.followedBy = append(dr.followedBy[:0], rg.followedBy...)
	dr.opts = config.Merge(rg.opts)
	dr.localOpts = config.CloneExplicitOptions(rg.localOpts)
	dr.metadataURI = rg.metadataURI
	dr.filePath = resultFilePath(rg)
	dr.statusSnapshot = e.makeStoppedStatus(rg, state, errCode, errMsg)
	dr.totalLength = rg.totalLength
	dr.completedLength = rg.completedLength
	dr.sessionDownloadLength = rg.completedLength
	dr.sessionTime = 0
	if !rg.created.IsZero() {
		dr.sessionTime = time.Since(rg.created)
	}

	e.stoppedRing.push(dr)
	e.stoppedTotal.Add(1)

	// Handle eviction-based error tracking.
	e.stoppedRing.mu.Lock()
	_, errors, lastErr := e.stoppedRing.evictionInfo()
	e.stoppedRing.mu.Unlock()
	e.removedErrors.Store(int64(errors))
	e.removedLastErr.Store(int64(lastErr))

	// Handle keep-unfinished logic (keep evicted unfinished in ring if configured).
	e.stoppedRing.mu.Lock()
	maxResults := e.cfg.MaxDownloadResult
	if maxResults <= 0 {
		maxResults = 1000
	}
	for e.stoppedRing.size > maxResults {
		evicted := e.stoppedRing.buf[e.stoppedRing.head]
		delete(e.stoppedRing.index, evicted.gid)
		e.stoppedRing.head = (e.stoppedRing.head + 1) % len(e.stoppedRing.buf)
		e.stoppedRing.size--
		e.stoppedRing.evictedTotal++
		if evicted.belongsTo == 0 && evicted.errCode != core.ExitSuccess {
			e.stoppedRing.evictedErrors++
			e.stoppedRing.evictedLastErr = evicted.errCode
			e.removedErrors.Store(int64(e.stoppedRing.evictedErrors))
			e.removedLastErr.Store(int64(evicted.errCode))
			if e.cfg.KeepUnfinishedDownloadResult {
				if evicted.state != core.StatusRemoved || e.cfg.ForceSave {
					// Re-insert the evicted entry.
					pos := (e.stoppedRing.head + e.stoppedRing.size) % len(e.stoppedRing.buf)
					e.stoppedRing.buf[pos] = evicted
					e.stoppedRing.index[evicted.gid] = pos
					e.stoppedRing.size++
				}
			}
		}
	}
	e.stoppedRing.mu.Unlock()

	if errCode == core.ExitSuccess {
		if rg.opts != nil && rg.opts.ForceSave {
			e.saveControlFile(rg)
		} else {
			e.removeControlFile(rg)
		}
	} else {
		e.saveControlFile(rg)
	}
	stopThrottle(rg.downloadLimit)
	stopThrottle(rg.uploadLimit)
	rg.downloadLimit = nil
	rg.uploadLimit = nil

	// Match aria2's stop-hook/event split: IN_PROGRESS and REMOVED are stop events,
	// successful completion is complete, and the remaining error codes are errors.
	switch errCode {
	case core.ExitSuccess:
		e.emit(core.EvComplete, rg.gid)
	case core.ExitInProgress, core.ExitRemoved:
		e.emit(core.EvStop, rg.gid)
	default:
		e.emit(core.EvError, rg.gid)
	}

	e.runStopHook(rg, errCode)
}

// runDownload executes the actual data transfer for a download, matching
// aria2's HttpDownloadCommand / FtpDownloadCommand lifecycle (DownloadCommand
// reads from socket → writes to DiskAdaptor → segment completion → finish).
//
// The download goroutine watches rg.ctx for cancellation (triggered by Pause,
// Remove, or Shutdown). On dry-run, it immediately transitions to complete
// without I/O. On error, it sets the error code and cancels the context so
// removeStoppedGroup picks it up.
func (e *Engine) runDownload(rg *requestGroup) {
	defer e.wg.Done()

	ctx := rg.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	defer e.finishControlFile(rg)

	if e.cfg.DryRun || rg.opts.DryRun {
		e.log.Info("dry-run mode, skipping download", "gid", rg.gid)
		if _, ok := e.groups.getLocked(rg.gid); ok {
			rg.errCode = core.ExitSuccess
			e.groups.unlock(rg.gid)
		}
		rg.cancel()
		return
	}

	// BitTorrent downloads are driven by torrent metadata, not URIs.
	if len(rg.torrent) > 0 {
		if err := e.runBTDownload(ctx, rg, rg.torrent); err != nil {
			e.log.Error("BT download failed", "gid", rg.gid, "error", err)
		}
		rg.cancel()
		return
	}
	if len(rg.metalinkData) > 0 {
		e.runMetalinkDownload(ctx, rg, rg.metalinkData)
		rg.cancel()
		return
	}

	if len(rg.uris) == 0 {
		e.log.Error("download has no URIs", "gid", rg.gid)
		rg.errCode = core.ExitResourceNotFound
		rg.errMsg = "no URIs specified"
		rg.cancel()
		return
	}

	selectedURIs := e.selectDownloadURIs(rg, 1)
	uri := rg.uris[0]
	if len(selectedURIs) > 0 {
		uri = selectedURIs[0]
	}
	rg.statusMu.Lock()
	rg.uriUsed = true
	rg.statusMu.Unlock()
	host, _ := uriHostProto(uri)
	rg.statusMu.Lock()
	rg.activeURI = uri
	rg.statusMu.Unlock()
	if host != "" {
		rg.activeHosts = map[string]int{host: 1}
	} else {
		rg.activeHosts = nil
	}
	if strings.HasPrefix(uri, "magnet:?") {
		e.runMagnetDownload(ctx, rg, uri)
		rg.cancel()
		return
	}
	u, err := url.Parse(uri)
	if err != nil {
		e.log.Error("cannot parse URI", "gid", rg.gid, "uri", uri, "error", err)
		rg.errCode = core.ExitResourceNotFound
		rg.errMsg = fmt.Sprintf("invalid URI: %s", uri)
		rg.cancel()
		return
	}

	outPath := rg.filePath
	outPathExplicit := rg.opts.Out != "" || (rg.filePath != "" && !rg.filePathFromURI)
	if outPath == "" {
		outPath = filepath.Base(u.Path)
		if outPath == "" || outPath == "." || outPath == "/" {
			outPath = "index.html"
		}
		if rg.opts.Dir != "" {
			outPath = filepath.Join(rg.opts.Dir, outPath)
		}
	} else {
		if rg.opts.Out == "" && rg.opts.Dir != "" && !filepath.IsAbs(outPath) {
			outPath = filepath.Join(rg.opts.Dir, outPath)
		}
	}

	proto := strings.ToLower(u.Scheme)
	expectedControlTotal := int64(-1)
	expectedControlPieceLen := controlPieceLength(rg.opts)
	if outPathExplicit {
		resolvedPath, ok := e.resolveFileCollision(rg, outPath, expectedControlTotal, expectedControlPieceLen)
		if !ok {
			rg.cancel()
			return
		}
		outPath = resolvedPath
	}
	if proto == "http" || proto == "https" {
		var stopHTTP bool
		outPath, expectedControlTotal, stopHTTP = e.prepareHTTPMetadata(ctx, rg, uri, outPath, outPathExplicit)
		if stopHTTP {
			rg.cancel()
			return
		}
	}

	if !outPathExplicit {
		resolvedPath, ok := e.resolveFileCollision(rg, outPath, expectedControlTotal, expectedControlPieceLen)
		if !ok {
			rg.cancel()
			return
		}
		outPath = resolvedPath
	}

	switch proto {
	case "http", "https":
		if e.shouldFollowTorrent(rg, uri) {
			e.runTorrentFollowDownload(ctx, rg, uri, outPath)
			rg.cancel()
			return
		}
		e.runHTTPDownload(ctx, rg, uri, outPath)
	case "ftp":
		e.runFTPDownload(ctx, rg, uri, u, outPath)
	case "sftp":
		e.runSFTPDownload(ctx, rg, uri, u, outPath)
	default:
		e.log.Error("unsupported protocol", "gid", rg.gid, "protocol", proto)
		rg.errCode = core.ExitResourceNotFound
		rg.errMsg = fmt.Sprintf("unsupported protocol: %s", proto)
		rg.cancel()
		return
	}

	rg.cancel()
}

func (e *Engine) resolveFileCollision(rg *requestGroup, outPath string, expectedControlTotal, expectedControlPieceLen int64) (string, bool) {
	// Resolve filename collision and auto-renaming under queuesMu lock to prevent race conditions.
	e.queuesMu.Lock()
	defer e.queuesMu.Unlock()

	originalPath := outPath
	suffix := 1
	for {
		collision := false
		if e.isSameFileBeingDownloadedLocked(outPath, rg.gid) {
			collision = true
		} else if e.controlFileAllowsResume(outPath, rg.opts, expectedControlTotal, expectedControlPieceLen, nil) {
			collision = false
		} else {
			// If file exists on disk and we are not continuing (continuing means rg.opts.Continue is true)
			if _, err := os.Stat(outPath); err == nil && !rg.opts.Continue && !rg.opts.AllowOverwrite {
				collision = true
			}
		}

		if collision {
			if !rg.opts.AutoFileRenaming {
				e.log.Error("file collision detected but auto-file-renaming is disabled", "gid", rg.gid, "path", outPath)
				if _, ok := e.groups.getLocked(rg.gid); ok {
					rg.errCode = core.ExitFileAlreadyExists
					rg.errMsg = fmt.Sprintf("file already exists: %s", outPath)
					e.groups.unlock(rg.gid)
				}
				return outPath, false
			}
			outPath = tryAutoFileRenamingWithSuffix(originalPath, suffix)
			suffix++
		} else {
			break
		}
	}

	// Update the request group's filePath and fileName under lock
	if _, ok := e.groups.getLocked(rg.gid); ok {
		rg.filePath = outPath
		rg.fileName = filepath.Base(outPath)
		rg.filePathFromURI = false
		e.groups.unlock(rg.gid)
	}
	return outPath, true
}

func (e *Engine) runMagnetDownload(ctx context.Context, rg *requestGroup, uri string) {
	m, err := magnet.Parse(uri)
	if err != nil {
		e.log.Error("magnet parse failed", "gid", rg.gid, "error", err)
		rg.errCode = protocolErrorCode(err)
		rg.errMsg = err.Error()
		return
	}
	if m.InfoHashV1 == nil {
		rg.errCode = core.ExitMagnetParseError
		rg.errMsg = "magnet link missing BitTorrent v1 info hash"
		return
	}

	loaded, err := e.tryLoadSavedMagnetTorrent(ctx, rg, m)
	if err != nil {
		e.log.Error("magnet saved metadata load failed", "gid", rg.gid, "error", err)
		rg.errCode = protocolErrorCode(err)
		rg.errMsg = protocolErrorMessage(err)
		return
	}
	if loaded {
		return
	}

	if err := e.runMagnetMetadataSession(ctx, rg, m); err != nil {
		e.log.Error("magnet metadata download failed", "gid", rg.gid, "error", err)
		rg.errCode = protocolErrorCode(err)
		rg.errMsg = protocolErrorMessage(err)
	}
}

func (e *Engine) prepareHTTPMetadata(ctx context.Context, rg *requestGroup, uri, outPath string, outPathExplicit bool) (string, int64, bool) {
	driver, err := e.httpDriverForURI(rg, uri)
	if err != nil {
		rg.errCode = protocolErrorCode(err)
		rg.errMsg = err.Error()
		return outPath, -1, false
	}
	info, err := e.probeHTTPInfoWithRetry(ctx, rg, driver, uri, outPath)
	if errors.Is(err, httpproto.ErrNotModified) {
		e.completeHTTPNotModified(rg, outPath)
		return outPath, -1, true
	}
	if err != nil {
		e.log.Error("HTTP probe failed", "gid", rg.gid, "uri", uri, "error", err)
		rg.errCode = protocolErrorCode(err)
		rg.errMsg = err.Error()
		return outPath, -1, true
	}
	if err := e.applyHTTPResponseDigests(rg, info.Digests); err != nil {
		rg.errCode = core.ExitChecksumError
		rg.errMsg = err.Error()
		return outPath, -1, true
	}

	rg.probed = true
	rg.probedSize = info.Size
	rg.acceptsRanges = info.AcceptsRanges
	rg.inflatedResponse = info.Inflated
	rg.cdFilename = info.ContentDispositionFilename
	rg.lastModified = info.LastModified
	rg.contentType = info.ContentType

	if !outPathExplicit && info.ContentDispositionFilename != "" {
		outPath = httpContentDispositionPath(rg.opts, info.ContentDispositionFilename)
	}
	return outPath, info.Size, false
}

type httpRetryState struct {
	maxTries        int
	retryWait       time.Duration
	maxFileNotFound int
	failures        int
	fileNotFound    int
}

func newHTTPRetryState(opts *config.Options) httpRetryState {
	if opts == nil {
		return httpRetryState{}
	}
	return httpRetryState{
		maxTries:        opts.MaxTries,
		retryWait:       time.Duration(parseInt(opts.RetryWait)) * time.Second,
		maxFileNotFound: opts.MaxFileNotFound,
	}
}

func (e *Engine) shouldRetryHTTP(ctx context.Context, state *httpRetryState, err error) (bool, error) {
	if state == nil || err == nil {
		return false, err
	}

	statusCode := 0
	var statusErr *httpproto.HTTPStatusError
	if errors.As(err, &statusErr) {
		statusCode = statusErr.StatusCode()
	}

	shouldRetry := false
	switch statusCode {
	case http.StatusNotFound:
		if state.maxFileNotFound == 0 {
			return false, err
		}
		state.fileNotFound++
		if state.fileNotFound >= state.maxFileNotFound {
			return false, fmt.Errorf("http: max-file-not-found reached: %w",
				core.NewError(core.ExitMaxFileNotFound, "max file not found"))
		}
		shouldRetry = true
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		shouldRetry = state.retryWait > 0
	case http.StatusGatewayTimeout:
		shouldRetry = true
	}
	if !shouldRetry {
		return false, err
	}

	state.failures++
	if state.maxTries > 0 && state.failures >= state.maxTries {
		return false, err
	}
	if state.retryWait > 0 {
		timer := time.NewTimer(state.retryWait)
		defer func() {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return true, nil
}

func (e *Engine) probeHTTPInfoWithRetry(ctx context.Context, rg *requestGroup, driver *httpproto.Driver, uri, outPath string) (httpproto.ResourceInfo, error) {
	opts := e.httpRequestOptions(rg, outPath)
	retryState := newHTTPRetryState(rg.opts)

	for {
		info, err := driver.ProbeInfoWithOptions(ctx, uri, opts)
		if err == nil || errors.Is(err, httpproto.ErrNotModified) {
			return info, err
		}
		retry, retryErr := e.shouldRetryHTTP(ctx, &retryState, err)
		if retryErr != nil && !retry {
			return info, retryErr
		}
		if !retry {
			return info, err
		}
	}
}

func (e *Engine) httpDriverForURI(rg *requestGroup, rawURI string) (*httpproto.Driver, error) {
	acceptEncoding := ""
	if opts := rgOptionsOrDefault(rg, e.cfg); opts.HTTPAcceptGzip {
		acceptEncoding = "deflate, gzip"
	}
	return e.httpDriverForURIWithAcceptEncoding(rg, rawURI, acceptEncoding)
}

func (e *Engine) httpDriverForURIWithAcceptEncoding(rg *requestGroup, rawURI string, acceptEncoding string) (*httpproto.Driver, error) {
	opts := e.cfg
	if rg != nil && rg.opts != nil {
		opts = rg.opts
	}
	proto := "http"
	targetHost := ""
	if u, err := url.Parse(rawURI); err == nil && u.Scheme != "" {
		proto = strings.ToLower(u.Scheme)
		targetHost = u.Hostname()
	}
	httpTLS, err := httpClientTLSConfig(opts)
	if err != nil {
		return nil, err
	}
	proxyURI := resolveProxyURIForTarget(proto, targetHost, opts)
	proxyMethod := resolveHTTPProxyMethod(proto, opts)
	dialer, err := e.dialerForProtocol(proto, targetHost, opts)
	if err != nil {
		return nil, err
	}
	var transportProxyURL *url.URL
	if proxyURI != "" && proto == "http" && proxyMethod == "get" {
		transportProxyURL, err = url.Parse(proxyURI)
		if err != nil {
			return nil, err
		}
		dialer, err = netx.NewDialer(engineDialerConfigWithoutProxy(opts))
		if err != nil {
			return nil, err
		}
	}
	httpUser := opts.HTTPUser
	httpPasswd := opts.HTTPPasswd
	if e.authFactory != nil {
		if ac := e.authFactory.CreateAuthConfig(rawURI, opts); ac != nil {
			httpUser = ac.User()
			httpPasswd = ac.Password()
		}
	}
	jar := e.cookieJar
	if jar == nil {
		jar = newHTTPCookieJar(opts, e.log)
	}
	return httpproto.NewDriver(httpproto.Opts{
		Dialer:                        dialer,
		TLS:                           httpTLS,
		Jar:                           httpCookieJar(jar),
		Timeout:                       time.Duration(parseInt(opts.Timeout)) * time.Second,
		UserAgent:                     opts.UserAgent,
		Header:                        opts.Header,
		ProxyURL:                      transportProxyURL,
		CheckCertificate:              &opts.CheckCertificate,
		MaxRedirs:                     20,
		AcceptEncoding:                acceptEncoding,
		Referer:                       opts.Referer,
		HTTPUser:                      httpUser,
		HTTPPasswd:                    httpPasswd,
		HTTPAuthChallenge:             opts.HTTPAuthChallenge,
		ContentDispositionDefaultUTF8: opts.ContentDispositionDefaultUTF8,
		DisableKeepAlive:              !opts.EnableHTTPKeepAlive,
		NoCache:                       &opts.HTTPNoCache,
		EnableWantDigest:              boolPtr(!opts.NoWantDigestHeader),
		UseHead:                       opts.UseHead,
		DryRun:                        opts.DryRun,
	}), nil
}

func rgOptionsOrDefault(rg *requestGroup, fallback *config.Options) *config.Options {
	if rg != nil && rg.opts != nil {
		return rg.opts
	}
	return fallback
}

func (e *Engine) httpRequestOptions(rg *requestGroup, outPath string) httpproto.RequestOptions {
	if rg == nil || rg.opts == nil || !rg.opts.ConditionalGet || outPath == "" {
		return httpproto.RequestOptions{}
	}
	if _, err := os.Stat(outPath + btprogress.Suffix); err == nil {
		return httpproto.RequestOptions{}
	}
	st, err := os.Stat(outPath)
	if err != nil || st.IsDir() {
		return httpproto.RequestOptions{}
	}
	return httpproto.RequestOptions{IfModifiedSince: st.ModTime().UTC().Format(http.TimeFormat)}
}

func (e *Engine) completeHTTPNotModified(rg *requestGroup, outPath string) {
	st, err := os.Stat(outPath)
	if err != nil {
		rg.errCode = core.ExitFileIOError
		rg.errMsg = err.Error()
		return
	}
	rg.filePath = outPath
	rg.fileName = filepath.Base(outPath)
	rg.filePathFromURI = false
	rg.statusMu.Lock()
	rg.totalLength = st.Size()
	rg.statusMu.Unlock()
	rg.statusMu.Lock()
	rg.completedLength = st.Size()
	rg.statusMu.Unlock()
	rg.errCode = core.ExitSuccess
	e.log.Info("HTTP resource not modified", "gid", rg.gid, "path", outPath)
}

func httpContentDispositionPath(opts *config.Options, filename string) string {
	if opts != nil && opts.Dir != "" {
		return filepath.Join(opts.Dir, filename)
	}
	return filename
}

func (e *Engine) downloadHTTPWithRetry(ctx context.Context, rg *requestGroup, driver *httpproto.Driver, uri string, offset, size int64, opts httpproto.RequestOptions) (*httpproto.DownloadResponse, error) {
	retryState := newHTTPRetryState(rg.opts)
	for {
		resp, err := driver.DownloadResponseWithOptions(ctx, uri, offset, size, opts)
		if err == nil || errors.Is(err, httpproto.ErrNotModified) || errors.Is(err, httpproto.ErrRangeIgnored) {
			return resp, err
		}
		retry, retryErr := e.shouldRetryHTTP(ctx, &retryState, err)
		if retryErr != nil && !retry {
			return nil, retryErr
		}
		if !retry {
			return nil, err
		}
	}
}

func (e *Engine) applyHTTPResponseDigests(rg *requestGroup, digests []httpproto.ResponseDigest) error {
	if rg == nil || len(digests) == 0 {
		return nil
	}
	rg.integrityMu.Lock()
	defer rg.integrityMu.Unlock()

	if rg.integrity.hasWholeChecksum() {
		for _, digest := range digests {
			if digest.Kind != rg.integrity.wholeKind {
				continue
			}
			if !bytes.Equal(digest.Digest, rg.integrity.wholeDigest) {
				return core.NewError(core.ExitChecksumError, "invalid hash found in Digest header field")
			}
			return nil
		}
		return nil
	}

	first := digests[0]
	rg.integrity.wholeKind = first.Kind
	rg.integrity.wholeDigest = append([]byte(nil), first.Digest...)
	return nil
}

func (e *Engine) nextHTTPResumeFallbackURI(rg *requestGroup, currentURI string, sessionDownloaded int64) (string, bool) {
	if rg == nil || rg.opts == nil || rg.opts.AlwaysResume || sessionDownloaded > 0 {
		return "", false
	}
	rg.resumeFailureCount++
	if currentURI != "" {
		if rg.resumeBlockedURIs == nil {
			rg.resumeBlockedURIs = make(map[string]struct{})
		}
		rg.resumeBlockedURIs[currentURI] = struct{}{}
	}
	maxTries := rg.opts.MaxResumeFailureTries
	if maxTries > 0 && rg.resumeFailureCount >= maxTries {
		rg.resumeBlockedURIs = nil
		return "", true
	}
	for _, candidate := range rg.uris {
		if candidate == "" || blockedURI(rg.resumeBlockedURIs, candidate) {
			continue
		}
		return candidate, false
	}
	rg.resumeBlockedURIs = nil
	return "", true
}

func (e *Engine) clearHTTPResumeFallbackURIs(rg *requestGroup) {
	if rg == nil {
		return
	}
	rg.resumeBlockedURIs = nil
}

func ensureDownloadPlaceholder(outPath string) error {
	if _, err := os.Stat(outPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := openHTTPScratchFile(outPath)
	if err != nil {
		return err
	}
	return f.Close()
}

func (e *Engine) failHashCheckOnlyIncomplete(rg *requestGroup, outPath string) {
	if rg == nil {
		return
	}
	if err := ensureDownloadPlaceholder(outPath); err != nil {
		rg.errCode = core.ExitFileCreateError
		rg.errMsg = err.Error()
		return
	}
	rg.errCode = core.ExitUnknownError
	rg.errMsg = "download not complete"
}

func openHTTPScratchFile(outPath string) (*os.File, error) {
	if dir := filepath.Dir(outPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
}

// setError writes the error code and message under statusMu. Worker
// goroutines call this after their context is cancelled, concurrent with
// the reaper's final write in addStoppedLocked and status polls.
func (rg *requestGroup) setError(code core.ErrorCode, msg string) {
	rg.statusMu.Lock()
	rg.errCode = code
	rg.errMsg = msg
	rg.statusMu.Unlock()
}

// errorStatus reads the error code and message under statusMu.
func (rg *requestGroup) errorStatus() (core.ErrorCode, string) {
	rg.statusMu.Lock()
	defer rg.statusMu.Unlock()
	return rg.errCode, rg.errMsg
}

func markTransferCanceled(rg *requestGroup) {
	if rg == nil {
		return
	}
	switch rg.haltReason {
	case haltReasonUserRequest:
		rg.setError(core.ExitRemoved, "")
		return
	case haltReasonShutdown:
		if rg.haltRequested && !rg.forceHaltReq {
			// Mirrors aria2's SHUTDOWN_SIGNAL path: graceful halt leaves
			// lastErrorCode undefined so the final DownloadResult becomes IN_PROGRESS.
			rg.setError(0, "")
			return
		}
	}
	if rg.haltRequested && !rg.forceHaltReq {
		rg.setError(0, "")
		return
	}
	rg.setError(core.ExitRemoved, "download cancelled")
}

func (e *Engine) downloadToFile(ctx context.Context, rg *requestGroup, f *os.File, body io.Reader, guard *speedGuard) int64 {
	buf := make([]byte, 64*1024)
	var written int64
	for {
		select {
		case <-ctx.Done():
			markTransferCanceled(rg)
			return -1
		default:
		}
		n, readErr := body.Read(buf)
		if n > 0 {
			if err := e.rateGlobal.Wait(ctx, n); err != nil {
				markTransferCanceled(rg)
				return -1
			}
			if rg.downloadLimit != nil {
				if err := rg.downloadLimit.Wait(ctx, n); err != nil {
					markTransferCanceled(rg)
					return -1
				}
			}
			wn, writeErr := f.Write(buf[:n])
			if writeErr != nil {
				e.log.Error("disk write failed", "gid", rg.gid, "error", writeErr)
				rg.errCode = core.ExitFileIOError
				rg.errMsg = writeErr.Error()
				return -1
			}
			written += int64(wn)
			atomic.AddInt64(&rg.bytesDownloaded, int64(wn))
			if err := guard.Add(wn); err != nil {
				rg.errCode = core.ExitTooSlow
				rg.errMsg = err.Error()
				return -1
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			if errors.Is(readErr, context.Canceled) {
				markTransferCanceled(rg)
				return -1
			}
			e.log.Error("read failed", "gid", rg.gid, "error", readErr)
			rg.errCode = protocolErrorCode(readErr)
			rg.errMsg = readErr.Error()
			return -1
		}
	}
	return written
}

// runHTTPDownload performs an HTTP/HTTPS download.
func (e *Engine) runHTTPDownload(ctx context.Context, rg *requestGroup, uri, outPath string) {
	driver, err := e.httpDriverForURI(rg, uri)
	if err != nil {
		rg.errCode = protocolErrorCode(err)
		rg.errMsg = err.Error()
		return
	}
	recordURI := uri
	defer func() {
		if recordURI == "" {
			return
		}
		if rg.errCode == core.ExitSuccess {
			e.recordServerStatSuccess(recordURI, max64(rg.downloadSpeed, downloadAverageSpeed(rg)), max(1, int(rg.numConnections.Load())))
			return
		}
		if rg.errCode != 0 {
			e.markServerStatError(recordURI)
		}
	}()
	size := rg.probedSize
	acceptsRanges := rg.acceptsRanges
	inflated := rg.inflatedResponse
	cdFilename := rg.cdFilename
	lastModified := rg.lastModified
	requestOpts := e.httpRequestOptions(rg, outPath)
	if !rg.probed {
		info, err := e.probeHTTPInfoWithRetry(ctx, rg, driver, uri, outPath)
		if errors.Is(err, httpproto.ErrNotModified) {
			e.completeHTTPNotModified(rg, outPath)
			return
		}
		if err != nil {
			e.log.Error("HTTP probe failed", "gid", rg.gid, "uri", uri, "error", err)
			rg.errCode = protocolErrorCode(err)
			rg.errMsg = err.Error()
			return
		}
		if err := e.applyHTTPResponseDigests(rg, info.Digests); err != nil {
			rg.errCode = core.ExitChecksumError
			rg.errMsg = err.Error()
			return
		}
		size = info.Size
		acceptsRanges = info.AcceptsRanges
		inflated = info.Inflated
		cdFilename = info.ContentDispositionFilename
		lastModified = info.LastModified
	}
	if cdFilename != "" {
		e.log.Info("Content-Disposition filename", "gid", rg.gid, "filename", cdFilename)
	}

	rg.statusMu.Lock()
	rg.totalLength = size
	rg.statusMu.Unlock()
	rg.statusMu.Lock()
	rg.lastSpeedSample = time.Now()
	rg.statusMu.Unlock()
	e.initControlInfo(rg, outPath, size, rg.integrity.controlPieceLength(0), nil)
	existingSize := int64(0)
	if inflated {
		existingSize = 0
	} else if controlOffset := e.controlResumeOffset(rg, outPath); controlOffset > 0 {
		existingSize = controlOffset
		if size > 0 && existingSize >= size {
			if verifyErr := e.verifyExistingFileIntegrity(ctx, rg, outPath, size); verifyErr != nil {
				if e.allowIntegrityRetry(rg) {
					e.resetControlState(rg, outPath)
					if truncErr := os.Truncate(outPath, 0); truncErr != nil {
						rg.errCode = core.ExitFileIOError
						rg.errMsg = truncErr.Error()
						return
					}
					existingSize = 0
				} else {
					rg.errCode = core.ExitChecksumError
					rg.errMsg = verifyErr.Error()
					return
				}
			}
			if existingSize >= size {
				rg.statusMu.Lock()
				rg.completedLength = size
				rg.statusMu.Unlock()
				rg.errCode = core.ExitSuccess
				e.applyHTTPRemoteTime(rg, outPath, lastModified)
				e.log.Info("download already complete", "gid", rg.gid, "size", size)
				return
			}
		}
	} else if rg.opts.Continue {
		if st, statErr := os.Stat(outPath); statErr == nil && !st.IsDir() {
			existingSize = st.Size()
			if size > 0 && existingSize >= size {
				if verifyErr := e.verifyExistingFileIntegrity(ctx, rg, outPath, size); verifyErr != nil {
					if e.allowIntegrityRetry(rg) {
						e.resetControlState(rg, outPath)
						if truncErr := os.Truncate(outPath, 0); truncErr != nil {
							rg.errCode = core.ExitFileIOError
							rg.errMsg = truncErr.Error()
							return
						}
						existingSize = 0
					} else {
						rg.errCode = core.ExitChecksumError
						rg.errMsg = verifyErr.Error()
						return
					}
				}
				if existingSize >= size {
					rg.statusMu.Lock()
					rg.completedLength = size
					rg.statusMu.Unlock()
					rg.errCode = core.ExitSuccess
					e.applyHTTPRemoteTime(rg, outPath, lastModified)
					e.log.Info("download already complete", "gid", rg.gid, "size", size)
					return
				}
			}
		} else if statErr != nil && !os.IsNotExist(statErr) {
			rg.errCode = core.ExitFileIOError
			rg.errMsg = statErr.Error()
			return
		}
	}
	if rg.opts.HashCheckOnly {
		e.failHashCheckOnlyIncomplete(rg, outPath)
		return
	}
	if rg.opts.AllowOverwrite && !rg.opts.Continue && !e.controlLoaded(rg) {
		if err := os.Truncate(outPath, 0); err != nil && !os.IsNotExist(err) {
			rg.errCode = core.ExitFileIOError
			rg.errMsg = err.Error()
			return
		}
	}

	alloc := chooseAllocator(rg.opts, size)

	split := rg.opts.Split
	if split < 1 {
		split = 1
	}
	selectedURIs := e.selectDownloadURIs(rg, split)
	if len(selectedURIs) == 0 {
		selectedURIs = []string{uri}
	}
	rg.statusMu.Lock()
	rg.activeURI = selectedURIs[0]
	rg.statusMu.Unlock()
	rg.activeHosts = hostUseMap(selectedURIs)
	startupIdle := time.Duration(parseInt(rg.opts.StartupIdleTime)) * time.Second
	lowestLimit := e.effectiveLowestSpeedLimit(rg, selectedURIs)
	if acceptsRanges && size > 0 && len(selectedURIs) > 1 {
		adaptor, err := disk.NewSingleFile(outPath, size, alloc)
		if err != nil {
			e.log.Error("cannot create output file", "gid", rg.gid, "path", outPath, "error", err)
			rg.errCode = core.ExitFileCreateError
			rg.errMsg = err.Error()
			return
		}
		e.setControlAdaptor(rg, adaptor)
		defer adaptor.Close()
		defer e.syncControlAdaptor(rg)

		minSplitSize := parseSize(rg.opts.MinSplitSize)
		baseCompleted := int64(0)
		segMan := e.controlSegmentMan(rg)
		if segMan != nil {
			baseCompleted = e.controlCompletedLength(rg)
		} else {
			segMan = NewSegmentManWithSplit(size, split, minSplitSize)
		}
		if existingSize > 0 && !e.controlLoaded(rg) {
			segMan = newResumeSegmentMan(size, split, minSplitSize, existingSize)
		}
		if segMan.Done() {
			rg.statusMu.Lock()
			rg.completedLength = size
			rg.statusMu.Unlock()
			if mode, bad, verifyErr := e.verifyIntegrity(ctx, rg, adaptor, outPath); verifyErr != nil {
				if mode == "piece" && len(bad) > 0 && e.allowIntegrityRetry(rg) {
					_ = adaptor.Close()
					e.saveControlFile(rg)
					e.runHTTPDownload(ctx, rg, uri, outPath)
					return
				}
				rg.errCode = core.ExitChecksumError
				rg.errMsg = verifyErr.Error()
				return
			}
			rg.errCode = core.ExitSuccess
			e.applyHTTPRemoteTime(rg, outPath, lastModified)
			e.log.Info("download already complete", "gid", rg.gid, "size", size)
			return
		}
		rg.numConnections.Store(int64(len(selectedURIs)))

		segmentCtx, segmentCancel := context.WithCancel(ctx)
		defer segmentCancel()

		var segMu sync.Mutex
		firstErr := error(nil)
		rangeIgnoredURI := ""

		var wg sync.WaitGroup
		for i := 0; i < len(selectedURIs); i++ {
			workerURI := selectedURIs[i]
			wg.Add(1)
			go func(workerURI string) {
				defer wg.Done()
				workerDriver, derr := e.httpDriverForURI(rg, workerURI)
				if derr != nil {
					segMu.Lock()
					if firstErr == nil {
						firstErr = derr
					}
					segMu.Unlock()
					segmentCancel()
					return
				}
				host, _ := uriHostProto(workerURI)
				guard := newSpeedGuard(lowestLimit, startupIdle, host)
				for {
					seg := segMan.Next()
					if seg == nil {
						if segMan.Done() {
							return
						}
						select {
						case <-segmentCtx.Done():
							return
						case <-time.After(200 * time.Millisecond):
						}
						continue
					}

					segSize := int64(0)
					if seg.End != -1 {
						segSize = seg.End - seg.Start
					}

					resp, err := e.downloadHTTPWithRetry(segmentCtx, rg, workerDriver, workerURI, seg.Start, segSize, httpproto.RequestOptions{})
					if err != nil {
						e.log.Error("HTTP segment download failed", "gid", rg.gid, "start", seg.Start, "error", err)
						segMu.Lock()
						if firstErr == nil {
							firstErr = err
							if errors.Is(err, httpproto.ErrRangeIgnored) {
								rangeIgnoredURI = workerURI
							}
						}
						segMu.Unlock()
						segmentCancel()
						return
					}
					if derr := e.applyHTTPResponseDigests(rg, resp.Digests); derr != nil {
						resp.Body.Close()
						segMu.Lock()
						if firstErr == nil {
							firstErr = derr
						}
						segMu.Unlock()
						segmentCancel()
						return
					}

					written := e.downloadToAdaptor(segmentCtx, rg, adaptor, resp.Body, seg.Start, guard)
					resp.Body.Close()

					if written < 0 {
						segMu.Lock()
						if firstErr == nil {
							firstErr = fmt.Errorf("%s: %s", rg.errCode, rg.errMsg)
						}
						segMu.Unlock()
						segmentCancel()
						return
					}

					segMan.MarkDone(seg.Index, written)
				}
			}(workerURI)
		}
		wg.Wait()

		if firstErr != nil {
			if e.shouldRetryRealtimePieceCheck(rg) {
				_ = adaptor.Close()
				e.saveControlFile(rg)
				e.runHTTPDownload(ctx, rg, uri, outPath)
				return
			}
			if errors.Is(firstErr, httpproto.ErrRangeIgnored) {
				if rg.opts.AlwaysResume {
					rg.errCode = core.ExitFileAlreadyExists
					rg.errMsg = firstErr.Error()
					return
				}
				sessionDownloaded := segMan.Written() + atomic.LoadInt64(&rg.bytesDownloaded)
				if nextURI, restartScratch := e.nextHTTPResumeFallbackURI(rg, rangeIgnoredURI, sessionDownloaded); nextURI != "" {
					recordURI = ""
					if closeErr := adaptor.Close(); closeErr != nil {
						rg.errCode = core.ExitFileIOError
						rg.errMsg = closeErr.Error()
						return
					}
					rg.statusMu.Lock()
					rg.activeURI = nextURI
					rg.statusMu.Unlock()
					e.runHTTPDownload(ctx, rg, nextURI, outPath)
					return
				} else if !restartScratch {
					rg.errCode = protocolErrorCode(firstErr)
					rg.errMsg = firstErr.Error()
					return
				}
				e.clearHTTPResumeFallbackURIs(rg)
				e.log.Warn("HTTP server ignored resume range; restarting from scratch", "gid", rg.gid, "path", outPath)
				if closeErr := adaptor.Close(); closeErr != nil {
					rg.errCode = core.ExitFileIOError
					rg.errMsg = closeErr.Error()
					return
				}
				if truncErr := os.Truncate(outPath, 0); truncErr != nil {
					rg.errCode = core.ExitFileIOError
					rg.errMsg = truncErr.Error()
					return
				}
				oldContinue, oldSplit := rg.opts.Continue, rg.opts.Split
				rg.opts.Continue = false
				rg.opts.Split = 1
				recordURI = ""
				e.runHTTPDownload(ctx, rg, uri, outPath)
				rg.opts.Continue, rg.opts.Split = oldContinue, oldSplit
				return
			}
			rg.errCode = protocolErrorCode(firstErr)
			rg.errMsg = firstErr.Error()
			return
		}

		if err := adaptor.Sync(); err != nil {
			e.log.Error("file sync failed", "gid", rg.gid, "error", err)
			rg.errCode = core.ExitFileIOError
			rg.errMsg = err.Error()
			return
		}

		rg.statusMu.Lock()
		rg.completedLength = baseCompleted + segMan.Written()
		rg.statusMu.Unlock()
		if size > 0 && rg.completedLength > size {
			rg.statusMu.Lock()
			rg.completedLength = size
			rg.statusMu.Unlock()
		}
		if mode, bad, verifyErr := e.verifyIntegrity(ctx, rg, adaptor, outPath); verifyErr != nil {
			if mode == "piece" && len(bad) > 0 && e.allowIntegrityRetry(rg) {
				_ = adaptor.Close()
				e.saveControlFile(rg)
				e.runHTTPDownload(ctx, rg, uri, outPath)
				return
			}
			if mode == "whole" && e.allowIntegrityRetry(rg) {
				_ = adaptor.Close()
				e.resetControlState(rg, outPath)
				if truncErr := os.Truncate(outPath, 0); truncErr != nil {
					rg.errCode = core.ExitFileIOError
					rg.errMsg = truncErr.Error()
					return
				}
				e.runHTTPDownload(ctx, rg, uri, outPath)
				return
			}
			rg.errCode = core.ExitChecksumError
			rg.errMsg = verifyErr.Error()
			return
		}
		e.clearHTTPResumeFallbackURIs(rg)
		rg.resumeFailureCount = 0
		rg.errCode = core.ExitSuccess
		rg.numConnections.Store(int64(len(segMan.segments)))
		e.applyHTTPRemoteTime(rg, outPath, lastModified)
		e.log.Info("download complete", "gid", rg.gid, "size", rg.completedLength)
		return
	}

	// Single-connection path (split <= 1 or unknown size).
	rg.numConnections.Store(1)

	offset := existingSize
	requestSize := int64(0)
	if size > 0 && offset > 0 {
		requestSize = size - offset
	}
	resp, err := e.downloadHTTPWithRetry(ctx, rg, driver, uri, offset, requestSize, requestOpts)
	if errors.Is(err, httpproto.ErrRangeIgnored) && offset > 0 {
		if rg.opts.AlwaysResume {
			rg.errCode = core.ExitFileAlreadyExists
			rg.errMsg = err.Error()
			return
		}
		if nextURI, restartScratch := e.nextHTTPResumeFallbackURI(rg, uri, 0); nextURI != "" {
			recordURI = ""
			rg.statusMu.Lock()
			rg.activeURI = nextURI
			rg.statusMu.Unlock()
			e.runHTTPDownload(ctx, rg, nextURI, outPath)
			return
		} else if !restartScratch {
			rg.errCode = protocolErrorCode(err)
			rg.errMsg = err.Error()
			return
		}
		e.clearHTTPResumeFallbackURIs(rg)
		e.log.Warn("HTTP server ignored resume range; restarting from scratch", "gid", rg.gid, "path", outPath)
		if truncErr := os.Truncate(outPath, 0); truncErr != nil {
			rg.errCode = core.ExitFileIOError
			rg.errMsg = truncErr.Error()
			return
		}
		offset = 0
		requestSize = 0
		resp, err = e.downloadHTTPWithRetry(ctx, rg, driver, uri, offset, requestSize, requestOpts)
	}
	if errors.Is(err, httpproto.ErrNotModified) {
		e.completeHTTPNotModified(rg, outPath)
		return
	}
	if err != nil {
		e.log.Error("HTTP download failed", "gid", rg.gid, "uri", uri, "error", err)
		rg.errCode = protocolErrorCode(err)
		rg.errMsg = err.Error()
		return
	}
	if err := e.applyHTTPResponseDigests(rg, resp.Digests); err != nil {
		resp.Body.Close()
		rg.errCode = core.ExitChecksumError
		rg.errMsg = err.Error()
		return
	}

	defer resp.Body.Close()

	if size <= 0 || resp.Inflated {
		rg.statusMu.Lock()
		rg.totalLength = 0
		rg.statusMu.Unlock()
		e.initControlInfo(rg, outPath, 0, 0, nil)
		f, fileErr := openHTTPScratchFile(outPath)
		if fileErr != nil {
			rg.errCode = core.ExitFileCreateError
			rg.errMsg = fileErr.Error()
			return
		}
		host, _ := uriHostProto(uri)
		guard := newSpeedGuard(lowestLimit, startupIdle, host)
		written := e.downloadToFile(ctx, rg, f, resp.Body, guard)
		syncErr := f.Sync()
		closeErr := f.Close()
		if written < 0 {
			if syncErr != nil && !errors.Is(syncErr, os.ErrClosed) {
				e.log.Debug("discarding sync error after failed HTTP write", "gid", rg.gid, "error", syncErr)
			}
			if closeErr != nil {
				e.log.Debug("discarding close error after failed HTTP write", "gid", rg.gid, "error", closeErr)
			}
			return
		}
		if syncErr != nil {
			e.log.Error("file sync failed", "gid", rg.gid, "error", syncErr)
			rg.errCode = core.ExitFileIOError
			rg.errMsg = syncErr.Error()
			return
		}
		if closeErr != nil {
			e.log.Error("file close failed", "gid", rg.gid, "error", closeErr)
			rg.errCode = core.ExitFileIOError
			rg.errMsg = closeErr.Error()
			return
		}
		rg.statusMu.Lock()
		rg.completedLength = written
		rg.statusMu.Unlock()
		if mode, _, verifyErr := e.verifyIntegrity(ctx, rg, nil, outPath); verifyErr != nil {
			if mode == "whole" && e.allowIntegrityRetry(rg) {
				e.resetControlState(rg, outPath)
				if truncErr := os.Truncate(outPath, 0); truncErr != nil {
					rg.errCode = core.ExitFileIOError
					rg.errMsg = truncErr.Error()
					return
				}
				e.runHTTPDownload(ctx, rg, uri, outPath)
				return
			}
			rg.errCode = core.ExitChecksumError
			rg.errMsg = verifyErr.Error()
			return
		}
		e.clearHTTPResumeFallbackURIs(rg)
		rg.resumeFailureCount = 0
		rg.errCode = core.ExitSuccess
		e.applyHTTPRemoteTime(rg, outPath, lastModified)
		e.log.Info("download complete", "gid", rg.gid, "size", rg.completedLength)
		return
	}

	adaptor, err := disk.NewSingleFile(outPath, size, alloc)
	if err != nil {
		e.log.Error("cannot create output file", "gid", rg.gid, "path", outPath, "error", err)
		rg.errCode = core.ExitFileCreateError
		rg.errMsg = err.Error()
		return
	}
	e.setControlAdaptor(rg, adaptor)
	defer adaptor.Close()
	defer e.syncControlAdaptor(rg)

	host, _ := uriHostProto(uri)
	guard := newSpeedGuard(lowestLimit, startupIdle, host)
	written := e.downloadToAdaptor(ctx, rg, adaptor, resp.Body, offset, guard)
	if written < 0 {
		if e.shouldRetryRealtimePieceCheck(rg) {
			_ = adaptor.Close()
			e.saveControlFile(rg)
			e.runHTTPDownload(ctx, rg, uri, outPath)
		}
		return
	}
	if err := adaptor.Sync(); err != nil {
		e.log.Error("file sync failed", "gid", rg.gid, "error", err)
		rg.errCode = core.ExitFileIOError
		rg.errMsg = err.Error()
		return
	}

	rg.statusMu.Lock()
	rg.completedLength = offset + written
	rg.statusMu.Unlock()
	if mode, bad, verifyErr := e.verifyIntegrity(ctx, rg, adaptor, outPath); verifyErr != nil {
		if mode == "piece" && len(bad) > 0 && acceptsRanges && e.allowIntegrityRetry(rg) {
			_ = adaptor.Close()
			e.saveControlFile(rg)
			e.runHTTPDownload(ctx, rg, uri, outPath)
			return
		}
		if mode == "whole" && e.allowIntegrityRetry(rg) {
			_ = adaptor.Close()
			e.resetControlState(rg, outPath)
			if truncErr := os.Truncate(outPath, 0); truncErr != nil {
				rg.errCode = core.ExitFileIOError
				rg.errMsg = truncErr.Error()
				return
			}
			e.runHTTPDownload(ctx, rg, uri, outPath)
			return
		}
		rg.errCode = core.ExitChecksumError
		rg.errMsg = verifyErr.Error()
		return
	}
	e.clearHTTPResumeFallbackURIs(rg)
	rg.resumeFailureCount = 0
	rg.errCode = core.ExitSuccess
	e.applyHTTPRemoteTime(rg, outPath, lastModified)
	e.log.Info("download complete", "gid", rg.gid, "size", rg.completedLength)
}

func (e *Engine) applyHTTPRemoteTime(rg *requestGroup, outPath string, lastModified time.Time) {
	if rg == nil || rg.opts == nil || !rg.opts.RemoteTime || outPath == "" || lastModified.IsZero() {
		return
	}
	if err := os.Chtimes(outPath, time.Now(), lastModified); err != nil {
		e.log.Warn("failed to apply Last-Modified time", "gid", rg.gid, "path", outPath, "error", err)
	}
}

func openTransferAdaptor(path string, size int64, alloc disk.Allocator) (disk.Adaptor, error) {
	if size > 0 {
		return disk.NewSingleFile(path, size, alloc)
	}
	return newGrowableFileAdaptor(path, alloc)
}

type growableFileAdaptor struct {
	path    string
	f       *os.File
	size    atomic.Int64
	pieceMu sync.RWMutex
	fileMu  sync.RWMutex
	closed  atomic.Bool
	pieces  []bool
}

func newGrowableFileAdaptor(path string, alloc disk.Allocator) (*growableFileAdaptor, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o666)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, disk.Wrap("open", path, err)
		}
		if dir := filepath.Dir(path); dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, disk.Wrap("mkdir", path, err)
			}
		}
		f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
		if err != nil {
			return nil, disk.Wrap("create", path, err)
		}
	}
	if err := alloc.Allocate(f, 0); err != nil {
		_ = f.Close()
		return nil, disk.Wrap("alloc", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, disk.Wrap("read", path, err)
	}
	a := &growableFileAdaptor{path: path, f: f}
	a.size.Store(info.Size())
	return a, nil
}

func (a *growableFileAdaptor) OpenForWrite() error {
	if a.closed.Load() {
		return disk.ErrFileClosed
	}
	return nil
}

func (a *growableFileAdaptor) WriteAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, disk.ErrInvalidOffset
	}
	if a.closed.Load() {
		return 0, disk.ErrFileClosed
	}
	a.fileMu.RLock()
	f := a.f
	a.fileMu.RUnlock()
	if f == nil {
		return 0, disk.ErrFileClosed
	}
	n, err := f.WriteAt(p, offset)
	if err != nil {
		return n, disk.Wrap("write", a.path, err)
	}
	end := offset + int64(n)
	for {
		cur := a.size.Load()
		if end <= cur || a.size.CompareAndSwap(cur, end) {
			break
		}
	}
	return n, nil
}

func (a *growableFileAdaptor) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, disk.ErrInvalidOffset
	}
	if a.closed.Load() {
		return 0, disk.ErrFileClosed
	}
	a.fileMu.RLock()
	f := a.f
	a.fileMu.RUnlock()
	if f == nil {
		return 0, disk.ErrFileClosed
	}
	n, err := f.ReadAt(p, offset)
	if err != nil && err != io.EOF {
		return n, disk.Wrap("read", a.path, err)
	}
	return n, err
}

func (a *growableFileAdaptor) Size() int64 {
	return a.size.Load()
}

func (a *growableFileAdaptor) Sync() error {
	if a.closed.Load() {
		return disk.ErrFileClosed
	}
	a.fileMu.RLock()
	f := a.f
	a.fileMu.RUnlock()
	if f == nil {
		return disk.ErrFileClosed
	}
	if err := f.Sync(); err != nil {
		return disk.Wrap("write", a.path, err)
	}
	return nil
}

func (a *growableFileAdaptor) Close() error {
	if !a.closed.CompareAndSwap(false, true) {
		return nil
	}
	a.fileMu.Lock()
	defer a.fileMu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	return err
}

func (a *growableFileAdaptor) SetPieceCount(n int) {
	if n < 0 {
		n = 0
	}
	a.pieceMu.Lock()
	defer a.pieceMu.Unlock()
	if len(a.pieces) == n {
		return
	}
	a.pieces = make([]bool, n)
}

func (a *growableFileAdaptor) MarkPiece(i int, ok bool) {
	a.pieceMu.Lock()
	defer a.pieceMu.Unlock()
	if i < 0 || i >= len(a.pieces) {
		return
	}
	a.pieces[i] = ok
}

func (a *growableFileAdaptor) Have(i int) bool {
	a.pieceMu.RLock()
	defer a.pieceMu.RUnlock()
	return i >= 0 && i < len(a.pieces) && a.pieces[i]
}

func (a *growableFileAdaptor) Bitfield() []byte {
	a.pieceMu.RLock()
	defer a.pieceMu.RUnlock()
	out := make([]byte, (len(a.pieces)+7)/8)
	for i, have := range a.pieces {
		if have {
			out[i/8] |= 1 << (7 - uint(i%8))
		}
	}
	return out
}

func (a *growableFileAdaptor) Missing() []int {
	a.pieceMu.RLock()
	defer a.pieceMu.RUnlock()
	var out []int
	for i, have := range a.pieces {
		if !have {
			out = append(out, i)
		}
	}
	return out
}

func newResumeSegmentMan(totalSize int64, split int, minSplitSize, completed int64) *SegmentMan {
	if split <= 1 || completed <= 0 || totalSize <= 0 {
		return NewSegmentManWithSplit(totalSize, split, minSplitSize)
	}
	if completed > totalSize {
		completed = totalSize
	}
	segments := []*Segment{{
		Index:   0,
		Start:   0,
		End:     completed,
		Written: completed,
		Done:    true,
	}}
	remaining := totalSize - completed
	if remaining <= 0 {
		return &SegmentMan{segments: segments, totalSize: totalSize, minSplitSize: minSplitSize}
	}
	remainingSegments := split - 1
	if int64(remainingSegments) > remaining {
		remainingSegments = int(remaining)
	}
	chunkSize := remaining / int64(remainingSegments)
	start := completed
	for i := 0; i < remainingSegments; i++ {
		end := start + chunkSize
		if i == remainingSegments-1 {
			end = totalSize
		}
		segments = append(segments, &Segment{Index: len(segments), Start: start, End: end})
		start = end
	}
	return &SegmentMan{segments: segments, totalSize: totalSize, minSplitSize: minSplitSize}
}

// downloadToAdaptor reads from body and writes to adaptor at the given startOffset.
// Returns the number of bytes written, or -1 on error (caller already set rg.errCode).
func (e *Engine) downloadToAdaptor(ctx context.Context, rg *requestGroup, adaptor disk.Adaptor, body io.Reader, startOffset int64, guard *speedGuard) int64 {
	buf := make([]byte, 64*1024)
	var written int64
	for {
		select {
		case <-ctx.Done():
			markTransferCanceled(rg)
			return -1
		default:
		}
		n, readErr := body.Read(buf)
		if n > 0 {
			if err := e.rateGlobal.Wait(ctx, n); err != nil {
				markTransferCanceled(rg)
				return -1
			}
			if rg.downloadLimit != nil {
				if err := rg.downloadLimit.Wait(ctx, n); err != nil {
					markTransferCanceled(rg)
					return -1
				}
			}
			writeOffset := startOffset + written
			wn, writeErr := adaptor.WriteAt(buf[:n], writeOffset)
			if writeErr != nil {
				e.log.Error("disk write failed", "gid", rg.gid, "error", writeErr)
				rg.errCode = core.ExitFileIOError
				rg.errMsg = writeErr.Error()
				return -1
			}
			written += int64(wn)
			completedPieces := e.markControlWritten(rg, writeOffset, int64(wn))
			atomic.AddInt64(&rg.bytesDownloaded, int64(wn))
			if err := guard.Add(wn); err != nil {
				rg.errCode = core.ExitTooSlow
				rg.errMsg = err.Error()
				return -1
			}
			if rg.opts != nil && rg.opts.RealtimeChunkChecksum {
				if err := e.verifyCompletedPieces(ctx, rg, adaptor, completedPieces); err != nil {
					rg.errCode = core.ExitChecksumError
					rg.errMsg = err.Error()
					return -1
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			if errors.Is(readErr, context.Canceled) {
				markTransferCanceled(rg)
				return -1
			}
			e.log.Error("read failed", "gid", rg.gid, "error", readErr)
			rg.errCode = protocolErrorCode(readErr)
			rg.errMsg = readErr.Error()
			return -1
		}
	}
	return written
}

type ftpTransferConn interface {
	Close() error
	Size(context.Context, string) (int64, error)
	Mdtm(context.Context, string) (time.Time, error)
	Retrieve(context.Context, string, int64) (io.ReadCloser, error)
}

var ftpDial = func(ctx context.Context, dialer *netx.Dialer, addr string, opt ftpproto.Opt) (ftpTransferConn, error) {
	return ftpproto.Dial(ctx, dialer, addr, opt)
}

type ftpProxyGETConn struct {
	dialer   *netx.Dialer
	proxyURL *url.URL
	target   *url.URL
	timeout  time.Duration

	metaMu sync.Mutex
	meta   *ftpProxyGETMetadata
}

type ftpProxyGETMetadata struct {
	size    int64
	hasSize bool
	mdtm    time.Time
	hasMDTM bool
}

type ftpProxyGETBody struct {
	io.ReadCloser
	conn net.Conn
	done chan struct{}
}

func (b *ftpProxyGETBody) Close() error {
	select {
	case <-b.done:
	default:
		close(b.done)
	}
	bodyErr := b.ReadCloser.Close()
	connErr := b.conn.Close()
	if bodyErr != nil && connErr != nil {
		return errors.Join(bodyErr, connErr)
	}
	if bodyErr != nil {
		return bodyErr
	}
	return connErr
}

func (c *ftpProxyGETConn) Close() error { return nil }

func (c *ftpProxyGETConn) Size(ctx context.Context, _ string) (int64, error) {
	meta, err := c.headMetadata(ctx)
	if err != nil {
		return 0, err
	}
	if !meta.hasSize {
		return 0, ftpproto.ErrSizeUnsupported
	}
	return meta.size, nil
}

func (c *ftpProxyGETConn) Mdtm(ctx context.Context, _ string) (time.Time, error) {
	meta, err := c.headMetadata(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if !meta.hasMDTM {
		return time.Time{}, errors.New("ftp proxy GET: missing Last-Modified header")
	}
	return meta.mdtm, nil
}

func (c *ftpProxyGETConn) Retrieve(ctx context.Context, _ string, offset int64) (io.ReadCloser, error) {
	resp, conn, err := c.do(ctx, http.MethodGet, offset)
	if err != nil {
		return nil, err
	}
	if offset > 0 && resp.StatusCode != http.StatusPartialContent {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("ftp proxy GET: expected 206 for offset %d, got %d", offset, resp.StatusCode)
	}
	if offset == 0 && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("ftp proxy GET: unexpected status %d", resp.StatusCode)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return &ftpProxyGETBody{ReadCloser: resp.Body, conn: conn, done: done}, nil
}

func (c *ftpProxyGETConn) headMetadata(ctx context.Context) (*ftpProxyGETMetadata, error) {
	c.metaMu.Lock()
	if c.meta != nil {
		meta := *c.meta
		c.metaMu.Unlock()
		return &meta, nil
	}
	c.metaMu.Unlock()

	resp, conn, err := c.do(ctx, http.MethodHead, 0)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ftp proxy HEAD: unexpected status %d", resp.StatusCode)
	}

	meta := &ftpProxyGETMetadata{}
	if cl := strings.TrimSpace(resp.Header.Get("Content-Length")); cl != "" {
		size, err := strconv.ParseInt(cl, 10, 64)
		if err == nil && size >= 0 {
			meta.size = size
			meta.hasSize = true
		}
	}
	if lm := strings.TrimSpace(resp.Header.Get("Last-Modified")); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			meta.mdtm = t.UTC()
			meta.hasMDTM = true
		}
	}

	c.metaMu.Lock()
	c.meta = meta
	c.metaMu.Unlock()
	return meta, nil
}

func (c *ftpProxyGETConn) do(ctx context.Context, method string, offset int64) (*http.Response, net.Conn, error) {
	if c.dialer == nil {
		return nil, nil, errors.New("ftp proxy GET: missing dialer")
	}
	proxyAddr := c.proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		switch c.proxyURL.Scheme {
		case "https":
			proxyAddr = netJoinHostPort(proxyAddr, "443")
		default:
			proxyAddr = netJoinHostPort(proxyAddr, "80")
		}
	}
	conn, err := c.dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, nil, err
	}

	if deadline := requestHeaderDeadline(ctx, c.timeout); !deadline.IsZero() {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
	}

	if c.proxyURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: proxyTLSServerName(c.proxyURL.Hostname())})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		conn = tlsConn
	}

	req, err := http.NewRequestWithContext(ctx, method, c.target.String(), nil)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	req.Close = true
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	if auth := proxyAuthorizationHeader(c.proxyURL); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	if err := req.WriteProxy(conn); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Time{})
	}
	return resp, conn, nil
}

type sftpTransferSession interface {
	Close() error
	Stat(context.Context, string) (sftpproto.FileInfo, error)
	OpenFile(context.Context, string, int64) (io.ReadCloser, error)
}

var sftpOpen = func(ctx context.Context, dialer *netx.Dialer, opt sftpproto.Opts) (sftpTransferSession, error) {
	return sftpproto.Open(ctx, dialer, opt)
}

// runFTPDownload performs an FTP download.
func (e *Engine) runFTPDownload(ctx context.Context, rg *requestGroup, uri string, u *url.URL, outPath string) {
	host := u.Host
	if u.Port() == "" {
		host = netJoinHostPort(u.Host, "21")
	}
	defer func() {
		if rg.errCode == core.ExitSuccess {
			e.recordServerStatSuccess(uri, max64(rg.downloadSpeed, downloadAverageSpeed(rg)), max(1, int(rg.numConnections.Load())))
			return
		}
		if rg.errCode != 0 {
			e.markServerStatError(uri)
		}
	}()

	ftpUser, ftpPass := e.ftpAuthConfig(uri, u, rg.opts)

	conn, err := e.newFTPTransferConn(ctx, uri, u, host, ftpUser, ftpPass, rg.opts, rg.opts.FTPPasv)
	if err != nil {
		e.log.Error("FTP dial failed", "gid", rg.gid, "host", host, "error", err)
		rg.errCode = core.ExitFTPProtocolError
		rg.errMsg = err.Error()
		return
	}
	defer conn.Close()

	var lastModified time.Time
	if rg.opts.RemoteTime {
		lastModified, err = conn.Mdtm(ctx, u.Path)
		if err != nil {
			e.log.Info("FTP MDTM failed; continuing without remote time", "gid", rg.gid, "path", u.Path, "error", err)
			lastModified = time.Time{}
		}
	}

	size, err := conn.Size(ctx, u.Path)
	if err != nil {
		if errors.Is(err, ftpproto.ErrSizeUnsupported) {
			e.log.Info("FTP SIZE unsupported; continuing with unknown length", "gid", rg.gid, "path", u.Path)
			size = 0
		} else {
			e.log.Error("FTP SIZE failed", "gid", rg.gid, "path", u.Path, "error", err)
			rg.errCode = core.ExitFTPProtocolError
			rg.errMsg = err.Error()
			return
		}
	}

	rg.statusMu.Lock()
	rg.totalLength = size
	rg.statusMu.Unlock()
	rg.statusMu.Lock()
	rg.lastSpeedSample = time.Now()
	rg.statusMu.Unlock()
	e.initControlInfo(rg, outPath, size, rg.integrity.controlPieceLength(0), nil)
	offset := e.controlResumeOffset(rg, outPath)
	if offset == 0 && rg.opts.Continue {
		if st, statErr := os.Stat(outPath); statErr == nil && !st.IsDir() {
			offset = st.Size()
			if size > 0 && offset >= size {
				if verifyErr := e.verifyExistingFileIntegrity(ctx, rg, outPath, size); verifyErr != nil {
					if e.allowIntegrityRetry(rg) {
						e.resetControlState(rg, outPath)
						if truncErr := os.Truncate(outPath, 0); truncErr != nil {
							rg.errCode = core.ExitFileIOError
							rg.errMsg = truncErr.Error()
							return
						}
						offset = 0
					} else {
						rg.errCode = core.ExitChecksumError
						rg.errMsg = verifyErr.Error()
						return
					}
				}
				if offset >= size {
					rg.statusMu.Lock()
					rg.completedLength = size
					rg.statusMu.Unlock()
					rg.errCode = core.ExitSuccess
					return
				}
			}
		} else if statErr != nil && !os.IsNotExist(statErr) {
			rg.errCode = core.ExitFileIOError
			rg.errMsg = statErr.Error()
			return
		}
	}
	if rg.opts.HashCheckOnly {
		e.failHashCheckOnlyIncomplete(rg, outPath)
		return
	}

	alloc := chooseAllocator(rg.opts, size)

	adaptor, err := openTransferAdaptor(outPath, size, alloc)
	if err != nil {
		e.log.Error("cannot create output file", "gid", rg.gid, "path", outPath, "error", err)
		rg.errCode = core.ExitFileCreateError
		rg.errMsg = err.Error()
		return
	}
	e.setControlAdaptor(rg, adaptor)
	defer adaptor.Close()
	defer e.syncControlAdaptor(rg)
	hostOnly, _ := uriHostProto(uri)
	guard := newSpeedGuard(parseSize(rg.opts.LowestSpeedLimit), time.Duration(parseInt(rg.opts.StartupIdleTime))*time.Second, hostOnly)

	// Single-connection path.
	rg.numConnections.Store(1)

	body, err := conn.Retrieve(ctx, u.Path, offset)
	if err != nil {
		e.log.Error("FTP RETR failed", "gid", rg.gid, "path", u.Path, "error", err)
		rg.errCode = core.ExitFTPProtocolError
		rg.errMsg = err.Error()
		return
	}
	bodyClosed := false
	defer func() {
		if !bodyClosed {
			_ = body.Close()
		}
	}()

	written := e.downloadToAdaptor(ctx, rg, adaptor, body, offset, guard)
	if written < 0 {
		if e.shouldRetryRealtimePieceCheck(rg) {
			_ = adaptor.Close()
			e.saveControlFile(rg)
			e.runFTPDownload(ctx, rg, uri, u, outPath)
		}
		return
	}
	bodyClosed = true
	if err := body.Close(); err != nil {
		e.log.Error("FTP body close failed", "gid", rg.gid, "path", u.Path, "error", err)
		rg.errCode = core.ExitFTPProtocolError
		rg.errMsg = err.Error()
		return
	}

	if err := adaptor.Sync(); err != nil {
		e.log.Error("file sync failed", "gid", rg.gid, "error", err)
		rg.errCode = core.ExitFileIOError
		rg.errMsg = err.Error()
		return
	}

	rg.statusMu.Lock()
	rg.completedLength = offset + written
	rg.statusMu.Unlock()
	if mode, _, verifyErr := e.verifyIntegrity(ctx, rg, adaptor, outPath); verifyErr != nil {
		if mode == "whole" && e.allowIntegrityRetry(rg) {
			_ = adaptor.Close()
			e.resetControlState(rg, outPath)
			if truncErr := os.Truncate(outPath, 0); truncErr != nil {
				rg.errCode = core.ExitFileIOError
				rg.errMsg = truncErr.Error()
				return
			}
			e.runFTPDownload(ctx, rg, uri, u, outPath)
			return
		}
		rg.errCode = core.ExitChecksumError
		rg.errMsg = verifyErr.Error()
		return
	}
	rg.errCode = core.ExitSuccess
	e.applyHTTPRemoteTime(rg, outPath, lastModified)
	e.log.Info("download complete", "gid", rg.gid, "size", rg.completedLength)
}

// runSFTPDownload performs an SFTP download.
func (e *Engine) runSFTPDownload(ctx context.Context, rg *requestGroup, uri string, u *url.URL, outPath string) {
	host := u.Hostname()
	port := 22
	if p := u.Port(); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	defer func() {
		if rg.errCode == core.ExitSuccess {
			e.recordServerStatSuccess(uri, max64(rg.downloadSpeed, downloadAverageSpeed(rg)), max(1, int(rg.numConnections.Load())))
			return
		}
		if rg.errCode != 0 {
			e.markServerStatError(uri)
		}
	}()

	user, pass := e.ftpAuthConfig(uri, u, rg.opts)

	dialer, err := e.dialerForProtocol("sftp", host, rg.opts)
	if err != nil {
		e.log.Error("SFTP proxy setup failed", "gid", rg.gid, "error", err)
		rg.errCode = core.ExitFTPProtocolError
		rg.errMsg = err.Error()
		return
	}
	sess, err := sftpOpen(ctx, dialer, sftpproto.Opts{
		Host: host,
		Port: port,
		User: user,
		Auth: sftpproto.AuthMethods{
			Password:    pass,
			KeyFile:     rg.opts.PrivateKey,
			AgentSocket: os.Getenv("SSH_AUTH_SOCK"),
		},
		HostKeyMD: rg.opts.SSHHostKeyMD,
	})
	if err != nil {
		e.log.Error("SFTP open failed", "gid", rg.gid, "host", host, "error", err)
		if sftpproto.IsHostKeyDigestError(err) {
			rg.errCode = core.ExitUnknownError
		} else {
			rg.errCode = core.ExitFTPProtocolError
		}
		rg.errMsg = err.Error()
		return
	}
	defer sess.Close()

	info, err := sess.Stat(ctx, u.Path)
	if err != nil {
		e.log.Error("SFTP stat failed", "gid", rg.gid, "path", u.Path, "error", err)
		rg.errCode = core.ExitFTPProtocolError
		rg.errMsg = err.Error()
		return
	}

	size := info.Size
	lastModified := info.ModTime
	rg.statusMu.Lock()
	rg.totalLength = size
	rg.statusMu.Unlock()
	rg.statusMu.Lock()
	rg.lastSpeedSample = time.Now()
	rg.statusMu.Unlock()
	e.initControlInfo(rg, outPath, size, rg.integrity.controlPieceLength(0), nil)
	offset := e.controlResumeOffset(rg, outPath)
	if offset == 0 && rg.opts.Continue {
		if st, statErr := os.Stat(outPath); statErr == nil && !st.IsDir() {
			offset = st.Size()
			if size > 0 && offset >= size {
				if verifyErr := e.verifyExistingFileIntegrity(ctx, rg, outPath, size); verifyErr != nil {
					if e.allowIntegrityRetry(rg) {
						e.resetControlState(rg, outPath)
						if truncErr := os.Truncate(outPath, 0); truncErr != nil {
							rg.errCode = core.ExitFileIOError
							rg.errMsg = truncErr.Error()
							return
						}
						offset = 0
					} else {
						rg.errCode = core.ExitChecksumError
						rg.errMsg = verifyErr.Error()
						return
					}
				}
				if offset >= size {
					rg.statusMu.Lock()
					rg.completedLength = size
					rg.statusMu.Unlock()
					rg.errCode = core.ExitSuccess
					return
				}
			}
		} else if statErr != nil && !os.IsNotExist(statErr) {
			rg.errCode = core.ExitFileIOError
			rg.errMsg = statErr.Error()
			return
		}
	}
	if rg.opts.HashCheckOnly {
		e.failHashCheckOnlyIncomplete(rg, outPath)
		return
	}

	alloc := chooseAllocator(rg.opts, size)

	adaptor, err := openTransferAdaptor(outPath, size, alloc)
	if err != nil {
		e.log.Error("cannot create output file", "gid", rg.gid, "path", outPath, "error", err)
		rg.errCode = core.ExitFileCreateError
		rg.errMsg = err.Error()
		return
	}
	e.setControlAdaptor(rg, adaptor)
	defer adaptor.Close()
	defer e.syncControlAdaptor(rg)
	guard := newSpeedGuard(parseSize(rg.opts.LowestSpeedLimit), time.Duration(parseInt(rg.opts.StartupIdleTime))*time.Second, host)

	reader, err := sess.OpenFile(ctx, u.Path, offset)
	if err != nil {
		e.log.Error("SFTP open file failed", "gid", rg.gid, "path", u.Path, "error", err)
		rg.errCode = core.ExitFTPProtocolError
		rg.errMsg = err.Error()
		return
	}
	readerClosed := false
	defer func() {
		if !readerClosed {
			_ = reader.Close()
		}
	}()

	rg.numConnections.Store(1)
	written := e.downloadToAdaptor(ctx, rg, adaptor, reader, offset, guard)
	if written < 0 {
		if e.shouldRetryRealtimePieceCheck(rg) {
			_ = adaptor.Close()
			e.saveControlFile(rg)
			e.runSFTPDownload(ctx, rg, uri, u, outPath)
		}
		return
	}
	readerClosed = true
	if err := reader.Close(); err != nil {
		e.log.Error("SFTP reader close failed", "gid", rg.gid, "path", u.Path, "error", err)
		rg.errCode = core.ExitFTPProtocolError
		rg.errMsg = err.Error()
		return
	}

	if err := adaptor.Sync(); err != nil {
		e.log.Error("file sync failed", "gid", rg.gid, "error", err)
		rg.errCode = core.ExitFileIOError
		rg.errMsg = err.Error()
		return
	}

	rg.statusMu.Lock()
	rg.completedLength = offset + written
	rg.statusMu.Unlock()
	if mode, _, verifyErr := e.verifyIntegrity(ctx, rg, adaptor, outPath); verifyErr != nil {
		if mode == "whole" && e.allowIntegrityRetry(rg) {
			_ = adaptor.Close()
			e.resetControlState(rg, outPath)
			if truncErr := os.Truncate(outPath, 0); truncErr != nil {
				rg.errCode = core.ExitFileIOError
				rg.errMsg = truncErr.Error()
				return
			}
			e.runSFTPDownload(ctx, rg, uri, u, outPath)
			return
		}
		rg.errCode = core.ExitChecksumError
		rg.errMsg = verifyErr.Error()
		return
	}
	rg.errCode = core.ExitSuccess
	e.applyHTTPRemoteTime(rg, outPath, lastModified)
	e.log.Info("download complete", "gid", rg.gid, "size", rg.completedLength)
}

// runMetalinkDownload parses metalink data and downloads files by iterating
// over file entries and trying each URL in priority order.
func (e *Engine) runMetalinkDownload(ctx context.Context, rg *requestGroup, metalinkData []byte) {
	e.log.Info("starting metalink download", "gid", rg.gid)

	entries, err := metalinkDownloadEntries(metalinkData, rg.opts)
	if err != nil {
		e.log.Error("cannot parse metalink", "gid", rg.gid, "error", err)
		rg.errCode = core.ExitResourceNotFound
		rg.errMsg = fmt.Sprintf("invalid metalink: %v", err)
		return
	}
	if len(entries) == 0 && len(rg.uris) > 0 {
		for _, uri := range rg.uris {
			entries = append(entries, metalinkDownloadEntry{URI: uri})
		}
	}
	if len(entries) == 0 {
		e.log.Error("metalink download has no fallback URIs", "gid", rg.gid)
		rg.errCode = core.ExitResourceNotFound
		rg.errMsg = "no URIs in metalink"
		return
	}

	entries = metalinkPrimaryEntries(entries)
	entry := entries[0]
	rg.integrity = applyMetalinkIntegrity(rg.integrity, entry)
	if rg.filePath == "" && entry.Name != "" {
		rg.filePath = filepath.Join(rg.opts.Dir, entry.Name)
		rg.fileName = filepath.Base(entry.Name)
	}
	if entry.SizeKnown {
		rg.statusMu.Lock()
		rg.totalLength = entry.Size
		rg.statusMu.Unlock()
	}

	var (
		lastErrCode core.ErrorCode
		lastErrMsg  string
	)
	for i, entry := range entries {
		if entry.SizeKnown {
			rg.statusMu.Lock()
			rg.totalLength = entry.Size
			rg.statusMu.Unlock()
		}
		rg.errCode = 0
		rg.errMsg = ""
		if i > 0 {
			e.log.Warn("metalink mirror failed; trying next", "gid", rg.gid, "uri", entry.URI, "attempt", i+1, "mirrors", len(entries))
		}
		e.runMetalinkEntry(ctx, rg, entry)
		if rg.errCode == core.ExitSuccess {
			if code, msg := verifyMetalinkDownload(ctx, rg.filePath, entry); code != core.ExitSuccess {
				rg.errCode = code
				rg.errMsg = msg
			}
			return
		}
		lastErrCode, lastErrMsg = rg.errCode, rg.errMsg
		if rg.errCode == core.ExitRemoved || ctx.Err() != nil {
			return
		}
	}
	if lastErrCode != 0 {
		rg.errCode = lastErrCode
		rg.errMsg = lastErrMsg
		return
	}

	e.log.Error("metalink download exhausted all mirrors", "gid", rg.gid)
	rg.errCode = core.ExitResourceNotFound
	rg.errMsg = "no usable URIs in metalink"
}

func (e *Engine) runMetalinkEntry(ctx context.Context, rg *requestGroup, entry metalinkDownloadEntry) {
	uri := entry.URI
	u, errParse := url.Parse(uri)
	if errParse != nil {
		e.log.Error("cannot parse URI", "gid", rg.gid, "uri", uri, "error", errParse)
		rg.errCode = core.ExitResourceNotFound
		rg.errMsg = fmt.Sprintf("invalid URI: %s", uri)
		return
	}

	proto := strings.ToLower(u.Scheme)
	switch proto {
	case "http", "https":
		e.runHTTPDownload(ctx, rg, uri, rg.filePath)
	case "ftp":
		e.runFTPDownload(ctx, rg, uri, u, rg.filePath)
	case "sftp":
		e.runSFTPDownload(ctx, rg, uri, u, rg.filePath)
	default:
		e.log.Error("unsupported protocol in metalink", "gid", rg.gid, "protocol", proto)
		rg.errCode = core.ExitResourceNotFound
		rg.errMsg = fmt.Sprintf("unsupported protocol: %s", proto)
	}
}

type metalinkDownloadEntry struct {
	URI           string
	Name          string
	Size          int64
	SizeKnown     bool
	Hashes        map[hash.Kind][]byte
	Pieces        [][]byte
	PieceHashKind hash.Kind
	PieceLength   int64
	Version       string
	Languages     []string
	OSes          []string
}

func metalinkDownloadEntries(data []byte, opts *config.Options) ([]metalinkDownloadEntry, error) {
	parseOpts, queryOpts := metalinkOptions(opts)
	doc, err := metalink.ParseWithOptions(bytes.NewReader(data), parseOpts)
	if err != nil {
		return nil, err
	}
	doc = metalink.Query(doc, queryOpts)
	var entries []metalinkDownloadEntry
	for _, f := range doc.Files {
		urls := metalink.OrderURLs(f.URLs, queryOpts)
		for _, u := range urls {
			if u.URL == "" {
				continue
			}
			entries = append(entries, metalinkDownloadEntry{
				URI:           u.URL,
				Name:          f.Name,
				Size:          f.Size,
				SizeKnown:     f.SizeKnown,
				Hashes:        cloneMetalinkHashes(f.Hashes),
				Pieces:        cloneByteSlices(f.Pieces),
				PieceHashKind: f.PieceHashKind,
				PieceLength:   f.PieceLength,
				Version:       f.Version,
				Languages:     append([]string(nil), f.Languages...),
				OSes:          append([]string(nil), f.OSes...),
			})
		}
	}
	return entries, nil
}

func metalinkOptions(opts *config.Options) (metalink.ParseOptions, metalink.QueryOptions) {
	parseOpts := metalink.ParseOptions{}
	queryOpts := metalink.QueryOptions{}
	if opts == nil {
		return parseOpts, queryOpts
	}
	parseOpts.BaseURI = opts.MetalinkBaseURI
	queryOpts.Version = opts.MetalinkVersion
	queryOpts.Language = opts.MetalinkLanguage
	queryOpts.OS = opts.MetalinkOS
	queryOpts.PreferredProtocol = opts.MetalinkPreferredProtocol
	if opts.MetalinkLocation != "" {
		for _, location := range strings.Split(opts.MetalinkLocation, ",") {
			location = strings.TrimSpace(location)
			if location == "" {
				continue
			}
			queryOpts.Locations = append(queryOpts.Locations, location)
		}
	}
	return parseOpts, queryOpts
}

func metalinkPrimaryEntries(entries []metalinkDownloadEntry) []metalinkDownloadEntry {
	if len(entries) < 2 {
		return entries
	}
	primary := entries[0]
	limit := 1
	for limit < len(entries) && sameMetalinkEntryFile(primary, entries[limit]) {
		limit++
	}
	return entries[:limit]
}

func sameMetalinkEntryFile(a, b metalinkDownloadEntry) bool {
	if a.Name != b.Name || a.SizeKnown != b.SizeKnown {
		return false
	}
	if a.SizeKnown && a.Size != b.Size {
		return false
	}
	return true
}

func cloneMetalinkHashes(src map[hash.Kind][]byte) map[hash.Kind][]byte {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[hash.Kind][]byte, len(src))
	for k, v := range src {
		dst[k] = append([]byte(nil), v...)
	}
	return dst
}

func cloneByteSlices(src [][]byte) [][]byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([][]byte, len(src))
	for i := range src {
		dst[i] = append([]byte(nil), src[i]...)
	}
	return dst
}

func ftpCredentials(u *url.URL, opts, global *config.Options) (string, string) {
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" && opts != nil {
		user = opts.FTPUser
	}
	if user == "" && global != nil {
		user = global.FTPUser
	}
	if pass == "" && opts != nil {
		pass = opts.FTPPasswd
	}
	if pass == "" && global != nil {
		pass = global.FTPPasswd
	}
	return user, pass
}

func (e *Engine) ftpAuthConfig(rawURI string, u *url.URL, opts *config.Options) (string, string) {
	if e.authFactory != nil {
		if ac := e.authFactory.CreateAuthConfig(rawURI, opts); ac != nil {
			return ac.User(), ac.Password()
		}
	}
	return ftpCredentials(u, opts, e.cfg)
}

func verifyMetalinkDownload(ctx context.Context, path string, entry metalinkDownloadEntry) (core.ErrorCode, string) {
	if len(entry.Pieces) > 0 && entry.PieceHashKind != "" && entry.PieceLength > 0 {
		if err := verifyMetalinkPieceHashes(ctx, path, entry.PieceHashKind, entry.PieceLength, entry.Pieces); err != nil {
			return metalinkVerificationError(err)
		}
	}
	if kind, digest, ok := metalink.StrongestHash(entry.Hashes); ok {
		if err := verifyMetalinkFileHash(ctx, path, kind, digest); err != nil {
			return metalinkVerificationError(err)
		}
	}
	return core.ExitSuccess, ""
}

func metalinkVerificationError(err error) (core.ErrorCode, string) {
	if err == nil {
		return core.ExitSuccess, ""
	}
	if errors.Is(err, context.Canceled) {
		return core.ExitRemoved, "download cancelled"
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return core.ExitFileIOError, err.Error()
	}
	return core.ExitChecksumError, err.Error()
}

func verifyMetalinkFileHash(ctx context.Context, path string, kind hash.Kind, want []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s for hash verification: %w", path, err)
	}
	defer f.Close()

	h, err := hash.New(kind)
	if err != nil {
		return err
	}
	defer hash.PoolPut(kind, h)

	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, readErr := f.Read(buf)
		if n > 0 {
			if _, err := h.Write(buf[:n]); err != nil {
				return err
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return fmt.Errorf("read %s for hash verification: %w", path, readErr)
		}
	}

	if got := h.Sum(nil); !bytes.Equal(got, want) {
		return fmt.Errorf("metalink file hash mismatch for %s (%s)", path, kind)
	}
	return nil
}

func verifyMetalinkPieceHashes(ctx context.Context, path string, kind hash.Kind, pieceLength int64, pieces [][]byte) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s for piece verification: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s for piece verification: %w", path, err)
	}
	size := info.Size()
	if pieceLength <= 0 {
		return fmt.Errorf("invalid metalink piece length %d", pieceLength)
	}
	if int64(len(pieces))*pieceLength < size {
		return fmt.Errorf("metalink piece hash set shorter than file %s", path)
	}

	h, err := hash.New(kind)
	if err != nil {
		return err
	}
	defer hash.PoolPut(kind, h)

	buf := make([]byte, 64*1024)
	for i, want := range pieces {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		start := int64(i) * pieceLength
		if start >= size {
			return fmt.Errorf("metalink piece hash set longer than file %s", path)
		}
		length := pieceLength
		if remaining := size - start; remaining < length {
			length = remaining
		}
		h.Reset()
		n, err := io.CopyBuffer(h, io.LimitReader(f, length), buf)
		if err != nil {
			return fmt.Errorf("read piece %d for %s: %w", i, path, err)
		}
		if n != length {
			return fmt.Errorf("short read verifying piece %d for %s", i, path)
		}
		if got := h.Sum(nil); !bytes.Equal(got, want) {
			return fmt.Errorf("metalink piece hash mismatch for %s piece %d (%s)", path, i, kind)
		}
	}

	return nil
}

func (e *Engine) dialerForProtocol(proto, targetHost string, opts *config.Options) (*netx.Dialer, error) {
	if opts == nil {
		opts = e.cfg
	}
	proxyURI := resolveProxyURIForTarget(proto, targetHost, opts)
	if proxyURI == "" && opts == e.cfg {
		return e.netDialer, nil
	}
	cfg := engineDialerConfig(opts)
	if proxyURI != "" {
		cfg.ProxyURL = proxyURI
		cfg.NoProxy = ""
	}
	return netx.NewDialer(cfg)
}

func (e *Engine) dialerWithoutProxy(opts *config.Options) (*netx.Dialer, error) {
	if opts == nil || opts == e.cfg {
		return e.netDialer, nil
	}
	return netx.NewDialer(engineDialerConfigWithoutProxy(opts))
}

func (e *Engine) newFTPTransferConn(ctx context.Context, rawURI string, u *url.URL, host, user, pass string, opts *config.Options, pasv bool) (ftpTransferConn, error) {
	if opts == nil {
		opts = e.cfg
	}
	if proxyURI := resolveProxyURIForTarget("ftp", u.Hostname(), opts); proxyURI != "" && resolveHTTPProxyMethod("ftp", opts) == "get" {
		proxyURL, err := url.Parse(proxyURI)
		if err != nil {
			return nil, err
		}
		dialer, err := e.dialerWithoutProxy(opts)
		if err != nil {
			return nil, err
		}
		return &ftpProxyGETConn{
			dialer:   dialer,
			proxyURL: proxyURL,
			target:   ftpProxyTargetURL(u, rawURI, user, pass),
			timeout:  time.Duration(parseInt(opts.ConnectTimeout)) * time.Second,
		}, nil
	}

	dialer, err := e.dialerForProtocol("ftp", host, opts)
	if err != nil {
		return nil, err
	}
	return ftpDial(ctx, dialer, host, ftpproto.Opt{
		User:            user,
		Pass:            pass,
		Type:            opts.FTPType,
		Passive:         pasv,
		ReuseConnection: opts.FTPReuseConnection,
	})
}

// downloadFTPSegment performs a ranged FTP download segment. It opens a new
// FTP connection, retrieves the given byte range, and writes to the adaptor.
func (e *Engine) downloadFTPSegment(ctx context.Context, host, path, user, pass string, pasv bool, rg *requestGroup, adaptor disk.Adaptor, seg *Segment) (int64, error) {
	targetURL := &url.URL{Scheme: "ftp", Host: host, Path: path}
	conn, err := e.newFTPTransferConn(ctx, targetURL.String(), targetURL, host, user, pass, rg.opts, pasv)
	if err != nil {
		return -1, err
	}
	defer conn.Close()

	body, err := conn.Retrieve(ctx, path, seg.Start)
	if err != nil {
		return -1, err
	}
	bodyToClose := body
	bodyClosed := false
	defer func() {
		if !bodyClosed {
			_ = bodyToClose.Close()
		}
	}()

	if seg.End != -1 {
		body = io.NopCloser(io.LimitReader(body, seg.End-seg.Start))
	}

	hostOnly, _ := uriHostProto("ftp://" + host)
	guard := newSpeedGuard(parseSize(rg.opts.LowestSpeedLimit), time.Duration(parseInt(rg.opts.StartupIdleTime))*time.Second, hostOnly)
	written := e.downloadToAdaptor(ctx, rg, adaptor, body, seg.Start, guard)
	if written < 0 {
		return -1, fmt.Errorf("%s: %s", rg.errCode, rg.errMsg)
	}
	if !bodyClosed {
		bodyClosed = true
		if err := bodyToClose.Close(); err != nil {
			return -1, err
		}
	}
	return written, nil
}

// boolPtr returns a pointer to b.
func boolPtr(b bool) *bool { return &b }

// parseInt parses a string to int, returning 0 on error.
func parseInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// parseDHTPort parses the DHT listen port string to an int, defaulting to 6881.
func parseDHTPort(s string) int {
	if s == "" {
		return 6881
	}
	parts := strings.SplitN(s, "-", 2)
	n, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
	if n <= 0 {
		return 6881
	}
	return n
}

// parseListenPort parses the listen port range string to the first port.
func parseListenPort(s string) int {
	if s == "" {
		return 6881
	}
	parts := strings.SplitN(s, "-", 2)
	n, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
	if n <= 0 {
		return 6881
	}
	return n
}

// runHookExec fires a hook command with the standard aria2 arguments:
// command, GID (hex), numFiles (decimal), firstFilename. aria2 passes the
// first requested file-entry path directly, which can legitimately be empty
// before a path is fully resolved for an active transfer.
func (e *Engine) runHookExec(rg *requestGroup, numFiles int, command string) {
	if command == "" {
		return
	}
	e.log.Debug("executing hook", "command", command, "gid", rg.gid)
	if err := hookrunner.Run(e.ctx, command, rg.gid.Hex(), strconv.Itoa(numFiles), rg.hookFirstFilename()); err != nil {
		e.log.Error("hook execution failed", "command", command, "error", err)
	}
}

// runHookByName looks up the hook command from engine config by option name
// and fires it. numFiles defaults to 1; BT downloads should pass the actual count.
func (e *Engine) runHookByName(rg *requestGroup, numFiles int, hookName string) {
	var command string
	switch hookName {
	case "on-download-start":
		command = e.cfg.OnDownloadStart
	case "on-download-pause":
		command = e.cfg.OnDownloadPause
	case "on-download-stop":
		command = e.cfg.OnDownloadStop
	case "on-download-complete":
		command = e.cfg.OnDownloadComplete
	case "on-download-error":
		command = e.cfg.OnDownloadError
	case "on-bt-download-complete":
		command = e.cfg.OnBTDownloadComplete
	}
	e.runHookExec(rg, numFiles, command)
}

// runStopHook fires the appropriate stop-completion hook for a download that
// transitioned to the stopped/results queue. Priority matches aria2's
// executeStopHook: if result is FINISHED and on-download-complete is set,
// use complete; else if error (not IN_PROGRESS/REMOVED) and on-download-error
// is set, use error; otherwise fall back to on-download-stop.
func (e *Engine) runStopHook(rg *requestGroup, errCode core.ErrorCode) {
	hookName := ""
	if e.cfg.OnDownloadStop != "" {
		hookName = "on-download-stop"
	}
	if errCode == core.ExitSuccess && e.cfg.OnDownloadComplete != "" {
		hookName = "on-download-complete"
	} else if errCode != core.ExitSuccess &&
		errCode != core.ExitInProgress &&
		errCode != core.ExitRemoved &&
		e.cfg.OnDownloadError != "" {
		hookName = "on-download-error"
	}
	e.runHookByName(rg, 1, hookName)
}

// protocolErrorCode maps protocol-level errors to aria2 error codes.
func protocolErrorCode(err error) core.ErrorCode {
	if err == nil {
		return core.ExitUnknownError
	}
	if errors.Is(err, context.Canceled) {
		return core.ExitRemoved
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return core.ExitTimeout
	}
	return core.CodeFrom(err)
}

func protocolErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	var coreErr *core.Error
	if errors.As(err, &coreErr) {
		if coreErr.Cause != nil {
			return coreErr.Message + ": " + coreErr.Cause.Error()
		}
		return coreErr.Message
	}
	return err.Error()
}

// netJoinHostPort is a local copy of net.JoinHostPort to avoid import cycle.
func netJoinHostPort(host, port string) string {
	if strings.IndexByte(host, ':') >= 0 {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

func defaultOutputPathFromURI(rawURI string) string {
	u, err := url.Parse(rawURI)
	if err == nil && u.Path != "" {
		base := filepath.Base(u.Path)
		if base != "" && base != "." && base != "/" {
			return base
		}
	}
	base := filepath.Base(rawURI)
	if base == "" || base == "." || base == "/" {
		return "index.html"
	}
	return base
}

// getFirstFilePath returns the first file path for this download.
// For in-memory downloads, returns "[MEMORY]<basename>" (matching aria2's
// RequestGroup::getFirstFilePath which prepends "[MEMORY]" with basename).
// For regular downloads, returns the full file path.
func (rg *requestGroup) getFirstFilePath() string {
	if rg.inMemory {
		return "[MEMORY]" + filepath.Base(rg.filePath)
	}
	return rg.filePath
}

func (rg *requestGroup) hookFirstFilename() string {
	if rg == nil || rg.inMemory {
		return ""
	}
	if rg.filePath == "" || !filepath.IsAbs(rg.filePath) {
		return ""
	}
	return rg.filePath
}

func resultFilePath(rg *requestGroup) string {
	if rg == nil {
		return ""
	}
	path := rg.getFirstFilePath()
	if path != "" {
		return path
	}
	if len(rg.uris) > 0 {
		return rg.uris[0]
	}
	return ""
}

// tryAutoFileRenaming generates the auto-renamed path for a file that would
// conflict with an existing file. Mirrors aria2's RequestGroup::tryAutoFileRenaming:
// it extracts the extension from the path (respecting dotfile and path boundary
// rules), then appends a ".1" suffix before the extension.
//
// The extension extraction logic:
//   - foo.txt      → name=foo,      ext=.txt  → foo.1.txt
//   - .dotfile     → name=.dotfile,  ext=      → .dotfile.1
//   - dir/.hidden  → name=dir/.hidden, ext=    → dir/.hidden.1
//   - foo.tar.gz   → name=foo.tar,  ext=.gz   → foo.tar.1.gz
//
// In aria2, the actual suffix number (1..9999) is incremented until a non-conflicting
// path is found. This function always returns suffix 1; callers must loop to find
// a non-conflicting path in their filesystem context.
func tryAutoFileRenaming(fileName string) string {
	if fileName == "" {
		return fileName
	}
	fn := fileName
	ext := ""
	idx := strings.LastIndexByte(fn, '.')
	slash := strings.LastIndexByte(fn, '/')
	if bsl := strings.LastIndexByte(fn, '\\'); bsl > slash {
		slash = bsl
	}

	if idx != -1 &&
		idx != 0 &&
		(slash == -1 || slash < idx-1) {
		ext = fn[idx:]
		fn = fn[:idx]
	}
	var b strings.Builder
	b.Grow(len(fn) + len(ext) + 4)
	b.WriteString(fn)
	b.WriteString(".1")
	b.WriteString(ext)
	return b.String()
}

// tryAutoFileRenamingWithSuffix generates the auto-renamed path for a file with a specific suffix counter.
func tryAutoFileRenamingWithSuffix(fileName string, suffix int) string {
	if fileName == "" {
		return fileName
	}
	fn := fileName
	ext := ""
	idx := strings.LastIndexByte(fn, '.')
	slash := strings.LastIndexByte(fn, '/')
	if bsl := strings.LastIndexByte(fn, '\\'); bsl > slash {
		slash = bsl
	}

	if idx != -1 &&
		idx != 0 &&
		(slash == -1 || slash < idx-1) {
		ext = fn[idx:]
		fn = fn[:idx]
	}
	var b strings.Builder
	b.Grow(len(fn) + len(ext) + 12)
	b.WriteString(fn)
	b.WriteString(fmt.Sprintf(".%d", suffix))
	b.WriteString(ext)
	return b.String()
}

// isSameFileBeingDownloadedLocked checks whether any active or waiting download
// is already targeting the given path. Caller must hold e.queuesMu lock.
func (e *Engine) isSameFileBeingDownloadedLocked(path string, excludeGID core.GID) bool {
	path = normalizedFileIdentity(path)
	for _, gid := range e.active {
		if gid == excludeGID {
			continue
		}
		rg, ok := e.groups.get(gid)
		if !ok {
			continue
		}
		if rg.filePath != "" && normalizedFileIdentity(rg.filePath) == path {
			return true
		}
	}
	for _, gid := range e.waiting {
		if gid == excludeGID {
			continue
		}
		rg, ok := e.groups.get(gid)
		if !ok {
			continue
		}
		if rg.filePath != "" && normalizedFileIdentity(rg.filePath) == path {
			return true
		}
	}
	return false
}

func normalizedFileIdentity(path string) string {
	if path == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(path))
}

// isSameFileBeingDownloaded checks whether any active or waiting download
// is already targeting the given path. Mirrors aria2's RequestGroupMan::
// isSameFileBeingDownloaded which collects all FileEntry paths from all
// request groups (excluding the one being checked) and checks for overlap.
func (e *Engine) isSameFileBeingDownloaded(path string, excludeGID core.GID) bool {
	e.queuesMu.Lock()
	defer e.queuesMu.Unlock()
	return e.isSameFileBeingDownloadedLocked(path, excludeGID)
}

// makeProxyURI parses and reconstructs a proxy URI, merging in optional
// username and password. If the proxy URI is empty or fails to parse,
// returns an empty string. Mirrors aria2's makeProxyUri in AbstractCommand.cc.
func makeProxyURI(proxyURI, user, passwd string) string {
	if proxyURI == "" {
		return ""
	}
	schemeEnd := strings.Index(proxyURI, "://")
	if schemeEnd < 0 || schemeEnd == 0 {
		return ""
	}
	hostStart := schemeEnd + 3
	if hostStart >= len(proxyURI) {
		return ""
	}
	if user == "" {
		return proxyURI
	}
	var b strings.Builder
	b.Grow(len(proxyURI) + len(user) + len(passwd) + 2)
	b.WriteString(proxyURI[:hostStart])
	b.WriteString(user)
	if passwd != "" {
		b.WriteByte(':')
		b.WriteString(passwd)
	}
	b.WriteByte('@')
	b.WriteString(proxyURI[hostStart:])
	return b.String()
}

// resolveProxyURI returns the proxy URI for the given protocol and options.
// It first checks the protocol-specific proxy option (e.g. http-proxy for "http").
// If that is empty or unparseable, falls back to the all-proxy option.
// Returns an empty string if no proxy is configured.
//
// Mirrors aria2's getProxyUri + getProxyOptionFor in AbstractCommand.cc,
// which dispatches on protocol ("http", "https", "ftp"/"sftp") and falls back
// to PREF_ALL_PROXY / PREF_ALL_PROXY_USER / PREF_ALL_PROXY_PASSWD.
func resolveProxyURI(proto string, opts *config.Options) string {
	switch proto {
	case "http":
		if uri := makeProxyURI(opts.HTTPProxy, opts.HTTPProxyUser, opts.HTTPProxyPasswd); uri != "" {
			return uri
		}
		return makeProxyURI(opts.AllProxy, opts.AllProxyUser, opts.AllProxyPasswd)
	case "https":
		if uri := makeProxyURI(opts.HTTPSProxy, opts.HTTPSProxyUser, opts.HTTPSProxyPasswd); uri != "" {
			return uri
		}
		return makeProxyURI(opts.AllProxy, opts.AllProxyUser, opts.AllProxyPasswd)
	case "ftp", "sftp":
		if uri := makeProxyURI(opts.FTPProxy, opts.FTPProxyUser, opts.FTPProxyPasswd); uri != "" {
			return uri
		}
		return makeProxyURI(opts.AllProxy, opts.AllProxyUser, opts.AllProxyPasswd)
	default:
		return ""
	}
}

func resolveProxyURIForTarget(proto, targetHost string, opts *config.Options) string {
	if proxyBypassed(targetHost, opts) {
		return ""
	}
	return resolveProxyURI(proto, opts)
}

func proxyBypassed(targetHost string, opts *config.Options) bool {
	if opts == nil || opts.NoProxy == "" || targetHost == "" {
		return false
	}
	host := normalizeProxyHost(targetHost)
	if host == "" {
		return false
	}
	for _, raw := range strings.Split(opts.NoProxy, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if noProxyEntryMatchesHost(host, entry) {
			return true
		}
	}
	return false
}

func noProxyEntryMatchesHost(host, entry string) bool {
	host = normalizeProxyHost(host)
	entry = normalizeProxyHost(entry)
	if host == "" || entry == "" {
		return false
	}
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return false
		}
		addr, err := netip.ParseAddr(host)
		return err == nil && prefix.Contains(addr)
	}
	if strings.HasPrefix(entry, ".") && !isNumericHost(host) {
		return strings.HasSuffix(host, entry)
	}
	return host == entry
}

func normalizeProxyHost(host string) string {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func isNumericHost(host string) bool {
	_, err := netip.ParseAddr(normalizeProxyHost(host))
	return err == nil
}

func resolveHTTPProxyMethod(proto string, opts *config.Options) string {
	if opts != nil && opts.ProxyMethod == "tunnel" {
		return "tunnel"
	}
	if proto == "https" || proto == "sftp" {
		return "tunnel"
	}
	return "get"
}

func ftpProxyTargetURL(u *url.URL, rawURI, user, pass string) *url.URL {
	target := *u
	if rawURI != "" {
		if parsed, err := url.Parse(rawURI); err == nil {
			target = *parsed
		}
	}
	if user != "" || pass != "" {
		target.User = url.UserPassword(user, pass)
	}
	return &target
}

func proxyAuthorizationHeader(proxyURL *url.URL) string {
	if proxyURL == nil || proxyURL.User == nil {
		return ""
	}
	user := proxyURL.User.Username()
	pass, _ := proxyURL.User.Password()
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func proxyTLSServerName(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ""
	}
	return host
}

func requestHeaderDeadline(ctx context.Context, timeout time.Duration) time.Time {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && (deadline.IsZero() || ctxDeadline.Before(deadline)) {
		deadline = ctxDeadline
	}
	return deadline
}

// GlobalStat holds aggregate engine statistics matching aria2's getGlobalStat
// RPC response (downloadSpeed, uploadSpeed, numActive, numWaiting, numStopped,
// numStoppedTotal).
type GlobalStat struct {
	DownloadSpeed   int64
	UploadSpeed     int64
	NumActive       int
	NumWaiting      int
	NumStopped      int
	NumStoppedTotal int64
}

// GetGlobalStat returns aggregate statistics about the engine's current state,
// matching aria2's GetGlobalStatRpcMethod which calls RequestGroupMan::calculateStat
// plus getReservedGroups().size(), getDownloadResults().size(), and getNumStoppedTotal().
func (e *Engine) GetGlobalStat() GlobalStat {
	e.queuesMu.Lock()
	activeCopy := make([]core.GID, len(e.active))
	copy(activeCopy, e.active)
	waitingCopy := make([]core.GID, len(e.waiting))
	copy(waitingCopy, e.waiting)
	e.queuesMu.Unlock()

	return GlobalStat{
		DownloadSpeed:   e.downloadSpeed.Load(),
		UploadSpeed:     e.uploadSpeed.Load(),
		NumActive:       len(activeCopy),
		NumWaiting:      len(waitingCopy),
		NumStopped:      e.stoppedRing.len(),
		NumStoppedTotal: e.stoppedTotal.Load(),
	}
}

// statusToRPC converts a Status snapshot to the aria2 JSON-RPC map format,
// optionally filtering to only the requested keys. If keys is nil or empty
// all fields are included. Mirrors the C++ gatherProgressCommon +
// gatherStoppedDownload in RpcMethodImpl.cc.
func (e *Engine) statusToRPC(s *Status, keys []string) map[string]any {
	m := map[string]any{
		"gid":             s.GID.Hex(),
		"status":          s.Status.String(),
		"totalLength":     fmt.Sprintf("%d", s.TotalLength),
		"completedLength": fmt.Sprintf("%d", s.CompletedLength),
		"uploadLength":    fmt.Sprintf("%d", s.UploadLength),
		"downloadSpeed":   fmt.Sprintf("%d", s.DownloadSpeed),
		"uploadSpeed":     fmt.Sprintf("%d", s.UploadSpeed),
		"connections":     fmt.Sprintf("%d", s.Connections),
		"dir":             s.Dir,
		"pieceLength":     fmt.Sprintf("%d", s.PieceLength),
		"numPieces":       fmt.Sprintf("%d", s.NumPieces),
	}
	if s.VerifiedLength > 0 {
		m["verifiedLength"] = fmt.Sprintf("%d", s.VerifiedLength)
	}
	if s.VerifyIntegrityPending {
		m["verifyIntegrityPending"] = "true"
	}

	switch s.Status {
	case core.StatusComplete, core.StatusError, core.StatusRemoved:
		m["errorCode"] = fmt.Sprintf("%d", s.ErrorCode)
		m["errorMessage"] = s.ErrorMessage
	}
	if s.InfoHash != "" {
		m["infoHash"] = s.InfoHash
	}
	if s.NumSeeders > 0 || s.InfoHash != "" {
		m["numSeeders"] = fmt.Sprintf("%d", s.NumSeeders)
		if s.InfoHash != "" && s.TotalLength > 0 && s.CompletedLength >= s.TotalLength {
			m["seeder"] = "true"
		} else {
			m["seeder"] = "false"
		}
	}
	if s.Bitfield != "" {
		m["bitfield"] = s.Bitfield
	}
	if len(s.FollowedBy) > 0 {
		followed := make([]string, len(s.FollowedBy))
		for i, g := range s.FollowedBy {
			followed[i] = g.Hex()
		}
		m["followedBy"] = followed
	}
	if s.Following != 0 {
		m["following"] = s.Following.Hex()
	}
	if s.BelongsTo != 0 {
		m["belongsTo"] = s.BelongsTo.Hex()
	}
	if s.Bittorrent != nil {
		m["bittorrent"] = s.Bittorrent
	}
	if s.VerifyIntegrityPending {
		m["verifyIntegrityPending"] = "true"
	}

	files := make([]map[string]any, len(s.Files))
	for i, f := range s.Files {
		fm := map[string]any{
			"index":           fmt.Sprintf("%d", f.Index),
			"path":            f.Path,
			"length":          fmt.Sprintf("%d", f.Length),
			"completedLength": fmt.Sprintf("%d", f.CompletedLength),
			"selected":        boolStrVal(f.Selected),
		}
		uris := make([]map[string]any, len(f.URIs))
		for j, u := range f.URIs {
			uris[j] = map[string]any{
				"uri":    u.URI,
				"status": u.Status,
			}
		}
		fm["uris"] = uris
		files[i] = fm
	}
	m["files"] = files

	if len(keys) > 0 {
		filtered := make(map[string]any, len(keys))
		for _, k := range keys {
			if v, ok := m[k]; ok {
				filtered[k] = v
			}
		}
		return filtered
	}

	return m
}

func boolStrVal(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// TellStatusKeys returns the current status of a single download as an aria2
// RPC-compatible map. If keys is non-empty, only the requested keys are included
// (matching aria2's tellStatus keys parameter behavior).
func (e *Engine) TellStatusKeys(gid core.GID, keys []string) (map[string]any, error) {
	rg, ok := e.groups.getLocked(gid)
	if ok {
		status := e.makeStatus(rg)
		e.groups.unlock(gid)
		return e.statusToRPC(status, keys), nil
	}

	dr, found := e.stoppedRing.getByGID(gid)
	if !found {
		return nil, fmt.Errorf("engine: download GID#%s not found", gid)
	}
	s := cloneStatusSnapshot(dr.statusSnapshot)
	return e.statusToRPC(&s, keys), nil
}

// TellActiveKeys returns status maps of all active downloads, filtered to the
// requested keys.
func (e *Engine) TellActiveKeys(keys []string) []map[string]any {
	e.queuesMu.Lock()
	activeCopy := make([]core.GID, len(e.active))
	copy(activeCopy, e.active)
	e.queuesMu.Unlock()

	result := make([]map[string]any, 0, len(activeCopy))
	for _, gid := range activeCopy {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}
		result = append(result, e.statusToRPC(e.makeStatus(rg), keys))
		e.groups.unlock(gid)
	}
	return result
}

// TellWaitingKeys returns status maps of waiting/paused downloads, starting at
// offset, up to num entries, filtered to the requested keys.
func (e *Engine) TellWaitingKeys(offset, num int, keys []string) []map[string]any {
	e.queuesMu.Lock()
	waitingCopy := make([]core.GID, len(e.waiting))
	copy(waitingCopy, e.waiting)
	e.queuesMu.Unlock()

	if offset >= len(waitingCopy) {
		return nil
	}
	end := offset + num
	if end > len(waitingCopy) {
		end = len(waitingCopy)
	}

	result := make([]map[string]any, 0, end-offset)
	for _, gid := range waitingCopy[offset:end] {
		rg, ok := e.groups.getLocked(gid)
		if !ok {
			continue
		}
		result = append(result, e.statusToRPC(e.makeStatus(rg), keys))
		e.groups.unlock(gid)
	}
	return result
}

// TellStoppedKeys returns status maps of completed/error/removed downloads,
// starting at offset, up to num entries, filtered to the requested keys.
func (e *Engine) TellStoppedKeys(offset, num int, keys []string) []map[string]any {
	statuses := e.stoppedRing.snapshotStatuses(offset, num)
	result := make([]map[string]any, len(statuses))
	for i := range statuses {
		result[i] = e.statusToRPC(&statuses[i], keys)
	}
	return result
}
