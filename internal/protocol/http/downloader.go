// Package http provides an HTTP download driver that wraps a single
// http.Client configured with caller-supplied dialer, TLS, cookie jar,
// headers, and timeout.
package http

import (
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/smartass08/aria2go/internal/core"
	"github.com/smartass08/aria2go/internal/hash"
	"github.com/smartass08/aria2go/internal/ioutilx"
	"github.com/smartass08/aria2go/internal/netx"
)

// defaultUserAgent is used when Opts.UserAgent is empty.
const defaultUserAgent = "aria2go/1.37.0"

// ErrRangeIgnored reports that a server responded with a full 200 OK body to
// a resumed range request. Callers should discard partial local data and retry
// from offset 0.
var ErrRangeIgnored = errors.New("http: server ignored requested range")

// ErrNotModified reports that the server returned 304 Not Modified to a
// conditional request. Callers should keep the existing local file.
var ErrNotModified = errors.New("http: resource not modified")

// metalinkContentTypes are appended to Accept when AcceptMetalink is enabled.
var metalinkContentTypes = []string{
	"application/metalink4+xml",
	"application/metalink+xml",
}

type headerKV struct {
	key, value string
}

// RequestOptions configures headers for a single HTTP request sequence.
type RequestOptions struct {
	// IfModifiedSince sets If-Modified-Since for this request sequence.
	IfModifiedSince string
}

// ResponseDigest is a parsed Digest response-header entry.
type ResponseDigest struct {
	Kind   hash.Kind
	Digest []byte
}

// ResourceInfo describes HTTP metadata discovered during probing.
type ResourceInfo struct {
	Size                       int64
	ETag                       string
	AcceptsRanges              bool
	Inflated                   bool
	ContentDispositionFilename string
	ContentType                string
	LastModified               time.Time
	Digests                    []ResponseDigest
}

// DownloadResponse wraps an HTTP response body with metadata needed by the
// engine to preserve aria2's content-encoding semantics.
type DownloadResponse struct {
	Body     io.ReadCloser
	Inflated bool
	Digests  []ResponseDigest
}

type pendingProbeResponse struct {
	uri    string
	opts   RequestOptions
	resp   *http.Response
	cancel context.CancelFunc
}

// Driver is an HTTP download driver wrapping a single http.Client.
type Driver struct {
	client                        *http.Client
	ua                            string
	hdrs                          http.Header
	acceptEncoding                string
	noCache                       bool
	disableKeepAlive              bool
	enableWantDigest              bool
	referer                       string
	ifModifiedSince               string
	httpUser                      string
	httpPasswd                    string
	httpAuthChallenge             bool
	contentDispositionDefaultUTF8 bool
	acceptMetalink                bool
	useHead                       bool
	dryRun                        bool

	userOverrideKeys map[string]bool
	builtinHeaders   []headerKV
	authMu           sync.Mutex
	basicAuthScopes  map[basicAuthScope]struct{}
	probeMu          sync.Mutex
	pendingProbe     *pendingProbeResponse
}

// Opts configures a Driver.
type Opts struct {
	Dialer           *netx.Dialer
	TLS              *tls.Config
	Jar              http.CookieJar
	ProxyURL         *url.URL
	UserAgent        string
	Header           []string
	Headers          http.Header
	CheckCertificate *bool
	Timeout          time.Duration
	MaxRedirs        int
	AcceptEncoding   string
	NoCache          *bool

	// DisableKeepAlive sends "Connection: close" in every request.
	DisableKeepAlive bool

	// EnableWantDigest sends Want-Digest header with SHA-512, SHA-256, SHA-1.
	// Defaults to true when nil.
	EnableWantDigest *bool

	// Referer sets the Referer request header.
	Referer string

	// IfModifiedSince sets the If-Modified-Since request header.
	IfModifiedSince string

	// HTTPUser and HTTPPasswd generate a Basic Authorization header.
	HTTPUser   string
	HTTPPasswd string

	// HTTPAuthChallenge sends HTTP Authorization only after a 401 challenge.
	HTTPAuthChallenge bool

	// ContentDispositionDefaultUTF8 treats plain Content-Disposition filename
	// parameters as UTF-8 instead of ISO-8859-1.
	ContentDispositionDefaultUTF8 bool

	// AcceptMetalink appends metalink MIME types to the Accept header.
	AcceptMetalink bool

	// UseHead probes resource metadata with HEAD before falling back to GET.
	UseHead bool

	// DryRun uses HEAD for probe requests, matching aria2 dry-run behavior.
	DryRun bool
}

// NewDriver creates a new Driver from opts.  When opts.Dialer is nil a
// net.Dialer with sensible defaults is used.  When opts.TLS is nil TLS
// is disabled.  When opts.Timeout is zero a 30s timeout is applied.
func NewDriver(opts Opts) *Driver {
	tlsConfig := tlsClientConfig(opts.TLS, opts.CheckCertificate)
	tr := &http.Transport{
		TLSClientConfig:       tlsConfig,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if opts.Dialer != nil {
				return opts.Dialer.DialContext(ctx, network, addr)
			}
			return (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	if opts.ProxyURL != nil {
		tr.Proxy = http.ProxyURL(opts.ProxyURL)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ua := opts.UserAgent
	if ua == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			ua = bi.Path + "/" + bi.Main.Version
		}
		if ua == "" {
			ua = defaultUserAgent
		}
	}

	noCache := true
	if opts.NoCache != nil {
		noCache = *opts.NoCache
	}

	enableWantDigest := true
	if opts.EnableWantDigest != nil {
		enableWantDigest = *opts.EnableWantDigest
	}

	clonedHdrs := cloneHeaders(opts.Headers)
	addHeaderStrings(clonedHdrs, opts.Header)

	userOverrideKeys := make(map[string]bool, len(clonedHdrs))
	for k := range clonedHdrs {
		userOverrideKeys[http.CanonicalHeaderKey(k)] = true
	}

	builtinHeaders := buildBuiltinHeaders(ua, opts.AcceptMetalink, noCache,
		opts.AcceptEncoding, opts.DisableKeepAlive, enableWantDigest,
		opts.Referer, opts.IfModifiedSince, opts.HTTPUser, opts.HTTPPasswd,
		opts.HTTPAuthChallenge)

	return &Driver{
		client: &http.Client{
			Transport:     tr,
			Timeout:       timeout,
			Jar:           opts.Jar,
			CheckRedirect: redirectPolicy(opts.MaxRedirs),
		},
		ua:                            ua,
		hdrs:                          clonedHdrs,
		acceptEncoding:                opts.AcceptEncoding,
		noCache:                       noCache,
		disableKeepAlive:              opts.DisableKeepAlive,
		enableWantDigest:              enableWantDigest,
		referer:                       opts.Referer,
		ifModifiedSince:               opts.IfModifiedSince,
		httpUser:                      opts.HTTPUser,
		httpPasswd:                    opts.HTTPPasswd,
		httpAuthChallenge:             opts.HTTPAuthChallenge,
		contentDispositionDefaultUTF8: opts.ContentDispositionDefaultUTF8,
		acceptMetalink:                opts.AcceptMetalink,
		useHead:                       opts.UseHead,
		dryRun:                        opts.DryRun,
		userOverrideKeys:              userOverrideKeys,
		builtinHeaders:                builtinHeaders,
		basicAuthScopes:               make(map[basicAuthScope]struct{}),
	}
}

func tlsClientConfig(base *tls.Config, checkCertificate *bool) *tls.Config {
	if checkCertificate == nil || *checkCertificate {
		return base
	}
	if base != nil {
		base = base.Clone()
	} else {
		base = &tls.Config{}
	}
	base.InsecureSkipVerify = true
	return base
}

func cloneHeaders(h http.Header) http.Header {
	if len(h) == 0 {
		return make(http.Header)
	}
	return h.Clone()
}

func addHeaderStrings(h http.Header, values []string) {
	for _, raw := range values {
		name, value, ok := strings.Cut(raw, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			continue
		}
		h.Add(name, strings.TrimLeft(value, " \t"))
	}
}

// Probe checks if a URL is reachable and returns the resource size. By default
// it uses a GET with Range: bytes=0-0. When transparent content inflation is
// enabled, ranged probing is avoided and the full GET response can be reused
// for the subsequent download. When UseHead or DryRun is enabled, probing
// starts with HEAD and falls back as needed.
// cdFilename is the Content-Disposition filename if present and valid.
func (d *Driver) Probe(ctx context.Context, uri string) (size int64, etag string, acceptsRanges bool, cdFilename string, err error) {
	info, err := d.ProbeInfo(ctx, uri)
	if err != nil {
		return 0, "", false, "", err
	}
	return info.Size, info.ETag, info.AcceptsRanges, info.ContentDispositionFilename, nil
}

// ProbeInfo checks if a URL is reachable and returns HTTP resource metadata.
func (d *Driver) ProbeInfo(ctx context.Context, uri string) (ResourceInfo, error) {
	return d.ProbeInfoWithOptions(ctx, uri, RequestOptions{})
}

// ProbeInfoWithOptions checks if a URL is reachable using per-request options
// and returns HTTP resource metadata.
func (d *Driver) ProbeInfoWithOptions(ctx context.Context, uri string, opts RequestOptions) (ResourceInfo, error) {
	d.clearPendingProbeResponse()

	unescapedURI := unescapeURI(uri)
	if d.acceptEncoding != "" && !d.useHead && !d.dryRun {
		return d.probeGETNoRange(ctx, uri, unescapedURI, opts, true)
	}
	if d.acceptEncoding == "" && !d.useHead && !d.dryRun {
		info, err := d.probeGETRange(ctx, uri, unescapedURI, opts)
		if err == nil {
			return info, nil
		}
		if !probeGETShouldFallbackForError(err) {
			return ResourceInfo{}, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, uri, nil)
	if err != nil {
		return ResourceInfo{}, fmt.Errorf("http: probe request: %w", err)
	}
	d.setHeadersWithOptions(req, opts)

	resp, err := d.client.Do(req)
	var headErr error
	var headInfo ResourceInfo
	if err != nil {
		headErr = fmt.Errorf("http: probe head: %w", err)
		if !probeHEADShouldFallbackForError(err) {
			return ResourceInfo{}, headErr
		}
	} else {
		if resp.StatusCode == 401 {
			retryResp, retryErr := d.authRetry(ctx, http.MethodHead, uri, unescapedURI, resp, opts)
			if retryErr != nil {
				headErr = fmt.Errorf("http: probe head auth retry: %w", retryErr)
				if !probeHEADShouldFallbackForError(retryErr) {
					return ResourceInfo{}, headErr
				}
			} else if retryResp != nil {
				resp = retryResp
			}
		}

		if headErr == nil {
			headInfo = d.responseResourceInfo(resp)
			resp.Body.Close()

			if resp.StatusCode == http.StatusNotModified && requestIsConditional(opts, d.ifModifiedSince) {
				return headInfo, ErrNotModified
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && d.shouldInflateContentEncoding(resp) {
				headInfo.Size = 0
				headInfo.AcceptsRanges = false
				return headInfo, nil
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && resp.ContentLength > 0 {
				headInfo.Size = resp.ContentLength
				return headInfo, nil
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				headErr = probeHTTPStatusError(http.MethodHead, resp)
				if !probeHEADStatusAllowsFallback(resp.StatusCode) {
					return ResourceInfo{}, headErr
				}
			}
		}
	}

	if d.acceptEncoding != "" {
		fbInfo, fbErr := d.probeGETNoRange(ctx, uri, unescapedURI, opts, true)
		if fbErr != nil {
			if headErr != nil {
				return ResourceInfo{}, fmt.Errorf("http: probe fallback could not determine size after HEAD failure: %v: %w", fbErr, headErr)
			}
			return ResourceInfo{}, fbErr
		}
		if fbInfo.ContentDispositionFilename == "" {
			fbInfo.ContentDispositionFilename = headInfo.ContentDispositionFilename
		}
		if fbInfo.LastModified.IsZero() {
			fbInfo.LastModified = headInfo.LastModified
		}
		return fbInfo, nil
	}

	fbInfo, fbErr := d.probeGETRange(ctx, uri, unescapedURI, opts)
	if fbErr != nil {
		if headErr != nil {
			return ResourceInfo{}, fmt.Errorf("http: probe fallback could not determine size after HEAD failure: %v: %w", fbErr, headErr)
		}
		return ResourceInfo{}, fbErr
	}
	if fbInfo.ContentDispositionFilename == "" {
		fbInfo.ContentDispositionFilename = headInfo.ContentDispositionFilename
	}
	if fbInfo.LastModified.IsZero() {
		fbInfo.LastModified = headInfo.LastModified
	}
	return fbInfo, nil
}

// HTTPStatusError carries an HTTP response status code while preserving the
// aria2-style core error code wrapped alongside it.
type HTTPStatusError struct {
	op         string
	statusCode int
	status     string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("%s: %s", e.op, e.status)
}

func (e *HTTPStatusError) StatusCode() int {
	if e == nil {
		return 0
	}
	return e.statusCode
}

func httpStatusError(prefix string, statusCode int, status string) error {
	statusErr := &HTTPStatusError{op: prefix, statusCode: statusCode, status: status}
	code := statusErrorCode(statusCode)
	if code == core.ExitUnknownError {
		return statusErr
	}
	return fmt.Errorf("%w: %w", statusErr, core.NewError(code, http.StatusText(statusCode)))
}

func probeHTTPStatusError(method string, resp *http.Response) error {
	return httpStatusError(fmt.Sprintf("http: probe %s", strings.ToLower(method)), resp.StatusCode, resp.Status)
}

func statusErrorCode(statusCode int) core.ErrorCode {
	switch statusCode {
	case http.StatusUnauthorized:
		return core.ExitHTTPAuthFailed
	case http.StatusNotFound:
		return core.ExitResourceNotFound
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return core.ExitHTTPServiceUnavailable
	default:
		if statusCode >= 400 {
			return core.ExitHTTPProtocolError
		}
		return core.ExitUnknownError
	}
}

func (d *Driver) probeGETRange(ctx context.Context, uri, unescapedURI string, opts RequestOptions) (ResourceInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return ResourceInfo{}, fmt.Errorf("http: probe get request: %w", err)
	}
	d.setHeadersWithOptions(req, opts)
	req.Header.Set("Range", "bytes=0-0")

	resp, err := d.client.Do(req)
	if err != nil {
		return ResourceInfo{}, fmt.Errorf("http: probe get: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		retryResp, retryErr := d.authRetry(ctx, http.MethodGet, uri, unescapedURI, resp, opts)
		if retryErr != nil {
			return ResourceInfo{}, fmt.Errorf("http: probe get auth retry: %w", retryErr)
		}
		if retryResp != nil {
			resp = retryResp
		}
	}
	defer resp.Body.Close()

	info := d.responseResourceInfo(resp)
	if resp.StatusCode == http.StatusNotModified && requestIsConditional(opts, d.ifModifiedSince) {
		return info, ErrNotModified
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && d.shouldInflateContentEncoding(resp) {
		info.Size = 0
		info.AcceptsRanges = false
		return info, nil
	}

	switch {
	case resp.StatusCode == http.StatusPartialContent:
		if cr := resp.Header.Get("Content-Range"); cr != "" {
			if s, ok := parseContentRangeTotal(cr); ok {
				info.Size = s
				info.AcceptsRanges = true
				return info, nil
			}
		}
		if resp.ContentLength > 0 {
			info.Size = resp.ContentLength
			info.AcceptsRanges = true
			return info, nil
		}
	case resp.StatusCode == http.StatusOK:
		if resp.ContentLength > 0 {
			info.Size = resp.ContentLength
			info.AcceptsRanges = false
			return info, nil
		}
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return ResourceInfo{}, probeHTTPStatusError(http.MethodGet, resp)
	}

	return info, fmt.Errorf("http: probe get could not determine size for %s", uri)
}

func probeHEADStatusAllowsFallback(statusCode int) bool {
	return statusCode == http.StatusMethodNotAllowed || statusCode == http.StatusNotImplemented
}

func probeHEADShouldFallbackForError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "unexpected EOF")
}

func probeGETShouldFallbackForError(err error) bool {
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		return probeHEADStatusAllowsFallback(statusErr.statusCode)
	}
	return probeHEADShouldFallbackForError(err)
}

func (d *Driver) probeGETNoRange(ctx context.Context, uri, unescapedURI string, opts RequestOptions, cacheBody bool) (ResourceInfo, error) {
	reqCtx := ctx
	cancel := func() {}
	if cacheBody {
		reqCtx, cancel = context.WithCancel(ctx)
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, uri, nil)
	if err != nil {
		cancel()
		return ResourceInfo{}, fmt.Errorf("http: probe get request: %w", err)
	}
	d.setHeadersWithOptions(req, opts)

	resp, err := d.client.Do(req)
	if err != nil {
		cancel()
		return ResourceInfo{}, fmt.Errorf("http: probe get: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		retryResp, retryErr := d.authRetry(reqCtx, http.MethodGet, uri, unescapedURI, resp, opts)
		if retryErr != nil {
			cancel()
			return ResourceInfo{}, fmt.Errorf("http: probe get auth retry: %w", retryErr)
		}
		if retryResp != nil {
			resp = retryResp
		}
	}

	info := d.responseResourceInfo(resp)
	if resp.StatusCode == http.StatusNotModified && requestIsConditional(opts, d.ifModifiedSince) {
		resp.Body.Close()
		cancel()
		return info, ErrNotModified
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		cancel()
		return ResourceInfo{}, probeHTTPStatusError(http.MethodGet, resp)
	}
	if d.shouldInflateContentEncoding(resp) {
		info.Size = 0
		info.AcceptsRanges = false
		if cacheBody {
			d.storePendingProbeResponse(&pendingProbeResponse{
				uri:    uri,
				opts:   opts,
				resp:   resp,
				cancel: cancel,
			})
			return info, nil
		}
		resp.Body.Close()
		cancel()
		return info, nil
	}
	if resp.ContentLength > 0 {
		info.Size = resp.ContentLength
		info.AcceptsRanges = false
	}
	if cacheBody {
		d.storePendingProbeResponse(&pendingProbeResponse{
			uri:    uri,
			opts:   opts,
			resp:   resp,
			cancel: cancel,
		})
		return info, nil
	}
	resp.Body.Close()
	cancel()
	return info, nil
}

// Download streams a URL to the returned io.ReadCloser starting at the
// given offset.  When size > 0, a closed range (bytes=OFFSET-OFFSET+SIZE-1)
// is requested.  When the returned reader is closed the underlying
// request context is cancelled so idle connections are not leaked.
func (d *Driver) Download(ctx context.Context, uri string, offset, size int64) (io.ReadCloser, error) {
	resp, err := d.DownloadResponseWithOptions(ctx, uri, offset, size, RequestOptions{})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// DownloadWithOptions streams a URL using per-request options.
func (d *Driver) DownloadWithOptions(ctx context.Context, uri string, offset, size int64, opts RequestOptions) (io.ReadCloser, error) {
	resp, err := d.DownloadResponseWithOptions(ctx, uri, offset, size, opts)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// DownloadResponseWithOptions streams a URL using per-request options and
// reports whether the body is being transparently inflated from
// Content-Encoding.
func (d *Driver) DownloadResponseWithOptions(ctx context.Context, uri string, offset, size int64, opts RequestOptions) (*DownloadResponse, error) {
	if pending := d.takePendingProbeResponse(uri, opts, offset, size); pending != nil {
		return d.finishDownloadResponse(pending.resp, offset, size, opts, pending.cancel)
	}

	reqCtx, cancel := context.WithCancel(ctx)

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, uri, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("http: download request: %w", err)
	}
	d.setHeadersWithOptions(req, opts)
	if size > 0 || offset > 0 {
		req.Header.Set("Range", formatRange(offset, size))
	}

	resp, err := d.client.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("http: download: %w", err)
	}

	if resp.StatusCode == 401 {
		unescapedURI := unescapeURI(req.URL.String())
		retryResp, retryErr := d.authRetry(reqCtx, http.MethodGet, uri, unescapedURI, resp, opts)
		if retryErr == nil && retryResp != nil {
			resp = retryResp
		}
	}
	return d.finishDownloadResponse(resp, offset, size, opts, cancel)
}

func (d *Driver) finishDownloadResponse(resp *http.Response, offset, size int64, opts RequestOptions, cancel context.CancelFunc) (*DownloadResponse, error) {
	inflated := d.shouldInflateContentEncoding(resp)
	if err := validateDownloadResponse(resp, offset, size, requestIsConditional(opts, d.ifModifiedSince), inflated); err != nil {
		resp.Body.Close()
		cancel()
		return nil, err
	}

	body, err := d.responseBody(resp)
	if err != nil {
		resp.Body.Close()
		cancel()
		return nil, err
	}

	return &DownloadResponse{
		Body:     &cancelReadCloser{ReadCloser: newBufReadCloser(body), cancel: cancel},
		Inflated: inflated,
		Digests:  cloneResponseDigests(parseResponseDigests(resp)),
	}, nil
}

func validateDownloadResponse(resp *http.Response, offset, size int64, conditional, inflated bool) error {
	if resp.StatusCode == http.StatusNotModified && conditional {
		return ErrNotModified
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return httpStatusError("http: download", resp.StatusCode, resp.Status)
	}
	if inflated && (offset > 0 || size > 0 || resp.StatusCode == http.StatusPartialContent) {
		return fmt.Errorf("%w: %s: %w", ErrRangeIgnored, resp.Status,
			core.NewError(core.ExitRemoteFileError, "cannot resume"))
	}
	if resp.StatusCode == http.StatusPartialContent && offset == 0 && size == 0 {
		return fmt.Errorf("http: download: unexpected partial response without requested range: %w",
			core.NewError(core.ExitRemoteFileError, "cannot resume"))
	}
	if offset > 0 && resp.StatusCode == http.StatusOK {
		return fmt.Errorf("%w: %s: %w", ErrRangeIgnored, resp.Status,
			core.NewError(core.ExitRemoteFileError, "cannot resume"))
	}
	if resp.StatusCode == http.StatusPartialContent && (offset > 0 || size > 0) {
		cr := resp.Header.Get("Content-Range")
		start, end, ok := parseContentRange(cr)
		if !ok {
			return fmt.Errorf("http: download: invalid Content-Range %q for %s: %w",
				cr, formatRange(offset, size), core.NewError(core.ExitRemoteFileError, "cannot resume"))
		}
		if start != offset {
			return fmt.Errorf("http: download: Content-Range %q does not match %s: %w",
				cr, formatRange(offset, size), core.NewError(core.ExitRemoteFileError, "cannot resume"))
		}
		if size > 0 && end != offset+size-1 {
			return fmt.Errorf("http: download: Content-Range %q does not match %s: %w",
				cr, formatRange(offset, size), core.NewError(core.ExitRemoteFileError, "cannot resume"))
		}
	}
	return nil
}

func (d *Driver) shouldInflateContentEncoding(resp *http.Response) bool {
	if resp == nil || d.acceptEncoding == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "gzip", "x-gzip", "deflate":
		return true
	default:
		return false
	}
}

func (d *Driver) responseBody(resp *http.Response) (io.ReadCloser, error) {
	if d.acceptEncoding == "" {
		return resp.Body, nil
	}
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "", "identity":
		return resp.Body, nil
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("http: gzip response: %w", err)
		}
		return &decodeReadCloser{Reader: zr, decoder: zr, body: resp.Body}, nil
	case "deflate":
		zr, err := zlib.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("http: deflate response: %w", err)
		}
		return &decodeReadCloser{Reader: zr, decoder: zr, body: resp.Body}, nil
	default:
		return resp.Body, nil
	}
}

type decodeReadCloser struct {
	io.Reader
	decoder io.Closer
	body    io.Closer
}

func (r *decodeReadCloser) Close() error {
	decErr := r.decoder.Close()
	bodyErr := r.body.Close()
	if decErr != nil {
		return decErr
	}
	return bodyErr
}

// Close closes the driver's idle connections.
func (d *Driver) Close() error {
	d.clearPendingProbeResponse()
	d.client.CloseIdleConnections()
	return nil
}

func (d *Driver) storePendingProbeResponse(pending *pendingProbeResponse) {
	d.replacePendingProbeResponse(pending)
}

func (d *Driver) clearPendingProbeResponse() {
	d.replacePendingProbeResponse(nil)
}

func (d *Driver) takePendingProbeResponse(uri string, opts RequestOptions, offset, size int64) *pendingProbeResponse {
	d.probeMu.Lock()
	pending := d.pendingProbe
	d.pendingProbe = nil
	d.probeMu.Unlock()

	if pending == nil {
		return nil
	}
	if offset == 0 && size == 0 && pending.uri == uri && pending.opts == opts {
		return pending
	}
	closePendingProbeResponse(pending)
	return nil
}

func (d *Driver) replacePendingProbeResponse(pending *pendingProbeResponse) {
	d.probeMu.Lock()
	prev := d.pendingProbe
	d.pendingProbe = pending
	d.probeMu.Unlock()

	closePendingProbeResponse(prev)
}

func closePendingProbeResponse(pending *pendingProbeResponse) {
	if pending == nil {
		return
	}
	if pending.resp != nil && pending.resp.Body != nil {
		pending.resp.Body.Close()
	}
	if pending.cancel != nil {
		pending.cancel()
	}
}

func buildBuiltinHeaders(ua string, acceptMetalink, noCache bool,
	acceptEncoding string, disableKeepAlive, enableWantDigest bool,
	referer, ifModifiedSince, httpUser, httpPasswd string,
	httpAuthChallenge bool) []headerKV {

	var hdrs []headerKV
	hdrs = append(hdrs, headerKV{"User-Agent", ua})

	var acceptSB strings.Builder
	acceptSB.WriteString("*/*")
	if acceptMetalink {
		for _, t := range metalinkContentTypes {
			acceptSB.WriteByte(',')
			acceptSB.WriteString(t)
		}
	}
	hdrs = append(hdrs, headerKV{"Accept", acceptSB.String()})

	if noCache {
		hdrs = append(hdrs,
			headerKV{"Pragma", "no-cache"},
			headerKV{"Cache-Control", "no-cache"},
		)
	}

	if acceptEncoding != "" {
		hdrs = append(hdrs, headerKV{"Accept-Encoding", acceptEncoding})
	}

	if disableKeepAlive {
		hdrs = append(hdrs, headerKV{"Connection", "close"})
	}

	if enableWantDigest {
		hdrs = append(hdrs, headerKV{"Want-Digest", "SHA-512;q=1, SHA-256;q=1, SHA;q=0.1"})
	}

	if referer != "" {
		hdrs = append(hdrs, headerKV{"Referer", referer})
	}

	if ifModifiedSince != "" {
		hdrs = append(hdrs, headerKV{"If-Modified-Since", ifModifiedSince})
	}

	if httpUser != "" && !httpAuthChallenge {
		auth := base64.StdEncoding.EncodeToString([]byte(httpUser + ":" + httpPasswd))
		hdrs = append(hdrs, headerKV{"Authorization", "Basic " + auth})
	}

	return hdrs
}

func (d *Driver) setHeaders(req *http.Request) {
	d.setHeadersWithOptions(req, RequestOptions{})
}

func (d *Driver) setHeadersWithOptions(req *http.Request, opts RequestOptions) {
	if req.URL != nil && !d.userOverrideKeys["Host"] {
		host := req.URL.Hostname()
		port := req.URL.Port()
		if port != "" && port != "80" && port != "443" {
			host = net.JoinHostPort(host, port)
		}
		req.Host = host
	}

	for _, h := range d.builtinHeaders {
		if d.userOverrideKeys[http.CanonicalHeaderKey(h.key)] {
			continue
		}
		req.Header.Set(h.key, h.value)
	}
	d.setActivatedBasicAuth(req)

	for key, vals := range d.hdrs {
		if strings.EqualFold(key, "Host") {
			if len(vals) > 0 {
				req.Host = vals[len(vals)-1]
			}
			continue
		}
		for _, v := range vals {
			req.Header.Add(key, v)
		}
	}

	if opts.IfModifiedSince != "" && !d.userOverrideKeys["If-Modified-Since"] {
		req.Header.Set("If-Modified-Since", opts.IfModifiedSince)
	}
}

func contentDispositionFilename(resp *http.Response, defaultUTF8 bool) string {
	if resp == nil {
		return ""
	}
	cd := resp.Header.Get("Content-Disposition")
	if cd == "" {
		return ""
	}
	filename, ok := ParseContentDispositionWithOptions(cd, defaultUTF8)
	if !ok {
		return ""
	}
	return filename
}

func (d *Driver) responseResourceInfo(resp *http.Response) ResourceInfo {
	if resp == nil {
		return ResourceInfo{}
	}
	return ResourceInfo{
		ETag:                       resp.Header.Get("ETag"),
		AcceptsRanges:              strings.EqualFold(resp.Header.Get("Accept-Ranges"), "bytes"),
		Inflated:                   d.shouldInflateContentEncoding(resp),
		ContentDispositionFilename: contentDispositionFilename(resp, d.contentDispositionDefaultUTF8),
		ContentType:                resp.Header.Get("Content-Type"),
		LastModified:               lastModifiedTime(resp),
		Digests:                    parseResponseDigests(resp),
	}
}

func parseResponseDigests(resp *http.Response) []ResponseDigest {
	if resp == nil {
		return nil
	}
	values := resp.Header.Values("Digest")
	if len(values) == 0 {
		return nil
	}
	digests := make([]ResponseDigest, 0, len(values))
	for _, rawValue := range values {
		for _, part := range strings.Split(rawValue, ",") {
			name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok {
				continue
			}
			kind, ok := responseDigestKind(name)
			if !ok {
				continue
			}
			sum, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
			if err != nil || len(sum) != kind.Size() {
				continue
			}
			digests = append(digests, ResponseDigest{
				Kind:   kind,
				Digest: append([]byte(nil), sum...),
			})
		}
	}
	if len(digests) == 0 {
		return nil
	}
	return digests
}

func responseDigestKind(name string) (hash.Kind, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "md5":
		return hash.MD5, true
	case "sha", "sha-1":
		return hash.SHA1, true
	case "sha-224":
		return hash.SHA224, true
	case "sha-256":
		return hash.SHA256, true
	case "sha-384":
		return hash.SHA384, true
	case "sha-512":
		return hash.SHA512, true
	default:
		return "", false
	}
}

func cloneResponseDigests(src []ResponseDigest) []ResponseDigest {
	if len(src) == 0 {
		return nil
	}
	dst := make([]ResponseDigest, len(src))
	for i, digest := range src {
		dst[i] = ResponseDigest{
			Kind:   digest.Kind,
			Digest: append([]byte(nil), digest.Digest...),
		}
	}
	return dst
}

func lastModifiedTime(resp *http.Response) time.Time {
	if resp == nil {
		return time.Time{}
	}
	raw := resp.Header.Get("Last-Modified")
	if raw == "" {
		return time.Time{}
	}
	t, err := http.ParseTime(raw)
	if err != nil {
		return time.Time{}
	}
	return t
}

func requestIsConditional(opts RequestOptions, driverIfModifiedSince string) bool {
	return opts.IfModifiedSince != "" || driverIfModifiedSince != ""
}

func unescapeURI(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	return u.RequestURI()
}

func (d *Driver) authRetry(ctx context.Context, method, uri, unescapedURI string, resp *http.Response, opts RequestOptions) (*http.Response, error) {
	retryResp, err := d.digestAuthRetry(ctx, method, uri, unescapedURI, resp, opts)
	if err != nil || retryResp != nil {
		return retryResp, err
	}
	return d.basicAuthChallengeRetry(ctx, method, uri, resp, opts)
}

func (d *Driver) digestAuthRetry(ctx context.Context, method, uri, unescapedURI string, resp *http.Response, opts RequestOptions) (*http.Response, error) {
	if resp == nil || resp.StatusCode != 401 {
		return nil, nil
	}
	authHeader := resp.Header.Get("Www-Authenticate")
	if authHeader == "" {
		authHeader = resp.Header.Get("WWW-Authenticate")
	}
	if authHeader == "" || !strings.HasPrefix(authHeader, "Digest ") {
		return nil, nil
	}
	if d.httpUser == "" {
		return nil, nil
	}

	challenge, err := ParseChallenge(authHeader)
	if err != nil {
		return nil, nil
	}

	challenge.Username = d.httpUser
	challenge.Password = d.httpPasswd
	challenge.URI = unescapedURI
	challenge.Method = method
	challenge.NonceCount = 1
	if challenge.CNonce == "" {
		challenge.CNonce = fmt.Sprintf("%08x", time.Now().UnixNano())
	}

	authValue := challenge.ComputeResponse()

	resp.Body.Close()

	retryReq, err := http.NewRequestWithContext(ctx, method, uri, nil)
	if err != nil {
		return nil, err
	}
	d.setHeadersWithOptions(retryReq, opts)
	retryReq.Header.Set("Authorization", authValue)
	if method == http.MethodGet && (resp.Request != nil && resp.Request.Header.Get("Range") != "") {
		retryReq.Header.Set("Range", resp.Request.Header.Get("Range"))
	}

	return d.client.Do(retryReq)
}

func (d *Driver) basicAuthChallengeRetry(ctx context.Context, method, uri string, resp *http.Response, opts RequestOptions) (*http.Response, error) {
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return nil, nil
	}
	if !d.httpAuthChallenge || d.httpUser == "" || d.userOverrideKeys["Authorization"] {
		return nil, nil
	}
	if resp.Request != nil && resp.Request.Header.Get("Authorization") != "" {
		return nil, nil
	}

	resp.Body.Close()

	retryReq, err := http.NewRequestWithContext(ctx, method, uri, nil)
	if err != nil {
		return nil, err
	}
	d.activateBasicAuthScope(retryReq.URL)
	d.setHeadersWithOptions(retryReq, opts)
	retryReq.Header.Set("Authorization", d.basicAuthorizationValue())
	if method == http.MethodGet && resp.Request != nil && resp.Request.Header.Get("Range") != "" {
		retryReq.Header.Set("Range", resp.Request.Header.Get("Range"))
	}

	return d.client.Do(retryReq)
}

type basicAuthScope struct {
	host string
	port string
	path string
}

func (d *Driver) basicAuthorizationValue() string {
	auth := base64.StdEncoding.EncodeToString([]byte(d.httpUser + ":" + d.httpPasswd))
	return "Basic " + auth
}

func (d *Driver) setActivatedBasicAuth(req *http.Request) {
	if !d.httpAuthChallenge || d.httpUser == "" || d.userOverrideKeys["Authorization"] || req.URL == nil {
		return
	}
	if !d.basicAuthActivated(req.URL) {
		return
	}
	req.Header.Set("Authorization", d.basicAuthorizationValue())
}

func (d *Driver) activateBasicAuthScope(u *url.URL) {
	if u == nil {
		return
	}
	scope := basicAuthScopeForURL(u)
	d.authMu.Lock()
	d.basicAuthScopes[scope] = struct{}{}
	d.authMu.Unlock()
}

func (d *Driver) basicAuthActivated(u *url.URL) bool {
	scope := basicAuthScopeForURL(u)
	d.authMu.Lock()
	defer d.authMu.Unlock()
	for active := range d.basicAuthScopes {
		if active.host == scope.host && active.port == scope.port && strings.HasPrefix(scope.path, active.path) {
			return true
		}
	}
	return false
}

func basicAuthScopeForURL(u *url.URL) basicAuthScope {
	return basicAuthScope{
		host: strings.ToLower(u.Hostname()),
		port: portForURL(u),
		path: authScopePath(u),
	}
}

func portForURL(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func authScopePath(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	if strings.HasSuffix(p, "/") {
		return p
	}
	idx := strings.LastIndexByte(p, '/')
	if idx < 0 {
		return "/"
	}
	return p[:idx+1]
}

func redirectPolicy(maxRedirs int) func(*http.Request, []*http.Request) error {
	if maxRedirs <= 0 {
		maxRedirs = 20
	}
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirs {
			return fmt.Errorf("http: stopped after %d redirects: %w",
				maxRedirs, core.NewError(core.ExitTooManyRedirects, "too many redirects"))
		}
		return nil
	}
}

type bufReadCloser struct {
	r       io.ReadCloser
	buf     *ioutilx.Buf
	offset  int
	end     int
	pending error
}

func newBufReadCloser(r io.ReadCloser) *bufReadCloser {
	return &bufReadCloser{
		r:   r,
		buf: ioutilx.Pool64K.Get(),
	}
}

func (b *bufReadCloser) Read(p []byte) (n int, err error) {
	if b.offset >= b.end {
		if b.pending != nil {
			err = b.pending
			b.pending = nil
			return 0, err
		}
		b.offset = 0
		b.end, b.pending = b.r.Read(b.buf.B[:cap(b.buf.B)])
		if b.end == 0 {
			err = b.pending
			b.pending = nil
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}
	}
	n = copy(p, b.buf.B[b.offset:b.end])
	b.offset += n
	return n, nil
}

func (b *bufReadCloser) Close() error {
	b.buf.Free()
	return b.r.Close()
}

type cancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelReadCloser) Close() error {
	c.cancel()
	return c.ReadCloser.Close()
}

// ParseContentRangeTotalForTest is exported for tests only.
func ParseContentRangeTotalForTest(cr string) (int64, bool) {
	return parseContentRangeTotal(cr)
}

func formatRange(offset, size int64) string {
	var buf [64]byte
	b := append(buf[:0], "bytes="...)
	b = strconv.AppendInt(b, offset, 10)
	b = append(b, '-')
	if size > 0 {
		b = strconv.AppendInt(b, offset+size-1, 10)
	}
	return string(b)
}

func parseContentRangeTotal(cr string) (int64, bool) {
	rest := cr
	switch {
	case strings.HasPrefix(cr, "bytes "):
		rest = cr[6:]
	case strings.HasPrefix(cr, "bytes="):
		rest = cr[6:]
	default:
		return 0, false
	}
	slash := strings.LastIndexByte(rest, '/')
	if slash < 0 {
		return 0, false
	}
	total := rest[slash+1:]
	if total == "*" {
		return 0, false
	}
	n, err := strconv.ParseInt(total, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func parseContentRange(cr string) (start, end int64, ok bool) {
	rest := cr
	switch {
	case strings.HasPrefix(cr, "bytes "):
		rest = cr[6:]
	case strings.HasPrefix(cr, "bytes="):
		rest = cr[6:]
	default:
		return 0, 0, false
	}
	slash := strings.LastIndexByte(rest, '/')
	if slash < 0 || slash == len(rest)-1 {
		return 0, 0, false
	}
	rangePart := rest[:slash]
	totalPart := rest[slash+1:]
	if strings.Contains(rangePart, "*") || totalPart == "*" {
		return 0, 0, false
	}
	dash := strings.IndexByte(rangePart, '-')
	if dash <= 0 || dash == len(rangePart)-1 {
		return 0, 0, false
	}
	start, err := strconv.ParseInt(rangePart[:dash], 10, 64)
	if err != nil || start < 0 {
		return 0, 0, false
	}
	end, err = strconv.ParseInt(rangePart[dash+1:], 10, 64)
	if err != nil || end < start {
		return 0, 0, false
	}
	total, err := strconv.ParseInt(totalPart, 10, 64)
	if err != nil || total <= end {
		return 0, 0, false
	}
	return start, end, true
}
