package engine

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/smartass08/aria2go/internal/config"
	"github.com/smartass08/aria2go/internal/core"
	"github.com/smartass08/aria2go/internal/torrent"
)

// torrentContentType is the Content-Type aria2 treats as a torrent file
// when follow-torrent is enabled (RequestGroup.cc checkContentType).
const torrentContentType = "application/x-bittorrent"

// followTorrentEnabled reports whether follow-torrent is active for the
// request group. Any value other than "false" enables following, matching
// aria2's parameter option where the default is "true".
func followTorrentEnabled(opts *config.Options) bool {
	if opts == nil {
		return true
	}
	return opts.FollowTorrent != "false"
}

// uriPathHasTorrentSuffix reports whether the URI path names a .torrent file.
func uriPathHasTorrentSuffix(rawURI string) bool {
	u, err := url.Parse(rawURI)
	if err != nil {
		return false
	}
	name := filepath.Base(u.Path)
	return strings.HasSuffix(name, ".torrent")
}

// isTorrentContentType reports whether a Content-Type header value names the
// bittorrent media type. Parameters after ";" are ignored.
func isTorrentContentType(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), torrentContentType)
}

// shouldFollowTorrent reports whether an HTTP(S) download must be treated as
// a torrent metadata fetch, matching aria2's --follow-torrent trigger: the
// URI names a .torrent file or the server answers with the bittorrent
// content type. prepareHTTPMetadata must have probed the URI already so
// rg.contentType is populated.
func (e *Engine) shouldFollowTorrent(rg *requestGroup, uri string) bool {
	if !followTorrentEnabled(rg.opts) {
		return false
	}
	if uriPathHasTorrentSuffix(uri) {
		return true
	}
	return isTorrentContentType(rg.contentType)
}

// runTorrentFollowDownload downloads a .torrent file over HTTP(S), saves it
// when follow-torrent is "true", and enqueues the torrent it describes as a
// child download wired through followedBy/following, matching aria2's
// follow-torrent behavior. The metadata download completes with the .torrent
// file size.
func (e *Engine) runTorrentFollowDownload(ctx context.Context, rg *requestGroup, uri, outPath string) {
	driver, err := e.httpDriverForURI(rg, uri)
	if err != nil {
		rg.errCode = protocolErrorCode(err)
		rg.errMsg = err.Error()
		return
	}

	requestOpts := e.httpRequestOptions(rg, outPath)
	resp, err := e.downloadHTTPWithRetry(ctx, rg, driver, uri, 0, rg.probedSize, requestOpts)
	if err != nil {
		e.log.Error("torrent metadata download failed", "gid", rg.gid, "uri", uri, "error", err)
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
	data, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		rg.errCode = core.ExitFileIOError
		rg.errMsg = readErr.Error()
		return
	}

	if _, err := torrent.Load(data); err != nil {
		rg.errCode = core.ExitTorrentParseError
		rg.errMsg = err.Error()
		return
	}

	if rg.opts.FollowTorrent != "mem" {
		if dir := filepath.Dir(outPath); dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				rg.errCode = core.ExitDirCreateError
				rg.errMsg = err.Error()
				return
			}
		}
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			rg.errCode = core.ExitFileIOError
			rg.errMsg = err.Error()
			return
		}
	}

	childOpts := config.Merge(rg.opts)
	childOpts.Out = ""
	if e.keepRunning && rg.opts.PauseMetadata {
		childOpts.Pause = true
	}

	childGID, err := e.Add(AddSpec{
		Torrent:   data,
		Options:   childOpts,
		BelongsTo: rg.gid,
	})
	if err != nil {
		rg.errCode = core.ExitUnknownError
		rg.errMsg = fmt.Sprintf("follow torrent: %s", err)
		return
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

	rg.statusMu.Lock()
	rg.totalLength = int64(len(data))
	rg.statusMu.Unlock()
	rg.statusMu.Lock()
	rg.completedLength = int64(len(data))
	rg.statusMu.Unlock()
	rg.errCode = core.ExitSuccess
	e.log.Info("torrent followed", "gid", rg.gid, "child", childGID, "size", len(data))
}
