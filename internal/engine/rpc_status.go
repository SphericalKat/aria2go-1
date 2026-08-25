package engine

import (
	"encoding/hex"
	"path/filepath"

	"github.com/smartass08/aria2go/internal/core"
	"github.com/smartass08/aria2go/internal/disk"
	btprogress "github.com/smartass08/aria2go/internal/protocol/bittorrent/progress"
)

func cloneStatusSnapshot(src Status) Status {
	dst := src
	if len(src.FollowedBy) > 0 {
		dst.FollowedBy = append([]core.GID(nil), src.FollowedBy...)
	}
	if len(src.Files) > 0 {
		dst.Files = make([]FileStatus, len(src.Files))
		for i, file := range src.Files {
			dst.Files[i] = file
			if len(file.URIs) > 0 {
				dst.Files[i].URIs = append([]URIStatus(nil), file.URIs...)
			}
		}
	}
	return dst
}

func (e *Engine) makeStoppedStatus(rg *requestGroup, state core.Status, errCode core.ErrorCode, errMsg string) Status {
	status := cloneStatusSnapshot(*e.makeStatus(rg))
	status.Status = state
	status.ErrorCode = errCode
	status.ErrorMessage = errMsg
	status.DownloadSpeed = 0
	status.UploadSpeed = 0
	status.Connections = 0
	e.applyStoppedStatusSourceTruth(rg, &status, state, errCode)
	return status
}

func (e *Engine) applyStoppedStatusSourceTruth(rg *requestGroup, status *Status, state core.Status, errCode core.ErrorCode) {
	if rg == nil || status == nil {
		return
	}

	if status.PieceLength <= 0 {
		status.PieceLength = controlPieceLength(rg.opts)
		if status.TotalLength > 0 && status.NumPieces == 0 {
			status.NumPieces = int64(controlNumPieces(status.TotalLength, status.PieceLength))
		}
	}

	if !isUserRemovedPreStartURIResult(rg, state, errCode) {
		return
	}

	if len(status.Files) == 0 {
		status.Files = []FileStatus{{
			Index:    1,
			Selected: true,
		}}
	}

	if rg.filePathFromURI {
		status.Files[0].Path = ""
	}
	status.Files[0].URIs = removedPreStartURIs(rg)
}

func isUserRemovedPreStartURIResult(rg *requestGroup, state core.Status, errCode core.ErrorCode) bool {
	if rg == nil {
		return false
	}
	return state == core.StatusRemoved &&
		errCode == core.ExitRemoved &&
		rg.haltReason == haltReasonUserRequest &&
		len(rg.uris) > 0 &&
		len(rg.torrent) == 0 &&
		len(rg.metalinkData) == 0 &&
		rg.completedLength == 0 &&
		rg.totalLength == 0 &&
		len(rg.fileEntries) == 0
}

func waitingURIs(rg *requestGroup) []URIStatus {
	if rg == nil || len(rg.uris) == 0 {
		return nil
	}

	uris := make([]URIStatus, 0, len(rg.uris))
	for _, uri := range rg.uris {
		uris = append(uris, URIStatus{URI: uri, Status: "waiting"})
	}
	return uris
}

func removedPreStartURIs(rg *requestGroup) []URIStatus {
	if rg == nil || len(rg.uris) == 0 {
		return nil
	}

	used := rg.activeURI
	if used == "" {
		used = rg.uris[0]
	}

	uris := make([]URIStatus, 0, len(rg.uris)+1)
	uris = append(uris, URIStatus{URI: used, Status: "used"})
	uris = append(uris, waitingURIs(rg)...)
	return uris
}

func (e *Engine) statusControlSnapshot(rg *requestGroup) (*btprogress.Info, []byte) {
	rg.controlMu.Lock()
	info := cloneControlInfo(rg.controlInfo)
	adaptor := rg.adaptor
	rg.controlMu.Unlock()

	if adaptor != nil {
		if bitfield := adaptor.Bitfield(); len(bitfield) > 0 {
			return info, bitfield
		}
	}
	if info != nil && len(info.Bitfield) > 0 {
		return info, append([]byte(nil), info.Bitfield...)
	}
	return info, nil
}

func (e *Engine) groupFileEntries(rg *requestGroup) []disk.FileEntry {
	if len(rg.fileEntries) > 0 {
		files := make([]disk.FileEntry, len(rg.fileEntries))
		copy(files, rg.fileEntries)
		return files
	}

	path := firstFilePathForRPC(rg)
	if path == "" {
		return nil
	}

	return []disk.FileEntry{{
		Name:      path,
		Length:    rg.totalLength,
		Offset:    0,
		Requested: true,
	}}
}

func firstFilePathForRPC(rg *requestGroup) string {
	if rg == nil {
		return ""
	}

	path := rg.filePath
	if path == "" && len(rg.uris) > 0 {
		path = defaultOutputPathFromURI(rg.uris[0])
	}
	if path == "" {
		return ""
	}
	if rg.inMemory {
		return "[MEMORY]" + filepath.Base(path)
	}
	if filepath.IsAbs(path) || rg.opts == nil || rg.opts.Dir == "" {
		return path
	}
	return filepath.Join(rg.opts.Dir, path)
}

func fileEntryPathForRPC(rg *requestGroup, entry disk.FileEntry) string {
	path := entry.Name
	if path == "" {
		return firstFilePathForRPC(rg)
	}
	if rg != nil && rg.inMemory {
		return "[MEMORY]" + filepath.Base(path)
	}
	if filepath.IsAbs(path) || rg == nil || rg.opts == nil || rg.opts.Dir == "" {
		return path
	}
	return filepath.Join(rg.opts.Dir, path)
}

func fileCompletedLength(entry disk.FileEntry, totalLength, pieceLength int64, bitfield []byte, fallback int64) int64 {
	if entry.Length <= 0 {
		if fallback < 0 {
			return 0
		}
		return fallback
	}
	if pieceLength <= 0 || len(bitfield) == 0 || totalLength <= 0 {
		if fallback < 0 {
			return 0
		}
		if fallback > entry.Length {
			return entry.Length
		}
		return fallback
	}

	end := entry.Offset + entry.Length
	if end > totalLength {
		end = totalLength
	}
	if entry.Offset >= end {
		return 0
	}

	var completed int64
	firstPiece := int(entry.Offset / pieceLength)
	lastPiece := int((end - 1) / pieceLength)
	for piece := firstPiece; piece <= lastPiece; piece++ {
		if !controlBit(bitfield, piece) {
			continue
		}
		pieceStart := int64(piece) * pieceLength
		pieceEnd := pieceStart + controlPieceSize(totalLength, pieceLength, piece)
		overlapStart := max64(entry.Offset, pieceStart)
		overlapEnd := min64(end, pieceEnd)
		if overlapEnd > overlapStart {
			completed += overlapEnd - overlapStart
		}
	}
	return completed
}

func (e *Engine) groupFileURIs(rg *requestGroup, fileIndex int) []URIStatus {
	if rg == nil || fileIndex != 0 || len(rg.uris) == 0 {
		return nil
	}

	uris := make([]URIStatus, 0, len(rg.uris))
	usedURI, used := e.statusUsedURI(rg)
	if usedURI == "" {
		usedURI = rg.uris[0]
	}
	usedAssigned := false
	for _, uri := range rg.uris {
		status := "waiting"
		if used && !usedAssigned && uri == usedURI {
			status = "used"
			usedAssigned = true
		}
		uris = append(uris, URIStatus{URI: uri, Status: status})
	}
	if used && !usedAssigned && len(uris) > 0 {
		uris[0].Status = "used"
	}
	return uris
}

func (e *Engine) statusUsedURI(rg *requestGroup) (string, bool) {
	if rg == nil {
		return "", false
	}

	if rg.activeURI != "" {
		return rg.activeURI, rg.uriUsed
	}
	if len(rg.uris) == 0 {
		return "", false
	}
	if rg.uriUsed || rg.state == core.StatusActive {
		return rg.uris[0], true
	}
	return "", false
}

func (e *Engine) buildFileStatus(rg *requestGroup) []FileStatus {
	files := e.groupFileEntries(rg)
	if len(files) == 0 {
		return nil
	}

	info, bitfield := e.statusControlSnapshot(rg)
	totalLength := rg.totalLength
	pieceLength := int64(0)
	if info != nil {
		if totalLength == 0 {
			totalLength = info.TotalLength
		}
		pieceLength = info.PieceLength
	}

	result := make([]FileStatus, 0, len(files))
	for i, entry := range files {
		requested := entry.Requested
		if len(rg.fileEntries) == 0 {
			requested = true
		}

		fallbackCompleted := int64(0)
		if len(files) == 1 {
			fallbackCompleted = rg.completedLength
		}

		result = append(result, FileStatus{
			Index:           i + 1,
			Path:            fileEntryPathForRPC(rg, entry),
			Length:          entry.Length,
			CompletedLength: fileCompletedLength(entry, totalLength, pieceLength, bitfield, fallbackCompleted),
			Selected:        requested,
			URIs:            e.groupFileURIs(rg, i),
		})
	}
	return result
}

func (e *Engine) makeStatus(rg *requestGroup) *Status {
	dir := ""
	if rg.opts != nil {
		dir = rg.opts.Dir
	}
	st := rg.state
	if rg.pauseReq && st == core.StatusWaiting {
		st = core.StatusPaused
	}

	// Worker goroutines publish progress and completion state without the
	// group lock, so snapshot the whole status under the status mutex.
	rg.statusMu.Lock()
	defer rg.statusMu.Unlock()

	info, bitfield := e.statusControlSnapshot(rg)
	totalLength := rg.totalLength
	uploadLength := int64(0)
	pieceLength := int64(0)
	numPieces := int64(0)
	infoHash := ""
	bitfieldHex := ""
	if info != nil {
		if totalLength == 0 {
			totalLength = info.TotalLength
		}
		uploadLength = info.UploadLength
		pieceLength = info.PieceLength
		numPieces = int64(controlNumPieces(info.TotalLength, info.PieceLength))
		if len(info.InfoHash) > 0 {
			infoHash = hex.EncodeToString(info.InfoHash)
		}
	}
	if pieceLength <= 0 {
		pieceLength = controlPieceLength(rg.opts)
		if totalLength > 0 && numPieces == 0 {
			numPieces = int64(controlNumPieces(totalLength, pieceLength))
		}
	}
	if len(bitfield) > 0 {
		bitfieldHex = hex.EncodeToString(bitfield)
	}

	return &Status{
		GID:             rg.gid,
		Status:          st,
		TotalLength:     totalLength,
		CompletedLength: rg.completedLength,
		UploadLength:    uploadLength,
		DownloadSpeed:   rg.downloadSpeed,
		UploadSpeed:     rg.uploadSpeed,
		InfoHash:        infoHash,
		NumSeeders:      rg.numSeeders.Load(),
		Connections:     int(rg.numConnections.Load()),
		ErrorCode:       rg.errCode,
		ErrorMessage:    rg.errMsg,
		FollowedBy:      append([]core.GID(nil), rg.followedBy...),
		BelongsTo:       rg.belongsTo,
		Following:       rg.following,
		Dir:             dir,
		Files:           e.buildFileStatus(rg),
		Seeder:          rg.seeder,
		Bitfield:        bitfieldHex,
		PieceLength:     pieceLength,
		NumPieces:       numPieces,
	}
}
