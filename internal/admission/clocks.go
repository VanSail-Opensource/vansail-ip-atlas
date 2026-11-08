package admission

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const clockName = "publication-clocks-v1.json"
const maxClockReceipts = 25000

type clockReceipt struct {
	Hash      string `json:"payload_sha256"`
	Published string `json:"published_at"`
}

type clockFile struct {
	Version  uint16         `json:"schema_version"`
	Receipts []clockReceipt `json:"receipts"`
}

// Clock receipts contain only content hashes and the earliest verified upstream
// publication. They are private anti-replay audit, not retained source snapshots
// or raw blobs. Their count and file size are bounded; overflow fails closed.
// Removing this private history deliberately loses the first-seen clock guard.
func (e *Engine) loadClocks() error {
	e.clocks = map[[32]byte]time.Time{}
	directory := filepath.Join(e.workspace, ".atlas-private")
	path := filepath.Join(directory, clockName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("publication history unavailable")
	}
	verified, err := privateFile(directory, path)
	if err != nil {
		return errors.New("publication history path invalid")
	}
	data, err := boundedFile(context.Background(), verified, 4<<20)
	if err != nil {
		return errors.New("publication history unavailable")
	}
	var file clockFile
	if strictJSON(data, &file) != nil || file.Version != 1 || len(file.Receipts) > maxClockReceipts {
		return errors.New("publication history invalid")
	}
	for _, receipt := range file.Receipts {
		digest, err := decodeHash(receipt.Hash)
		if err != nil {
			return errors.New("publication history hash invalid")
		}
		published, err := timestamp(receipt.Published)
		if err != nil {
			return errors.New("publication history clock invalid")
		}
		if _, exists := e.clocks[digest]; exists {
			return errors.New("publication history duplicate hash")
		}
		e.clocks[digest] = published
	}
	return nil
}

func (e *Engine) retainClock(ctx context.Context, hash [32]byte, published time.Time) (time.Time, error) {
	e.clockMu.Lock()
	defer e.clockMu.Unlock()
	if e.closed || e.lock == nil {
		return time.Time{}, errors.New("admission engine is closed")
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if e.clocks == nil {
		e.clocks = map[[32]byte]time.Time{}
	}
	previous, exists := e.clocks[hash]
	if exists && !published.Before(previous) {
		return previous, nil
	}
	if !exists && len(e.clocks) >= maxClockReceipts {
		return time.Time{}, errors.New("publication history budget exceeded")
	}
	directory := filepath.Join(e.workspace, ".atlas-private")
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return time.Time{}, errors.New("publication history escaped workspace")
	}
	file := clockFile{Version: 1, Receipts: make([]clockReceipt, 0, len(e.clocks)+1)}
	for key, value := range e.clocks {
		if key != hash {
			file.Receipts = append(file.Receipts, clockReceipt{hashString(key), value.Format(time.RFC3339Nano)})
		}
	}
	file.Receipts = append(file.Receipts, clockReceipt{hashString(hash), published.Format(time.RFC3339Nano)})
	sort.Slice(file.Receipts, func(i, j int) bool { return file.Receipts[i].Hash < file.Receipts[j].Hash })
	data, err := json.Marshal(file)
	if err != nil || len(data) > 4<<20 {
		return time.Time{}, errors.New("publication history budget exceeded")
	}
	path := filepath.Join(directory, clockName)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() || err != nil && !errors.Is(err, os.ErrNotExist) {
		return time.Time{}, errors.New("publication history destination invalid")
	}
	temporary, err := os.CreateTemp(directory, "clock-*.partial")
	if err != nil {
		return time.Time{}, errors.New("publication history unavailable")
	}
	defer os.Remove(temporary.Name())
	if temporary.Chmod(0600) != nil {
		temporary.Close()
		return time.Time{}, errors.New("publication history unavailable")
	}
	_, err = temporary.Write(data)
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil || closeErr != nil || ctx.Err() != nil {
		return time.Time{}, errors.New("publication history write failed")
	}
	if os.Rename(temporary.Name(), path) != nil {
		return time.Time{}, errors.New("publication history replacement failed")
	}
	e.clocks[hash] = published
	return published, nil
}
