package agentfim

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchPaths watches FIM paths and invokes onChange (debounced) when files change.
// Missing paths are skipped until they appear (best-effort).
func WatchPaths(log *slog.Logger, paths []string, onChange func()) (stop func(), err error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	added := 0
	for _, p := range paths {
		p = filepath.Clean(p)
		if _, err := os.Stat(p); err != nil {
			log.Info("fim watch skip", "path", p, "err", err)
			continue
		}
		if err := watcher.Add(p); err != nil {
			log.Warn("fim watch add", "path", p, "err", err)
			continue
		}
		added++
	}
	log.Info("fim watcher started", "watching", added)

	done := make(chan struct{})
	go func() {
		var timer *time.Timer
		fire := func() {
			onChange()
		}
		for {
			select {
			case <-done:
				if timer != nil {
					timer.Stop()
				}
				_ = watcher.Close()
				return
			case ev, ok := <-watcher.Events:
				if !ok {
					return
				}
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
					continue
				}
				log.Info("fim change", "path", ev.Name, "op", ev.Op.String())
				if timer != nil {
					timer.Stop()
				}
				timer = time.AfterFunc(750*time.Millisecond, fire)
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Warn("fim watch error", "err", err)
			}
		}
	}()

	return func() { close(done) }, nil
}
