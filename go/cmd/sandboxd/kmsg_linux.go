//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/auditlog"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
)

// followDrops reads the kernel log from now on and records each session's link drops (the
// gateway namespaces' nftables log them as "sbx <session> <rule> ...") in that session's audit log.
func followDrops(ctx context.Context, d *daemon.Daemon) error {
	f, err := os.Open("/dev/kmsg")
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); f.Close() }()
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	for {
		n, err := f.Read(buf) // one record per read
		if errors.Is(err, syscall.EPIPE) {
			continue // records were overwritten before we read them
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		rec := string(buf[:n])
		if i := strings.IndexByte(rec, ';'); i >= 0 {
			rec = rec[i+1:]
		}
		if session, fields, ok := auditlog.Drop(strings.TrimSpace(rec)); ok {
			d.RecordDrop(session, fields)
		}
	}
}
