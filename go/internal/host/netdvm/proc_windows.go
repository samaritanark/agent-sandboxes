//go:build windows

package netdvm

import (
	"context"
	"errors"
	"fmt"
	"os"
)

var errWindows = errors.New("the netd VM drivers (vfkit, qemu) do not run on Windows")

func (d *Driver) Start(context.Context) error  { return errWindows }
func (d *Driver) Stop(context.Context) error   { return errWindows }
func (d *Driver) Delete(context.Context) error { return errWindows }

func (d *Driver) ours(string, string) int { return 0 }

func NetdMain([]string) int {
	fmt.Fprintln(os.Stderr, errWindows)
	return 1
}
