//go:build !linux

package main

import "errors"

func serve() error { return errors.New("sandboxd runs only in the appliance VM (Linux)") }
