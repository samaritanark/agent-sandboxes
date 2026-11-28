//go:build !linux

package main

func uname() (release, version string) { return "", "" }
