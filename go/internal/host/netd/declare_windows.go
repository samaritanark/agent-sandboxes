//go:build windows

package netd

func lockEndpoints(string) (func(), error) { return nil, errWindows }
