package broker

// The workload half of a cluster's deny-list (design 5.9.5; the rest is method and path rules,
// package kubeapi): a write to a cluster's API that asks for a workload reaching the node is
// refused, whatever the identity's role allows. The broker buffers the body of every POST, PUT,
// and PATCH to a cluster and looks, anywhere in it, for what lets a container out of its sandbox
// on the node: a privileged container, a hostPath volume, and the host's network, PID, or IPC
// namespace. That covers pods, every workload controller's pod template, custom resources that
// embed one, and JSON patches that set those fields. Bodies it cannot read (YAML that is not
// JSON, protobuf) are refused rather than passed.

import (
	"encoding/json"
	"strings"
)

// hostFlags are the pod spec fields that put a container in a node namespace.
var hostFlags = map[string]bool{"hostNetwork": true, "hostPID": true, "hostIPC": true}

// riskyWorkload is why a write's body may not go to the cluster, or "".
func riskyWorkload(contentType string, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	switch ct {
	case "", "application/json", "application/merge-patch+json", "application/strategic-merge-patch+json",
		"application/json-patch+json", "application/apply-patch+yaml":
	default:
		return "a " + ct + " body to a cluster, which the sandbox does not inspect (send JSON)"
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "a body to a cluster that is not JSON, which the sandbox does not inspect"
	}
	if ops, ok := v.([]any); ok && ct == "application/json-patch+json" {
		for _, o := range ops {
			if why := riskyPatchOp(o); why != "" {
				return why
			}
		}
	}
	return riskyValue(v)
}

// riskyValue walks a JSON value for the node-reaching fields.
func riskyValue(v any) string {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			switch {
			case k == "privileged" && val == true:
				return "a privileged container"
			case hostFlags[k] && val == true:
				return "a workload in the node's " + strings.TrimPrefix(strings.ToLower(k), "host") + " namespace (" + k + ")"
			case k == "hostPath" && val != nil:
				if _, ok := val.(map[string]any); ok {
					return "a hostPath volume"
				}
			}
			if why := riskyValue(val); why != "" {
				return why
			}
		}
	case []any:
		for _, e := range x {
			if why := riskyValue(e); why != "" {
				return why
			}
		}
	}
	return ""
}

// riskyPatchOp is a JSON Patch operation that sets a node-reaching field by its path.
func riskyPatchOp(o any) string {
	op, ok := o.(map[string]any)
	if !ok {
		return ""
	}
	path, _ := op["path"].(string)
	segs := strings.Split(path, "/")
	last := segs[len(segs)-1]
	for _, s := range segs {
		if s == "hostPath" {
			return "a hostPath volume"
		}
	}
	if op["value"] == true && (last == "privileged" || hostFlags[last]) {
		if last == "privileged" {
			return "a privileged container"
		}
		return "a workload in the node's " + strings.TrimPrefix(strings.ToLower(last), "host") + " namespace (" + last + ")"
	}
	return ""
}
