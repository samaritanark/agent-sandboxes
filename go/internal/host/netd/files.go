package netd

// The supervisor's files in its state directory.
const (
	LockFile      = "netd.lock" // held (flock) by the supervisor and the hypervisor while the VM lives
	PIDFile       = "netd.pid"
	VMPIDFile     = "vm.pid" // the hypervisor's process id
	SSHPortFile   = "ssh.port"
	EndpointsName = "endpoints" // declared host endpoints, one ip:port per line
)
