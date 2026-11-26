package brokerkey

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CredMan keeps the key as a generic credential in Windows Credential Manager, local to this
// machine (CRED_PERSIST_LOCAL_MACHINE: it does not roam with the profile).
type CredMan struct{ Target string }

var (
	advapi32      = windows.NewLazySystemDLL("advapi32.dll")
	procCredRead  = advapi32.NewProc("CredReadW")
	procCredWrite = advapi32.NewProc("CredWriteW")
	procCredFree  = advapi32.NewProc("CredFree")
)

// credential is CREDENTIALW.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
)

func (c CredMan) Where() string { return "Windows Credential Manager" }
func (c CredMan) Weak() bool    { return false }

func (c CredMan) Load() ([]byte, error) {
	target, err := windows.UTF16PtrFromString(c.Target)
	if err != nil {
		return nil, err
	}
	var p *credential
	r, _, err := procCredRead.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&p)))
	if r == 0 {
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			return nil, ErrNoKey
		}
		return nil, err
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(p)))
	blob := unsafe.Slice(p.CredentialBlob, p.CredentialBlobSize)
	key := append([]byte(nil), blob...)
	for i := range blob {
		blob[i] = 0
	}
	return key, nil
}

func (c CredMan) Save(key []byte) error {
	target, err := windows.UTF16PtrFromString(c.Target)
	if err != nil {
		return err
	}
	user, _ := windows.UTF16PtrFromString("sandbox")
	cred := credential{
		Type:               credTypeGeneric,
		TargetName:         target,
		CredentialBlobSize: uint32(len(key)),
		CredentialBlob:     &key[0],
		Persist:            credPersistLocalMachine,
		UserName:           user,
	}
	if r, _, err := procCredWrite.Call(uintptr(unsafe.Pointer(&cred)), 0); r == 0 {
		return err
	}
	return nil
}
