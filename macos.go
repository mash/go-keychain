// +build darwin,!ios

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"os"
)

// AccessibleKey is key for kSecAttrAccessible
var AccessibleKey = attrKey(C.CFTypeRef(C.kSecAttrAccessible))
var accessibleTypeRef = map[Accessible]C.CFTypeRef{
	AccessibleWhenUnlocked:                   C.CFTypeRef(C.kSecAttrAccessibleWhenUnlocked),
	AccessibleAfterFirstUnlock:               C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlock),
	AccessibleAlways:                         C.CFTypeRef(C.kSecAttrAccessibleAlways),
	AccessibleWhenUnlockedThisDeviceOnly:     C.CFTypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
	AccessibleAfterFirstUnlockThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
	AccessibleAccessibleAlwaysThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAlwaysThisDeviceOnly),

	// Only available in 10.10
	//AccessibleWhenPasscodeSetThisDeviceOnly:  C.CFTypeRef(C.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly),
}

// DeleteItemRef deletes a keychain item reference.
func DeleteItemRef(ref C.CFTypeRef) error {
	errCode := C.SecKeychainItemDelete(C.SecKeychainItemRef(ref))
	return checkError(errCode)
}

var (
	// KeychainKey is key for kSecUseKeychain
	KeychainKey = attrKey(C.CFTypeRef(C.kSecUseKeychain))
	// MatchSearchListKey is key for kSecMatchSearchList
	MatchSearchListKey = attrKey(C.CFTypeRef(C.kSecMatchSearchList))
)

// Keychain represents the path to a specific OSX keychain
type Keychain struct {
	path string
}

// NewWithPath to use an existing keychain
func NewWithPath(path string) Keychain {
	return Keychain{
		path: path,
	}
}

// Delete the Keychain
func (kc *Keychain) Delete() error {
	return os.Remove(kc.path)
}

type keychainArray []Keychain

// SetMatchSearchList sets match type on keychains
func (k *Item) SetMatchSearchList(karr ...Keychain) {
	k.attr[MatchSearchListKey] = keychainArray(karr)
}

// UseKeychain tells item to use the specified Keychain
func (k *Item) UseKeychain(kc Keychain) {
	k.attr[KeychainKey] = kc
}
