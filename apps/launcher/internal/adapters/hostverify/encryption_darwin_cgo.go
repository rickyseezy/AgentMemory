//go:build darwin && cgo

package hostverify

/*
#cgo LDFLAGS: -framework CoreFoundation -framework DiskArbitration
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>

static int agentmemory_disk_encrypted(const char *path) {
	int result = 0;
	CFStringRef pathString = CFStringCreateWithCString(kCFAllocatorDefault, path, kCFStringEncodingUTF8);
	if (pathString == NULL) return 0;
	CFURLRef url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, pathString, kCFURLPOSIXPathStyle, true);
	CFRelease(pathString);
	if (url == NULL) return 0;
	DASessionRef session = DASessionCreate(kCFAllocatorDefault);
	if (session == NULL) { CFRelease(url); return 0; }
	DADiskRef disk = DADiskCreateFromVolumePath(kCFAllocatorDefault, session, url);
	CFRelease(url);
	if (disk == NULL) { CFRelease(session); return 0; }
	CFDictionaryRef description = DADiskCopyDescription(disk);
	if (description != NULL) {
		CFTypeRef encrypted = CFDictionaryGetValue(description, kDADiskDescriptionMediaEncryptedKey);
		CFTypeRef internal = CFDictionaryGetValue(description, kDADiskDescriptionDeviceInternalKey);
		CFTypeRef removable = CFDictionaryGetValue(description, kDADiskDescriptionMediaRemovableKey);
		if (encrypted != NULL && CFGetTypeID(encrypted) == CFBooleanGetTypeID() && CFBooleanGetValue((CFBooleanRef)encrypted) &&
			internal != NULL && CFGetTypeID(internal) == CFBooleanGetTypeID() && CFBooleanGetValue((CFBooleanRef)internal) &&
			removable != NULL && CFGetTypeID(removable) == CFBooleanGetTypeID() && !CFBooleanGetValue((CFBooleanRef)removable)) {
			result = 1;
		}
		CFRelease(description);
	}
	CFRelease(disk);
	CFRelease(session);
	return result;
}
*/
import "C"

import (
	"strings"
	"unsafe"
)

func darwinEncryptionAttested(path string) bool {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return false
	}
	cPath := C.CString(path)
	if cPath == nil {
		return false
	}
	defer C.free(unsafe.Pointer(cPath))
	return C.agentmemory_disk_encrypted(cPath) == 1
}
