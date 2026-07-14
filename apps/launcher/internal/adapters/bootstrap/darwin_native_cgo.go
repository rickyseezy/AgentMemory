//go:build darwin && cgo

package bootstrap

/*
#cgo LDFLAGS: -framework Security -framework IOKit -framework CoreFoundation -framework LocalAuthentication
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOKitKeys.h>
#include <Security/Security.h>
#include <membership.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

void *am_create_no_ui_authentication_context(void);
void am_release_authentication_context(void *pointer);

static int am_copy_platform_uuid(char *output, size_t capacity) {
	io_service_t service = IOServiceGetMatchingService(
		kIOMainPortDefault,
		IOServiceMatching("IOPlatformExpertDevice")
	);
	if (service == IO_OBJECT_NULL) {
		return 1;
	}
	CFTypeRef value = IORegistryEntryCreateCFProperty(
		service,
		CFSTR(kIOPlatformUUIDKey),
		kCFAllocatorDefault,
		0
	);
	IOObjectRelease(service);
	if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID()) {
		if (value != NULL) CFRelease(value);
		return 2;
	}
	Boolean copied = CFStringGetCString((CFStringRef)value, output, capacity, kCFStringEncodingUTF8);
	CFRelease(value);
	return copied ? 0 : 3;
}

static int am_copy_user_uuid(uid_t uid, char *output, size_t capacity) {
	if (capacity < 37) return 1;
	uuid_t value;
	int result = mbr_uid_to_uuid(uid, value);
	if (result != 0) return result;
	uuid_unparse_lower(value, output);
	return 0;
}

static CFStringRef am_cfstring(const char *value) {
	return CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
}

static CFDictionaryRef am_keychain_query(const char *service_value, const char *account_value, Boolean include_return) {
	CFStringRef service = am_cfstring(service_value);
	CFStringRef account = am_cfstring(account_value);
	void *authentication_context = am_create_no_ui_authentication_context();
	if (service == NULL || account == NULL || authentication_context == NULL) {
		if (service != NULL) CFRelease(service);
		if (account != NULL) CFRelease(account);
		if (authentication_context != NULL) am_release_authentication_context(authentication_context);
		return NULL;
	}
	const void *keys[9];
	const void *values[9];
	CFIndex count = 0;
	keys[count] = kSecClass; values[count++] = kSecClassGenericPassword;
	keys[count] = kSecAttrService; values[count++] = service;
	keys[count] = kSecAttrAccount; values[count++] = account;
	keys[count] = kSecAttrSynchronizable; values[count++] = kCFBooleanFalse;
	keys[count] = kSecUseDataProtectionKeychain; values[count++] = kCFBooleanTrue;
	keys[count] = kSecUseAuthenticationContext; values[count++] = authentication_context;
	if (include_return) {
		keys[count] = kSecReturnData; values[count++] = kCFBooleanTrue;
		keys[count] = kSecMatchLimit; values[count++] = kSecMatchLimitOne;
	}
	CFDictionaryRef query = CFDictionaryCreate(
		kCFAllocatorDefault,
		keys,
		values,
		count,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	CFRelease(service);
	CFRelease(account);
	am_release_authentication_context(authentication_context);
	return query;
}

static OSStatus am_keychain_add(
	const char *service_value,
	const char *account_value,
	const unsigned char *bytes,
	size_t length
) {
	CFDictionaryRef base = am_keychain_query(service_value, account_value, false);
	if (base == NULL) return errSecAllocate;
	CFMutableDictionaryRef query = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, base);
	CFRelease(base);
	if (query == NULL) return errSecAllocate;
	CFDataRef data = CFDataCreate(kCFAllocatorDefault, bytes, (CFIndex)length);
	if (data == NULL) {
		CFRelease(query);
		return errSecAllocate;
	}
	CFDictionarySetValue(query, kSecValueData, data);
	CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
	OSStatus status = SecItemAdd(query, NULL);
	CFRelease(data);
	CFRelease(query);
	return status;
}

static OSStatus am_keychain_get(
	const char *service_value,
	const char *account_value,
	unsigned char **output,
	size_t *length
) {
	*output = NULL;
	*length = 0;
	CFDictionaryRef query = am_keychain_query(service_value, account_value, true);
	if (query == NULL) return errSecAllocate;
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status != errSecSuccess) return status;
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result != NULL) CFRelease(result);
		return errSecDecode;
	}
	CFDataRef data = (CFDataRef)result;
	CFIndex count = CFDataGetLength(data);
	if (count <= 0 || count > 4096) {
		CFRelease(result);
		return errSecDecode;
	}
	unsigned char *copy = (unsigned char *)malloc((size_t)count);
	if (copy == NULL) {
		CFRelease(result);
		return errSecAllocate;
	}
	memcpy(copy, CFDataGetBytePtr(data), (size_t)count);
	CFRelease(result);
	*output = copy;
	*length = (size_t)count;
	return errSecSuccess;
}

static OSStatus am_keychain_delete(const char *service_value, const char *account_value) {
	CFDictionaryRef query = am_keychain_query(service_value, account_value, false);
	if (query == NULL) return errSecAllocate;
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	return status;
}

static void am_zero_free(void *pointer, size_t length) {
	if (pointer == NULL) return;
	(void)memset_s(pointer, length, 0, length);
	free(pointer);
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"unsafe"
)

type darwinNativeIdentity struct{}

func newDarwinIdentityCapability() (darwinIdentityCapability, error) {
	return darwinNativeIdentity{}, nil
}

func (darwinNativeIdentity) PlatformUUID(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	buffer := make([]byte, 64)
	result := C.am_copy_platform_uuid((*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer)))
	if result != 0 {
		return "", fmt.Errorf("read native Darwin platform UUID: status %d", int(result))
	}
	return cStringFromBuffer(buffer), nil
}

func (darwinNativeIdentity) UserUUID(ctx context.Context, uid int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if uid < 0 {
		return "", errors.New("macOS UID must not be negative")
	}
	buffer := make([]byte, 64)
	result := C.am_copy_user_uuid(
		C.uid_t(uid),
		(*C.char)(unsafe.Pointer(&buffer[0])),
		C.size_t(len(buffer)),
	)
	if result != 0 {
		return "", fmt.Errorf("resolve native Darwin user UUID: status %d", int(result))
	}
	return cStringFromBuffer(buffer), nil
}

func cStringFromBuffer(buffer []byte) string {
	for index, value := range buffer {
		if value == 0 {
			return string(buffer[:index])
		}
	}
	return string(buffer)
}

type darwinNativeKeychain struct{ service string }

func newDarwinKeychainCapability(service string) (darwinKeychainCapability, error) {
	if service == "" {
		return nil, errors.New("macOS Keychain service is required")
	}
	return &darwinNativeKeychain{service: service}, nil
}

func (k *darwinNativeKeychain) Add(ctx context.Context, account string, record []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if account == "" || len(record) == 0 {
		return errors.New("macOS Keychain account and record are required")
	}
	service := C.CString(k.service)
	accountValue := C.CString(account)
	secret := C.CBytes(record)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(accountValue))
	defer C.am_zero_free(secret, C.size_t(len(record)))
	status := C.am_keychain_add(
		service,
		accountValue,
		(*C.uchar)(secret),
		C.size_t(len(record)),
	)
	return mapDarwinKeychainStatus("add", status)
}

func (k *darwinNativeKeychain) Get(ctx context.Context, account string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if account == "" {
		return nil, errors.New("macOS Keychain account is required")
	}
	service := C.CString(k.service)
	accountValue := C.CString(account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(accountValue))
	var output *C.uchar
	var length C.size_t
	//nolint:gocritic // cgo exposes distinct output and length pointers despite dupSubExpr's generated-AST false positive.
	status := C.am_keychain_get(service, accountValue, &output, &length)
	if err := mapDarwinKeychainStatus("get", status); err != nil {
		return nil, err
	}
	defer C.am_zero_free(unsafe.Pointer(output), length)
	if uint64(length) > uint64(^uint(0)>>1) {
		return nil, errors.New("macOS Keychain record exceeds addressable memory")
	}
	return C.GoBytes(unsafe.Pointer(output), C.int(length)), nil
}

func (k *darwinNativeKeychain) delete(ctx context.Context, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	service := C.CString(k.service)
	accountValue := C.CString(account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(accountValue))
	return mapDarwinKeychainStatus("delete", C.am_keychain_delete(service, accountValue))
}

func mapDarwinKeychainStatus(operation string, status C.OSStatus) error {
	return mapDarwinKeychainStatusCode(operation, int32(status))
}

var (
	darwinKeychainStatusSuccess   = int32(C.errSecSuccess)
	darwinKeychainStatusDuplicate = int32(C.errSecDuplicateItem)
	darwinKeychainStatusNotFound  = int32(C.errSecItemNotFound)
)

func mapDarwinKeychainStatusCode(operation string, status int32) error {
	switch status {
	case darwinKeychainStatusSuccess:
		return nil
	case darwinKeychainStatusDuplicate:
		return errDarwinKeychainDuplicate
	case darwinKeychainStatusNotFound:
		return errDarwinKeychainNotFound
	default:
		return fmt.Errorf("macOS Keychain %s failed with status %d", operation, status)
	}
}
