//go:build windows

package windowssecurity

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	cryptMessageSignerCountParameter = uint32(5) // CMSG_SIGNER_COUNT_PARAM
	cryptMessageSignerInfoParameter  = uint32(7) // CMSG_SIGNER_CERT_INFO_PARAM
	maximumAuthenticodeSignerBytes   = 1 << 20
)

var (
	authenticodeCrypt32           = windows.NewLazySystemDLL("crypt32.dll")
	authenticodeCryptMessageParam = authenticodeCrypt32.NewProc("CryptMsgGetParam")
	authenticodeCryptMessageClose = authenticodeCrypt32.NewProc("CryptMsgClose")
)

// AuthenticodeLeafCertificateSHA256 extracts the one primary signer selected
// by the embedded PKCS#7 message and hashes the exact DER bytes of the matching
// certificate. The pathname is retained without write/delete sharing for the
// entire query so the certificate cannot be read from a substituted object.
func AuthenticodeLeafCertificateSHA256(
	ctx context.Context,
	path string,
) ([sha256.Size]byte, error) {
	if ctx == nil || ctx.Err() != nil || filepath.Clean(path) != path {
		return [sha256.Size]byte{}, ErrAuthenticodeIdentity
	}
	file, err := openAuthenticodeFile(ctx, path)
	if err != nil {
		return [sha256.Size]byte{}, ErrAuthenticodeIdentity
	}
	defer func() { _ = file.Close() }()
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return [sha256.Size]byte{}, ErrAuthenticodeIdentity
	}
	var encoding, contentType, formatType uint32
	var store, message windows.Handle
	err = windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(pathPointer), // #nosec G103 -- documented CryptQueryObject file-name ABI.
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&encoding,
		&contentType,
		&formatType,
		&store,
		&message,
		nil,
	)
	runtime.KeepAlive(pathPointer)
	if err != nil || store == 0 || message == 0 ||
		contentType != windows.CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED ||
		formatType != windows.CERT_QUERY_FORMAT_BINARY ||
		encoding&(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING) !=
			windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING {
		closeAuthenticodeHandles(store, message)
		return [sha256.Size]byte{}, ErrAuthenticodeIdentity
	}
	defer closeAuthenticodeHandles(store, message)

	signerInfo, err := exactAuthenticodeSignerInfo(message)
	if err != nil {
		return [sha256.Size]byte{}, ErrAuthenticodeIdentity
	}
	certificate, err := windows.CertFindCertificateInStore(
		store,
		encoding,
		0,
		windows.CERT_FIND_SUBJECT_CERT,
		unsafe.Pointer(signerInfo), // #nosec G103 -- documented CERT_INFO lookup boundary.
		nil,
	)
	runtime.KeepAlive(signerInfo)
	if err != nil || certificate == nil || certificate.EncodedCert == nil ||
		certificate.Length == 0 || certificate.Length > maximumAuthenticodeCertificateBytes {
		return [sha256.Size]byte{}, ErrAuthenticodeIdentity
	}
	defer func() { _ = windows.CertFreeCertificateContext(certificate) }()
	encoded := unsafe.Slice(certificate.EncodedCert, int(certificate.Length)) // #nosec G103 -- length is bounded above.
	digest, err := authenticodeCertificateDigest(encoded)
	runtime.KeepAlive(certificate)
	if err != nil || ctx.Err() != nil || !sameAuthenticodeFile(file, path) {
		return [sha256.Size]byte{}, ErrAuthenticodeIdentity
	}
	return digest, nil
}

func openAuthenticodeFile(ctx context.Context, path string) (*os.File, error) {
	if err := ValidateLocalPath(path); err != nil {
		return nil, err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, ErrAuthenticodeIdentity
	}
	if !sameAuthenticodeFile(file, path) || ctx.Err() != nil {
		_ = file.Close()
		return nil, errors.Join(ErrAuthenticodeIdentity, ctx.Err())
	}
	return file, nil
}

func sameAuthenticodeFile(file *os.File, path string) bool {
	if file == nil {
		return false
	}
	var information windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information) != nil ||
		information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|
			windows.FILE_ATTRIBUTE_DEVICE) != 0 || information.NumberOfLinks != 1 {
		return false
	}
	pathInfo, pathError := os.Lstat(path)
	openedInfo, openedError := file.Stat()
	return pathError == nil && openedError == nil && pathInfo.Mode().IsRegular() &&
		pathInfo.Mode()&os.ModeSymlink == 0 && os.SameFile(pathInfo, openedInfo)
}

func exactAuthenticodeSignerInfo(message windows.Handle) (*windows.CertInfo, error) {
	var count, countBytes uint32 = 0, uint32(unsafe.Sizeof(uint32(0)))
	if !cryptMessageGetParameter(message, cryptMessageSignerCountParameter, 0, unsafe.Pointer(&count), &countBytes) ||
		countBytes != uint32(unsafe.Sizeof(count)) || count != 1 {
		return nil, ErrAuthenticodeIdentity
	}
	var signerBytes uint32
	if !cryptMessageGetParameter(message, cryptMessageSignerInfoParameter, 0, nil, &signerBytes) ||
		signerBytes < uint32(unsafe.Sizeof(windows.CertInfo{})) || signerBytes > maximumAuthenticodeSignerBytes {
		return nil, ErrAuthenticodeIdentity
	}
	buffer := make([]byte, signerBytes)
	if !cryptMessageGetParameter(
		message,
		cryptMessageSignerInfoParameter,
		0,
		unsafe.Pointer(&buffer[0]), // #nosec G103 -- buffer size comes from the bounded API query.
		&signerBytes,
	) || signerBytes < uint32(unsafe.Sizeof(windows.CertInfo{})) || signerBytes > uint32(len(buffer)) {
		return nil, ErrAuthenticodeIdentity
	}
	info := (*windows.CertInfo)(unsafe.Pointer(&buffer[0])) // #nosec G103 -- exact CMSG_SIGNER_CERT_INFO_PARAM ABI.
	runtime.KeepAlive(buffer)
	return info, nil
}

func cryptMessageGetParameter(
	message windows.Handle,
	parameter,
	index uint32,
	data unsafe.Pointer,
	size *uint32,
) bool {
	result, _, _ := authenticodeCryptMessageParam.Call(
		uintptr(message),
		uintptr(parameter),
		uintptr(index),
		uintptr(data),                 // #nosec G103 -- documented CryptMsgGetParam ABI.
		uintptr(unsafe.Pointer(size)), // #nosec G103 -- documented CryptMsgGetParam ABI.
	)
	runtime.KeepAlive(data)
	runtime.KeepAlive(size)
	return result != 0
}

func closeAuthenticodeHandles(store, message windows.Handle) {
	if message != 0 {
		_, _, _ = authenticodeCryptMessageClose.Call(uintptr(message))
	}
	if store != 0 {
		_ = windows.CertCloseStore(store, 0)
	}
}
