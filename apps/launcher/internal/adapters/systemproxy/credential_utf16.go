package systemproxy

import (
	"unicode/utf16"
	"unicode/utf8"
)

// utf16CredentialBytes converts one bounded, null-terminated native credential
// field directly into mutable UTF-8 bytes. It deliberately avoids immutable Go
// strings so callers can clear every owned plaintext copy.
func utf16CredentialBytes(value []uint16) ([]byte, bool) {
	if len(value) == 0 {
		return nil, false
	}
	terminator := -1
	for index, unit := range value {
		if unit == 0 {
			terminator = index
			break
		}
	}
	if terminator < 0 {
		return nil, false
	}
	result := make([]byte, 0, terminator*utf8.UTFMax)
	for index := 0; index < terminator; index++ {
		unit := rune(value[index])
		switch {
		case unit >= 0xD800 && unit <= 0xDBFF:
			if index+1 >= terminator {
				clear(result)
				return nil, false
			}
			next := rune(value[index+1])
			if next < 0xDC00 || next > 0xDFFF {
				clear(result)
				return nil, false
			}
			unit = utf16.DecodeRune(unit, next)
			index++
		case unit >= 0xDC00 && unit <= 0xDFFF:
			clear(result)
			return nil, false
		}
		result = utf8.AppendRune(result, unit)
	}
	return result, true
}
