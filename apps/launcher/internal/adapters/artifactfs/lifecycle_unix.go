//go:build darwin || linux || windows

package artifactfs

import (
	"errors"
	"os"
)

func (s *Store) beginOperation() bool {
	if s == nil {
		return false
	}
	s.lifecycle.RLock()
	if s.closed || !s.valid() {
		s.lifecycle.RUnlock()
		return false
	}
	return true
}

func (s *Store) endOperation() { s.lifecycle.RUnlock() }

// Close releases retained directory descriptors. It is safe to call more than
// once and waits for in-flight operations to finish before closing them.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	identityError := closeDirectories(s.identityFile, s.identityDir)
	return errors.Join(identityError, closeDirectories(s.casRoot, s.reservationRoot, s.partialRoot, s.rootDirectory))
}

func (f *BundleFetcher) beginOperation() bool {
	if f == nil {
		return false
	}
	f.lifecycle.RLock()
	if f.closed || !safeBundleDirectoryDescriptor(f.rootDirectory, f.accessPolicy) {
		f.lifecycle.RUnlock()
		return false
	}
	return true
}

func (f *BundleFetcher) endOperation() { f.lifecycle.RUnlock() }

// Close releases the retained offline-bundle root descriptor idempotently.
func (f *BundleFetcher) Close() error {
	if f == nil {
		return nil
	}
	f.lifecycle.Lock()
	defer f.lifecycle.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	return closeDirectories(f.rootDirectory)
}

func closeDirectories(directories ...*os.File) error {
	var result error
	for _, directory := range directories {
		if directory != nil {
			result = errors.Join(result, directory.Close())
		}
	}
	return result
}
