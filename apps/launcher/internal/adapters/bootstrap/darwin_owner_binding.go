//go:build darwin

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

type darwinIdentityCapability interface {
	PlatformUUID(context.Context) (string, error)
	UserUUID(context.Context, int) (string, error)
}

// DarwinOwnerBindingSource binds state to the native hardware platform UUID,
// effective UID, and membership UUID resolved for that invoking UID.
type DarwinOwnerBindingSource struct {
	identity     darwinIdentityCapability
	effectiveUID func() int
}

var _ bootstrapport.OwnerBindingSource = (*DarwinOwnerBindingSource)(nil)

// NewDarwinOwnerBindingSource creates the native macOS owner source. It fails
// closed when this build cannot provide IOKit and membership capabilities.
func NewDarwinOwnerBindingSource() (*DarwinOwnerBindingSource, error) {
	identity, err := newDarwinIdentityCapability()
	if err != nil {
		return nil, err
	}
	return newDarwinOwnerBindingSource(identity, os.Geteuid)
}

func newDarwinOwnerBindingSource(
	identity darwinIdentityCapability,
	effectiveUID func() int,
) (*DarwinOwnerBindingSource, error) {
	if nilDependency(identity) || effectiveUID == nil {
		return nil, errors.New("macOS owner source requires native identity and effective UID capabilities")
	}
	return &DarwinOwnerBindingSource{identity: identity, effectiveUID: effectiveUID}, nil
}

// Current resolves and hashes only canonical native identities. No username or
// raw UUID is retained in the returned binding.
func (s *DarwinOwnerBindingSource) Current(ctx context.Context) (install.OwnerBinding, error) {
	if err := ctx.Err(); err != nil {
		return install.OwnerBinding{}, err
	}
	if s == nil || nilDependency(s.identity) || s.effectiveUID == nil {
		return install.OwnerBinding{}, fmt.Errorf("%w: Darwin owner source is not configured", bootstrapport.ErrIntegrity)
	}
	uid := s.effectiveUID()
	if uid < 0 {
		return install.OwnerBinding{}, fmt.Errorf("%w: Darwin effective UID is invalid", bootstrapport.ErrIntegrity)
	}
	platformUUID, err := s.identity.PlatformUUID(ctx)
	if err != nil {
		return install.OwnerBinding{}, err
	}
	userUUID, err := s.identity.UserUUID(ctx, uid)
	if err != nil {
		return install.OwnerBinding{}, err
	}
	platformUUID, ok := canonicalDarwinUUID(platformUUID)
	if !ok {
		return install.OwnerBinding{}, fmt.Errorf("%w: Darwin platform UUID is invalid", bootstrapport.ErrIntegrity)
	}
	userUUID, ok = canonicalDarwinUUID(userUUID)
	if !ok {
		return install.OwnerBinding{}, fmt.Errorf("%w: Darwin user UUID is invalid", bootstrapport.ErrIntegrity)
	}
	if err := ctx.Err(); err != nil {
		return install.OwnerBinding{}, err
	}
	return install.BindOwner(
		"darwin:platform-uuid:"+platformUUID,
		"darwin:uid:"+strconv.Itoa(uid)+":user-uuid:"+userUUID,
	)
}

func canonicalDarwinUUID(value string) (string, bool) {
	if len(value) != 36 {
		return "", false
	}
	value = strings.ToLower(value)
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return "", false
			}
		default:
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return "", false
			}
		}
	}
	return value, true
}
