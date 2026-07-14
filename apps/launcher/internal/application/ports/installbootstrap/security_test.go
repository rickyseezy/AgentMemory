package installbootstrap

import (
	"errors"
	"testing"
)

func TestPF001BootstrapSecurityErrorsRemainDistinct(t *testing.T) {
	t.Parallel()
	if errors.Is(ErrNotFound, ErrConflict) || errors.Is(ErrNotFound, ErrIntegrity) || errors.Is(ErrConflict, ErrIntegrity) {
		t.Fatal("bootstrap security error taxonomy collapsed")
	}
}
