package dockercli

import (
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

// Executors is the closed, release-bound Docker toolchain. Docker Engine and
// Compose are independent executables and runners; ambient CLI-plugin lookup
// is never part of execution authority.
type Executors struct {
	docker           argvprocess.Runner
	compose          argvprocess.Runner
	dockerAuthority  argvprocess.ExecutableAuthority
	composeAuthority argvprocess.ExecutableAuthority
}

// NewExecutors accepts exactly one Docker CLI and one direct Compose
// executable from the same signed release manifest and runtime plan.
func NewExecutors(docker, compose argvprocess.Runner) (Executors, error) {
	if nilRunner(docker) || nilRunner(compose) {
		return Executors{}, argvprocess.ErrInvalidInvocation
	}
	dockerAuthority := docker.ExecutableAuthority()
	composeAuthority := compose.ExecutableAuthority()
	if !dockerAuthority.Valid() || !composeAuthority.Valid() ||
		dockerAuthority.Role() != argvprocess.ExecutableRoleDockerCLI ||
		composeAuthority.Role() != argvprocess.ExecutableRoleComposePlugin ||
		!dockerAuthority.SameSignedPlan(composeAuthority) ||
		dockerAuthority.CanonicalID() == composeAuthority.CanonicalID() ||
		dockerAuthority.CanonicalPath() == composeAuthority.CanonicalPath() {
		return Executors{}, argvprocess.ErrInvalidInvocation
	}
	return Executors{
		docker: docker, compose: compose,
		dockerAuthority: dockerAuthority, composeAuthority: composeAuthority,
	}, nil
}

func (e Executors) valid() bool {
	return !nilRunner(e.docker) && !nilRunner(e.compose) && e.dockerAuthority.Valid() &&
		e.composeAuthority.Valid() && e.dockerAuthority.Role() == argvprocess.ExecutableRoleDockerCLI &&
		e.composeAuthority.Role() == argvprocess.ExecutableRoleComposePlugin &&
		e.dockerAuthority.SameSignedPlan(e.composeAuthority) &&
		e.docker.ExecutableAuthority().Equal(e.dockerAuthority) &&
		e.compose.ExecutableAuthority().Equal(e.composeAuthority)
}

func (e Executors) dockerBinding() (argvprocess.Runner, string, error) {
	if !e.valid() {
		return nil, "", argvprocess.ErrInvalidInvocation
	}
	return e.docker, e.dockerAuthority.CanonicalPath(), nil
}

func (e Executors) composeBinding() (argvprocess.Runner, string, error) {
	if !e.valid() {
		return nil, "", argvprocess.ErrInvalidInvocation
	}
	return e.compose, e.composeAuthority.CanonicalPath(), nil
}

// SessionRunners returns the independently authorized Docker and Compose
// capabilities needed by the transient MCP composition. The verified runners
// remain inseparable from their executable authorities, so callers cannot
// substitute a PATH lookup or an ambient Compose plugin.
func (e Executors) SessionRunners() (
	argvprocess.StreamingRunner,
	argvprocess.Runner,
	error,
) {
	if !e.valid() {
		return nil, nil, argvprocess.ErrInvalidInvocation
	}
	docker, ok := e.docker.(argvprocess.StreamingRunner)
	if !ok || nilRunner(docker) {
		return nil, nil, argvprocess.ErrInvalidInvocation
	}
	return docker, e.compose, nil
}

func nilRunner(runner argvprocess.Runner) bool {
	if runner == nil {
		return true
	}
	value := reflect.ValueOf(runner)
	//nolint:exhaustive // Non-nilable reflection kinds are intentionally handled by default.
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

var errInvalidExecutors = errors.New("docker and Compose executors must be independently authorized by one signed plan")
