package containerengine

import (
	"errors"
	"testing"
)

func TestPF001ContainerEndpointAcceptsOnlyLocalTransports(t *testing.T) {
	t.Parallel()

	accepted := []string{
		"unix:///var/run/docker.sock",
		"unix:///Users/name with space/.docker/run/docker.sock",
		"npipe:////./pipe/docker_engine",
	}
	for _, value := range accepted {
		value := value
		t.Run("accept "+value, func(t *testing.T) {
			t.Parallel()
			endpoint, err := NewEndpoint(value)
			if err != nil || endpoint.String() != value {
				t.Fatalf("endpoint/error = %q/%v", endpoint.String(), err)
			}
		})
	}

	rejected := []string{
		"",
		"default",
		"tcp://127.0.0.1:2375",
		"tcp://example.com:2376",
		"ssh://host",
		"http://localhost",
		"unix://relative.sock",
		"unix:///var/run/../docker.sock",
		"unix:///var//run/docker.sock",
		"npipe:////./pipe/../docker_engine",
		"unix:///var/run/docker.sock\n--context=evil",
	}
	for _, value := range rejected {
		value := value
		t.Run("reject "+value, func(t *testing.T) {
			t.Parallel()
			if _, err := NewEndpoint(value); !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
