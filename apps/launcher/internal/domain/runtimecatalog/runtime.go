package runtimecatalog

import "errors"

// RuntimeComponentInput declares one exact component version.
type RuntimeComponentInput struct {
	Name    ComponentName
	Version string
}

// RuntimeComponent is an immutable exact component selection.
type RuntimeComponent struct {
	name    ComponentName
	version string
}

// Name returns the closed component identity.
func (c RuntimeComponent) Name() ComponentName { return c.name }

// Version returns the exact immutable version.
func (c RuntimeComponent) Version() string { return c.version }

// RuntimePolicyInput declares the certified stable runtime and Compose versions.
type RuntimePolicyInput struct {
	Product        RuntimeProduct
	Channel        RuntimeChannel
	Version        string
	ComposeVersion string
	Components     []RuntimeComponentInput
}

// RuntimePolicy is an immutable exact runtime inventory.
type RuntimePolicy struct {
	product        RuntimeProduct
	channel        RuntimeChannel
	version        string
	composeVersion string
	components     []RuntimeComponent
}

func newRuntimePolicy(input RuntimePolicyInput, platform OSKind) (RuntimePolicy, error) {
	if !input.Product.valid() || input.Channel != StableChannel || !validStableVersion(input.Version) ||
		!validStableVersion(input.ComposeVersion) || len(input.Components) < 5 || len(input.Components) > 6 ||
		platform == OSKindLinux && input.Product != RuntimeProductDockerEngine ||
		platform != OSKindLinux && input.Product != RuntimeProductDockerDesktop {
		return RuntimePolicy{}, ErrManifestIntegrity
	}
	components := make([]RuntimeComponent, 0, len(input.Components))
	seen := make(map[ComponentName]struct{}, len(input.Components))
	previousRank := 0
	for _, candidate := range input.Components {
		rank := componentRank(candidate.Name)
		if !candidate.Name.valid() || !validStableVersion(candidate.Version) || rank <= previousRank {
			return RuntimePolicy{}, ErrManifestIntegrity
		}
		if _, duplicate := seen[candidate.Name]; duplicate {
			return RuntimePolicy{}, ErrManifestIntegrity
		}
		seen[candidate.Name] = struct{}{}
		previousRank = rank
		components = append(components, RuntimeComponent{name: candidate.Name, version: candidate.Version})
	}
	for _, required := range []ComponentName{
		ComponentEngine, ComponentCLI, ComponentContainerd, ComponentBuildx, ComponentCompose,
	} {
		if _, present := seen[required]; !present {
			return RuntimePolicy{}, ErrManifestIntegrity
		}
	}
	if componentVersion(components, ComponentEngine) != input.Version ||
		componentVersion(components, ComponentCompose) != input.ComposeVersion ||
		platform == OSKindLinux && componentVersion(components, ComponentRootlessExtras) == "" {
		return RuntimePolicy{}, ErrManifestIntegrity
	}
	return RuntimePolicy{
		product: input.Product, channel: input.Channel, version: input.Version,
		composeVersion: input.ComposeVersion, components: components,
	}, nil
}

func validStableVersion(value string) bool {
	_, err := parseStableVersion(value)
	return err == nil
}

func componentVersion(components []RuntimeComponent, wanted ComponentName) string {
	for _, component := range components {
		if component.name == wanted {
			return component.version
		}
	}
	return ""
}

// Product returns the exact vendor product.
func (p RuntimePolicy) Product() RuntimeProduct { return p.product }

// Channel returns the stable vendor channel.
func (p RuntimePolicy) Channel() RuntimeChannel { return p.channel }

// Version returns the exact runtime version.
func (p RuntimePolicy) Version() string { return p.version }

// ComposeVersion returns the exact Compose plugin version.
func (p RuntimePolicy) ComposeVersion() string { return p.composeVersion }

// Components returns a defensive copy of the exact component inventory.
func (p RuntimePolicy) Components() []RuntimeComponent {
	return append([]RuntimeComponent(nil), p.components...)
}

func (p RuntimePolicy) valid(platform OSKind) bool {
	inputs := make([]RuntimeComponentInput, 0, len(p.components))
	for _, component := range p.components {
		inputs = append(inputs, RuntimeComponentInput{Name: component.name, Version: component.version})
	}
	validated, err := newRuntimePolicy(RuntimePolicyInput{
		Product: p.product, Channel: p.channel, Version: p.version,
		ComposeVersion: p.composeVersion, Components: inputs,
	}, platform)
	return err == nil && len(validated.components) == len(p.components)
}

// RuntimeComponentFor returns one exact component or a closed error.
func (p RuntimePolicy) RuntimeComponentFor(name ComponentName) (RuntimeComponent, error) {
	for _, component := range p.components {
		if component.name == name {
			return component, nil
		}
	}
	return RuntimeComponent{}, errors.New("runtime component is not declared")
}
