//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/capacityhelper"
)

func TestPF001CapacityHelperCommandEmitsOnlyCanonicalStdout(t *testing.T) {
	t.Parallel()
	request := commandRequest(t)
	var stdout, stderr bytes.Buffer
	if code := run(request.Arguments(), &stdout, &stderr, commandStore{}); code != 0 || stderr.Len() != 0 {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
	response, err := capacityhelper.ParseResponseLine(stdout.Bytes())
	if err != nil || response.LeaseID != request.LeaseID() {
		t.Fatalf("response=%+v error=%v", response, err)
	}
}

func TestPF001CapacityHelperCommandUsesOneFixedFailureMessage(t *testing.T) {
	t.Parallel()
	request := commandRequest(t)
	for _, test := range []struct {
		name   string
		store  capacityhelper.Store
		stdout *failingCommandWriter
	}{
		{name: "nil store"},
		{name: "store failure", store: commandStore{fail: true}},
		{name: "stdout failure", store: commandStore{}, stdout: &failingCommandWriter{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			writer := interface{ Write([]byte) (int, error) }(&stdout)
			if test.stdout != nil {
				writer = test.stdout
			}
			var stderr bytes.Buffer
			if code := run(request.Arguments(), writer, &stderr, test.store); code != 1 ||
				stderr.String() != "capacity helper operation failed\n" {
				t.Fatalf("run code=%d stderr=%q", code, stderr.String())
			}
		})
	}
}

type commandStore struct{ fail bool }

func (s commandStore) Reserve(_ context.Context, request capacityhelper.Request) (capacityhelper.Observation, error) {
	if s.fail {
		return capacityhelper.Observation{}, errors.New("failed")
	}
	metadata, err := capacityhelper.NewMetadata(request, request.Owner(), capacityhelper.MetadataReserved)
	if err != nil {
		return capacityhelper.Observation{}, err
	}
	return capacityhelper.Observation{
		AllocatedBlockBytes: request.Bytes(), AvailableBytes: 8192, FileSizeBytes: request.Bytes(),
		Metadata: metadata, Owner: request.Owner(), State: string(capacityhelper.MetadataReserved),
	}, nil
}

func (s commandStore) Inspect(context.Context, capacityhelper.Request) (capacityhelper.Observation, error) {
	return capacityhelper.Observation{}, errors.New("unexpected inspect")
}

func (s commandStore) Transfer(context.Context, capacityhelper.Request) (capacityhelper.Observation, error) {
	return capacityhelper.Observation{}, errors.New("unexpected transfer")
}

func (s commandStore) ActivateProjection(context.Context, capacityhelper.Request) (capacityhelper.Observation, error) {
	return capacityhelper.Observation{}, errors.New("unexpected projection activation")
}

func (s commandStore) DeleteProof(context.Context, capacityhelper.Request) (capacityhelper.Observation, error) {
	return capacityhelper.Observation{}, errors.New("unexpected delete")
}

type failingCommandWriter struct{}

func (*failingCommandWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func commandRequest(t *testing.T) capacityhelper.Request {
	t.Helper()
	request, err := capacityhelper.NewRequest(capacityhelper.RequestInput{
		Operation: capacityhelper.OperationReserve, LeaseID: "l-" + strings.Repeat("a", 64),
		PlanDigest: strings.Repeat("b", 64), PoolID: "d-" + strings.Repeat("c", 64),
		PoolKind: "docker-engine", Bytes: 4096, Owner: "install-owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	return request
}
