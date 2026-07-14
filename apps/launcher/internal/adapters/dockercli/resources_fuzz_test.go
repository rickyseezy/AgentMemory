package dockercli

import "testing"

func FuzzPF001ManagedResourceJSONDuplicateScanner(f *testing.F) {
	f.Add([]byte(`{"Name":"agentmemory_example","Labels":{"a":"b"}}`))
	f.Add([]byte(`{"Name":"first","Name":"second"}`))
	f.Add([]byte(`[{"nested":[true,false,null,1]}]`))
	f.Fuzz(func(_ *testing.T, payload []byte) {
		_ = rejectDuplicateJSONKeys(payload)
	})
}
