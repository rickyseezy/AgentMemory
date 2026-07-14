package secretprojector

import "testing"

func TestPF001DefaultProjectionContractIsClosedAndLeastPrivilege(t *testing.T) {
	t.Parallel()

	contract := defaultContract()
	if len(contract) != 6 || contract[0].purpose != purposeCore || len(contract[0].files) != 8 {
		t.Fatalf("default contract = %#v", contract)
	}
	if contract[1].files[0].userID != 10_001 || contract[2].files[0].userID != 7474 ||
		contract[2].files[0].groupID != 7474 || contract[0].files[7].maxBytes != maximumAttestationBytes {
		t.Fatalf("projection ownership/length contract = %#v", contract)
	}
	seen := make(map[string]struct{}, len(contract))
	for _, volume := range contract {
		if volume.purpose == "" || len(volume.files) == 0 {
			t.Fatalf("empty projection contract = %#v", volume)
		}
		if _, duplicate := seen[volume.purpose]; duplicate {
			t.Fatalf("duplicate projection purpose %q", volume.purpose)
		}
		seen[volume.purpose] = struct{}{}
		for _, file := range volume.files {
			if file.name == "" || file.maxBytes == 0 || inputPath(file.name) == inputRoot ||
				outputPath(volume.purpose) == outputRoot {
				t.Fatalf("invalid projection file = %#v", file)
			}
		}
	}
}
