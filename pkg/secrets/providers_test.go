package secrets

import "testing"

func TestAWSSM_Name(t *testing.T) {
	p := NewAWSSM("us-east-1", testLogger())
	if p.Name() != "aws_sm" {
		t.Fatalf("expected aws_sm, got %s", p.Name())
	}
}

func TestAWSSM_Available(t *testing.T) {
	p := NewAWSSM("", testLogger())
	if p.Available() {
		t.Fatal("expected not available with empty region")
	}
	p = NewAWSSM("us-east-1", testLogger())
	if !p.Available() {
		t.Fatal("expected available with region set")
	}
}

func TestGCPSM_Name(t *testing.T) {
	p := NewGCPSM("my-project", "", testLogger())
	if p.Name() != "gcp_sm" {
		t.Fatalf("expected gcp_sm, got %s", p.Name())
	}
}

func TestGCPSM_Available(t *testing.T) {
	p := NewGCPSM("", "", testLogger())
	if p.Available() {
		t.Fatal("expected not available with empty project_id")
	}
	p = NewGCPSM("my-project", "", testLogger())
	if !p.Available() {
		t.Fatal("expected available with project_id set")
	}
}

func TestAzureKV_Name(t *testing.T) {
	p := NewAzureKV("https://vault.azure.net", "", "", testLogger())
	if p.Name() != "azure_kv" {
		t.Fatalf("expected azure_kv, got %s", p.Name())
	}
}

func TestAzureKV_Available(t *testing.T) {
	p := NewAzureKV("", "", "", testLogger())
	if p.Available() {
		t.Fatal("expected not available with empty vault_url")
	}
	p = NewAzureKV("https://vault.azure.net", "", "", testLogger())
	if !p.Available() {
		t.Fatal("expected available with vault_url set")
	}
}

// Integration with Manager: verify providers register correctly
func TestManager_CloudProviders(t *testing.T) {
	aws := NewAWSSM("us-east-1", testLogger())
	gcp := NewGCPSM("my-project", "", testLogger())
	azure := NewAzureKV("https://vault.azure.net", "", "", testLogger())
	noAWS := NewAWSSM("", testLogger())

	mgr := NewManager(testLogger(), aws, gcp, azure, noAWS)

	// aws_sm, gcp_sm, azure_kv should be registered; noAWS should be skipped
	if _, ok := mgr.providers["aws_sm"]; !ok {
		t.Fatal("aws_sm not registered")
	}
	if _, ok := mgr.providers["gcp_sm"]; !ok {
		t.Fatal("gcp_sm not registered")
	}
	if _, ok := mgr.providers["azure_kv"]; !ok {
		t.Fatal("azure_kv not registered")
	}
	if len(mgr.providers) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(mgr.providers))
	}
}
