package cmd

import (
	"strings"
	"testing"
)

func TestGoreeCloudProxyHasNoInheritedCloudManagementDefault(t *testing.T) {
	if DefaultManagementURL != "" {
		t.Fatal("proxy must not implicitly connect to a hosted management plane")
	}
	for _, value := range []string{"", " ", "\t", "\n"} {
		if err := requireExplicitManagementAddress(value); err == nil {
			t.Errorf("empty or whitespace management address %q accepted", value)
		}
	}
	for _, value := range []string{"https://control.example.test:443", "https://127.0.0.1:33073"} {
		if err := requireExplicitManagementAddress(value); err != nil {
			t.Errorf("explicit management address %q rejected: %v", value, err)
		}
	}
}

func TestGoreeCloudProxyCannotStartWithoutManagementAddress(t *testing.T) {
	previous := mgmtAddr
	mgmtAddr = ""
	t.Cleanup(func() { mgmtAddr = previous })
	t.Setenv(envProxyToken, "synthetic-test-token")
	err := runServer(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "management address required") {
		t.Fatalf("expected fail-closed management configuration error, got %v", err)
	}
}
