package manager

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProxyURLTemplateValidationAndExpansion(t *testing.T) {
	template := "http://user-{email_local}-{session}:proxy-secret@127.0.0.1:7890"
	patch, errValidate := (BatchPatch{ProxyURL: &template}).Validate()
	if errValidate != nil {
		t.Fatalf("Validate() error = %v", errValidate)
	}
	summary := patch.Summary()
	if !summary.ProxyMutation || !summary.ProxyTemplate {
		t.Fatalf("summary = %#v", summary)
	}
	summaryJSON, errMarshal := json.Marshal(summary)
	if errMarshal != nil {
		t.Fatalf("Marshal() error = %v", errMarshal)
	}
	if strings.Contains(string(summaryJSON), "proxy-secret") || strings.Contains(string(summaryJSON), template) {
		t.Fatalf("summary leaked template details: %s", summaryJSON)
	}

	accountA := Account{ID: "auth-a", AuthID: "auth-a", Name: "a.json", Email: "alice@example.com", Provider: "codex"}
	accountB := Account{ID: "auth-b", AuthID: "auth-b", Name: "b.json", Email: "bob@example.com", Provider: "codex"}
	expandedA, errA := expandProxyURLForAccount(template, accountA, 0)
	if errA != nil {
		t.Fatalf("expand A error = %v", errA)
	}
	expandedB, errB := expandProxyURLForAccount(template, accountB, 1)
	if errB != nil {
		t.Fatalf("expand B error = %v", errB)
	}
	if expandedA == expandedB {
		t.Fatalf("expected different sticky proxies, got %q", expandedA)
	}
	if !strings.Contains(expandedA, "user-alice-") || !strings.Contains(expandedB, "user-bob-") {
		t.Fatalf("expanded values = %q / %q", expandedA, expandedB)
	}
	againA, errAgain := expandProxyURLForAccount(template, accountA, 0)
	if errAgain != nil {
		t.Fatalf("expand A again error = %v", errAgain)
	}
	if againA != expandedA {
		t.Fatalf("sticky session changed: first=%q second=%q", expandedA, againA)
	}
}

func TestProxyURLTemplateRejectsUnknownVariablesWithoutEchoingSecrets(t *testing.T) {
	invalid := "http://user-{unknown}:do-not-echo@127.0.0.1:7890"
	_, errValidate := (BatchPatch{ProxyURL: &invalid}).Validate()
	if errValidate == nil {
		t.Fatal("expected unknown variable error")
	}
	if strings.Contains(errValidate.Error(), "do-not-echo") {
		t.Fatalf("validation leaked secret: %v", errValidate)
	}
}

func TestProxyURLTemplateIndexAndNameStem(t *testing.T) {
	template := "socks5://{name_stem}-{index}:{rand8}@proxy.example:1080"
	account := Account{ID: "id-1", Name: "team/account.json", Email: "ops@example.com"}
	expanded, errExpand := expandProxyURLForAccount(template, account, 4)
	if errExpand != nil {
		t.Fatalf("expand error = %v", errExpand)
	}
	if !strings.HasPrefix(expanded, "socks5://account-5:") {
		t.Fatalf("expanded = %q", expanded)
	}
	if errValidate := validateProxyURL(expanded); errValidate != nil {
		t.Fatalf("expanded invalid: %v", errValidate)
	}
}
