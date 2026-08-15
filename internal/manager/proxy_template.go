package manager

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const (
	proxyTemplateSeedPrefix = "cpa-account-config-manager/proxy-template/v1|"
	maxProxyTemplateVars    = 32
)

var proxyTemplateVariablePattern = regexp.MustCompile(`\{([a-z0-9_]+)\}`)

var allowedProxyTemplateVariables = map[string]struct{}{
	"id":          {},
	"auth_id":     {},
	"name":        {},
	"name_stem":   {},
	"email":       {},
	"email_local": {},
	"email_slug":  {},
	"provider":    {},
	"type":        {},
	"label":       {},
	"label_slug":  {},
	"index":       {},
	"index0":      {},
	"uuid":        {},
	"session":     {},
	"short_id":    {},
	"rand8":       {},
	"rand12":      {},
	"rand16":      {},
}

type proxyTemplateContext struct {
	Account Account
	Index   int
}

func proxyURLUsesTemplate(value string) bool {
	return proxyTemplateVariablePattern.MatchString(value)
}

func listProxyTemplateVariables(value string) ([]string, error) {
	matches := proxyTemplateVariablePattern.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	if len(matches) > maxProxyTemplateVars {
		return nil, fmt.Errorf("proxy_url template exceeds %d variables", maxProxyTemplateVars)
	}
	seen := make(map[string]struct{}, len(matches))
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		name := match[1]
		if _, allowed := allowedProxyTemplateVariables[name]; !allowed {
			return nil, fmt.Errorf("proxy_url template variable %q is not supported", name)
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names, nil
}

func validateProxyURLTemplate(value string) error {
	if !proxyURLUsesTemplate(value) {
		return validateProxyURL(value)
	}
	if _, errVariables := listProxyTemplateVariables(value); errVariables != nil {
		return errVariables
	}
	expanded, errExpand := expandProxyURLTemplate(value, sampleProxyTemplateValues())
	if errExpand != nil {
		return errExpand
	}
	if errValidate := validateProxyURL(expanded); errValidate != nil {
		return fmt.Errorf("proxy_url template must expand to a valid proxy URL")
	}
	return nil
}

func expandProxyURLForAccount(template string, account Account, index int) (string, error) {
	values, errValues := proxyTemplateValues(proxyTemplateContext{Account: account, Index: index})
	if errValues != nil {
		return "", errValues
	}
	expanded, errExpand := expandProxyURLTemplate(template, values)
	if errExpand != nil {
		return "", errExpand
	}
	if errValidate := validateProxyURL(expanded); errValidate != nil {
		return "", fmt.Errorf("expanded proxy_url is invalid for this account")
	}
	return expanded, nil
}

func expandProxyURLTemplate(template string, values map[string]string) (string, error) {
	if _, errVariables := listProxyTemplateVariables(template); errVariables != nil {
		return "", errVariables
	}
	var expandErr error
	expanded := proxyTemplateVariablePattern.ReplaceAllStringFunc(template, func(match string) string {
		if expandErr != nil {
			return ""
		}
		name := match[1 : len(match)-1]
		value, ok := values[name]
		if !ok {
			expandErr = fmt.Errorf("proxy_url template variable %q is unavailable", name)
			return ""
		}
		return value
	})
	if expandErr != nil {
		return "", expandErr
	}
	return expanded, nil
}

func proxyTemplateValues(context proxyTemplateContext) (map[string]string, error) {
	account := context.Account
	index := context.Index
	if index < 0 {
		index = 0
	}
	seed := firstNonEmpty(strings.TrimSpace(account.ID), strings.TrimSpace(account.AuthID), strings.TrimSpace(account.Name), "account")
	name := strings.TrimSpace(account.Name)
	email := strings.TrimSpace(account.Email)
	label := strings.TrimSpace(account.Label)
	values := map[string]string{
		"id":          strings.TrimSpace(account.ID),
		"auth_id":     firstNonEmpty(strings.TrimSpace(account.AuthID), strings.TrimSpace(account.ID)),
		"name":        name,
		"name_stem":   proxyNameStem(name),
		"email":       email,
		"email_local": proxyEmailLocal(email),
		"email_slug":  proxySlug(email),
		"provider":    strings.TrimSpace(account.Provider),
		"type":        strings.TrimSpace(account.Type),
		"label":       label,
		"label_slug":  proxySlug(firstNonEmpty(label, email, name, account.ID)),
		"index":       strconv.Itoa(index + 1),
		"index0":      strconv.Itoa(index),
		"uuid":        stickyHexID(seed, 32),
		"session":     stickyHexID(seed, 16),
		"short_id":    stickyHexID(seed, 8),
	}
	rand8, errRand8 := randomHexID(8)
	if errRand8 != nil {
		return nil, errRand8
	}
	rand12, errRand12 := randomHexID(12)
	if errRand12 != nil {
		return nil, errRand12
	}
	rand16, errRand16 := randomHexID(16)
	if errRand16 != nil {
		return nil, errRand16
	}
	values["rand8"] = rand8
	values["rand12"] = rand12
	values["rand16"] = rand16
	return values, nil
}

func sampleProxyTemplateValues() map[string]string {
	return map[string]string{
		"id":          "auth-sample",
		"auth_id":     "auth-sample",
		"name":        "account.json",
		"name_stem":   "account",
		"email":       "user@example.com",
		"email_local": "user",
		"email_slug":  "user-example-com",
		"provider":    "codex",
		"type":        "oauth",
		"label":       "sample-label",
		"label_slug":  "sample-label",
		"index":       "1",
		"index0":      "0",
		"uuid":        "0123456789abcdef0123456789abcdef",
		"session":     "0123456789abcdef",
		"short_id":    "01234567",
		"rand8":       "89abcdef",
		"rand12":      "89abcdef0123",
		"rand16":      "89abcdef01234567",
	}
}

func stickyHexID(seed string, length int) string {
	if length <= 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(proxyTemplateSeedPrefix + seed))
	encoded := hex.EncodeToString(sum[:])
	if length >= len(encoded) {
		return encoded
	}
	return encoded[:length]
}

func randomHexID(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("random id length must be positive")
	}
	raw := make([]byte, (length+1)/2)
	if _, errRead := rand.Read(raw); errRead != nil {
		return "", fmt.Errorf("generate random proxy id")
	}
	encoded := hex.EncodeToString(raw)
	if length >= len(encoded) {
		return encoded, nil
	}
	return encoded[:length], nil
}

func proxyNameStem(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	base := path.Base(strings.ReplaceAll(trimmed, "\\", "/"))
	ext := path.Ext(base)
	if ext == "" {
		return base
	}
	return strings.TrimSuffix(base, ext)
}

func proxyEmailLocal(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return ""
	}
	local, _, found := strings.Cut(email, "@")
	if !found {
		return email
	}
	return local
}

func proxySlug(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(value))
	lastDash := false
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9':
			builder.WriteRune(char)
			lastDash = false
		default:
			if builder.Len() == 0 || lastDash {
				continue
			}
			builder.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(builder.String(), "-")
}
