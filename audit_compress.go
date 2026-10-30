package middle

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

const (
	maxAuditHotBytes   = 8 * 1024
	maxAuditChanges    = 80
	auditDiffMarkerKey = "__audit"
	auditDiffVersion   = "diff_v1"
)

// AuditChange is the write-side field diff stored in After for updates.
type AuditChange struct {
	Path   string      `json:"path"`
	Before interface{} `json:"before"`
	After  interface{} `json:"after"`
	Kind   string      `json:"kind"` // added / removed / changed
}

type auditDiffEnvelope struct {
	Audit   string        `json:"__audit"`
	Changes []AuditChange `json:"changes"`
}

var auditSkipExact = map[string]struct{}{
	"password": {}, "passwd": {}, "old_password": {}, "new_password": {},
	"token": {}, "access_token": {}, "refresh_token": {}, "secret": {},
	"session_key": {}, "jwt": {}, "otp": {}, "otp_secret": {}, "opt_secret": {},
	"sms_code": {}, "authorization": {}, "cookie": {},
	"context": {}, "logs": {},
	"phone_hash": {}, "phone_enc": {}, "phone_sec": {},
	"private": {}, "merchant_api_key": {}, "api_key": {}, "user_key": {},
}

var auditSkipSuffix = []string{
	"updated_at", "updated_time", "created_time", "created_at", "join_at",
}

var auditSummaryKeys = []string{
	"id", "_id", "name", "nickname", "title", "status", "level",
	"merchant_id", "account_id", "user_id", "target_id", "phone", "email",
	"code", "type",
}

// CompressAuditBodies shrinks Before/After for hot storage (P1).
// update → After holds {"__audit":"diff_v1","changes":[...]}, Before empty.
// create → After is a small summary object; delete → Before is a small summary.
func CompressAuditBodies(action, before, after string) (string, string) {
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "update":
		changes := DiffAuditJSON(before, after)
		if len(changes) == 0 {
			return "", ""
		}
		raw, err := json.Marshal(auditDiffEnvelope{Audit: auditDiffVersion, Changes: changes})
		if err != nil {
			return "", truncateAuditBytes(after, maxAuditHotBytes)
		}
		return "", truncateAuditBytes(string(raw), maxAuditHotBytes)
	case "create":
		return "", truncateAuditBytes(compactAuditSummary(after), maxAuditHotBytes)
	case "delete":
		return truncateAuditBytes(compactAuditSummary(before), maxAuditHotBytes), ""
	default:
		return truncateAuditBytes(before, maxAuditHotBytes), truncateAuditBytes(after, maxAuditHotBytes)
	}
}

// ParseAuditDiffAfter returns write-side changes when After is a diff envelope.
func ParseAuditDiffAfter(after string) ([]AuditChange, bool) {
	s := strings.TrimSpace(after)
	if s == "" || s[0] != '{' {
		return nil, false
	}
	var env auditDiffEnvelope
	if err := json.Unmarshal([]byte(s), &env); err != nil {
		return nil, false
	}
	if env.Audit != auditDiffVersion || env.Changes == nil {
		return nil, false
	}
	return env.Changes, true
}

func compactAuditSummary(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return truncateAuditBytes(s, maxAuditHotBytes)
	}
	root, ok := v.(map[string]interface{})
	if !ok {
		return truncateAuditBytes(s, maxAuditHotBytes)
	}
	out := map[string]interface{}{}
	for _, key := range auditSummaryKeys {
		if val, ok := lookupFold(root, key); ok {
			if _, sensitive := auditSkipExact[strings.ToLower(key)]; sensitive {
				out[key] = "***"
				continue
			}
			out[key] = val
		}
	}
	if inner, ok := root["_"].(map[string]interface{}); ok {
		if mid, ok := lookupFold(inner, "merchant_id"); ok {
			out["merchant_id"] = mid
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return truncateAuditBytes(s, maxAuditHotBytes)
	}
	return string(b)
}

func lookupFold(m map[string]interface{}, key string) (interface{}, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	low := strings.ToLower(key)
	for k, v := range m {
		if strings.ToLower(k) == low {
			return v, true
		}
	}
	return nil, false
}

// DiffAuditJSON compares two JSON snapshots and returns changed fields only.
func DiffAuditJSON(beforeRaw, afterRaw string) []AuditChange {
	before := parseAuditValue(beforeRaw)
	after := parseAuditValue(afterRaw)
	if before == nil && after == nil {
		return nil
	}
	out := make([]AuditChange, 0)
	diffAuditValue("", normalizeAuditValue(before), normalizeAuditValue(after), &out)
	if len(out) > maxAuditChanges {
		out = out[:maxAuditChanges]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func parseAuditValue(raw string) interface{} {
	s := strings.TrimSpace(raw)
	if s == "" || s == "null" {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	return v
}

func normalizeAuditValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, child := range t {
			if k == "context" || k == "logs" {
				continue
			}
			if k == "_" {
				if nested, ok := child.(map[string]interface{}); ok {
					if meta, ok := nested["meta"].(map[string]interface{}); ok {
						out["meta"] = normalizeAuditValue(meta)
					}
					for nk, nv := range nested {
						if nk == "meta" || nk == "context" {
							continue
						}
						out[nk] = normalizeAuditValue(nv)
					}
				}
				continue
			}
			if k == "_id" {
				out["id"] = fmt.Sprint(child)
				continue
			}
			out[k] = normalizeAuditValue(child)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, item := range t {
			out[i] = normalizeAuditValue(item)
		}
		return out
	default:
		return v
	}
}

func skipAuditPath(path string) bool {
	if path == "" {
		return false
	}
	last := path
	if i := strings.LastIndex(path, "."); i >= 0 {
		last = path[i+1:]
	}
	if _, ok := auditSkipExact[strings.ToLower(last)]; ok {
		return true
	}
	low := strings.ToLower(path)
	for _, s := range auditSkipSuffix {
		if strings.HasSuffix(low, s) || last == s {
			return true
		}
	}
	if strings.HasPrefix(low, "logs") || strings.HasPrefix(low, "context.") {
		return true
	}
	return false
}

func diffAuditValue(path string, before, after interface{}, out *[]AuditChange) {
	if skipAuditPath(path) {
		return
	}
	if equalAudit(before, after) {
		return
	}
	bm, bMap := before.(map[string]interface{})
	am, aMap := after.(map[string]interface{})
	if (bMap || before == nil) && (aMap || after == nil) && (bMap || aMap) {
		keys := map[string]struct{}{}
		if bMap {
			for k := range bm {
				keys[k] = struct{}{}
			}
		}
		if aMap {
			for k := range am {
				keys[k] = struct{}{}
			}
		}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			var bv, av interface{}
			if bMap {
				bv = bm[k]
			}
			if aMap {
				av = am[k]
			}
			child := k
			if path != "" {
				child = path + "." + k
			}
			diffAuditValue(child, bv, av, out)
		}
		return
	}
	kind := "changed"
	if before == nil {
		kind = "added"
	} else if after == nil {
		kind = "removed"
	}
	*out = append(*out, AuditChange{Path: path, Before: before, After: after, Kind: kind})
}

func equalAudit(a, b interface{}) bool {
	return reflect.DeepEqual(a, b)
}

func truncateAuditBytes(s string, n int) string {
	if n <= 0 || s == "" || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
