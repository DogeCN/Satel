// Package strategy 定义 Satel 的策略模型：canonical 字符串、参数默认值表、
// 以及由 canonical 派生的策略 ID。两侧（本客户端与 Worker）必须逐字节一致，
// 规范见 docs/protocol.md 第 2 节。
package strategy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Proto 是策略适用的首段类型。
const (
	ProtoTLS  = "tls"
	ProtoHTTP = "http"
)

// Op 是一个招法实例。Params 的取值类型只有三种：int64、bool、string。
type Op struct {
	Name   string
	Params map[string]any
}

// Spec 是一条完整策略：proto + 有序的 ops。canon/id 在构造时算好并缓存。
type Spec struct {
	Proto string
	Ops   []Op

	canon string
	id    string
}

// defaults 是参数默认值表，同时定义了每个招法的合法参数集合与参数类型。
// 取值域（用于 Worker 侧变异钳制）见 protocol.md §2.1。
var defaults = map[string]map[string]any{
	"split":     {"at": "sni", "pos": int64(1), "len": int64(1), "count": int64(2), "delay_ms": int64(8)},
	"tlsrf":     {"chunk": int64(8), "limit": int64(400), "delay_ms": int64(8)},
	"oob":       {"byte": int64(0)},
	"dup":       {"count": int64(1), "delay_ms": int64(0)},
	"hostsplit": {"gap": int64(1)},
	"case":      {"seed": int64(0)},
	"fake":      {"count": int64(1), "ttl": int64(3), "badsum": true, "badseq": true, "len": int64(64), "delay_ms": int64(0)},
	"disorder":  {"gap_ms": int64(0)},
}

// Ops 返回全部已知招法名（升序）。
func Ops() []string {
	names := make([]string, 0, len(defaults))
	for n := range defaults {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Defaults 返回某招法的参数默认值副本；未知招法返回 ok=false。
func Defaults(name string) (map[string]any, bool) {
	d, ok := defaults[name]
	if !ok {
		return nil, false
	}
	out := make(map[string]any, len(d))
	for k, v := range d {
		out[k] = v
	}
	return out, true
}

// New 用 proto 与 ops 构造一条策略：补齐默认值、校验招法与参数类型，算出 canon 与 id。
func New(proto string, ops []Op) (*Spec, error) {
	if proto != ProtoTLS && proto != ProtoHTTP {
		return nil, fmt.Errorf("strategy: 未知 proto %q", proto)
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("strategy: ops 为空")
	}
	filled := make([]Op, 0, len(ops))
	for _, op := range ops {
		d, ok := defaults[op.Name]
		if !ok {
			return nil, fmt.Errorf("strategy: 未知招法 %q", op.Name)
		}
		params := make(map[string]any, len(d))
		for k, dv := range d {
			params[k] = dv
		}
		for k, v := range op.Params {
			dv, known := d[k]
			if !known {
				return nil, fmt.Errorf("strategy: 招法 %s 无参数 %q", op.Name, k)
			}
			if err := checkType(op.Name, k, dv, v); err != nil {
				return nil, err
			}
			params[k] = v
		}
		filled = append(filled, Op{Name: op.Name, Params: params})
	}
	s := &Spec{Proto: proto, Ops: filled}
	s.canon = s.buildCanonical()
	sum := sha256.Sum256([]byte(s.canon))
	s.id = hex.EncodeToString(sum[:])[:8]
	return s, nil
}

// checkType 要求值的类型与默认值一致，避免 "1" 与 1 混用导致 canonical 歧义。
func checkType(op, param string, def, got any) error {
	switch def.(type) {
	case int64:
		if _, ok := got.(int64); !ok {
			return fmt.Errorf("strategy: %s.%s 需要整数，得到 %T", op, param, got)
		}
	case bool:
		if _, ok := got.(bool); !ok {
			return fmt.Errorf("strategy: %s.%s 需要布尔，得到 %T", op, param, got)
		}
	case string:
		if _, ok := got.(string); !ok {
			return fmt.Errorf("strategy: %s.%s 需要字符串，得到 %T", op, param, got)
		}
	}
	return nil
}

// Parse 解析 canonical 字符串（或等价的手写形式：省略的参数按默认值补齐）。
func Parse(canonical string) (*Spec, error) {
	canonical = strings.TrimSpace(canonical)
	if canonical == "" {
		return nil, fmt.Errorf("strategy: 空字符串")
	}
	parts := strings.Split(canonical, "|")
	proto := parts[0]
	ops := make([]Op, 0, len(parts)-1)
	for _, raw := range parts[1:] {
		op, err := parseOp(raw)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return New(proto, ops)
}

func parseOp(raw string) (Op, error) {
	open := strings.IndexByte(raw, '(')
	if open < 0 {
		// 裸招法名：全部参数取默认值。
		name := strings.TrimSpace(raw)
		if _, ok := defaults[name]; !ok {
			return Op{}, fmt.Errorf("strategy: 未知招法 %q", name)
		}
		return Op{Name: name, Params: map[string]any{}}, nil
	}
	close := strings.LastIndexByte(raw, ')')
	if close < open {
		return Op{}, fmt.Errorf("strategy: 招法格式非法 %q", raw)
	}
	name := strings.TrimSpace(raw[:open])
	d, ok := defaults[name]
	if !ok {
		return Op{}, fmt.Errorf("strategy: 未知招法 %q", name)
	}
	params := map[string]any{}
	body := strings.TrimSpace(raw[open+1 : close])
	if body != "" {
		for _, kv := range strings.Split(body, ",") {
			eq := strings.IndexByte(kv, '=')
			if eq < 0 {
				return Op{}, fmt.Errorf("strategy: 参数格式非法 %q", kv)
			}
			k := strings.TrimSpace(kv[:eq])
			v := strings.TrimSpace(kv[eq+1:])
			def, known := d[k]
			if !known {
				return Op{}, fmt.Errorf("strategy: 招法 %s 无参数 %q", name, k)
			}
			val, err := parseValue(name, k, def, v)
			if err != nil {
				return Op{}, err
			}
			params[k] = val
		}
	}
	return Op{Name: name, Params: params}, nil
}

func parseValue(op, param string, def any, raw string) (any, error) {
	switch def.(type) {
	case int64:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("strategy: %s.%s 需要整数，得到 %q", op, param, raw)
		}
		return n, nil
	case bool:
		switch raw {
		case "1", "true":
			return true, nil
		case "0", "false":
			return false, nil
		}
		return nil, fmt.Errorf("strategy: %s.%s 需要 0/1，得到 %q", op, param, raw)
	default:
		return raw, nil
	}
}

// Canonical 返回规范化字符串（参数按名升序、全部参数含默认值）。
func (s *Spec) Canonical() string { return s.canon }

// ID 返回策略 ID：sha256(canonical) 的前 8 个小写十六进制字符。
func (s *Spec) ID() string { return s.id }

// Get 取某招法的第一个实例。
func (s *Spec) Get(name string) (Op, bool) {
	for _, op := range s.Ops {
		if op.Name == name {
			return op, true
		}
	}
	return Op{}, false
}

// Int 读一个整数参数；缺失或类型不符时返回 def。
func (o Op) Int(name string, def int64) int64 {
	if v, ok := o.Params[name]; ok {
		if n, ok := v.(int64); ok {
			return n
		}
	}
	return def
}

// Bool 读一个布尔参数。
func (o Op) Bool(name string, def bool) bool {
	if v, ok := o.Params[name]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

// Str 读一个字符串参数。
func (o Op) Str(name string, def string) string {
	if v, ok := o.Params[name]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func (s *Spec) buildCanonical() string {
	var b strings.Builder
	b.WriteString(s.Proto)
	for _, op := range s.Ops {
		b.WriteString("|")
		b.WriteString(op.Name)
		b.WriteString("(")
		keys := make([]string, 0, len(op.Params))
		for k := range op.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(formatValue(op.Params[k]))
		}
		b.WriteString(")")
	}
	return b.String()
}

func formatValue(v any) string {
	switch t := v.(type) {
	case int64:
		return strconv.FormatInt(t, 10)
	case bool:
		if t {
			return "1"
		}
		return "0"
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}
