package ech

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// realData 是 2026-10-11 从 223.5.5.5 取到的 satel.0xa.cc.cd 的 HTTPS RR 原文。
const realData = `1 . alpn="h3,h2" ipv4hint="104.21.75.248,172.67.184.15" ech="AEX+DQBBvgAgACBweY36Jk+IMXpd7bfdo77EYDdLEQeJCuEjWOlbqBv3XwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=" ipv6hint="2606:4700:3033::ac43:b80f,2606:4700:3035::6815:4bf8"`

func TestParseHTTPSDataReal(t *testing.T) {
	cfg, ips, err := parseHTTPSData(realData)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg) == 0 {
		t.Fatal("未解出 ECH 配置")
	}
	// ECHConfigList = uint16 总长 + ECHConfig 条目；条目首字节是版本 0xfe0d
	// （draft-ietf-tls-esni 的最终版本）。
	total := int(cfg[0])<<8 | int(cfg[1])
	if total != len(cfg)-2 {
		t.Fatalf("长度前缀 %d 与实际 %d 不符", total, len(cfg)-2)
	}
	if cfg[2] != 0xfe || cfg[3] != 0x0d {
		t.Fatalf("ECHConfig 版本前缀 = %02x%02x, want fe0d", cfg[2], cfg[3])
	}
	want := []string{"104.21.75.248", "172.67.184.15"}
	if len(ips) != len(want) {
		t.Fatalf("ipv4hint = %v, want %v", ips, want)
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("ipv4hint[%d] = %s, want %s", i, ips[i], want[i])
		}
	}
	// 必须与独立解码一致
	raw, err := base64.StdEncoding.DecodeString("AEX+DQBBvgAgACBweY36Jk+IMXpd7bfdo77EYDdLEQeJCuEjWOlbqBv3XwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cfg, raw) {
		t.Fatal("解码结果与独立解码不一致")
	}
}

func TestParseHTTPSDataNoECH(t *testing.T) {
	cfg, ips, err := parseHTTPSData(`1 . alpn="h2" ipv4hint="1.2.3.4"`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Fatal("没有 ech= 却解出了配置")
	}
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Fatalf("ips = %v", ips)
	}
}

func TestDecodeBase64BothAlphabets(t *testing.T) {
	std := base64.StdEncoding.EncodeToString([]byte("hello world!!"))
	url := base64.RawURLEncoding.EncodeToString([]byte("hello world!!"))
	for _, s := range []string{std, url} {
		got, err := decodeBase64(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if string(got) != "hello world!!" {
			t.Fatalf("%q -> %q", s, got)
		}
	}
}

func TestQueryRejectsBadEndpoint(t *testing.T) {
	if _, err := query(nil, "", "example.com", "A"); err == nil {
		t.Fatal("空端点应报错")
	}
	if _, err := query(nil, "://bad", "example.com", "A"); err == nil {
		t.Fatal("非法端点应报错")
	}
}

// TestParseHTTPSDataUnquoted 锁住 Cloudflare Gateway 的展示格式：参数值**不带引号**。
// 2026-12 实测该端点干净但慢，是解析器的首选；换端点时若只认带引号的形式，
// 就会静默地拿不到 ECH 配置，MITM 分支整条失效。
func TestParseHTTPSDataUnquoted(t *testing.T) {
	const gateway = `1 . alpn=h2 ipv4hint=162.159.135.79,162.159.136.79 ` +
		`ech=AEX+DQBBvgAgACAnc+9IO/WWQSMj7W2mLvaFlY3UbvRlOsLeK+qbQ6pgVwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA= ` +
		`ipv6hint=2606:4700:7::a29f:874f`
	cfg, ips, err := parseHTTPSData(gateway)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg) == 0 {
		t.Fatal("未解出不带引号的 ech=")
	}
	if cfg[0] != 0x00 || cfg[1] != 0x45 {
		t.Fatalf("长度前缀 %02x%02x，应为 0x0045", cfg[0], cfg[1])
	}
	want := []string{"162.159.135.79", "162.159.136.79"}
	if len(ips) != len(want) {
		t.Fatalf("ipv4hint = %v, want %v", ips, want)
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("ipv4hint[%d] = %s, want %s", i, ips[i], want[i])
		}
	}
}
