package ech

import "testing"

func TestIsCloudflareIP(t *testing.T) {
	cf := []string{"104.17.175.133", "172.67.184.15", "162.159.135.79", "104.18.34.63"}
	for _, ip := range cf {
		if !IsCloudflareIP(ip) {
			t.Errorf("%s 应判定为 Cloudflare", ip)
		}
	}
	notCF := []string{"142.251.152.119", "47.102.115.14", "8.8.8.8", "162.125.18.129", "not-an-ip"}
	for _, ip := range notCF {
		if IsCloudflareIP(ip) {
			t.Errorf("%s 不应判定为 Cloudflare", ip)
		}
	}
}

func TestAnyCloudflare(t *testing.T) {
	if !AnyCloudflare([]string{"1.2.3.4", "162.159.136.232"}) {
		t.Fatal("列表中含 CF 地址却返回 false")
	}
	if AnyCloudflare([]string{"1.2.3.4", "142.251.152.119"}) {
		t.Fatal("列表中没有 CF 地址却返回 true")
	}
	if AnyCloudflare(nil) {
		t.Fatal("空列表应返回 false")
	}
}
