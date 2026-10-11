package engine

import (
	"satel/internal/failkind"
	"satel/internal/strategy"
)

// 方法 ID。策略是 8 位 hex，伪方法用 "@" 前缀，两者不冲突，可以放进同一张表。
// 真实方法恒定，策略方法按 Spec 的 ID 动态产生。
const (
	MethodDirect = "@direct"  // 明文直连
	MethodTunnel = "@tunnel"  // 协调端隧道（非 CF 承载的 IP 黑洞）
	MethodECH    = "@ech"     // MITM + ECH 直连 Cloudflare 边缘
	MethodProxy  = "@proxyip" // 本机中继（CF 承载但锁国区）
)

// PseudoMethods 是四种真实方法，按"典型代价"从低到高排（见 methodCost）。
var PseudoMethods = []string{MethodDirect, MethodECH, MethodTunnel, MethodProxy}

func isPseudo(id string) bool { return len(id) > 0 && id[0] == '@' }

// methodCost 越小越先试。只在 rate_h 相同时用来破平，表达的是"典型代价序"，
// 不是严格的时间估计：
//
//	0 @direct   一次明文直连，最便宜
//	1 包级策略  一次拨号 + 一次首段改写
//	2 @ech      一次到 CF 边缘的 TLS 握手
//	3 @tunnel   开一条协调端流 + 隧道内握手
//	4 @proxyip  要逐个试多条公共中继，最贵
//
// 三个 TLS 终止层方法**成本必须递增且互不相同**。曾经它们同成本、靠 ID 字典序
// 破平，而 "@proxyip" 字母序在 "@tunnel" 之前——实测在 IP 黑洞站上先跑 @proxyip、
// 白烧 20 秒（9 条公共中继逐个超时）才轮到真正管用的 @tunnel。
// 见 docs/findings.md 第十轮。
func methodCost(id string) int {
	switch id {
	case MethodDirect:
		return 0
	case MethodECH:
		return 2
	case MethodTunnel:
		return 3
	case MethodProxy:
		return 4
	default:
		return 1 // 策略
	}
}

// strategyMethod 把一条策略变成方法 ID。
func strategyMethod(s *strategy.Spec) string { return s.ID() }

// GroupKey 导出给 proxy：它知道 isCF，把组键显式传进记忆，避免在记忆层
// 反过来解析域名（会引入循环依赖且重复解析）。
func GroupKey(isCF bool, firstKind failkind.Kind) string { return groupKey(isCF, firstKind) }

// TerminatingMethods 是**需要终止客户端 TLS** 的方法。
//
// 它们与普通方法有个本质区别：`MITM.Terminate` 是**一次性**的——第一次终止就
// 消费掉了客户端的 ClientHello，随后的 ctls.Close() 还会关掉底层连接。所以这三
// 个方法**不能各自独立尝试**：同一条连接上最多只能走一次终止，之后的上游方法必须
// 复用同一个已解密的会话。
var TerminatingMethods = []string{MethodECH, MethodTunnel, MethodProxy}

// NeedsTermination 判断某方法是否要先终止客户端 TLS。
func NeedsTermination(id string) bool {
	for _, m := range TerminatingMethods {
		if m == id {
			return true
		}
	}
	return false
}
