package mitm

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// memStore 记录调用，让"启动装、关闭删"的逻辑在默认测试里就被覆盖，
// 而不必改动系统信任区。真实存储只有 platform 那一层是实现差异。
type memStore struct {
	installed   map[string][]byte
	removed     []string
	sweeps      int
	sweptTotal  int
	nextID      int
	failInstall bool
}

func (m *memStore) install(der []byte) (string, error) {
	if m.failInstall {
		return "", errors.New("boom")
	}
	if m.installed == nil {
		m.installed = map[string][]byte{}
	}
	m.nextID++
	id := fmt.Sprintf("id-%d", m.nextID)
	m.installed[id] = der
	return id, nil
}

func (m *memStore) remove(id string) error {
	m.removed = append(m.removed, id)
	delete(m.installed, id)
	return nil
}

func (m *memStore) contains(der []byte) bool {
	for _, v := range m.installed {
		if bytes.Equal(v, der) {
			return true
		}
	}
	return false
}

func (m *memStore) sweep(string) (int, error) {
	m.sweeps++
	n := len(m.installed)
	m.sweptTotal += n
	m.installed = map[string][]byte{}
	return n, nil
}

// TestInstallSweepsStale 是"启动清残留"的核心断言：上一次被强杀留下的那张
// 必须在装新的之前被清掉，任何时刻最多一张 Satel CA。
func TestInstallSweepsStale(t *testing.T) {
	st := &memStore{installed: map[string][]byte{"stale": {0xde, 0xad}}}
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.InstallTo(st); err != nil {
		t.Fatal(err)
	}
	if st.sweeps != 1 || st.sweptTotal != 1 {
		t.Fatalf("应清理 1 条残留（sweeps=%d swept=%d）", st.sweeps, st.sweptTotal)
	}
	if len(st.installed) != 1 {
		t.Fatalf("装完后信任区里有 %d 条，应为 1", len(st.installed))
	}
	for _, der := range st.installed {
		if string(der) != string(ca.der) {
			t.Fatal("装进去的不是本 CA 的 DER")
		}
	}
}

// TestInstallThenRemove 验证关闭时按指纹精确删掉自己那张，并兜底扫一遍。
func TestInstallThenRemove(t *testing.T) {
	st := &memStore{}
	ca, _ := NewCA()
	if err := ca.InstallTo(st); err != nil {
		t.Fatal(err)
	}
	if err := ca.RemoveFrom(st); err != nil {
		t.Fatal(err)
	}
	if len(st.installed) != 0 {
		t.Fatalf("移除后还剩 %d 条", len(st.installed))
	}
	if len(st.removed) != 1 || st.removed[0] != "id-1" {
		t.Fatalf("未按 install 返回的标识精确移除: %v", st.removed)
	}
	if st.sweeps != 2 {
		t.Fatalf("sweeps = %d, 应为 2（装前清残留 + 移除兜底）", st.sweeps)
	}
}

// TestRemoveWithoutInstall 覆盖"从没装过就退出"：不该去 remove 一个空标识，
// 但仍要扫一遍（可能清掉别人的残留）。
func TestRemoveWithoutInstall(t *testing.T) {
	st := &memStore{installed: map[string][]byte{"stale": {1}}}
	ca, _ := NewCA()
	if err := ca.RemoveFrom(st); err != nil {
		t.Fatal(err)
	}
	if len(st.removed) != 0 {
		t.Fatalf("没装过就不该调用 remove: %v", st.removed)
	}
	if st.sweeps != 1 || st.sweptTotal != 1 {
		t.Fatalf("应兜底清掉 1 条残留（sweeps=%d swept=%d）", st.sweeps, st.sweptTotal)
	}
}

// TestInstallSweepsBeforeFailing 保证即使安装失败，残留也已经被清掉。
func TestInstallSweepsBeforeFailing(t *testing.T) {
	st := &memStore{installed: map[string][]byte{"stale": {1}}, failInstall: true}
	ca, _ := NewCA()
	if err := ca.InstallTo(st); err == nil {
		t.Fatal("安装失败时应返回错误")
	}
	if st.sweeps != 1 {
		t.Fatal("失败路径也必须先清残留")
	}
}

// TestLeafIPHost 验证 IP 字面量目标写进 IPAddresses 而不是 DNSNames。
func TestLeafIPHost(t *testing.T) {
	ca, _ := NewCA()
	lc, err := ca.Leaf("203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if len(lc.Leaf.IPAddresses) != 1 || lc.Leaf.IPAddresses[0].String() != "203.0.113.9" {
		t.Fatalf("IPAddresses = %v", lc.Leaf.IPAddresses)
	}
	if len(lc.Leaf.DNSNames) != 0 {
		t.Fatalf("IP 目标不该写 DNSNames: %v", lc.Leaf.DNSNames)
	}
	if err := lc.Leaf.VerifyHostname("203.0.113.9"); err != nil {
		t.Fatalf("IP 校验失败: %v", err)
	}
	if err := lc.Leaf.CheckSignatureFrom(ca.Cert()); err != nil {
		t.Fatalf("叶证书不是本 CA 签发: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 以下会真的改动系统信任区，默认跳过：
//
//	SATEL_CATEST=1 go test ./internal/mitm/ -run TestCAStoreLifecycle -v
//
// 必须用 -run 只跑这一个：Go 的 crypto/x509 会把系统根证书池缓存在进程内，
// 若其它用例先加载过，新装的 CA 就看不见了。
// ---------------------------------------------------------------------------

// countInstalled 数当前用户根证书区里本 CA 的条数。
// 只数 Subject 行——certutil 对一张证书会同时打印 Issuer 与 Subject，按行数会翻倍。
func countInstalled(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("certutil", "-store", "-user", "Root").Output()
	if err != nil {
		t.Skipf("certutil 不可用: %v", err)
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "使用者:") && !strings.HasPrefix(l, "Subject:") {
			continue
		}
		if strings.Contains(l, "CN="+CAName) {
			n++
		}
	}
	return n
}

// handshakeWithSystemPool 用**系统根证书池**（不传 RootCAs）与本地 CA 握手。
// 成功即证明"装进信任区"真的生效——这是唯一能证明信任而不只是"存在"的判据。
func handshakeWithSystemPool(t *testing.T, ca *CA, host string) error {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ca.ServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		_, _ = c.Write([]byte("PONG"))
	}()

	cc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := cc.Write([]byte("PING")); err != nil {
		return err
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(cc, got); err != nil {
		return err
	}
	return nil
}

func TestCAStoreLifecycle(t *testing.T) {
	if os.Getenv("SATEL_CATEST") == "" {
		t.Skip("设置 SATEL_CATEST=1 才跑（会改动用户根证书区）")
	}
	if before := countInstalled(t); before != 0 {
		t.Logf("测试前信任区里本就有 %d 条同名记录（多半是上次被强杀的残留），Install 会清掉", before)
	}

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Install(); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if ca.id == "" {
		t.Fatal("Install 未记录指纹，Remove 无法精确删除")
	}
	if got := countInstalled(t); got != 1 {
		t.Fatalf("安装后信任区里有 %d 条本 CA，应为 1", got)
	}

	// 真正的判据：用系统根证书池握手。这一步证明它不只是"在存储里"，而是被信任。
	if err := handshakeWithSystemPool(t, ca, "satel-ca-test.example"); err != nil {
		t.Fatalf("用系统根证书池握手失败（说明装进去没被信任）: %v", err)
	}

	// 再装一张不同的（模拟上次残留）：按 CN 清理应让它不累积。
	ca2, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	if err := ca2.Install(); err != nil {
		t.Fatalf("第二次 Install: %v", err)
	}
	if n := countInstalled(t); n != 1 {
		t.Fatalf("装两次后有 %d 条，应只保留 1 条", n)
	}

	if err := ca2.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if got := countInstalled(t); got != 0 {
		t.Fatalf("移除后还剩 %d 张", got)
	}
}
