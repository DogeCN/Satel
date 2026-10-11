package mitm

import (
	"fmt"
	"os"
)

// trustStore 是信任区的最小抽象。抽出来是为了让"启动装、关闭删"这条逻辑能在
// 不改动系统信任区的前提下被默认测试覆盖——只有 platform 那一层是实现差异。
type trustStore interface {
	// install 把 DER 编码的证书加入信任区，返回可用于精确移除的标识。
	install(der []byte) (id string, err error)
	// remove 按 install 返回的标识精确移除。
	remove(id string) error
	// sweep 删除信任区里所有 Subject 匹配 subject 的证书，返回删除数量。
	sweep(subject string) (int, error)
	// contains 判断这张证书是否已在信任区里。只查不写——开发通道靠它决定
	// 要不要重装（装会弹确认框，查不会）。
	contains(der []byte) bool
}

// Installed 报告本 CA 是否已在信任区里。
func (c *CA) Installed() bool { return c.InstalledIn(systemStore()) }

// InstalledIn 用指定存储实现查询（测试注入用）。
func (c *CA) InstalledIn(st trustStore) bool { return st.contains(c.der) }

// Install 把根证书装进信任区，**先清掉上一次运行的残留**。
//
// 清残留是必需的：进程被强杀时 defer 跑不到，上一次的 CA 会留在信任区里。
// 每次启动先按 CN 扫一遍，保证任何时刻最多只有一张 Satel CA。
func (c *CA) Install() error { return c.InstallTo(systemStore()) }

// InstallTo 用指定存储实现安装（测试注入用）。
func (c *CA) InstallTo(st trustStore) error {
	if _, err := st.sweep(CAName); err != nil {
		return fmt.Errorf("mitm: 清理残留失败: %w", err)
	}
	id, err := st.install(c.der)
	if err != nil {
		return fmt.Errorf("mitm: 安装根证书失败: %w", err)
	}
	c.mu.Lock()
	c.id = id
	c.mu.Unlock()
	return nil
}

// Remove 从信任区移除本 CA。先按指纹精确删自己那张，再按 CN 扫一遍兜底——
// 兜底是给"上一次被强杀留下的另一张 Satel CA"准备的。
func (c *CA) Remove() error { return c.RemoveFrom(systemStore()) }

// RemoveFrom 用指定存储实现移除（测试注入用）。
func (c *CA) RemoveFrom(st trustStore) error {
	c.mu.Lock()
	id := c.id
	c.mu.Unlock()

	if id != "" {
		if err := st.remove(id); err != nil {
			return fmt.Errorf("mitm: 移除根证书失败: %w", err)
		}
	}
	if _, err := st.sweep(CAName); err != nil {
		return fmt.Errorf("mitm: 清理根证书失败: %w", err)
	}
	return nil
}

// RemoveAll 清理全部名为 CAName 的证书，并删除落盘的 CA 文件。
//
// 不依赖内存里有没有 CA 对象——"移除"这件事必须能在没有 CA 文件（或文件已坏）
// 时也成立，否则用户就没有干净的退路了。返回删掉的证书数与文件是否被删。
func RemoveAll(caPath string) (removed int, fileGone bool, err error) {
	n, serr := systemStore().sweep(CAName)
	if serr != nil {
		return 0, false, fmt.Errorf("mitm: 清除信任区失败: %w", serr)
	}
	if caPath != "" {
		switch rerr := os.Remove(caPath); {
		case rerr == nil:
			fileGone = true
		case os.IsNotExist(rerr):
		default:
			return n, false, fmt.Errorf("mitm: 删除 CA 文件失败: %w", rerr)
		}
	}
	return n, fileGone, nil
}
