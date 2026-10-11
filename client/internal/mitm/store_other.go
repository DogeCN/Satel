//go:build !windows

package mitm

import "errors"

// errUnsupported 在非 Windows 平台返回：信任区安装尚未实现，MITM 路径不激活。
var errUnsupported = errors.New("mitm: 本平台的信任区安装尚未实现")

// unsupportedStore 让非 Windows 平台的 Install/Remove 明确失败，
// 而不是静默"成功"却什么也没做。
type unsupportedStore struct{}

func systemStore() trustStore { return unsupportedStore{} }

func (unsupportedStore) install([]byte) (string, error) { return "", errUnsupported }
func (unsupportedStore) remove(string) error            { return errUnsupported }
func (unsupportedStore) sweep(string) (int, error)      { return 0, errUnsupported }
func (unsupportedStore) contains([]byte) bool           { return false }
