//go:build windows

package mitm

import (
	"encoding/hex"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// CERT_STORE_PROV_SYSTEM_REGISTRY_W：直接读写注册表形态的系统存储。
	//
	// 为什么不用 CERT_STORE_PROV_SYSTEM_W（值 10）：用它往 Root 存储添加证书时，
	// crypt32 会弹一次"安全警告"对话框（"你即将安装来自以下认证机构的证书…"），
	// 调用方没有参数能关掉。换成注册表 provider 后添加完全静默，且写的是同一个
	// 位置——实测添加后普通 provider 与独立进程的 certutil 都能立刻看到。
	certStoreProvSystemRegistryW = 13
	certSystemStoreCurrentUser   = 0x00010000
	x509AsnEncoding              = 0x00000001
	pkcs7AsnEncoding             = 0x00010000
	certFindSubjectStrW          = 0x00080007
	certStoreAddReplaceExisting  = 3
	certHashPropID               = 3 // CERT_HASH_PROP_ID：SHA-1 指纹，与注册表子键名同一字节序
)

const rootCertsKey = `Software\Microsoft\SystemCertificates\Root\Certificates`

var (
	crypt32                               = windows.NewLazySystemDLL("crypt32.dll")
	procCertOpenStore                     = crypt32.NewProc("CertOpenStore")
	procCertCloseStore                    = crypt32.NewProc("CertCloseStore")
	procCertAddEncodedCertificateToStore  = crypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertFindCertificateInStore        = crypt32.NewProc("CertFindCertificateInStore")
	procCertDeleteCertificateFromStore    = crypt32.NewProc("CertDeleteCertificateFromStore")
	procCertFreeCertificateContext        = crypt32.NewProc("CertFreeCertificateContext")
	procCertCreateCertificateContext      = crypt32.NewProc("CertCreateCertificateContext")
	procCertGetCertificateContextProperty = crypt32.NewProc("CertGetCertificateContextProperty")
)

// windowsStore 操作**当前用户**的根证书区（HKCU）：全程直接调 crypt32，
// 不写临时文件、不起 certutil 子进程。普通用户权限即可，不需要管理员、不弹 UAC。
//
// 已知代价：往 Root 存储添加证书时 crypt32 会弹一次"安全警告"对话框
// （"你即将安装来自以下认证机构的证书…"）。这是它的内置行为，没有参数能关掉。
// 唯一的静默办法是直写注册表，但 Root 的 Blob 是 crypt32 私有序列化
// （带一段由它计算的哈希属性前缀），实测拼不出来，已放弃——见 docs/findings.md。
type windowsStore struct{}

func systemStore() trustStore { return windowsStore{} }

// install 把 DER 加进用户根证书区，返回 SHA-1 指纹（注册表子键名的形式）。
func (windowsStore) install(der []byte) (string, error) {
	id, err := certThumbprint(der)
	if err != nil {
		return "", err
	}
	h, err := openUserRoot()
	if err != nil {
		return "", err
	}
	defer procCertCloseStore.Call(uintptr(h), 0)

	if len(der) == 0 {
		return "", fmt.Errorf("mitm: 证书为空")
	}
	ok, _, errno := procCertAddEncodedCertificateToStore.Call(
		uintptr(h),
		uintptr(x509AsnEncoding|pkcs7AsnEncoding),
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)),
		uintptr(certStoreAddReplaceExisting),
		0, // 不需要返回 context
	)
	if ok == 0 {
		return "", winErr("写入用户根证书区", errno)
	}
	return id, nil
}

// remove 按指纹从注册表删掉那条。直删子键比 crypt32 的"先找 context 再删"更省事，
// 且不受进程内存储缓存影响。
func (windowsStore) remove(id string) error {
	if id == "" {
		return nil
	}
	err := registry.DeleteKey(registry.CURRENT_USER, rootCertsKey+`\`+id)
	if err != nil && err != syscall.ERROR_FILE_NOT_FOUND {
		return winErr("删除根证书注册表项", err)
	}
	return nil
}

// sweep 用 crypt32 按 Subject 找并删。启动时调用——那时进程刚起、存储缓存是冷的，
// 能看到上一次运行留下的残留。
func (windowsStore) sweep(subject string) (int, error) {
	h, err := openUserRoot()
	if err != nil {
		return 0, err
	}
	defer procCertCloseStore.Call(uintptr(h), 0)

	subj, err := windows.UTF16PtrFromString(subject)
	if err != nil {
		return 0, err
	}
	n := 0
	for {
		// 每轮都从头找：找到就删，下一轮自然拿到下一张。
		ctx, _, _ := procCertFindCertificateInStore.Call(
			uintptr(h),
			uintptr(x509AsnEncoding|pkcs7AsnEncoding),
			0,
			uintptr(certFindSubjectStrW),
			uintptr(unsafe.Pointer(subj)),
			0,
		)
		if ctx == 0 {
			break // 没有更多匹配，正常结束
		}
		// CertDeleteCertificateFromStore 无论成败都会释放 context，不能再 free。
		del, _, _ := procCertDeleteCertificateFromStore.Call(ctx)
		if del == 0 {
			procCertFreeCertificateContext.Call(ctx)
			break
		}
		n++
	}
	return n, nil
}

// contains 判断这张证书是否已在用户根证书区里：算指纹、看对应的注册表子键在不在。
// 纯查询，不碰存储、不弹确认框。
func (windowsStore) contains(der []byte) bool {
	id, err := certThumbprint(der)
	if err != nil {
		return false
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, rootCertsKey+`\`+id, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// certThumbprint 取 CERT_HASH_PROP_ID（SHA-1），大写十六进制。
// 实测这个字节序与注册表子键名、PowerShell 的 Thumbprint 完全一致。
func certThumbprint(der []byte) (string, error) {
	if len(der) == 0 {
		return "", fmt.Errorf("mitm: 证书为空")
	}
	ctx, _, errno := procCertCreateCertificateContext.Call(
		uintptr(x509AsnEncoding), uintptr(unsafe.Pointer(&der[0])), uintptr(len(der)))
	if ctx == 0 {
		return "", winErr("解析证书", errno)
	}
	defer procCertFreeCertificateContext.Call(ctx)

	var size uint32
	ok, _, errno := procCertGetCertificateContextProperty.Call(
		ctx, uintptr(certHashPropID), 0, uintptr(unsafe.Pointer(&size)))
	if ok == 0 || size == 0 {
		return "", winErr("读取证书指纹", errno)
	}
	buf := make([]byte, size)
	ok, _, errno = procCertGetCertificateContextProperty.Call(
		ctx, uintptr(certHashPropID),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return "", winErr("读取证书指纹", errno)
	}
	return strings.ToUpper(hex.EncodeToString(buf[:size])), nil
}

// openUserRoot 打开**当前用户**的根证书区（HKCU）。普通用户权限即可，
// 不需要管理员、不弹 UAC、也不弹证书安全警告（见上面 provider 的说明）。
func openUserRoot() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString("Root")
	if err != nil {
		return 0, err
	}
	r, _, errno := procCertOpenStore.Call(
		uintptr(certStoreProvSystemRegistryW),
		0,
		0,
		uintptr(certSystemStoreCurrentUser),
		uintptr(unsafe.Pointer(name)),
	)
	if r == 0 {
		return 0, winErr("打开用户根证书区", errno)
	}
	return windows.Handle(r), nil
}

// winErr 把 syscall errno 包成可读错误；errno 为 0 时（少见）退回通用文案，
// 否则 %w 会打出"操作成功完成"这种误导信息。
func winErr(op string, errno error) error {
	if errno == nil || errno == windows.ERROR_SUCCESS {
		return fmt.Errorf("mitm: %s 失败", op)
	}
	return fmt.Errorf("mitm: %s 失败: %w", op, errno)
}
