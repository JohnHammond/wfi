package pe

import (
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modntdll    = NewLazySystemDLL("ntdll.dll")
	modkernel32 = NewLazySystemDLL("kernel32.dll")
	modpsapi    = NewLazySystemDLL("psapi.dll")
	modAdvapi32 = NewLazySystemDLL("Advapi32.dll")
	modnetapi32 = NewLazySystemDLL("netapi32.dll")
	modwintrust = NewLazySystemDLL("wintrust.dll")

	procNtOpenThreadToken                    = modntdll.NewProc("NtOpenThreadToken")
	procReadProcessMemory                    = modkernel32.NewProc("ReadProcessMemory")
	procGetProcessMemoryInfo                 = modpsapi.NewProc("GetProcessMemoryInfo")
	procGetProcessIoCounters                 = modkernel32.NewProc("GetProcessIoCounters")
	procQueryFullProcessImageNameW           = modkernel32.NewProc("QueryFullProcessImageNameW")
	procNtOpenDirectoryObject                = modntdll.NewProc("NtOpenDirectoryObject")
	procAdjustTokenPrivileges                = modAdvapi32.NewProc("AdjustTokenPrivileges")
	procLookupPrivilegeValueW                = modAdvapi32.NewProc("LookupPrivilegeValueW")
	procNtDuplicateObject                    = modntdll.NewProc("NtDuplicateObject")
	procNtQueryInformationProcess            = modntdll.NewProc("NtQueryInformationProcess")
	procNtQueryInformationThread             = modntdll.NewProc("NtQueryInformationThread")
	procNtQueryObject                        = modntdll.NewProc("NtQueryObject")
	procNtQuerySystemInformation             = modntdll.NewProc("NtQuerySystemInformation")
	procCloseHandle                          = modkernel32.NewProc("CloseHandle")
	procOpenProcess                          = modkernel32.NewProc("OpenProcess")
	procGetSystemInfo                        = modkernel32.NewProc("GetSystemInfo")
	procModule32NextW                        = modkernel32.NewProc("Module32NextW")
	procModule32FirstW                       = modkernel32.NewProc("Module32FirstW")
	procCreateToolhelp32Snapshot             = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procGetMappedFileNameW                   = modpsapi.NewProc("GetMappedFileNameW")
	procVirtualQueryEx                       = modkernel32.NewProc("VirtualQueryEx")
	procNetApiBufferFree                     = modnetapi32.NewProc("NetApiBufferFree")
	procNetUserEnum                          = modnetapi32.NewProc("NetUserEnum")
	procNetUserGetGroups                     = modnetapi32.NewProc("NetUserGetGroups")
	procCryptCATAdminAcquireContext2         = modwintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminReleaseContext          = modwintrust.NewProc("CryptCATAdminReleaseContext")
	procCryptCATAdminCalcHashFromFileHandle2 = modwintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash     = modwintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATCatalogInfoFromContext       = modwintrust.NewProc("CryptCATCatalogInfoFromContext")
	procCryptCATAdminReleaseCatalogContext   = modwintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procWinVerifyTrust                       = modwintrust.NewProc("WinVerifyTrust")
	procWTHelperProvDataFromStateData        = modwintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain       = modwintrust.NewProc("WTHelperGetProvSignerFromChain")
)

func NtOpenThreadToken(thread_handle syscall.Handle, DesiredAccess uint32, open_as_self bool, token_handle *syscall.Handle) (status uint32) {
	var _p0 uint32
	if open_as_self {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r0, _, _ := syscall.Syscall6(procNtOpenThreadToken.Addr(), 4, uintptr(thread_handle), uintptr(DesiredAccess), uintptr(_p0), uintptr(unsafe.Pointer(token_handle)), 0, 0)
	status = uint32(r0)
	return
}

func _ReadProcessMemory(handle syscall.Handle, baseAddress uintptr, buffer uintptr, size uintptr, numRead *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procReadProcessMemory.Addr(), 5, uintptr(handle), uintptr(baseAddress), uintptr(buffer), uintptr(size), uintptr(unsafe.Pointer(numRead)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetProcessMemoryInfo(handle syscall.Handle, memCounters *PROCESS_MEMORY_COUNTERS, cb uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetProcessMemoryInfo.Addr(), 3, uintptr(handle), uintptr(unsafe.Pointer(memCounters)), uintptr(cb))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetProcessIoCounters(hProcess syscall.Handle, lpIoCounters *IO_COUNTERS) (ok bool) {
	r0, _, _ := syscall.Syscall(procGetProcessIoCounters.Addr(), 2, uintptr(hProcess), uintptr(unsafe.Pointer(lpIoCounters)), 0)
	ok = r0 != 0
	return
}

func QueryFullProcessImageName(handle syscall.Handle, dwFlags uint32, buffer *byte, length *uint32) (ok bool) {
	r0, _, _ := syscall.Syscall6(procQueryFullProcessImageNameW.Addr(), 4, uintptr(handle), uintptr(dwFlags), uintptr(unsafe.Pointer(buffer)), uintptr(unsafe.Pointer(length)), 0, 0)
	ok = r0 != 0
	return
}

func NtOpenDirectoryObject(DirectoryHandle *uint32, DesiredAccess uint32, ObjectAttributes *OBJECT_ATTRIBUTES) (status uint32) {
	r0, _, _ := syscall.Syscall(procNtOpenDirectoryObject.Addr(), 3, uintptr(unsafe.Pointer(DirectoryHandle)), uintptr(DesiredAccess), uintptr(unsafe.Pointer(ObjectAttributes)))
	status = uint32(r0)
	return
}

func AdjustTokenPrivileges(TokenHandle syscall.Token, DisableAllPrivileges bool, NewState uintptr, BufferLength int, PreviousState uintptr, ReturnLength *int) (err error) {
	var _p0 uint32
	if DisableAllPrivileges {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r1, _, e1 := syscall.Syscall6(procAdjustTokenPrivileges.Addr(), 6, uintptr(TokenHandle), uintptr(_p0), uintptr(NewState), uintptr(BufferLength), uintptr(PreviousState), uintptr(unsafe.Pointer(ReturnLength)))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func LookupPrivilegeValue(lpSystemName uintptr, lpName uintptr, out uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procLookupPrivilegeValueW.Addr(), 3, uintptr(lpSystemName), uintptr(lpName), uintptr(out))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func NtDuplicateObject(SourceProcessHandle syscall.Handle, SourceHandle syscall.Handle, TargetProcessHandle syscall.Handle, TargetHandle *syscall.Handle, DesiredAccess uint32, InheritHandle uint32, Options uint32) (status uint32) {
	r0, _, _ := syscall.Syscall9(procNtDuplicateObject.Addr(), 7, uintptr(SourceProcessHandle), uintptr(SourceHandle), uintptr(TargetProcessHandle), uintptr(unsafe.Pointer(TargetHandle)), uintptr(DesiredAccess), uintptr(InheritHandle), uintptr(Options), 0, 0)
	status = uint32(r0)
	return
}

func NtQueryInformationProcess(Handle syscall.Handle, ObjectInformationClass uint32, ProcessInformation *byte, ProcessInformationLength uint32, ReturnLength *uint32) (status uint32) {
	r0, _, _ := syscall.Syscall6(procNtQueryInformationProcess.Addr(), 5, uintptr(Handle), uintptr(ObjectInformationClass), uintptr(unsafe.Pointer(ProcessInformation)), uintptr(ProcessInformationLength), uintptr(unsafe.Pointer(ReturnLength)), 0)
	status = uint32(r0)
	return
}

func NtQueryInformationThread(Handle syscall.Handle, ObjectInformationClass uint32, ThreadInformation *byte, ThreadInformationLength uint32, ReturnLength *uint32) (status uint32, err error) {
	r0, _, e1 := syscall.Syscall6(procNtQueryInformationThread.Addr(), 5, uintptr(Handle), uintptr(ObjectInformationClass), uintptr(unsafe.Pointer(ThreadInformation)), uintptr(ThreadInformationLength), uintptr(unsafe.Pointer(ReturnLength)), 0)
	status = uint32(r0)
	if status == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func NtQueryObject(Handle syscall.Handle, ObjectInformationClass uint32, ObjectInformation *byte, ObjectInformationLength uint32, ReturnLength *uint32) (status uint32, err error) {
	r0, _, e1 := syscall.Syscall6(procNtQueryObject.Addr(), 5, uintptr(Handle), uintptr(ObjectInformationClass), uintptr(unsafe.Pointer(ObjectInformation)), uintptr(ObjectInformationLength), uintptr(unsafe.Pointer(ReturnLength)), 0)
	status = uint32(r0)
	if status == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func NtQuerySystemInformation(SystemInformationClass uint32, SystemInformation *byte, SystemInformationLength uint32, ReturnLength *uint32) (status uint32) {
	r0, _, _ := syscall.Syscall6(procNtQuerySystemInformation.Addr(), 4, uintptr(SystemInformationClass), uintptr(unsafe.Pointer(SystemInformation)), uintptr(SystemInformationLength), uintptr(unsafe.Pointer(ReturnLength)), 0, 0)
	status = uint32(r0)
	return
}

func CloseHandle(h syscall.Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procCloseHandle.Addr(), 1, uintptr(h), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func OpenProcess(dwDesiredAccess uint32, bInheritHandle bool, dwProcessId uint32) (handle syscall.Handle, err error) {
	var _p0 uint32
	if bInheritHandle {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r0, _, e1 := syscall.Syscall(procOpenProcess.Addr(), 3, uintptr(dwDesiredAccess), uintptr(_p0), uintptr(dwProcessId))
	handle = syscall.Handle(r0)
	if handle == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetSystemInfo(lpSystemInfo *SYSTEM_INFO) (err error) {
	r1, _, e1 := syscall.Syscall(procGetSystemInfo.Addr(), 1, uintptr(unsafe.Pointer(lpSystemInfo)), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func Module32Next(hSnapshot syscall.Handle, me *MODULEENTRY32W) (err error) {
	r1, _, e1 := syscall.Syscall(procModule32NextW.Addr(), 2, uintptr(hSnapshot), uintptr(unsafe.Pointer(me)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func Module32First(hSnapshot syscall.Handle, me *MODULEENTRY32W) (err error) {
	r1, _, e1 := syscall.Syscall(procModule32FirstW.Addr(), 2, uintptr(hSnapshot), uintptr(unsafe.Pointer(me)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func CreateToolhelp32Snapshot(dwFlags uint32, th32ProcessID uint32) (handle syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procCreateToolhelp32Snapshot.Addr(), 2, uintptr(dwFlags), uintptr(th32ProcessID), 0)
	handle = syscall.Handle(r0)
	if handle == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetMappedFileNameW(hProcess syscall.Handle, address uint64, lpFilename *uint16, nSize uint32) (len uint32, err error) {
	r0, _, e1 := syscall.Syscall6(procGetMappedFileNameW.Addr(), 4, uintptr(hProcess), uintptr(address), uintptr(unsafe.Pointer(lpFilename)), uintptr(nSize), 0, 0)
	len = uint32(r0)
	if len == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func VirtualQueryEx(handle syscall.Handle, address uint64, info *MEMORY_BASIC_INFORMATION, info_size uintptr) (size int32, err error) {
	r0, _, e1 := syscall.Syscall6(procVirtualQueryEx.Addr(), 4, uintptr(handle), uintptr(address), uintptr(unsafe.Pointer(info)), uintptr(info_size), 0, 0)
	size = int32(r0)
	if size == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func NetApiBufferFree(Buffer uintptr) (status NET_API_STATUS) {
	r0, _, _ := syscall.Syscall(procNetApiBufferFree.Addr(), 1, uintptr(Buffer), 0, 0)
	status = NET_API_STATUS(r0)
	return
}

func NetUserEnum(servername *uint16, level uint32, filter uint32, bufptr *uintptr, prefmaxlen uint32, entriesread *uint32, totalentries *uint32, resume_handle *uint32) (status NET_API_STATUS) {
	r0, _, _ := syscall.Syscall9(procNetUserEnum.Addr(), 8, uintptr(unsafe.Pointer(servername)), uintptr(level), uintptr(filter), uintptr(unsafe.Pointer(bufptr)), uintptr(prefmaxlen), uintptr(unsafe.Pointer(entriesread)), uintptr(unsafe.Pointer(totalentries)), uintptr(unsafe.Pointer(resume_handle)), 0)
	status = NET_API_STATUS(r0)
	return
}

func NetUserGetGroups(servername *LPCWSTR, username *LPCWSTR, level DWORD, bufptr *LPBYTE, prefmaxlen DWORD, entriesread *LPDWORD, totalentries *LPDWORD) (status NET_API_STATUS) {
	r0, _, _ := syscall.Syscall9(procNetUserGetGroups.Addr(), 7, uintptr(unsafe.Pointer(servername)), uintptr(unsafe.Pointer(username)), uintptr(level), uintptr(unsafe.Pointer(bufptr)), uintptr(prefmaxlen), uintptr(unsafe.Pointer(entriesread)), uintptr(unsafe.Pointer(totalentries)), 0, 0)
	status = NET_API_STATUS(r0)
	return
}

func CryptCATAdminAcquireContext2(handle *syscall.Handle, pgSubsystem *GUID, pwszHashAlgorithm *byte, pStrongHashPolicy *byte, dwFlags uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procCryptCATAdminAcquireContext2.Addr(), 5, uintptr(unsafe.Pointer(handle)), uintptr(unsafe.Pointer(pgSubsystem)), uintptr(unsafe.Pointer(pwszHashAlgorithm)), uintptr(unsafe.Pointer(pStrongHashPolicy)), uintptr(dwFlags), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func CryptCATAdminReleaseContext(handle syscall.Handle, unused int32) (ok bool) {
	r0, _, _ := syscall.Syscall(procCryptCATAdminReleaseContext.Addr(), 2, uintptr(handle), uintptr(unused), 0)
	ok = r0 != 0
	return
}

func CryptCATAdminCalcHashFromFileHandle2(handle syscall.Handle, fd uintptr, pcbHash *uint32, pbHash *byte, dwFlags uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procCryptCATAdminCalcHashFromFileHandle2.Addr(), 5, uintptr(handle), uintptr(fd), uintptr(unsafe.Pointer(pcbHash)), uintptr(unsafe.Pointer(pbHash)), uintptr(dwFlags), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func CryptCATAdminEnumCatalogFromHash(handle syscall.Handle, pbHash *byte, pcbHash uint32, dwFlags uint32, phPrevCatInfo *syscall.Handle) (HCATINFO syscall.Handle) {
	r0, _, _ := syscall.Syscall6(procCryptCATAdminEnumCatalogFromHash.Addr(), 5, uintptr(handle), uintptr(unsafe.Pointer(pbHash)), uintptr(pcbHash), uintptr(dwFlags), uintptr(unsafe.Pointer(phPrevCatInfo)), 0)
	HCATINFO = syscall.Handle(r0)
	return
}

func CryptCATCatalogInfoFromContext(handle syscall.Handle, psCatInfo *CATALOG_INFO, dwFlags uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procCryptCATCatalogInfoFromContext.Addr(), 3, uintptr(handle), uintptr(unsafe.Pointer(psCatInfo)), uintptr(dwFlags))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func CryptCATAdminReleaseCatalogContext(handle syscall.Handle, handle2 syscall.Handle, dwFlags uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procCryptCATAdminReleaseCatalogContext.Addr(), 3, uintptr(handle), uintptr(handle2), uintptr(dwFlags))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func WinVerifyTrust(handle syscall.Handle, action *windows.GUID, data *WINTRUST_DATA) (ret uint32, err error) {
	r0, _, e1 := syscall.Syscall(procWinVerifyTrust.Addr(), 3, uintptr(handle), uintptr(unsafe.Pointer(action)), uintptr(unsafe.Pointer(data)))
	ret = uint32(r0)
	if ret != 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func WTHelperProvDataFromStateData(handle syscall.Handle) (provider *CRYPT_PROVIDER_DATA, err error) {
	r0, _, e1 := syscall.Syscall(procWTHelperProvDataFromStateData.Addr(), 1, uintptr(handle), 0, 0)
	provider = (*CRYPT_PROVIDER_DATA)(unsafe.Pointer(r0))
	if provider == nil {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func WTHelperGetProvSignerFromChain(pProvData *CRYPT_PROVIDER_DATA, idxSigner uint32, fCounterSigner bool, idxCounterSigner uint32) (signer *CRYPT_PROVIDER_SGNR, err error) {
	var _p0 uint32
	if fCounterSigner {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r0, _, e1 := syscall.Syscall6(procWTHelperGetProvSignerFromChain.Addr(), 4, uintptr(unsafe.Pointer(pProvData)), uintptr(idxSigner), uintptr(_p0), uintptr(idxCounterSigner), 0, 0)
	signer = (*CRYPT_PROVIDER_SGNR)(unsafe.Pointer(r0))
	if signer == nil {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func NewLazySystemDLL(name string) *windows.LazyDLL {
	return windows.NewLazySystemDLL(name)
}

type (
	LPVOID         uintptr
	DWORD          uint32
	LPBYTE         *byte
	PBYTE          *byte
	LPDWORD        *uint32
	LPWSTR         *uint16
	LPCWSTR        *uint16
	NET_API_STATUS DWORD

	USER_INFO_3 struct {
		Name             LPWSTR
		Password         LPWSTR
		Password_age     DWORD
		Priv             DWORD
		Home_dir         LPWSTR
		Comment          LPWSTR
		Flags            DWORD
		Script_path      LPWSTR
		Auth_flags       DWORD
		Full_name        LPWSTR
		Usr_comment      LPWSTR
		Parms            LPWSTR
		Workstations     LPWSTR
		Last_logon       DWORD
		Last_logoff      DWORD
		Acct_expires     DWORD
		Max_storage      DWORD
		Units_per_week   DWORD
		Logon_hours      PBYTE
		Bad_pw_count     DWORD
		Num_logons       DWORD
		Logon_server     LPWSTR
		Country_code     DWORD
		Code_page        DWORD
		User_id          DWORD
		Primary_group_id DWORD
		Profile          LPWSTR
		Home_dir_drive   LPWSTR
		Password_expired DWORD
	}
)

const (
	// from LMaccess.h

	USER_PRIV_GUEST = 0
	USER_PRIV_USER  = 1
	USER_PRIV_ADMIN = 2

	UF_SCRIPT                          = 0x0001
	UF_ACCOUNTDISABLE                  = 0x0002
	UF_HOMEDIR_REQUIRED                = 0x0008
	UF_LOCKOUT                         = 0x0010
	UF_PASSWD_NOTREQD                  = 0x0020
	UF_PASSWD_CANT_CHANGE              = 0x0040
	UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x0080

	UF_TEMP_DUPLICATE_ACCOUNT    = 0x0100
	UF_NORMAL_ACCOUNT            = 0x0200
	UF_INTERDOMAIN_TRUST_ACCOUNT = 0x0800
	UF_WORKSTATION_TRUST_ACCOUNT = 0x1000
	UF_SERVER_TRUST_ACCOUNT      = 0x2000

	UF_ACCOUNT_TYPE_MASK = UF_TEMP_DUPLICATE_ACCOUNT |
		UF_NORMAL_ACCOUNT |
		UF_INTERDOMAIN_TRUST_ACCOUNT |
		UF_WORKSTATION_TRUST_ACCOUNT |
		UF_SERVER_TRUST_ACCOUNT

	UF_DONT_EXPIRE_PASSWD                     = 0x10000
	UF_MNS_LOGON_ACCOUNT                      = 0x20000
	UF_SMARTCARD_REQUIRED                     = 0x40000
	UF_TRUSTED_FOR_DELEGATION                 = 0x80000
	UF_NOT_DELEGATED                          = 0x100000
	UF_USE_DES_KEY_ONLY                       = 0x200000
	UF_DONT_REQUIRE_PREAUTH                   = 0x400000
	UF_PASSWORD_EXPIRED                       = 0x800000
	UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000
	UF_NO_AUTH_DATA_REQUIRED                  = 0x2000000
	UF_PARTIAL_SECRETS_ACCOUNT                = 0x4000000
	UF_USE_AES_KEYS                           = 0x8000000

	UF_SETTABLE_BITS = UF_SCRIPT |
		UF_ACCOUNTDISABLE |
		UF_LOCKOUT |
		UF_HOMEDIR_REQUIRED |
		UF_PASSWD_NOTREQD |
		UF_PASSWD_CANT_CHANGE |
		UF_ACCOUNT_TYPE_MASK |
		UF_DONT_EXPIRE_PASSWD |
		UF_MNS_LOGON_ACCOUNT |
		UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED |
		UF_SMARTCARD_REQUIRED |
		UF_TRUSTED_FOR_DELEGATION |
		UF_NOT_DELEGATED |
		UF_USE_DES_KEY_ONLY |
		UF_DONT_REQUIRE_PREAUTH |
		UF_PASSWORD_EXPIRED |
		UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION |
		UF_NO_AUTH_DATA_REQUIRED |
		UF_USE_AES_KEYS |
		UF_PARTIAL_SECRETS_ACCOUNT

	FILTER_TEMP_DUPLICATE_ACCOUNT    = uint32(0x0001)
	FILTER_NORMAL_ACCOUNT            = uint32(0x0002)
	FILTER_INTERDOMAIN_TRUST_ACCOUNT = uint32(0x0008)
	FILTER_WORKSTATION_TRUST_ACCOUNT = uint32(0x0010)
	FILTER_SERVER_TRUST_ACCOUNT      = uint32(0x0020)

	LG_INCLUDE_INDIRECT = (0x0001)

	ERROR_MORE_DATA = (234)

	// OpenProcess
	PROCESS_ALL_ACCESS        = 0x1F0FFF
	PROCESS_VM_READ           = 0x0010
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_DUP_HANDLE        = 0x0040

	// Memory protection constants
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
	PAGE_NOACCESS          = 0x1
	PAGE_READONLY          = 0x2
	PAGE_READWRITE         = 0x4
	PAGE_WRITECOPY         = 0x8

	// CreateToolhelp32Snapshot
	TH32CS_SNAPHEAPLIST = 0x1
	TH32CS_SNAPMODULE   = 0x00000008
	TH32CS_SNAPMODULE32 = 0x10
	TH32CS_SNAPPROCESS  = 0x2
	TH32CS_SNAPTHREAD   = 0x4

	MAX_MODULE_NAME32 = 255
	MAX_PATH          = 260

	// NtQuerySystemInformation
	SystemHandleInformation = 0x10
	SystemObjectInformation = 0x11

	// NtQueryObject
	ObjectBasicInformation = 0x0
	ObjectNameInformation  = 0x1
	ObjectTypeInformation  = 0x2

	// NtQueryInformationProcess
	ProcessBasicInformation       = 0x0
	ProcessImageFileName          = 27
	ProcessCommandLineInformation = 60

	// NtQueryInformationThread
	ThreadBasicInformation   = 0
	ThreadImpersonationToken = 5

	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	THREAD_QUERY_LIMITED_INFORMATION  = 0x0800

	// NtOpenDirectoryObject
	DIRECTORY_QUERY    = 1
	DIRECTORY_TRAVERSE = 2

	SYMBOLIC_LINK_QUERY = 1
)

type UNICODE_STRING struct {
	Length        uint16
	AllocatedSize uint16
	WString       *byte
}

func (self UNICODE_STRING) String() string {
	defer recover()

	var data []uint16

	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = uintptr(unsafe.Pointer(self.WString))
	sh.Len = int(self.Length * 2)
	sh.Cap = int(self.Length * 2)

	return windows.UTF16ToString(data[:])
}

// https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
type OBJECT_BASIC_INFORMATION struct {
	Attributes             uint32
	GrantedAccess          uint32
	HandleCount            uint32
	PointerCount           uint32
	PagedPoolCharge        uint32
	NonPagedPoolCharge     uint32
	Reserved               [3]uint32
	NameInfoSize           uint32
	TypeInfoSize           uint32
	SecurityDescriptorSize uint32
	CreationTime           uint64
}

// https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   uint64
	PebBaseAddress               uint64
	AffinityMask                 uint64
	BasePriority                 uint64
	UniqueProcessId              uint32
	InheritedFromUniqueProcessId uint64
}

// https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationthread
type THREAD_BASIC_INFORMATION struct {
	ExitStatus      uint64
	TebBaseAddress  uint64
	UniqueProcessId uint64
	UniqueThreadId  uint64
	AffinityMask    uint64
	Priority        uint32
	BasePriority    uint32
}

type OBJECT_TYPE_INFORMATION struct {
	TypeName               UNICODE_STRING
	TotalNumberOfObjects   uint32
	TotalNumberOfHandles   uint32
	TotalPagedPoolUsage    uint32
	TotalNonPagedPoolUsage uint32
}

type SYSTEM_HANDLE_TABLE_ENTRY_INFO64 struct {
	UniqueProcessId       uint16
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint8
	HandleAttributes      uint8
	HandleValue           uint16
	Object                uint64
	GrantedAccess         uint32
}

type SYSTEM_OBJECTTYPE_INFORMATION64 struct {
	NextEntryOffset   uint32
	NumberOfObjects   uint32
	NumberOfHandles   uint32
	TypeIndex         uint32
	InvalidAttributes uint32
	GenericMapping    uint64
	GenericMapping2   uint64
	ValidAccessMask   uint32
	PoolType          uint32
	SecurityRequired  uint8
	WaitableObject    uint8
	TypeName          UNICODE_STRING
}

type SYSTEM_INFO struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uint64
	MaximumApplicationAddress uint64
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uint64
	AllocationBase    uint64
	AllocationProtect uint32
	Allignment        uint32
	RegionSize        uint64
	State             uint32
	Protect           uint32
	Type              uint32
	Allignment2       uint32
}

type MODULEENTRY32W struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uint64
	ModBaseSize  uint32
	Module       syscall.Handle
	ModuleName   [MAX_MODULE_NAME32 + 1]uint16
	ExePath      [MAX_PATH]uint16
}

type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               uintptr // UNICODE_STRING
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type TOKEN_ELEVATION struct {
	TokenIsElevated uint32
}

type IO_COUNTERS struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type PROCESS_MEMORY_COUNTERS struct {
	cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

//sys NtOpenThreadToken(thread_handle syscall.Handle, DesiredAccess uint32, open_as_self bool, token_handle *syscall.Handle) (status uint32) = ntdll.NtOpenThreadToken
//sys _ReadProcessMemory(handle syscall.Handle, baseAddress uintptr, buffer uintptr, size uintptr, numRead *uintptr) (err error) = kernel32.ReadProcessMemory
//sys GetProcessMemoryInfo(handle syscall.Handle, memCounters *PROCESS_MEMORY_COUNTERS, cb uint32) (err error) = psapi.GetProcessMemoryInfo
//sys GetProcessIoCounters(hProcess syscall.Handle, lpIoCounters *IO_COUNTERS) (ok bool) = kernel32.GetProcessIoCounters
//sys QueryFullProcessImageName(handle syscall.Handle, dwFlags uint32, buffer *byte, length *uint32) (ok bool) = kernel32.QueryFullProcessImageNameW
//sys NtOpenDirectoryObject(DirectoryHandle *uint32,DesiredAccess uint32, ObjectAttributes *OBJECT_ATTRIBUTES) (status uint32) = ntdll.NtOpenDirectoryObject
//sys AdjustTokenPrivileges(TokenHandle syscall.Token, DisableAllPrivileges bool, NewState uintptr, BufferLength int, PreviousState uintptr, ReturnLength *int) (err error) = Advapi32.AdjustTokenPrivileges
//sys LookupPrivilegeValue(lpSystemName uintptr, lpName uintptr, out uintptr) (err error) = Advapi32.LookupPrivilegeValueW
//sys NtDuplicateObject(SourceProcessHandle syscall.Handle, SourceHandle syscall.Handle, TargetProcessHandle syscall.Handle, TargetHandle *syscall.Handle, DesiredAccess uint32, InheritHandle uint32, Options uint32) (status uint32) = ntdll.NtDuplicateObject
//sys NtQueryInformationProcess(Handle syscall.Handle, ObjectInformationClass uint32, ProcessInformation *byte, ProcessInformationLength uint32, ReturnLength *uint32) (status uint32) = ntdll.NtQueryInformationProcess
//sys NtQueryInformationThread(Handle syscall.Handle, ObjectInformationClass uint32, ThreadInformation *byte, ThreadInformationLength uint32, ReturnLength *uint32) (status uint32, err error) = ntdll.NtQueryInformationThread
//sys NtQueryObject(Handle syscall.Handle, ObjectInformationClass uint32, ObjectInformation *byte, ObjectInformationLength uint32, ReturnLength *uint32) (status uint32, err error) = ntdll.NtQueryObject
//sys NtQuerySystemInformation(SystemInformationClass uint32, SystemInformation *byte, SystemInformationLength uint32, ReturnLength *uint32) (status uint32) = ntdll.NtQuerySystemInformation
//sys CloseHandle(h syscall.Handle) (err error) = kernel32.CloseHandle
//sys OpenProcess(dwDesiredAccess uint32, bInheritHandle bool, dwProcessId uint32) (handle syscall.Handle, err error) = kernel32.OpenProcess
//sys GetSystemInfo(lpSystemInfo *SYSTEM_INFO) (err error) = kernel32.GetSystemInfo
//sys Module32Next(hSnapshot syscall.Handle, me *MODULEENTRY32W) (err error) = kernel32.Module32NextW
//sys Module32First(hSnapshot syscall.Handle, me *MODULEENTRY32W) (err error) = kernel32.Module32FirstW
//sys CreateToolhelp32Snapshot(dwFlags uint32, th32ProcessID uint32) (handle syscall.Handle, err error) = kernel32.CreateToolhelp32Snapshot
//sys GetMappedFileNameW(hProcess syscall.Handle, address uint64, lpFilename *uint16 , nSize uint32) (len uint32, err error) = psapi.GetMappedFileNameW
//sys VirtualQueryEx(handle syscall.Handle, address uint64, info *MEMORY_BASIC_INFORMATION, info_size uintptr) (size int32, err error) = kernel32.VirtualQueryEx
//sys NetApiBufferFree(Buffer uintptr) (status NET_API_STATUS) = netapi32.NetApiBufferFree
//sys NetUserEnum(servername *uint16, level uint32, filter uint32, bufptr *uintptr, prefmaxlen uint32, entriesread *uint32, totalentries *uint32, resume_handle *uint32) (status NET_API_STATUS) = netapi32.NetUserEnum
//sys NetUserGetGroups(servername *LPCWSTR, username *LPCWSTR, level DWORD, bufptr *LPBYTE, prefmaxlen DWORD, entriesread *LPDWORD, totalentries *LPDWORD) (status NET_API_STATUS) = netapi32.NetUserGetGroups

// Converts a pointer to a wide string to a regular go string. The
// underlying buffer may be freed afterwards by the Windows API.
func LPWSTRToString(ptr LPWSTR) string {
	p := (*[0xffff]uint16)(unsafe.Pointer(ptr))
	if p == nil {
		return ""
	}

	return windows.UTF16ToString(p[:])
}

// Convert a pointer to buffer and a length into a Go string. NOTE:
// This does not copy the buffer so it should not be kept around after
// the Windows API frees the underlying buffer.
func PointerToString(ptr uintptr, len int) string {
	var s string
	hdr := (*reflect.StringHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(ptr))
	hdr.Len = len

	return s
}

func NtCurrentProcess() syscall.Handle {
	return syscall.Handle(windows.CurrentProcess())
}

func ReadProcessMemory(handle syscall.Handle, baseAddress uint64, dest []byte) (int, error) {
	var numRead uintptr

	n := len(dest)
	if n == 0 {
		return 0, nil
	}
	err := _ReadProcessMemory(handle, uintptr(baseAddress),
		uintptr(unsafe.Pointer(&dest[0])), uintptr(n), &numRead)
	if err != nil {
		return 0, err
	}
	return int(numRead), nil
}

func HasWintrustDll() error {
	err := procCryptCATAdminAcquireContext2.Find()
	if err != nil {
		return err
	}

	return nil
}

// Wintrust dll functions - may not be there always.
//sys CryptCATAdminAcquireContext2(handle *syscall.Handle, pgSubsystem *GUID, pwszHashAlgorithm *byte, pStrongHashPolicy *byte, dwFlags uint32) (err error) = wintrust.CryptCATAdminAcquireContext2
//sys CryptCATAdminReleaseContext(handle syscall.Handle, unused int32) (ok bool) = wintrust.CryptCATAdminReleaseContext
//sys CryptCATAdminCalcHashFromFileHandle2(handle syscall.Handle, fd uintptr, pcbHash *uint32, pbHash *byte, dwFlags uint32) (err error) = wintrust.CryptCATAdminCalcHashFromFileHandle2
//sys CryptCATAdminEnumCatalogFromHash(handle syscall.Handle, pbHash *byte, pcbHash uint32, dwFlags uint32, phPrevCatInfo *syscall.Handle) (HCATINFO syscall.Handle) = wintrust.CryptCATAdminEnumCatalogFromHash
//sys CryptCATCatalogInfoFromContext(handle syscall.Handle, psCatInfo *CATALOG_INFO, dwFlags uint32) (err error) = wintrust.CryptCATCatalogInfoFromContext
//sys CryptCATAdminReleaseCatalogContext(handle syscall.Handle, handle2 syscall.Handle, dwFlags uint32) (err error) = wintrust.CryptCATAdminReleaseCatalogContext
//sys WinVerifyTrust(handle syscall.Handle, action *GUID, data *WINTRUST_DATA) (ret uint32, err error) [failretval!=0] = wintrust.WinVerifyTrust
//sys WTHelperProvDataFromStateData(handle syscall.Handle) (provider *CRYPT_PROVIDER_DATA, err error) [failretval==nil] = wintrust.WTHelperProvDataFromStateData
//sys WTHelperGetProvSignerFromChain(pProvData *CRYPT_PROVIDER_DATA, idxSigner uint32, fCounterSigner bool, idxCounterSigner uint32) (signer *CRYPT_PROVIDER_SGNR, err error) [failretval==nil] = wintrust.WTHelperGetProvSignerFromChain

type WINTRUST_FILE_INFO struct {
	CbStruct       uint32
	PcwszFilePath  uintptr
	HFile          uintptr
	PgKnownSubject *GUID
}

type CATALOG_INFO struct {
	CbStruct       uint32
	WszCatalogFile [1024]byte
}

type WINTRUST_CATALOG_INFO struct {
	CbStruct             uint32
	DwCatalogVersion     uint32
	PcwszCatalogFilePath uintptr
	PcwszMemberTag       uintptr
	PcwszMemberFilePath  uintptr
	HMemberFile          uintptr
	PbCalculatedFileHash uintptr
	CbCalculatedFileHash uint32
	PcCatalogContext     uintptr
	HCatAdmin            syscall.Handle
}

type WINTRUST_DATA struct {
	CbStruct            uint32                       //0-4
	PPolicyCallbackData uintptr                      //4-12
	PSIPClientData      uintptr                      //12-20
	DwUIChoice          uint32                       //20-24
	FdwRevocationChecks uint32                       //24-28
	DwUnionChoice       uint32                       //28-32
	Union               uintptr                      //32-40
	DwStateAction       uint32                       //40-44
	HWVTStateData       syscall.Handle               //44-48
	PwszURLReference    uintptr                      //48-56
	DwProvFlags         uint32                       //56-60
	DwUIContext         uint32                       // 60-64
	PSignatureSettings  *WINTRUST_SIGNATURE_SETTINGS // 64-72
} // 72

type WINTRUST_SIGNATURE_SETTINGS struct {
	CbStruct           uint32
	DwIndex            uint32
	DwFlags            uint32
	CSecondarySigs     uint32
	DwVerifiedSigIndex uint32
	PCryptoPolicy      *byte
}

// Opaque structure
type CRYPT_PROVIDER_DATA struct {
	Reserved uint32
}

type CRYPT_PROVIDER_SGNR struct {
	CbStruct                            uint32
	SftVerifyAsOfLow, SftVerifyAsOfHigh uint32 // Need to split into 2 uint32 to maintain alignment
	CsCertChain                         uint32
	PasCertChain                        *CRYPT_PROVIDER_CERT
	DwSignerType                        uint32
	PsSigner                            *CMSG_SIGNER_INFO
	DwError                             uint32
	CsCounterSigners                    uint32
	PasCounterSigners                   uintptr
	PChainContext                       uintptr
}

type CMSG_SIGNER_INFO struct {
	DwVersion               uint32
	Issuer                  CRYPTOAPI_BLOB
	SerialNumber            CRYPTOAPI_BLOB
	HashAlgorithm           CRYPT_ALGORITHM_IDENTIFIER
	HashEncryptionAlgorithm CRYPT_ALGORITHM_IDENTIFIER
	EncryptedHash           CRYPTOAPI_BLOB

	// Some extra fields we dont use
	//CRYPT_ATTRIBUTES           AuthAttrs;
	//CRYPT_ATTRIBUTES           UnauthAttrs;
}

type CRYPTOAPI_BLOB struct {
	CbData uint32
	PbData uintptr
}

type CRYPT_ALGORITHM_IDENTIFIER struct {
	PszObjId   *byte
	Parameters CRYPTOAPI_BLOB
}

type CRYPT_PROVIDER_CERT struct {
	CbStruct uint32
	PCert    *CERT_CONTEXT
	// More fields we dont care about
}

type CERT_CONTEXT struct {
	DwCertEncodingType uint32
	PbCertEncoded      *byte
	CbCertEncoded      uint32
	PCertInfo          uintptr
	HCertStore         uint32
}

const (
	WTD_UI_ALL    = 1
	WTD_UI_NONE   = 2
	WTD_UI_NOBAD  = 3
	WTD_UI_NOGOOD = 4

	WTD_REVOKE_NONE       = 0x00000000
	WTD_REVOKE_WHOLECHAIN = 0x00000001

	WTD_CHOICE_FILE    = 1
	WTD_CHOICE_CATALOG = 2
	WTD_CHOICE_BLOB    = 3
	WTD_CHOICE_SIGNER  = 4
	WTD_CHOICE_CERT    = 5

	WTD_STATEACTION_IGNORE           = 0x00000000
	WTD_STATEACTION_VERIFY           = 0x00000001
	WTD_STATEACTION_CLOSE            = 0x00000002
	WTD_STATEACTION_AUTO_CACHE       = 0x00000003
	WTD_STATEACTION_AUTO_CACHE_FLUSH = 0x00000004
	WTD_REVOCATION_CHECK_NONE        = 0x00000010
	WTD_SAFER_FLAG                   = 0x00000100
	WTD_CACHE_ONLY_URL_RETRIEVAL     = 0x00001000

	INVALID_HANDLE_VALUE = syscall.Handle(0xFFFFFFFF)
)
