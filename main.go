package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	tableFilter = "filter"

	nfInetNumHooks  = 5
	nfInetLocalOut  = 3
	nfAcceptVerdict = 1

	xtTableMaxNameLen = 32

	iptBaseCtl      = 64
	iptSoSetReplace = iptBaseCtl
	iptSoGetInfo    = iptBaseCtl
	iptSoGetEntries = iptBaseCtl + 1

	sizeOfIPTEntry         = 112
	sizeOfXTStandardTarget = 40
	sizeOfIPTGetInfo       = 84
	sizeOfIPTGetEntries    = 40
	sizeOfIPTReplace       = 96
)

func main() {
	if err := injectDummyRule(); err != nil {
		fmt.Fprintf(os.Stderr, "inject failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("dummy legacy iptables rule injected (or already present)")
}

func injectDummyRule() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("open raw socket (need CAP_NET_ADMIN/CAP_NET_RAW): %w", err)
	}
	defer syscall.Close(fd)

	info, tableName, err := getTableInfo(fd, tableFilter)
	if err != nil {
		return err
	}

	entriesBlob, err := getTableEntriesBlob(fd, tableName, info.size)
	if err != nil {
		return err
	}

	dummyRule := buildDummyAcceptRule()
	if bytes.Contains(entriesBlob, dummyRule) {
		return nil
	}

	insertAt := int(info.underflow[nfInetLocalOut])
	if insertAt < 0 || insertAt > len(entriesBlob) {
		return fmt.Errorf("invalid insertion offset %d for OUTPUT underflow", insertAt)
	}

	newEntries := make([]byte, 0, len(entriesBlob)+len(dummyRule))
	newEntries = append(newEntries, entriesBlob[:insertAt]...)
	newEntries = append(newEntries, dummyRule...)
	newEntries = append(newEntries, entriesBlob[insertAt:]...)

	ruleLen := uint32(len(dummyRule))
	replace := iptReplace{
		name:       tableName,
		validHooks: info.validHooks,
		numEntries: info.numEntries + 1,
		size:       info.size + ruleLen,
		hookEntry:  info.hookEntry,
		underflow:  info.underflow,
	}

	for i := 0; i < nfInetNumHooks; i++ {
		if replace.hookEntry[i] >= uint32(insertAt) {
			replace.hookEntry[i] += ruleLen
		}
		if replace.underflow[i] >= uint32(insertAt) {
			replace.underflow[i] += ruleLen
		}
	}

	replaceBuf := make([]byte, sizeOfIPTReplace+len(newEntries))
	marshalIPTReplace(replaceBuf[:sizeOfIPTReplace], replace)
	copy(replaceBuf[sizeOfIPTReplace:], newEntries)

	if err := setSockOpt(fd, syscall.SOL_IP, iptSoSetReplace, replaceBuf); err != nil {
		return fmt.Errorf("IPT_SO_SET_REPLACE failed (need legacy iptables ABI): %w", err)
	}

	return nil
}

func buildDummyAcceptRule() []byte {
	total := sizeOfIPTEntry + sizeOfXTStandardTarget
	buf := make([]byte, total)

	// ipt_entry.target_offset and next_offset.
	binary.LittleEndian.PutUint16(buf[88:90], uint16(sizeOfIPTEntry))
	binary.LittleEndian.PutUint16(buf[90:92], uint16(total))

	targetStart := sizeOfIPTEntry

	// xt_entry_target.target_size for a standard target.
	binary.LittleEndian.PutUint16(buf[targetStart:targetStart+2], uint16(sizeOfXTStandardTarget))

	// xt_standard_target.verdict for ACCEPT is -NF_ACCEPT-1 == -2.
	acceptVerdict := int32(-nfAcceptVerdict - 1)
	binary.LittleEndian.PutUint32(buf[targetStart+32:targetStart+36], uint32(acceptVerdict))

	return buf
}

type iptGetInfo struct {
	name       [xtTableMaxNameLen]byte
	validHooks uint32
	hookEntry  [nfInetNumHooks]uint32
	underflow  [nfInetNumHooks]uint32
	numEntries uint32
	size       uint32
}

type iptReplace struct {
	name       [xtTableMaxNameLen]byte
	validHooks uint32
	numEntries uint32
	size       uint32
	hookEntry  [nfInetNumHooks]uint32
	underflow  [nfInetNumHooks]uint32
}

func getTableInfo(fd int, table string) (iptGetInfo, [xtTableMaxNameLen]byte, error) {
	var tableName [xtTableMaxNameLen]byte
	copy(tableName[:], []byte(table))

	req := make([]byte, sizeOfIPTGetInfo)
	copy(req[:xtTableMaxNameLen], tableName[:])

	if err := getSockOpt(fd, syscall.SOL_IP, iptSoGetInfo, req); err != nil {
		return iptGetInfo{}, tableName, fmt.Errorf("IPT_SO_GET_INFO(%s): %w", table, err)
	}

	info := unmarshalIPTGetInfo(req)
	return info, tableName, nil
}

func getTableEntriesBlob(fd int, tableName [xtTableMaxNameLen]byte, tableSize uint32) ([]byte, error) {
	req := make([]byte, sizeOfIPTGetEntries+int(tableSize))
	copy(req[:xtTableMaxNameLen], tableName[:])
	binary.LittleEndian.PutUint32(req[32:36], tableSize)

	if err := getSockOpt(fd, syscall.SOL_IP, iptSoGetEntries, req); err != nil {
		return nil, fmt.Errorf("IPT_SO_GET_ENTRIES: %w", err)
	}

	payload := make([]byte, len(req)-sizeOfIPTGetEntries)
	copy(payload, req[sizeOfIPTGetEntries:])
	return payload, nil
}

func marshalIPTReplace(dst []byte, r iptReplace) {
	copy(dst[:xtTableMaxNameLen], r.name[:])
	binary.LittleEndian.PutUint32(dst[32:36], r.validHooks)
	binary.LittleEndian.PutUint32(dst[36:40], r.numEntries)
	binary.LittleEndian.PutUint32(dst[40:44], r.size)

	off := 44
	for i := 0; i < nfInetNumHooks; i++ {
		binary.LittleEndian.PutUint32(dst[off:off+4], r.hookEntry[i])
		off += 4
	}
	for i := 0; i < nfInetNumHooks; i++ {
		binary.LittleEndian.PutUint32(dst[off:off+4], r.underflow[i])
		off += 4
	}
	// num_counters and counters pointer are left zeroed.
}

func unmarshalIPTGetInfo(src []byte) iptGetInfo {
	var out iptGetInfo
	copy(out.name[:], src[:xtTableMaxNameLen])
	out.validHooks = binary.LittleEndian.Uint32(src[32:36])

	off := 36
	for i := 0; i < nfInetNumHooks; i++ {
		out.hookEntry[i] = binary.LittleEndian.Uint32(src[off : off+4])
		off += 4
	}
	for i := 0; i < nfInetNumHooks; i++ {
		out.underflow[i] = binary.LittleEndian.Uint32(src[off : off+4])
		off += 4
	}
	out.numEntries = binary.LittleEndian.Uint32(src[76:80])
	out.size = binary.LittleEndian.Uint32(src[80:84])
	return out
}

func getSockOpt(fd, level, name int, buf []byte) error {
	l := uint32(len(buf))
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&l)),
		0,
	)
	if errno != 0 {
		return errno
	}
	if int(l) < len(buf) {
		for i := int(l); i < len(buf); i++ {
			buf[i] = 0
		}
	}
	return nil
}

func setSockOpt(fd, level, name int, buf []byte) error {
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
