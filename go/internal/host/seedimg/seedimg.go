// Package seedimg writes the cloud-init NoCloud seed disk (design 5.3.3) for hypervisors that
// cannot build one themselves (qemu): a small FAT12 file system labelled CIDATA holding a few
// files, with long file names so cloud-init finds "user-data" and "meta-data" by their real names.
// It is written from scratch so the host binary needs no mkfs, mtools, or ISO tool.
package seedimg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	sectorSize        = 512
	sectorsPerCluster = 1
	reservedSectors   = 1
	numFATs           = 2
	rootEntries       = 64   // 4 sectors of 32-byte entries
	totalSectors      = 2880 // 1.44 MB, comfortably FAT12
	sectorsPerFAT     = 9
	mediaDescriptor   = 0xF8
)

// Label is the volume label cloud-init's NoCloud datasource looks for.
const Label = "CIDATA"

// Write returns a FAT12 disk image holding files (name -> content) in its root directory.
func Write(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		if err := checkName(n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	sort.Strings(names)

	img := make([]byte, totalSectors*sectorSize)
	writeBootSector(img)
	fatStart := reservedSectors * sectorSize
	rootStart := fatStart + numFATs*sectorsPerFAT*sectorSize
	dataStart := rootStart + rootEntries*32
	dataClusters := (len(img) - dataStart) / (sectorsPerCluster * sectorSize)

	fat := make([]uint16, dataClusters+2)
	fat[0], fat[1] = 0xF00|mediaDescriptor, 0xFFF
	var root [][]byte
	root = append(root, volumeLabelEntry())
	next := 2
	for i, n := range names {
		content := files[n]
		clusters := (len(content) + sectorSize*sectorsPerCluster - 1) / (sectorSize * sectorsPerCluster)
		first := 0
		if clusters > 0 {
			if next+clusters > len(fat) {
				return nil, errors.New("seed files do not fit the seed disk")
			}
			first = next
			for c := 0; c < clusters; c++ {
				off := dataStart + (next-2)*sectorSize*sectorsPerCluster
				end := min((c+1)*sectorSize*sectorsPerCluster, len(content))
				copy(img[off:], content[c*sectorSize*sectorsPerCluster:end])
				if c == clusters-1 {
					fat[next] = 0xFFF
				} else {
					fat[next] = uint16(next + 1)
				}
				next++
			}
		}
		short := shortName(i)
		root = append(root, lfnEntries(n, short)...)
		root = append(root, fileEntry(short, first, len(content)))
	}
	if len(root) > rootEntries {
		return nil, errors.New("too many seed files")
	}
	for i, e := range root {
		copy(img[rootStart+i*32:], e)
	}
	packed := packFAT12(fat)
	for k := 0; k < numFATs; k++ {
		copy(img[fatStart+k*sectorsPerFAT*sectorSize:], packed)
	}
	return img, nil
}

func checkName(n string) error {
	if n == "" || len(n) > 64 {
		return fmt.Errorf("seed file name %q: bad length", n)
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("seed file name %q: only letters, digits, '-', '_', and '.'", n)
		}
	}
	return nil
}

func writeBootSector(img []byte) {
	b := img[:sectorSize]
	copy(b[0:], []byte{0xEB, 0x3C, 0x90})
	copy(b[3:], "SANDBOX ")
	binary.LittleEndian.PutUint16(b[11:], sectorSize)
	b[13] = sectorsPerCluster
	binary.LittleEndian.PutUint16(b[14:], reservedSectors)
	b[16] = numFATs
	binary.LittleEndian.PutUint16(b[17:], rootEntries)
	binary.LittleEndian.PutUint16(b[19:], totalSectors)
	b[21] = mediaDescriptor
	binary.LittleEndian.PutUint16(b[22:], sectorsPerFAT)
	binary.LittleEndian.PutUint16(b[24:], 18) // sectors per track
	binary.LittleEndian.PutUint16(b[26:], 2)  // heads
	b[36] = 0x80                              // drive number
	b[38] = 0x29                              // extended boot signature
	binary.LittleEndian.PutUint32(b[39:], 0x5eed5eed)
	copy(b[43:], fmt.Sprintf("%-11s", Label))
	copy(b[54:], "FAT12   ")
	b[510], b[511] = 0x55, 0xAA
}

func volumeLabelEntry() []byte {
	e := make([]byte, 32)
	copy(e, fmt.Sprintf("%-11s", Label))
	e[11] = 0x08 // volume label
	return e
}

// shortName is the i-th file's 8.3 alias; the long name entries carry the real name.
func shortName(i int) [11]byte {
	var s [11]byte
	copy(s[:], fmt.Sprintf("SEED%04d   ", i))
	return s
}

func fileEntry(short [11]byte, first, size int) []byte {
	e := make([]byte, 32)
	copy(e, short[:])
	e[11] = 0x20                                // archive
	binary.LittleEndian.PutUint16(e[24:], 0x21) // 1980-01-01
	binary.LittleEndian.PutUint16(e[26:], uint16(first))
	binary.LittleEndian.PutUint32(e[28:], uint32(size))
	return e
}

func lfnChecksum(short [11]byte) byte {
	var sum byte
	for _, c := range short {
		sum = (sum>>1 | sum<<7) + c
	}
	return sum
}

// lfnEntries are the VFAT long-name entries for name, in on-disk order (last part first).
func lfnEntries(name string, short [11]byte) [][]byte {
	u := make([]uint16, 0, len(name)+1)
	for _, r := range name {
		u = append(u, uint16(r))
	}
	if len(u)%13 != 0 {
		u = append(u, 0)
		for len(u)%13 != 0 {
			u = append(u, 0xFFFF)
		}
	}
	n := len(u) / 13
	sum := lfnChecksum(short)
	out := make([][]byte, 0, n)
	for seq := n; seq >= 1; seq-- {
		e := make([]byte, 32)
		e[0] = byte(seq)
		if seq == n {
			e[0] |= 0x40
		}
		e[11] = 0x0F
		e[13] = sum
		part := u[(seq-1)*13 : seq*13]
		offs := []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30}
		for i, o := range offs {
			binary.LittleEndian.PutUint16(e[o:], part[i])
		}
		out = append(out, e)
	}
	return out
}

func packFAT12(fat []uint16) []byte {
	out := make([]byte, (len(fat)*3+1)/2)
	for i, v := range fat {
		off := i * 3 / 2
		if i%2 == 0 {
			out[off] = byte(v)
			out[off+1] = out[off+1]&0xF0 | byte(v>>8)&0x0F
		} else {
			out[off] = out[off]&0x0F | byte(v<<4)
			out[off+1] = byte(v >> 4)
		}
	}
	return out
}

// Read is the inverse of Write for images it wrote (tests and diagnostics): the root directory's
// files by long name.
func Read(img []byte) (map[string][]byte, error) {
	if len(img) < totalSectors*sectorSize || img[510] != 0x55 || img[511] != 0xAA {
		return nil, errors.New("not a seed image")
	}
	fatStart := reservedSectors * sectorSize
	rootStart := fatStart + numFATs*sectorsPerFAT*sectorSize
	dataStart := rootStart + rootEntries*32
	fat := img[fatStart : fatStart+sectorsPerFAT*sectorSize]
	entry := func(i int) int {
		off := i * 3 / 2
		v := int(fat[off]) | int(fat[off+1])<<8
		if i%2 == 0 {
			return v & 0xFFF
		}
		return v >> 4
	}
	out := map[string][]byte{}
	var long []uint16
	for i := 0; i < rootEntries; i++ {
		e := img[rootStart+i*32 : rootStart+(i+1)*32]
		switch {
		case e[0] == 0:
			return out, nil
		case e[11] == 0x0F:
			var part []uint16
			for _, o := range []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30} {
				part = append(part, binary.LittleEndian.Uint16(e[o:]))
			}
			long = append(part, long...)
		case e[11]&0x08 != 0:
			long = nil
		default:
			var sb strings.Builder
			for _, c := range long {
				if c == 0 || c == 0xFFFF {
					break
				}
				sb.WriteRune(rune(c))
			}
			long = nil
			size := int(binary.LittleEndian.Uint32(e[28:]))
			c := int(binary.LittleEndian.Uint16(e[26:]))
			var data []byte
			for c >= 2 && c < 0xFF8 && len(data) < size {
				off := dataStart + (c-2)*sectorSize
				data = append(data, img[off:off+sectorSize]...)
				c = entry(c)
			}
			if len(data) < size {
				return nil, fmt.Errorf("%s: truncated", sb.String())
			}
			out[sb.String()] = data[:size]
		}
	}
	return out, nil
}
