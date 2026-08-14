package status

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var procCPUInfo = "/proc/cpuinfo"

// readCPUModel returns a human-readable processor name.
//
// There is no portable field for this. x86 kernels expose "model name" with a
// full marketing string; arm64 kernels expose no name at all, only the numeric
// implementer and part IDs from the MIDR register. So this tries the easy
// source first and falls back to decoding the IDs, which is why the lookup
// table below exists.
func readCPUModel() (string, error) {
	f, err := os.Open(procCPUInfo)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", procCPUInfo, err)
	}
	defer f.Close()

	var implementer, part, hardware string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		switch key {
		case "model name", "Model Name":
			// x86, and a few arm64 kernels that synthesise it.
			return value, nil
		case "Hardware", "Model":
			// Single-board machines name the board here (a Raspberry Pi reports
			// "BCM2835"). Remember it as a fallback, but keep looking: the MIDR
			// IDs name the actual core, which is more precise.
			if hardware == "" {
				hardware = value
			}
		case "CPU implementer":
			implementer = value
		case "CPU part":
			part = value
		}
		// Once both arm64 IDs are known there is nothing further to gain.
		if implementer != "" && part != "" {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("read %s: %w", procCPUInfo, err)
	}

	if implementer == "" || part == "" {
		if hardware != "" {
			return hardware, nil
		}
		return "", fmt.Errorf("no processor name in %s", procCPUInfo)
	}
	return armModel(implementer, part), nil
}

// armImplementers maps the JEP106 code in MIDR_EL1 to a vendor.
var armImplementers = map[uint64]string{
	0x41: "ARM",
	0x42: "Broadcom",
	0x43: "Cavium",
	0x44: "DEC",
	0x46: "Fujitsu",
	0x48: "HiSilicon",
	0x4e: "NVIDIA",
	0x50: "Ampere",
	0x51: "Qualcomm",
	0x53: "Samsung",
	0x56: "Marvell",
	0x61: "Apple",
	0x69: "Intel",
	0xc0: "Ampere",
}

// armParts maps (implementer, part) to a core name. Only ARM's own cores are
// listed: they are what a cloud arm64 instance almost always reports, and an
// unknown part degrades to the raw IDs rather than a wrong guess.
var armParts = map[[2]uint64]string{
	{0x41, 0xd03}: "Cortex-A53",
	{0x41, 0xd04}: "Cortex-A35",
	{0x41, 0xd05}: "Cortex-A55",
	{0x41, 0xd07}: "Cortex-A57",
	{0x41, 0xd08}: "Cortex-A72",
	{0x41, 0xd09}: "Cortex-A73",
	{0x41, 0xd0a}: "Cortex-A75",
	{0x41, 0xd0b}: "Cortex-A76",
	{0x41, 0xd0c}: "Neoverse-N1",
	{0x41, 0xd0d}: "Cortex-A77",
	{0x41, 0xd40}: "Neoverse-V1",
	{0x41, 0xd41}: "Cortex-A78",
	{0x41, 0xd44}: "Cortex-X1",
	{0x41, 0xd49}: "Neoverse-N2",
	{0x41, 0xd4a}: "Neoverse-E1",
	{0x41, 0xd4f}: "Neoverse-V2",
	{0x61, 0x022}: "Apple M1",
	{0x61, 0x032}: "Apple M2",
}

// armModel renders the vendor and core name from the hex IDs.
func armModel(implementer, part string) string {
	imp, err1 := strconv.ParseUint(strings.TrimPrefix(implementer, "0x"), 16, 64)
	prt, err2 := strconv.ParseUint(strings.TrimPrefix(part, "0x"), 16, 64)
	if err1 != nil || err2 != nil {
		return fmt.Sprintf("ARM %s/%s", implementer, part)
	}

	vendor, haveVendor := armImplementers[imp]
	core, haveCore := armParts[[2]uint64{imp, prt}]

	switch {
	case haveVendor && haveCore:
		return vendor + " " + core
	case haveVendor:
		// A vendor we know with a core we do not. Naming the vendor and showing
		// the raw part is more useful than inventing a name.
		return fmt.Sprintf("%s (part %s)", vendor, part)
	default:
		return fmt.Sprintf("implementer %s, part %s", implementer, part)
	}
}
