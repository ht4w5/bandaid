package ipx

import (
	"net/netip"
	"strings"
)

func ParsePrefixOrAddr(s string) (netip.Prefix, error) {
	i := strings.LastIndexByte(s, '/')
	if i >= 0 {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	} else {
		return netip.PrefixFrom(addr, 128), nil
	}
}
