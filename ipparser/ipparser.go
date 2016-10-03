package ipparser

import (
	"encoding/binary"
	"fmt"
	"go-gogotester/re"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const ipv4Exp = `(?P<astr>(\d{1,3}\.){3}\d{1,3})/(?P<mstr>\d{1,2})|(?P<range>((\d{1,3}\-\d{1,3}|\d{1,3})\.){3}(\d{1,3}\-\d{1,3}|\d{1,3}))|(?P<domain>[\w\-\.]+\.\w+)`

var ipv4Regex *regexp.Regexp

func init() {
	ipv4Regex = regexp.MustCompile(ipv4Exp)
}

func ParseIp(strIpRange string) []net.IP {

	namedMatches := re.GetNamedMatches(ipv4Regex, strIpRange, -1)
	if namedMatches == nil {
		return nil
	}

	result := make([]net.IP, 0, len(namedMatches))

	for _, match := range namedMatches {
		astr := match["astr"]
		mstr := match["mstr"]
		rangestr := match["range"]
		domainstr := match["domain"]

		switch {
		case mstr != "":
			ip := net.ParseIP(astr)
			cidr, _ := strconv.ParseUint(mstr, 10, 32)
			mov := uint32(32) - uint32(cidr)
			msk := (0xffffffff >> mov) << mov
			num := binary.BigEndian.Uint32(ip.To4())
			min := uint32(num) & uint32(msk)
			max := uint32(num) | uint32(0xffffffff^msk)

			result = appendIpRange(result, min, max)

		case rangestr != "":
			var min, max uint32
			sps := strings.Split(rangestr, ".")
			for _, seg := range sps {
				if strings.Contains(seg, "-") {
					tps := strings.Split(seg, "-")
					va, _ := strconv.ParseUint(tps[0], 10, 8)
					vb, _ := strconv.ParseUint(tps[1], 10, 8)

					min = (min << 8) | uint32(va&0xff)
					max = (max << 8) | uint32(vb&0xff)
				} else {
					v, _ := strconv.ParseUint(seg, 10, 8)
					min = (min << 8) | uint32(v&0xff)
					max = (max << 8) | uint32(v&0xff)
				}
			}

			result = appendIpRange(result, min, max)

		case domainstr != "":
			ips, err := net.LookupIP(domainstr)
			if err == nil {
				for _, ip := range ips {
					result = append(result, ip)
				}
			}
		}
	}

	return result
}

func appendIpRange(ips []net.IP, min uint32, max uint32) []net.IP {
	result := ips
	for v := min; v <= max; v++ {
		hostiparr := make([]byte, 4)
		binary.BigEndian.PutUint32(hostiparr, v)
		if hostiparr[3] == 0 || hostiparr[3] == 255 {
			continue
		}

		hostip := net.IP(hostiparr)
		result = append(result, hostip)
	}

	return result
}

func main() {
	ipPool := `
		1.179.248-250.0-2,
		103.25.178.4-9,
		192.168.1.100/29,
		www.baidu.com`

	fmt.Println(ParseIp(ipPool))
}
