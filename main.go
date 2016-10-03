package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"go-gogotester/asset"
	"go-gogotester/ipparser"
	"io"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"time"
)

type IpInfo struct {
	ip  net.IP
	err error
}

type HandshakeError struct {
	err error
}

func (self HandshakeError) Error() string {
	return fmt.Sprintf("handshake error:%s", self.err.Error())
}

type ResponseError struct {
	response string
}

func (self ResponseError) Error() string {
	return fmt.Sprintf("response error:%s", self.response)
}

type ResponseMatchError struct {
	response string
}

func (self ResponseMatchError) Error() string {
	return "response match error:" + self.response
}

const (
	testChannelInitLen = 100
	googleHostName     = "google.com"
	connTimeout        = 1500

	defaultRetryCount = 3

	resultExp = `(?ms)HTTP/...\s(?P<status>\d+).*Server:\s*(?P<server>\w.*?)\r\s*.*?`
)

var (
	testChannel   = make(chan net.IP, testChannelInitLen)
	resultChannel = make(chan *IpInfo)

	ipPool      []net.IP
	goodIp      = make([]string, 0)
	resultRegex = regexp.MustCompile(resultExp)
	needTestNum = 5 // 需要测试的数量
	passedNum   = 0 // 已经测试完毕的ip数
	ipPoolLen   int // ipPool的大小
)

func removeFromIpPool(index int) net.IP {
	elem := ipPool[index]
	copy(ipPool[index:], ipPool[index+1:])
	ipPool[len(ipPool)-1] = nil
	ipPool = ipPool[:len(ipPool)-1]

	return elem
}

func removeWithoutOrderFromIpPool(index int) net.IP {
	elem := ipPool[index]
	ipPool[index] = ipPool[len(ipPool)-1]
	ipPool[len(ipPool)-1] = nil
	ipPool = ipPool[:len(ipPool)-1]

	return elem
}

func doTestIp(ipToTest net.IP) *IpInfo {

	ipinfo := &IpInfo{ip: ipToTest}

	raddr := &net.TCPAddr{Port: 443, IP: ipToTest}
	conn, err := net.DialTimeout("tcp", raddr.String(), time.Millisecond*connTimeout)

	if err != nil {
		fmt.Println("conn err:" + err.Error())
		ipinfo.err = err
		return ipinfo
	}

	defer func() {
		conn.Close()
	}()

	tlsConfig := &tls.Config{
		ServerName: googleHostName,
	}

	sslConn := tls.Client(conn, tlsConfig)
	err = sslConn.Handshake()
	if err != nil {
		ipinfo.err = HandshakeError{err}
		return ipinfo
	}

	defer func() {
		sslConn.Close()
	}()

	data := fmt.Sprintf("HEAD /search?q=g HTTP/1.1\r\nHost: www.google.com.hk\r\n\r\nGET /%s HTTP/1.1\r\nHost: azzvxgoagent%d.appspot.com\r\nConnection: close\r\n\r\n", "3.2.0", rand.Intn(7))

	dataToSend := []byte(data)
	sendNum := 0
	for err == nil && sendNum < len(dataToSend) {
		num, writeErr := sslConn.Write(dataToSend[sendNum:])
		err = writeErr
		sendNum += num
	}

	if err != nil {
		ipinfo.err = err
		return ipinfo
	}

	bufReader := bufio.NewReader(sslConn)

	for err == nil {
		line, _, readerr := bufReader.ReadLine()
		err = readerr

		if len(line) > 0 {
			strline := string(line)
			if strings.HasPrefix(strline, "HTTP/") {
				prefixLen := len("HTTP/1.1 ")
				status := strline[prefixLen : prefixLen+3]
				if status != "200" {
					err = ResponseError{fmt.Sprint("status:%s", status)}
				}
			} else if strings.HasPrefix(strline, "Server:") {
				prefixLen := len("Server:")
				server := strings.TrimSpace(strline[prefixLen:])

				if server != "gws" && server != "Google Frontend" {
					err = ResponseError{fmt.Sprint("server:%s", server)}
				}
			}
		}
	}

	if err != nil && err != io.EOF {
		ipinfo.err = err
		return ipinfo
	}

	return ipinfo
}

func testIp(ipToTest net.IP) {
	var ipinfo *IpInfo
	for retryCount := 0; retryCount < defaultRetryCount; retryCount++ {
		ipinfo = doTestIp(ipToTest)
		if ipinfo.err == nil {
			break
		}
	}

	// 执行完毕后，发送检测结果
	resultChannel <- ipinfo

}

func printGoodIp() {
	fmt.Println(strings.Join(goodIp, "|"))
}

func randTest(testNum int) {
	needTestNum = testNum
	fmt.Println("begin dispatch task...")

	for i := 0; i < testChannelInitLen && len(ipPool) > 0; i++ {
		index := rand.Intn(len(ipPool))
		testChannel <- removeWithoutOrderFromIpPool(index)
	}

	exit := false
	for !exit {
		select {
		case ipToTest := <-testChannel:
			go testIp(ipToTest)
		case ipinfo := <-resultChannel:
			passedNum++
			if ipinfo.err == nil {
				fmt.Printf("%s:%s\n", ipinfo.ip, "good ip")
				if needTestNum <= 0 {
					goodIp = append(goodIp, ipinfo.ip.String())
				} else {
					if len(goodIp) < needTestNum {
						goodIp = append(goodIp, ipinfo.ip.String())
					} else {
						exit = true
						printGoodIp()
					}
				}
			} else {
				fmt.Printf("%s:%s\n", ipinfo.ip, ipinfo.err.Error())
			}

			if len(goodIp) > 0 {
				fmt.Printf("had found:%d,%s\n", len(goodIp), strings.Join(goodIp, "|"))
			} else {
				fmt.Printf("had found:0\n")
			}

			if passedNum == ipPoolLen {
				exit = true
			}

			if !exit {
				index := rand.Intn(len(ipPool))
				testChannel <- removeFromIpPool(index)
			}
		}
	}
}

// 测试ipPool中的所有ip
func standTest() {
	needTestNum = -1
	fmt.Println("begin dispatch task...")

	for i := len(ipPool) - 1; i >= 0 && len(ipPool) > 0; i-- {
		testChannel <- removeWithoutOrderFromIpPool(i)
	}

	exit := false
	for !exit {
		select {
		case ipToTest := <-testChannel:
			go testIp(ipToTest)
		case ipinfo := <-resultChannel:
			passedNum++
			if ipinfo.err == nil {
				fmt.Printf("%s:%s\n", ipinfo.ip, "good ip")
				if needTestNum <= 0 {
					goodIp = append(goodIp, ipinfo.ip.String())
				} else {
					if len(goodIp) < needTestNum {
						goodIp = append(goodIp, ipinfo.ip.String())
					} else {
						exit = true
						printGoodIp()
					}
				}
			} else {
				fmt.Printf("%s:%s\n", ipinfo.ip, ipinfo.err.Error())
			}

			if len(goodIp) > 0 {
				fmt.Printf("had found:%d,%s\n", len(goodIp), strings.Join(goodIp, "|"))
			} else {
				fmt.Printf("had found:0\n")
			}

			if passedNum == ipPoolLen {
				exit = true
			}

			if !exit {
				index := len(ipPool) - 1
				testChannel <- removeFromIpPool(index)
			}
		}
	}
}

func main() {
	var randtest int
	var iprange string

	flag.IntVar(&randtest, "randtest", 0, "随机测试出指定个数可用的ip")
	flag.StringVar(&iprange, "iprange", "", "测试指定ip中所有可用的ip")

	flag.Parse()
	fmt.Println(randtest, iprange)

	if iprange != "" {
		fmt.Println("begin parse iprange...")
		ipPool = ipparser.ParseIp(iprange)
		if ipPool == nil {
			fmt.Errorf("iprange参数解析失败")
			return
		}

		ipPoolLen = len(ipPool)
		standTest()
	} else {
		fmt.Println("begin read inner iprange...")
		ipPool = ipparser.ParseIp(asset.InnerIpSet)
		if randtest == 0 {
			randtest = 20
		}

		ipPoolLen = len(ipPool)
		randTest(randtest)
	}

}
