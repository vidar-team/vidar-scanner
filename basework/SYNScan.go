package basework

import (
	//"crypto/rand"
	//"encoding/binary"
	"fmt"
	"net"
	//"time"

	//"github.com/google/gopacket"
	//"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type InterfaceInfo struct {
	Name string
	IPv4 string
	//MAC  string
}

func getOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

func getDefaultInterface() (*InterfaceInfo, error) {
	outboundIP, err := getOutboundIP()
	if err != nil {
		return nil, err
	}

	// 获取所有网卡信息
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if addr.IP != nil && addr.IP.To4() != nil {
				if addr.IP.Equal(outboundIP) {
					return &InterfaceInfo{
						Name: dev.Name,
						IPv4: addr.IP.String(),
					}, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("default interface not found")
}

func SYNScan(targetIP string, port int) (bool, error) {
	info, err := getDefaultInterface()
	if err != nil {
		return false, fmt.Errorf("failed to get default interface: %w", err)
	}

	fmt.Println("=== Default Network Interface ===")
	fmt.Println("Name:    ", info.Name)
	fmt.Println("IPv4:    ", info.IPv4)
	fmt.Printf("Scanning %s:%d", targetIP, port)

	return false, nil
}
