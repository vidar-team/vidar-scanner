//go:build linux

package basework

import (
	"fmt"
	"net"
	"sync"
	"time"

	//"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	//"github.com/google/gopacket"
	//"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

type SynScanner struct {
	handle  *pcap.Handle   //pcap句柄，发包以及收包
	iface   *net.Interface //网络接口，拿mac地址
	srcIP   net.IP
	dstIP   net.IP //目标主机ip
	srcMAC  net.HardwareAddr
	dstMAC  net.HardwareAddr //目标主机mac
	srcPort uint16           // 固定源端口，用来demux回包
	mu      sync.Mutex
	waiters map[uint16]chan string
}

func NewSynScanner(targetIp string, srcPort uint16) (*SynScanner, error) {

	dst := net.ParseIP(targetIp)
	if dst == nil {
		return nil, fmt.Errorf("invalid target ip: %s", targetIp)
	}

	router, err := routing.New() //读内核路由表
	if err != nil {
		return nil, fmt.Errorf("failed to create routing: %v", err)
	}

	iface, gw, srcIP, err := router.Route(dst) //确定访问dst这个ip时调用的接口(iface)，下一个ip(gw),源ip
	if err != nil {
		return nil, fmt.Errorf("failed to get routing: %v", err)
	}

	ifaceObj, err := net.InterfaceByName(iface.Name) // 通过接口名拿到完整网卡对象
	if err != nil {
		return nil, fmt.Errorf("failed to get interface by name: %v", err)
	}

	handle, err := pcap.OpenLive(iface.Name, 65535, false, 1*time.Second) //打开pcap句柄
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap: %v", err)
	}

	nextHop := dst //下一个ip
	if gw != nil {
		nextHop = gw
	}

	dstMAC, err := resolveMAC(handle, ifaceObj, srcIP, nextHop) //通过arp找到mac
	if err != nil {
		handle.Close()
		return nil, err
	}

	filter := fmt.Sprintf("tcp and src host %s and dst host %s and dst port %d", dst.String(), srcIP.String(), srcPort)

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, err
	}

	s := &SynScanner{
		handle:  handle,
		iface:   ifaceObj,
		srcIP:   srcIP,
		dstIP:   dst,
		srcMAC:  ifaceObj.HardwareAddr,
		dstMAC:  dstMAC,
		srcPort: srcPort,
		waiters: make(map[uint16]chan string),
	}

	go s.listenReply()

	return s, nil

}

func (s *SynScanner) Close() {
	if s.handle != nil {
		s.handle.Close()
	}
}

// 持续读包，结果送到对应端口的信道中
func (s *SynScanner) listenReply() {
	src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	for packet := range src.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if tcpLayer == nil {
			continue
		}

		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}

		if uint16(tcp.DstPort) != s.srcPort {
			continue
		}

		dstPort := uint16(tcp.SrcPort)
		s.mu.Lock()
		ch, ok := s.waiters[dstPort]

		if !ok {
			s.mu.Unlock()
			continue
		}

		state := "none"

		if tcp.SYN && tcp.ACK {
			state = "open"
		} else if tcp.RST {
			state = "close"
		}

		select {
		case ch <- state:
		default:
		}

		delete(s.waiters, dstPort)
		s.mu.Unlock()

	}
}

func (s *SynScanner) ScanPort(port uint16, timeout time.Duration) string {
	ch := make(chan string, 1)

	s.mu.Lock()
	s.waiters[port] = ch
	s.mu.Unlock()

	if err := s.sendSYN(port); err != nil {
		s.mu.Lock()
		delete(s.waiters, port)
		s.mu.Unlock()
		return "error"
	}

	select {
	case state := <-ch:
		return state
	case <-time.After(timeout):
		s.mu.Lock()
		delete(s.waiters, port)
		s.mu.Unlock()
		return "filtered/timeout"
	}
}

// 发送syn包
func (s *SynScanner) sendSYN(dstPort uint16) error {
	eth := &layers.Ethernet{
		SrcMAC:       s.srcMAC,
		DstMAC:       s.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    s.srcIP,
		DstIP:    s.dstIP,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(s.srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Window:  14600,
	}

	tcp.SetNetworkLayerForChecksum(ip4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, tcp); err != nil {
		return err
	}

	return s.handle.WritePacketData(buf.Bytes())

}

// 使用arp获得mac地址
func resolveMAC(handle *pcap.Handle, iface *net.Interface, srcIP, nextHopIP net.IP) (net.HardwareAddr, error) {

	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("set arp BPF failed: %w", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // 广播
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(nextHopIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return nil, fmt.Errorf("serialize arp failed: %w", err)
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("send arp failed: %w", err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(2 * time.Second)

	for {
		select {
		case pkt := <-src.Packets():
			if pkt == nil {
				continue
			}

			if arpLayer := pkt.Layer(layers.LayerTypeARP); arpLayer != nil {
				reply := arpLayer.(*layers.ARP)

				if reply.Operation != layers.ARPReply {
					continue
				}

				if net.IP(reply.SourceProtAddress).Equal(nextHopIP) {
					return net.HardwareAddr(reply.SourceHwAddress), nil
				}

			}

		case <-timeout:
			return nil, fmt.Errorf("arp timeout for %v", nextHopIP)
		}
	}
}
