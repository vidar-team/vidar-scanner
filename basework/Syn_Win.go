//go:build windows

package basework

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/libp2p/go-netroute"
)

type SynScanner struct {
	handle  *pcap.Handle
	iface   *net.Interface
	srcIP   net.IP
	dstIP   net.IP
	srcMAC  net.HardwareAddr
	dstMAC  net.HardwareAddr
	srcPort uint16
	mu      sync.Mutex
	waiters map[uint16]chan string
}

func NewSynScanner(targetIp string, srcPort uint16) (*SynScanner, error) {

	dst := net.ParseIP(targetIp)

	if dst == nil {
		return nil, fmt.Errorf("invalid target ip: %s", targetIp)
	}

	r, err := netroute.New()

	if err != nil {
		return nil, fmt.Errorf("failed to create routing: %v", err)
	}

	iface, gw, srcIP, err := r.Route(dst)

	if err != nil {
		return nil, fmt.Errorf("failed to get routing: %v", err)
	}

	deviceName, err := findPcapDeviceByIP(srcIP)

	if err != nil {
		return nil, fmt.Errorf("failed to find pcap device for ip %s: %v", srcIP, err)
	}

	handle, err := pcap.OpenLive(deviceName, 65535, false, 1*time.Second)

	if err != nil {
		return nil, fmt.Errorf("failed to open pcap: %v", err)
	}

	nextHop := dst

	if gw != nil {
		nextHop = gw
	}

	srcMAC := iface.HardwareAddr
	dstMAC, err := resolveMAC(handle, iface, srcIP, nextHop)

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
		iface:   iface,
		srcIP:   srcIP,
		dstIP:   dst,
		srcMAC:  srcMAC,
		dstMAC:  dstMAC,
		srcPort: srcPort,
		waiters: make(map[uint16]chan string),
	}

	go s.listenReply()
	return s, nil
}

func findPcapDeviceByIP(ip net.IP) (string, error) {
	devs, err := pcap.FindAllDevs()

	if err != nil {
		return "", err
	}

	for _, d := range devs {
		for _, addr := range d.Addresses {
			if addr.IP.Equal(ip) {
				return d.Name, nil
			}
		}
	}
	return "", fmt.Errorf("device not found for ip: %s", ip)
}

func (s *SynScanner) Close() {

	if s.handle != nil {
		s.handle.Close()
	}
}

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

	err := tcp.SetNetworkLayerForChecksum(ip4)
	if err != nil {
		return err
	}

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

func resolveMAC(handle *pcap.Handle, iface *net.Interface, srcIP, nextHopIP net.IP) (net.HardwareAddr, error) {

	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("set arp BPF failed: %w", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
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
