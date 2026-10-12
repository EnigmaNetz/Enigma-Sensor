// genpcap writes the synthetic capture behind the records package's parity fixtures. Run it,
// then run Zeek over the result once with tab-separated logs and once with JSON logs (see
// regenerate.sh next to it). The traffic is synthetic so no real network data is committed:
//
//   - DHCP: a DISCOVER/OFFER/REQUEST/ACK exchange carrying option 55 and a host name
//   - DNS: an A answer, a CNAME chain, an NXDOMAIN and an empty AAAA answer
//   - DHCP text fields: a client FQDN, a domain name and a server message
//   - DNS: a TXT answer with commas, which the tab-separated log escapes inside a list element,
//     and a query name holding a tab, a newline and a control byte
//   - TLS: a real crypto/tls handshake (TLS 1.3, SNI example.com) for ja3_ja4 and ja4s, then a
//     plain HTTP request from the same client port, whose User-Agent the JA3/JA4 script needs to
//     write ja4 and user_agent
//   - a rejected TCP connection, a UDP flow with no service, ICMP echo to a second host, a UDP
//     flow to a public address (local_resp false) and a VXLAN-encapsulated flow (tunnel_parents)
//
// Usage: go run ./internal/records/testdata/genpcap <out.pcap>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var (
	clientMAC = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	routerMAC = net.HardwareAddr{0x00, 0x66, 0x77, 0x88, 0x99, 0xaa}
	peerMAC   = net.HardwareAddr{0x00, 0x66, 0x77, 0x88, 0x99, 0xbb}

	clientIP = net.IPv4(192, 168, 50, 10).To4()
	vtepIP   = net.IPv4(192, 168, 50, 30).To4()
	// example.com's address: a public one, so Zeek marks the far end of the flow non-local.
	publicIP = net.IPv4(93, 184, 215, 14).To4()
	routerIP = net.IPv4(192, 168, 50, 1).To4()
	peerIP   = net.IPv4(192, 168, 50, 20).To4()
	webIP    = net.IPv4(203, 0, 113, 10).To4()
)

type writer struct {
	w  *pcapgo.Writer
	ts time.Time
}

// next advances the clock by d plus a sub-microsecond-free fraction, so timestamps exercise
// Zeek's six-decimal formatting.
func (w *writer) packet(d time.Duration, layersToWrite ...gopacket.SerializableLayer) {
	w.ts = w.ts.Add(d)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, layersToWrite...); err != nil {
		panic(err)
	}
	data := buf.Bytes()
	if err := w.w.WritePacket(gopacket.CaptureInfo{Timestamp: w.ts, CaptureLength: len(data), Length: len(data)}, data); err != nil {
		panic(err)
	}
}

func eth(src, dst net.HardwareAddr) *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: layers.EthernetTypeIPv4}
}

func ipv4(src, dst net.IP, proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{Version: 4, TTL: 64, Protocol: proto, SrcIP: src, DstIP: dst}
}

func udp(ip *layers.IPv4, sport, dport layers.UDPPort) *layers.UDP {
	u := &layers.UDP{SrcPort: sport, DstPort: dport}
	_ = u.SetNetworkLayerForChecksum(ip)
	return u
}

func dhcpExchange(w *writer) {
	xid := uint32(0x3903f326)
	params := []byte{1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252}
	msg := func(op layers.DHCPOp, t layers.DHCPMsgType, yiaddr net.IP, extra ...layers.DHCPOption) *layers.DHCPv4 {
		opts := []layers.DHCPOption{layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(t)})}
		opts = append(opts, extra...)
		opts = append(opts, layers.NewDHCPOption(layers.DHCPOptEnd, nil))
		return &layers.DHCPv4{
			Operation: op, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6, Xid: xid,
			ClientIP: net.IPv4zero.To4(), YourClientIP: yiaddr, ClientHWAddr: clientMAC, Options: opts,
		}
	}
	bcast := net.IPv4bcast.To4()
	clientOpts := []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptParamsRequest, params),
		layers.NewDHCPOption(layers.DHCPOptHostname, []byte("test-host")),
		// Client FQDN (option 81): flags, two RCODEs, then the name.
		layers.NewDHCPOption(layers.DHCPOpt(81), append([]byte{0x01, 0, 0}, []byte("test-host.corp.example")...)),
	}
	serverOpts := []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptServerID, routerIP),
		layers.NewDHCPOption(layers.DHCPOptLeaseTime, []byte{0x00, 0x01, 0x51, 0x80}),
		layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte{255, 255, 255, 0}),
		layers.NewDHCPOption(layers.DHCPOptRouter, routerIP),
		layers.NewDHCPOption(layers.DHCPOptDomainName, []byte("corp.example")),
		layers.NewDHCPOption(layers.DHCPOptMessage, []byte("lease granted, enjoy")),
	}
	send := func(src, dst net.IP, smac net.HardwareAddr, sport, dport layers.UDPPort, d *layers.DHCPv4) {
		ip := ipv4(src, dst, layers.IPProtocolUDP)
		w.packet(13*time.Millisecond+123457*time.Nanosecond, eth(smac, layers.EthernetBroadcast), ip, udp(ip, sport, dport), d)
	}
	send(net.IPv4zero.To4(), bcast, clientMAC, 68, 67, msg(layers.DHCPOpRequest, layers.DHCPMsgTypeDiscover, net.IPv4zero.To4(), clientOpts...))
	send(routerIP, bcast, routerMAC, 67, 68, msg(layers.DHCPOpReply, layers.DHCPMsgTypeOffer, clientIP, serverOpts...))
	req := append([]layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptRequestIP, clientIP),
		layers.NewDHCPOption(layers.DHCPOptServerID, routerIP),
	}, clientOpts...)
	send(net.IPv4zero.To4(), bcast, clientMAC, 68, 67, msg(layers.DHCPOpRequest, layers.DHCPMsgTypeRequest, net.IPv4zero.To4(), req...))
	send(routerIP, bcast, routerMAC, 67, 68, msg(layers.DHCPOpReply, layers.DHCPMsgTypeAck, clientIP, serverOpts...))
}

func dnsExchange(w *writer, sport layers.UDPPort, id uint16, name string, qtype layers.DNSType, rcode layers.DNSResponseCode, answers []layers.DNSResourceRecord) {
	q := layers.DNSQuestion{Name: []byte(name), Type: qtype, Class: layers.DNSClassIN}
	ip := ipv4(clientIP, routerIP, layers.IPProtocolUDP)
	w.packet(41*time.Millisecond+654321*time.Nanosecond, eth(clientMAC, routerMAC), ip, udp(ip, sport, 53),
		&layers.DNS{ID: id, RD: true, QDCount: 1, Questions: []layers.DNSQuestion{q}})
	rip := ipv4(routerIP, clientIP, layers.IPProtocolUDP)
	w.packet(7*time.Millisecond+250001*time.Nanosecond, eth(routerMAC, clientMAC), rip, udp(rip, 53, sport),
		&layers.DNS{ID: id, QR: true, RD: true, RA: true, ResponseCode: rcode, QDCount: 1,
			ANCount: uint16(len(answers)), Questions: []layers.DNSQuestion{q}, Answers: answers})
}

func dns(w *writer) {
	a := func(name string, ip net.IP, ttl uint32) layers.DNSResourceRecord {
		return layers.DNSResourceRecord{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: ttl, IP: ip}
	}
	dnsExchange(w, 53001, 0x1001, "example.com", layers.DNSTypeA, layers.DNSResponseCodeNoErr,
		[]layers.DNSResourceRecord{a("example.com", webIP, 300)})
	dnsExchange(w, 53002, 0x1002, "www.example.org", layers.DNSTypeA, layers.DNSResponseCodeNoErr,
		[]layers.DNSResourceRecord{
			{Name: []byte("www.example.org"), Type: layers.DNSTypeCNAME, Class: layers.DNSClassIN, TTL: 3600, CNAME: []byte("edge.example.net")},
			a("edge.example.net", net.IPv4(203, 0, 113, 77).To4(), 60),
		})
	dnsExchange(w, 53003, 0x1003, "missing.example.com", layers.DNSTypeA, layers.DNSResponseCodeNXDomain, nil)
	dnsExchange(w, 53004, 0x1004, "example.com", layers.DNSTypeAAAA, layers.DNSResponseCodeNoErr, nil)
	// A query name with a tab, a newline and a control byte, as DNS tunnelling can produce. The tab-separated
	// log escapes all three; the parity test checks JSON gives the same text.
	dnsExchange(w, 53006, 0x1006, "tun\tnel\nline\x01.example.com", layers.DNSTypeA, layers.DNSResponseCodeNXDomain, nil)
	dnsExchange(w, 53005, 0x1005, "example.com", layers.DNSTypeTXT, layers.DNSResponseCodeNoErr,
		[]layers.DNSResourceRecord{
			{Name: []byte("example.com"), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN, TTL: 120,
				TXTs: [][]byte{[]byte("v=spf1 a, mx, -all")}},
			{Name: []byte("example.com"), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN, TTL: 120,
				TXTs: [][]byte{[]byte("plain")}},
		})
}

// tlsBytes runs a real crypto/tls handshake over an in-memory pipe and returns what each side
// wrote, in order.
type segment struct {
	fromClient bool
	data       []byte
}

type recordingConn struct {
	net.Conn
	fromClient bool
	mu         *sync.Mutex
	log        *[]segment
}

func (c recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	*c.log = append(*c.log, segment{c.fromClient, append([]byte(nil), p...)})
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func tlsBytes() []segment {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	var mu sync.Mutex
	var log []segment
	c, s := net.Pipe()
	client := tls.Client(recordingConn{c, true, &mu, &log}, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	server := tls.Server(recordingConn{s, false, &mu, &log}, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	done := make(chan error, 1)
	go func() { done <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		panic(err)
	}
	if err := <-done; err != nil {
		panic(err)
	}
	go func() { _, _ = server.Read(make([]byte, 64)) }()
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		panic(err)
	}
	return log
}

func tcpConn(w *writer, sport, dport layers.TCPPort, src, dst net.IP, dmac net.HardwareAddr, payload []segment, reject bool) {
	cseq, sseq := uint32(1000), uint32(5000)
	pkt := func(fromClient bool, flags func(*layers.TCP), data []byte) {
		var t *layers.TCP
		var ip *layers.IPv4
		var e *layers.Ethernet
		if fromClient {
			ip, e = ipv4(src, dst, layers.IPProtocolTCP), eth(clientMAC, dmac)
			t = &layers.TCP{SrcPort: sport, DstPort: dport, Seq: cseq, Ack: sseq, Window: 64240}
			cseq += uint32(len(data))
		} else {
			ip, e = ipv4(dst, src, layers.IPProtocolTCP), eth(dmac, clientMAC)
			t = &layers.TCP{SrcPort: dport, DstPort: sport, Seq: sseq, Ack: cseq, Window: 65160}
			sseq += uint32(len(data))
		}
		flags(t)
		_ = t.SetNetworkLayerForChecksum(ip)
		w.packet(3*time.Millisecond+500003*time.Nanosecond, e, ip, t, gopacket.Payload(data))
	}
	pkt(true, func(t *layers.TCP) { t.SYN = true; t.Ack = 0 }, nil)
	cseq++
	if reject {
		pkt(false, func(t *layers.TCP) { t.RST = true; t.ACK = true }, nil)
		return
	}
	pkt(false, func(t *layers.TCP) { t.SYN = true; t.ACK = true }, nil)
	sseq++
	pkt(true, func(t *layers.TCP) { t.ACK = true }, nil)
	for _, s := range payload {
		pkt(s.fromClient, func(t *layers.TCP) { t.ACK = true; t.PSH = true }, s.data)
	}
	pkt(true, func(t *layers.TCP) { t.FIN = true; t.ACK = true }, nil)
	cseq++
	pkt(false, func(t *layers.TCP) { t.FIN = true; t.ACK = true }, nil)
	sseq++
	pkt(true, func(t *layers.TCP) { t.ACK = true }, nil)
}

// vxlan sends one UDP packet inside VXLAN (UDP 4789), so Zeek records the outer flow as the inner
// flow's tunnel parent.
func vxlan(w *writer) {
	inner := gopacket.NewSerializeBuffer()
	ip := ipv4(net.IPv4(10, 200, 0, 1).To4(), net.IPv4(10, 200, 0, 2).To4(), layers.IPProtocolUDP)
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(inner, opts, eth(clientMAC, peerMAC), ip, udp(ip, 41000, 7000), gopacket.Payload("inner")); err != nil {
		panic(err)
	}
	header := []byte{0x08, 0, 0, 0, 0, 0, 0x2a, 0} // flags: VNI present; VNI 42
	outer := ipv4(vtepIP, routerIP, layers.IPProtocolUDP)
	w.packet(500*time.Millisecond, eth(clientMAC, routerMAC), outer, udp(outer, 50500, 4789), gopacket.Payload(append(header, inner.Bytes()...)))
}

func icmp(w *writer) {
	for seq := uint16(1); seq <= 2; seq++ {
		ip := ipv4(clientIP, peerIP, layers.IPProtocolICMPv4)
		w.packet(time.Second, eth(clientMAC, peerMAC), ip,
			&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 7, Seq: seq}, gopacket.Payload("ping"))
		rip := ipv4(peerIP, clientIP, layers.IPProtocolICMPv4)
		w.packet(900*time.Microsecond, eth(peerMAC, clientMAC), rip,
			&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0), Id: 7, Seq: seq}, gopacket.Payload("ping"))
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genpcap <out.pcap>")
		os.Exit(2)
	}
	f, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		panic(err)
	}
	w := &writer{w: pw, ts: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}

	dhcpExchange(w)
	dns(w)
	tcpConn(w, 50000, 443, clientIP, webIP, routerMAC, tlsBytes(), false)
	tcpConn(w, 50000, 80, clientIP, webIP, routerMAC, []segment{
		{true, []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test-agent/1.0\r\n\r\n")},
		{false, []byte("HTTP/1.1 204 No Content\r\n\r\n")},
	}, false)
	tcpConn(w, 50001, 8443, clientIP, webIP, routerMAC, nil, true)
	ip := ipv4(clientIP, routerIP, layers.IPProtocolUDP)
	w.packet(2*time.Second, eth(clientMAC, routerMAC), ip, udp(ip, 40000, 9999), gopacket.Payload("no service here"))
	icmp(w)
	pub := ipv4(clientIP, publicIP, layers.IPProtocolUDP)
	w.packet(time.Second, eth(clientMAC, routerMAC), pub, udp(pub, 40001, 9999), gopacket.Payload("to a public address"))
	vxlan(w)
}
