package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"net"
	"os"
)

func main() {
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	gatewayMac, err := net.ParseMAC(os.Args[1])
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	nfq, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	defer nfq.Close()
	packets := nfq.GetPackets()

	handle, err := pcap.OpenLive("eth0", 1500, false, pcap.BlockForever)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	loop(packets, iface, gatewayMac, handle)
}

func loop(packets <-chan netfilter.NFPacket, iface *net.Interface, gatewayMac net.HardwareAddr, handle *pcap.Handle) {
	flows := map[string]int{}

	for {
		select {
		case p := <-packets:
			p6, ok := p.Packet.NetworkLayer().(*layers.IPv6)
			if !ok {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}

			icmp6, ok := p.Packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
			if !ok {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}

			p.SetVerdict(netfilter.NF_DROP)

			src := p6.SrcIP.String()
			dst := p6.DstIP.String()

			sum := sha256.Sum224(p6.SrcIP)
			key := base64.StdEncoding.EncodeToString(sum[:])

			fmt.Printf("%s -> %s [%s]\n", src, dst, key)

			seenFlow, seenBefore := flows[dst]
			thisFlow := int(p6.FlowLabel)
			if !seenBefore {
				flows[dst] = thisFlow
				seenFlow = thisFlow
			}

			receivedNonce := icmp6.Payload[4:12]
			bytes, err := craftResponsePacket(p6, iface.HardwareAddr, gatewayMac, receivedNonce, seenFlow == thisFlow, key)
			err = handle.WritePacketData(bytes)
			if err != nil {
				fmt.Printf("%+v\n", err)
			}
		}
	}
}

func craftResponsePacket(p6 *layers.IPv6, srcMac, dstMac net.HardwareAddr, nonce []byte, sameFlow bool, key string) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()

	network := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
		SrcIP:      p6.DstIP,
		DstIP:      p6.SrcIP,
	}

	icmpLayer := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(140, 0)}
	err := icmpLayer.SetNetworkLayerForChecksum(network)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	data := []byte(fmt.Sprintf("These non-fungible lyrics have already been claimed by %s", key[:8]))

	ctr := int(binary.BigEndian.Uint16(nonce))

	if ctr < len(Lines) && sameFlow {
		data = []byte(fmt.Sprintf("%d/%d %s", ctr+1, len(Lines), Lines[ctr]))
	}

	err = gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		&layers.Ethernet{
			SrcMAC:       srcMac,
			DstMAC:       dstMac,
			EthernetType: layers.EthernetTypeIPv6,
		},
		network,
		icmpLayer,
		&icmpNodeInformationResponse{
			Qtype: 2,
			Flags: 0,
			Nonce: nonce,
			Ttl:   0,
			Data:  data,
		},
	)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return buf.Bytes(), nil
}
