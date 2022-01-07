package main

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type icmpNodeInformationResponse struct {
	layers.BaseLayer
	Qtype uint16
	Flags uint16
	Nonce []byte
	Ttl   uint32
	Data  []byte
}

func (i *icmpNodeInformationResponse) LayerType() gopacket.LayerType {
	return layers.LayerTypeICMPv6Echo
}

func (i *icmpNodeInformationResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	buf, err := b.PrependBytes(19 + len(i.Data))
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint16(buf, i.Qtype)
	binary.BigEndian.PutUint16(buf[2:], i.Flags)
	copy(buf[4:], i.Nonce)
	binary.BigEndian.PutUint32(buf[12:], i.Ttl)
	buf[16] = byte(len(i.Data))
	copy(buf[17:], i.Data)
	binary.BigEndian.PutUint16(buf[17+len(i.Data):], 0)
	return nil
}
