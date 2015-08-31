package tunio

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"net"
	"sync"
)

type RawSocketServer struct {
	connOut net.Conn
	step    uint
	zero    uint32
	seq     uint32
	ack     uint32
	src     *srcNode
	dst     *dstNode

	r *bufio.Reader
	w *bufio.Writer

	wb  *bytes.Buffer
	wri io.Writer

	writeLock bool
	writeMu   sync.Mutex

	window uint16

	ipLayer *layers.IPv4
}

func (r *RawSocketServer) Write(message []byte) (n int, err error) {
	var messages int
	l := len(message)
	for i := 0; i < l; i += tcpMaxDatagramSize {
		push := false

		j := tcpMaxDatagramSize
		if i+j > l {
			j = l - i
			push = true
		}

		if messages%8 == 7 {
			push = true
		}

		if err = r.sendPayload(message[i:i+j], push); err != nil {
			return
		}
		n += j

		messages++
	}
	return
}

func (r *RawSocketServer) sendPayload(rawBytes []byte, push bool) error {
	if r.step != StatusEstablished {
		return errors.New("Can't send data while opening or closing connection.")
	}

	if len(rawBytes) > tcpMaxDatagramSize {
		return fmt.Errorf("Can't sent datagram larger than %d", tcpMaxDatagramSize)
	}

	r.writeMu.Lock()
	r.writeLock = true

	// Answering with SYN-ACK
	tcpLayer := &layers.TCP{
		ACK: true,
		PSH: push,
	}

	if err := r.injectPacketFromDst(tcpLayer, rawBytes); err != nil {
		return err
	}

	r.incrServerSeq(uint32(len(rawBytes)))

	return nil
}

func (r *RawSocketServer) replyFINACK() error {
	if r.step != StatusClosing {
		return errors.New("Can't FIN-ACK on a non-closing connection.")
	}

	// Answering with SYN-ACK
	tcpLayer := &layers.TCP{
		ACK: true,
		FIN: true,
	}

	if err := r.injectPacketFromDst(tcpLayer, nil); err != nil {
		return err
	}

	// Expecting this seq number.
	r.incrServerSeq(1)
	return nil
}

func (r *RawSocketServer) replyACK(seq uint32, incr uint32) error {
	if r.step != StatusEstablished {
		return errors.New("Can't ACK on a non-established connection.")
	}

	r.ack = seq + incr

	// Answering with SYN-ACK
	tcpLayer := &layers.TCP{
		ACK: true,
	}

	if err := r.injectPacketFromDst(tcpLayer, nil); err != nil {
		return err
	}

	return nil
}

func (r *RawSocketServer) replySYNACK(seq uint32) error {
	if r.step != StatusClientSYN {
		return errors.New("Unexpected SYN.")
	}

	r.step = StatusServerSYNACK
	r.zero = randomSeqNumber()

	r.ack = seq + 1
	r.seq = r.zero

	// Answering with SYN-ACK
	tcpLayer := &layers.TCP{
		ACK: true,
		SYN: true,
	}

	if err := r.injectPacketFromDst(tcpLayer, nil); err != nil {
		return err
	}

	// Expecting this seq number.
	r.incrServerSeq(1)
	return nil
}

func (r *RawSocketServer) relativeSeq(i uint32) uint32 {
	if i >= r.zero {
		return i - r.zero
	}
	return 0
}

func (r *RawSocketServer) incrServerSeq(i uint32) {
	r.seq = r.seq + i
}

func (r *RawSocketServer) injectPacketFromDst(tcpLayer *layers.TCP, rawBytes []byte) error {
	// Preparing ipLayer.
	ipLayer := &layers.IPv4{
		SrcIP:    r.dst.ip,
		DstIP:    r.src.ip,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	tcpLayer.SrcPort = r.dst.port
	tcpLayer.DstPort = r.src.port
	tcpLayer.Window = r.window

	tcpLayer.Ack = r.ack
	tcpLayer.Seq = r.seq

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ipLayer,
		tcpLayer,
		gopacket.Payload(rawBytes),
	)

	outgoingPacket := buffer.Bytes()

	_, err := r.wri.Write(outgoingPacket)
	return err
}
