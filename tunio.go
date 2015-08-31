// tunio package reads raw IP(v4) packets and creates a tunnel between the
package tunio

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"log"
	"math/rand"
	"net"
)

const (
	ipMaxDatagramSize  = 576
	tcpMaxDatagramSize = ipMaxDatagramSize - 40
)

type node struct {
	ip   net.IP
	port layers.TCPPort
}

type srcNode struct {
	node
}
type dstNode struct {
	node
}

func (n *node) String() string {
	return fmt.Sprintf("%s:%d", n.ip.String(), n.port)
}

var (
	fwdSockets map[string]map[string]*RawSocketServer
)

type Status uint

const (
	StatusClientSYN uint = iota
	StatusServerSYNACK
	StatusClientACK
	StatusEstablished
	StatusClosing
	StatusWaitClose
)

func init() {
	fwdSockets = make(map[string]map[string]*RawSocketServer)
}

type dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type TunIO struct {
	dialer dialer
}

func NewTunIO(d dialer) *TunIO {
	return &TunIO{
		dialer: d,
	}
}

func (t *TunIO) HandlePacket(reader io.Reader, wri io.Writer) error {
	var ip *layers.IPv4
	var tcp *layers.TCP

	b := make([]byte, ipMaxDatagramSize)

	if _, err := reader.Read(b); err != nil {
		return nil
	}

	// Decoding TCP/IP
	decoded := gopacket.NewPacket(
		b,
		layers.LayerTypeIPv4,
		gopacket.Default,
	)

	if decoded.NetworkLayer() == nil || decoded.TransportLayer() == nil ||
		decoded.TransportLayer().LayerType() != layers.LayerTypeTCP {
		return nil
	}

	// Get the IP layer.
	if ipLayer := decoded.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ = ipLayer.(*layers.IPv4)
	}

	// Get the TCP layer from this decoded packet.
	if tcpLayer := decoded.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ = tcpLayer.(*layers.TCP)
	}

	// Check for errors
	if err := decoded.ErrorLayer(); err != nil {
		return fmt.Errorf("Error decoding some part of the packet:", err)
	}

	src := &srcNode{
		node{
			ip:   ip.SrcIP,
			port: tcp.SrcPort,
		},
	}

	dst := &dstNode{
		node{
			ip:   ip.DstIP,
			port: tcp.DstPort,
		},
	}

	srcKey := src.String()
	dstKey := dst.String()

	var srv *RawSocketServer
	var ok bool

	if tcp.ACK {
		// Looking up srvection.

		if srv, ok = fwdSockets[srcKey][dstKey]; !ok {
			return errors.New("Unknown srvection.")
		}

		if tcp.Ack == srv.seq && tcp.Seq == srv.ack {

			switch srv.step {
			case StatusServerSYNACK:
				srv.step = StatusEstablished

				srv.ack = tcp.Seq
				srv.seq = tcp.Ack

				go func() {
					if err := srv.reader(); err != nil {
						log.Printf("reader: %q", err)
					}
				}()

			case StatusEstablished:
				if srv.writeLock {
					srv.writeMu.Unlock()
					srv.writeLock = false
				}

				payloadLen := uint32(len(tcp.Payload))

				if payloadLen > 0 {
					if err := srv.replyACK(tcp.Seq, payloadLen); err != nil {
						return err
					}
					srv.w.Write(tcp.Payload)
				}

				if tcp.PSH {
					// Forward data to application.
					srv.w.Flush()
					srv.connOut.Write(srv.wb.Bytes())
					srv.wb.Reset()
				}

				if tcp.FIN {
					if err := srv.replyACK(tcp.Seq, 1); err != nil {
						return err
					}
					srv.step = StatusClosing

					if err := srv.replyFINACK(); err != nil {
						return err
					}
					srv.step = StatusWaitClose
				}
			case StatusWaitClose:
				fwdSockets[srcKey][dstKey] = nil
			default:
				panic("Unsupported status.")
			}
		} else {
			return fmt.Errorf("%s -> %s: Unexpected (Seq=%d, Ack=%d) expecting (Seq=%d, Ack=%d).", srcKey, dstKey, tcp.Seq, tcp.Ack, srv.ack, srv.seq)
		}

	} else if tcp.SYN && tcp.Ack == 0 {
		// Someone is starting a connection.
		if fwdSockets[srcKey] == nil {
			fwdSockets[srcKey] = make(map[string]*RawSocketServer)
		}

		connOut, err := t.dialer.Dial("tcp", dstKey)
		if err != nil {
			// TODO: Reply RST
			return err
		}

		fwdSockets[srcKey][dstKey] = &RawSocketServer{
			connOut: connOut,
			src:     src,
			dst:     dst,
			window:  tcp.Window,
			wb:      bytes.NewBuffer(nil),
			wri:     wri,
		}

		srv = fwdSockets[srcKey][dstKey]
		srv.w = bufio.NewWriter(srv.wb)

		if err := srv.replySYNACK(tcp.Seq); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Unknown status.")
	}

	return nil
}

func randomSeqNumber() uint32 {
	return rand.Uint32()
}

func (r *RawSocketServer) reader() error {
	// TODO: handle closing
	var n, m int
	var err error

	for {
		buf := make([]byte, 1024)
		if n, err = r.connOut.Read(buf); err != nil {
			if err != io.EOF {
				return err
			}
		}
		if n > 0 {
			if m, err = r.Write(buf[0:n]); err != nil {
				return err
			}
			if n != m {
				return fmt.Errorf("Failed to write some bytes to tun device.")
			}
		}
	}

	return nil
}
