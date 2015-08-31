package tunio

import (
	"bytes"
	"fmt"
	"github.com/getlantern/tuntap"
	"io"
	"log"
	"net"
	"os/exec"
	"sync"
	"testing"
	"time"
)

const (
	deviceName = "tun87"
	deviceIP   = "192.168.87.3"
	deviceMask = "192.168.87.2/24"
)

type tuntapReadWriter struct {
	*tuntap.Interface
}

func (ttrw *tuntapReadWriter) Read(buf []byte) (n int, err error) {
	packet, err := ttrw.Interface.ReadPacket()
	if err != nil {
		return 0, err
	}
	return len(packet.Packet), nil
}

func (ttrw *tuntapReadWriter) Write(buf []byte) (n int, err error) {
	packet := tuntap.Packet{
		Protocol: 0x8000,
		Packet:   buf,
	}
	if err := ttrw.WritePacket(&packet); err != nil {
		return 0, err
	}
	return len(packet.Packet), nil
}

func newTunTapRW(deviceName string, devKind tuntap.DevKind) (*tuntapReadWriter, error) {
	iface, err := tuntap.Open(deviceName, devKind)
	if err != nil {
		return nil, err
	}
	return &tuntapReadWriter{iface}, nil
}

var (
	iface *tuntapReadWriter
	tunio *TunIO
)

type mockDialer struct {
}

func (d *mockDialer) Dial(network, address string) (net.Conn, error) {
	return &mockConn{}, nil
}

type mockConn struct {
	bytes.Buffer
	mu     sync.Mutex // For simulating network blocking.
	locked bool
}

func (e *mockConn) Write(b []byte) (n int, err error) {
	n, err = e.Buffer.Write(b)
	if err != nil {
		return
	}
	if e.locked {
		e.locked = false
		e.mu.Unlock()
	}
	return
}

func (e *mockConn) Read(b []byte) (n int, err error) {
	n, err = e.Buffer.Read(b)

	if err == io.EOF {
		// Simulating network blocking.
		e.mu.Lock()
		e.locked = true
	}

	return
}

func (e *mockConn) Close() (err error) {
	e.Buffer.Reset()
	return nil
}

func (e *mockConn) LocalAddr() net.Addr {
	return nil
}

func (e *mockConn) RemoteAddr() net.Addr {
	return nil
}

func (e *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (e *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (e *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestSetupTunDevice(t *testing.T) {
	var err error

	if err = exec.Command("sudo", "ip", "tuntap", "del", "tun87", "mode", "tun").Run(); err != nil {
		// t.Fatal(err)
	}

	if err = exec.Command("sudo", "ip", "tuntap", "add", deviceName, "mode", "tun").Run(); err != nil {
		t.Fatal(err)
	}

	if err = exec.Command("sudo", "ip", "link", "set", deviceName, "up").Run(); err != nil {
		t.Fatal(err)
	}

	if err = exec.Command("sudo", "ip", "addr", "add", deviceMask, "dev", deviceName).Run(); err != nil {
		t.Fatal(err)
	}

	if iface, err = newTunTapRW(deviceName, tuntap.DevTun); err != nil {
		t.Fatal(err)
	}

	tunio = NewTunIO(&mockDialer{})
	go runPacketCaptureLoop(iface, tunio)
}

func runPacketCaptureLoop(iface *tuntapReadWriter, tunio *TunIO) {
	for {
		if err := tunio.HandlePacket(iface, iface); err != nil {
			log.Fatalf("handlePacket: %q", err)
		}
	}
}

func TestOpenCloseConn(t *testing.T) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:1212", deviceIP))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenWriteCloseConn(t *testing.T) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:1213", deviceIP))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := conn.Write([]byte("Hello world!\n")); err != nil {
		t.Fatal(err)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenWriteReadCloseConn(t *testing.T) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:1214", deviceIP))
	if err != nil {
		t.Fatal(err)
	}

	buf := []byte("Hello world!")
	bufCopy := make([]byte, 0, len(buf))

	if _, err := conn.Write(buf); err != nil {
		t.Fatal(err)
	}

	read := 0
	for read < len(buf) {
		readBuf := make([]byte, 5)
		n, err := conn.Read(readBuf)
		if err != nil {
			t.Fatal(err)
		}
		bufCopy = append(bufCopy, readBuf[:n]...)
		read += n
	}

	if string(buf) != string(bufCopy) {
		t.Fatalf("Expecting echo %q but got %q", string(buf), string(bufCopy))
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseTunDevice(t *testing.T) {
	time.Sleep(time.Second * 1)

	if err := iface.Close(); err != nil {
		t.Fatal(err)
	}

}
