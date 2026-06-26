package transport

type PacketType uint8

const (
	PacketIP   PacketType = 0
	PacketMPLS PacketType = 1
)

type Packet struct {
	Type      PacketType
	Data      []byte
	Transport string
}

type Transport interface {
	Name() string
	MTU() int
	Read() <-chan Packet
	Write(pkt Packet) error
	Close() error
}
