package dnsmsg

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	dnsHeaderSize = 12
	ptrMask       = 0xC0
	ptrTargetMask = 0x3FFF
)

// ParseQuery 解析一个 DNS 查询报文。
func ParseQuery(raw []byte) (*Message, error) {
	return ParseMessage(raw)
}

// ParseMessage 解析 DNS 报文中的第一个 question。
//
// 这一版只支持标准查询、单 question、A 记录和 IN class。
func ParseMessage(raw []byte) (*Message, error) {
	if len(raw) < dnsHeaderSize {
		return nil, ErrShortPacket
	}

	hdr := decodeHeader(raw[:dnsHeaderSize])
	if hdr.QR {
		return nil, ErrUnsupportedQuery
	}
	if hdr.Opcode != 0 {
		return nil, ErrUnsupportedQuery
	}
	if hdr.QDCount == 0 {
		return nil, ErrUnsupportedQuestion
	}

	off := dnsHeaderSize
	qname, next, err := readName(raw, off, 0)
	if err != nil {
		return nil, err
	}
	off = next
	if off+4 > len(raw) {
		return nil, ErrShortPacket
	}

	qtype := QType(binary.BigEndian.Uint16(raw[off : off+2]))
	qclass := Class(binary.BigEndian.Uint16(raw[off+2 : off+4]))
	if qtype != QTypeA {
		return nil, ErrUnsupportedType
	}
	if qclass != ClassIN {
		return nil, ErrUnsupportedClass
	}

	hdr.QDCount = 1
	msg := &Message{
		Header: hdr,
		Questions: []Question{{
			QName:  qname,
			QType:  qtype,
			QClass: qclass,
		}},
	}
	return msg, nil
}

// EncodeResponse 根据请求报文编码一个 DNS 响应。
//
// answers 里传入的是结构化 Record，编码器会把它们写成 DNS answer section。
func EncodeResponse(req *Message, answers []Record, rcode RCode) ([]byte, error) {
	if req == nil || len(req.Questions) == 0 {
		return nil, ErrInvalidResponse
	}

	q := req.Questions[0]
	buf := make([]byte, 0, 256)

	hdr := req.Header
	hdr.QR = true
	hdr.AA = true
	hdr.RA = false
	hdr.RCode = rcode
	hdr.QDCount = 1
	hdr.ANCount = uint16(len(answers))
	hdr.NSCount = 0
	hdr.ARCount = 0

	buf = appendHeader(buf, hdr)
	var err error
	buf, err = appendName(buf, q.QName)
	if err != nil {
		return nil, err
	}
	buf = appendUint16(buf, uint16(q.QType))
	buf = appendUint16(buf, uint16(q.QClass))

	for _, ans := range answers {
		if ans.Type != QTypeA {
			return nil, ErrUnsupportedType
		}
		if ans.Class != ClassIN {
			return nil, ErrUnsupportedClass
		}
		ip := net.ParseIP(strings.TrimSpace(ans.Value)).To4()
		if ip == nil {
			return nil, ErrInvalidIPAddress
		}

		buf, err = appendName(buf, ans.Name)
		if err != nil {
			return nil, err
		}
		buf = appendUint16(buf, uint16(ans.Type))
		buf = appendUint16(buf, uint16(ans.Class))
		buf = appendUint32(buf, uint32(ans.TTL/time.Second))
		buf = appendUint16(buf, 4)
		buf = append(buf, ip...)
	}

	return buf, nil
}

// BuildAResponse 构造一个单答案的 A 记录响应。
func BuildAResponse(req *Message, ip string, ttl time.Duration) ([]byte, error) {
	if req == nil || len(req.Questions) == 0 {
		return nil, ErrInvalidResponse
	}

	q := req.Questions[0]
	if q.QType != QTypeA {
		return nil, ErrUnsupportedType
	}
	if q.QClass != ClassIN {
		return nil, ErrUnsupportedClass
	}

	return EncodeResponse(req, []Record{{
		Name:  q.QName,
		Type:  QTypeA,
		Class: ClassIN,
		TTL:   ttl,
		Value: ip,
	}}, RCodeNoError)
}

func decodeHeader(raw []byte) Header {
	flags := binary.BigEndian.Uint16(raw[2:4])
	return Header{
		ID:      binary.BigEndian.Uint16(raw[0:2]),
		QR:      flags&0x8000 != 0,
		Opcode:  uint8((flags >> 11) & 0x0F),
		AA:      flags&0x0400 != 0,
		TC:      flags&0x0200 != 0,
		RD:      flags&0x0100 != 0,
		RA:      flags&0x0080 != 0,
		Z:       uint8((flags >> 4) & 0x07),
		RCode:   RCode(flags & 0x0F),
		QDCount: binary.BigEndian.Uint16(raw[4:6]),
		ANCount: binary.BigEndian.Uint16(raw[6:8]),
		NSCount: binary.BigEndian.Uint16(raw[8:10]),
		ARCount: binary.BigEndian.Uint16(raw[10:12]),
	}
}

func appendHeader(dst []byte, hdr Header) []byte {
	flags := uint16(0)
	if hdr.QR {
		flags |= 0x8000
	}
	flags |= uint16(hdr.Opcode&0x0F) << 11
	if hdr.AA {
		flags |= 0x0400
	}
	if hdr.TC {
		flags |= 0x0200
	}
	if hdr.RD {
		flags |= 0x0100
	}
	if hdr.RA {
		flags |= 0x0080
	}
	flags |= uint16(hdr.Z&0x07) << 4
	flags |= uint16(hdr.RCode & 0x0F)

	dst = appendUint16(dst, hdr.ID)
	dst = appendUint16(dst, flags)
	dst = appendUint16(dst, hdr.QDCount)
	dst = appendUint16(dst, hdr.ANCount)
	dst = appendUint16(dst, hdr.NSCount)
	dst = appendUint16(dst, hdr.ARCount)
	return dst
}

func appendName(dst []byte, name string) ([]byte, error) {
	// 名称采用 DNS label 编码，第一版只保留最常见的无压缩写法。
	trimmed := strings.TrimSuffix(strings.TrimSpace(name), ".")
	if trimmed == "" {
		return nil, ErrMalformedName
	}
	for _, label := range strings.Split(trimmed, ".") {
		if len(label) == 0 {
			return nil, ErrMalformedName
		}
		if len(label) > 63 {
			return nil, ErrMalformedName
		}
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
	}
	return append(dst, 0x00), nil
}

func appendUint16(dst []byte, v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return append(dst, buf[:]...)
}

func appendUint32(dst []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(dst, buf[:]...)
}

func readName(raw []byte, off int, depth int) (string, int, error) {
	// 读取域名，支持最小化的压缩指针解析。
	// depth 用于避免压缩指针递归过深。
	if depth > 10 {
		return "", 0, ErrMalformedName
	}
	if off >= len(raw) {
		return "", 0, ErrShortPacket
	}

	var (
		labels  []string
		nextOff = off
		jumped  bool
	)

	for {
		if nextOff >= len(raw) {
			return "", 0, ErrShortPacket
		}
		l := int(raw[nextOff])
		if l == 0 {
			nextOff++
			break
		}
		if l&ptrMask == ptrMask {
			if nextOff+1 >= len(raw) {
				return "", 0, ErrShortPacket
			}
			ptr := int(binary.BigEndian.Uint16(raw[nextOff:nextOff+2]) & ptrTargetMask)
			if ptr >= len(raw) {
				return "", 0, ErrMalformedName
			}
			part, _, err := readName(raw, ptr, depth+1)
			if err != nil {
				return "", 0, err
			}
			if part != "" {
				labels = append(labels, part)
			}
			nextOff += 2
			jumped = true
			break
		}
		if l&ptrMask != 0 {
			return "", 0, ErrUnexpectedCompression
		}
		nextOff++
		if nextOff+l > len(raw) {
			return "", 0, ErrShortPacket
		}
		labels = append(labels, string(raw[nextOff:nextOff+l]))
		nextOff += l
	}

	name := strings.Join(labels, ".")
	if !jumped {
		return name, nextOff, nil
	}
	return name, nextOff, nil
}

// MustParseQuery 是测试里常用的小工具，解析失败时直接 panic。
func MustParseQuery(raw []byte) *Message {
	msg, err := ParseQuery(raw)
	if err != nil {
		panic(fmt.Sprintf("dnsmsg: parse query failed: %v", err))
	}
	return msg
}
