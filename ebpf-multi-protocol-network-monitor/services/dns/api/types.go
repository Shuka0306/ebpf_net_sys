package api

import (
	"fmt"
	"time"
)

// QType 表示 DNS 查询类型。
type QType uint16

const (
	// QTypeA 表示 A 记录类型。
	QTypeA QType = 1
)

// Class 表示 DNS class。
type Class uint16

const (
	// ClassIN 表示 Internet class。
	ClassIN Class = 1
)

// RCode 表示 DNS 响应码。
type RCode uint8

const (
	RCodeNoError        RCode = 0
	RCodeFormatError    RCode = 1
	RCodeServerFailure  RCode = 2
	RCodeNameError      RCode = 3
	RCodeNotImplemented RCode = 4
	RCodeRefused        RCode = 5
)

// Header 表示 DNS 报文头。
type Header struct {
	ID     uint16
	QR     bool
	Opcode uint8
	AA     bool
	TC     bool
	RD     bool
	RA     bool
	Z      uint8
	RCode  RCode

	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Question 表示 DNS question 部分的一条查询。
type Question struct {
	QName  string
	QType  QType
	QClass Class
}

// Record 表示最小版本里缓存或返回的 DNS 资源记录。
// 第一版只需要覆盖 A 记录即可。
type Record struct {
	Name  string
	Type  QType
	Class Class
	TTL   time.Duration
	Value string
}

// Message 表示一个完整的 DNS 报文。
type Message struct {
	Header    Header
	Questions []Question
	Answers   []Record
}

// Error values returned by dnsmsg 编解码器。
var (
	ErrShortPacket           = fmt.Errorf("dnsmsg: short packet")
	ErrMalformedName         = fmt.Errorf("dnsmsg: malformed name")
	ErrUnsupportedQuery      = fmt.Errorf("dnsmsg: unsupported query")
	ErrUnsupportedQuestion   = fmt.Errorf("dnsmsg: unsupported question")
	ErrUnsupportedType       = fmt.Errorf("dnsmsg: unsupported question type")
	ErrUnsupportedClass      = fmt.Errorf("dnsmsg: unsupported question class")
	ErrInvalidResponse       = fmt.Errorf("dnsmsg: invalid response")
	ErrInvalidIPAddress      = fmt.Errorf("dnsmsg: invalid ipv4 address")
	ErrUnexpectedCompression = fmt.Errorf("dnsmsg: unexpected compression")
)
