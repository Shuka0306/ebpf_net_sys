package dnsmsg

import api "ebpf-multi-protocol-network-monitor/services/dns/api"

type QType = api.QType
type Class = api.Class
type RCode = api.RCode
type Header = api.Header
type Question = api.Question
type Record = api.Record
type Message = api.Message

const (
	QTypeA  = api.QTypeA
	ClassIN = api.ClassIN
)

var (
	ErrShortPacket           = api.ErrShortPacket
	ErrMalformedName         = api.ErrMalformedName
	ErrUnsupportedQuery      = api.ErrUnsupportedQuery
	ErrUnsupportedQuestion   = api.ErrUnsupportedQuestion
	ErrUnsupportedType       = api.ErrUnsupportedType
	ErrUnsupportedClass      = api.ErrUnsupportedClass
	ErrInvalidResponse       = api.ErrInvalidResponse
	ErrInvalidIPAddress      = api.ErrInvalidIPAddress
	ErrUnexpectedCompression = api.ErrUnexpectedCompression
)

const (
	RCodeNoError        = api.RCodeNoError
	RCodeFormatError    = api.RCodeFormatError
	RCodeServerFailure  = api.RCodeServerFailure
	RCodeNameError      = api.RCodeNameError
	RCodeNotImplemented = api.RCodeNotImplemented
	RCodeRefused        = api.RCodeRefused
)
