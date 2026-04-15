package dnsmsg

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestParseQuery(t *testing.T) {
	raw := buildQueryPacket(t, 0x1234, "hot.example.com", QTypeA, ClassIN)

	msg, err := ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	if msg.Header.ID != 0x1234 {
		t.Fatalf("unexpected id: %x", msg.Header.ID)
	}
	if len(msg.Questions) != 1 {
		t.Fatalf("unexpected question count: %d", len(msg.Questions))
	}
	q := msg.Questions[0]
	if q.QName != "hot.example.com" {
		t.Fatalf("unexpected qname: %q", q.QName)
	}
	if q.QType != QTypeA {
		t.Fatalf("unexpected qtype: %d", q.QType)
	}
	if q.QClass != ClassIN {
		t.Fatalf("unexpected qclass: %d", q.QClass)
	}
}

func TestBuildAResponse(t *testing.T) {
	raw := buildQueryPacket(t, 0x4321, "api.example.com", QTypeA, ClassIN)
	req, err := ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}

	resp, err := BuildAResponse(req, "1.2.3.4", 60*time.Second)
	if err != nil {
		t.Fatalf("BuildAResponse failed: %v", err)
	}

	got, err := ParseMessageResponse(resp)
	if err != nil {
		t.Fatalf("ParseMessageResponse failed: %v", err)
	}
	if got.Header.ID != req.Header.ID {
		t.Fatalf("response id mismatch: got %x want %x", got.Header.ID, req.Header.ID)
	}
	if !got.Header.QR {
		t.Fatalf("response should set QR")
	}
	if got.Header.RCode != RCodeNoError {
		t.Fatalf("unexpected rcode: %d", got.Header.RCode)
	}
	if len(got.Answers) != 1 {
		t.Fatalf("unexpected answers count: %d", len(got.Answers))
	}
	ans := got.Answers[0]
	if ans.Name != "api.example.com" {
		t.Fatalf("unexpected answer name: %q", ans.Name)
	}
	if ans.Value != "1.2.3.4" {
		t.Fatalf("unexpected answer value: %q", ans.Value)
	}
	if ans.TTL != 60*time.Second {
		t.Fatalf("unexpected ttl: %s", ans.TTL)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"short", []byte{0x01, 0x02}},
		{"empty question", buildHeaderOnlyPacket(0x1000, 1)},
		{"not a query", buildQueryPacketWithFlags(t, 0x1001, 0x8000, "hot.example.com", QTypeA, ClassIN)},
		{"unsupported type", buildQueryPacket(t, 0x1002, "hot.example.com", 28, ClassIN)},
		{"unsupported class", buildQueryPacket(t, 0x1003, "hot.example.com", QTypeA, 3)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseQuery(tc.raw)
			if err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestEncodeResponseRejectsBadIP(t *testing.T) {
	req := MustParseQuery(buildQueryPacket(t, 0x5555, "bad.example.com", QTypeA, ClassIN))
	_, err := EncodeResponse(req, []Record{{
		Name:  "bad.example.com",
		Type:  QTypeA,
		Class: ClassIN,
		TTL:   time.Minute,
		Value: "not-an-ip",
	}}, RCodeNoError)
	if err == nil {
		t.Fatalf("expected invalid ip error")
	}
}

func TestEncodeResponseRejectsNilRequest(t *testing.T) {
	_, err := EncodeResponse(nil, nil, RCodeNoError)
	if err == nil {
		t.Fatalf("expected error for nil request")
	}
}

func TestEncodeResponseMultipleAnswers(t *testing.T) {
	req := MustParseQuery(buildQueryPacket(t, 0x6666, "multi.example.com", QTypeA, ClassIN))
	resp, err := EncodeResponse(req, []Record{
		{Name: "multi.example.com", Type: QTypeA, Class: ClassIN, TTL: 30 * time.Second, Value: "10.0.0.1"},
		{Name: "multi.example.com", Type: QTypeA, Class: ClassIN, TTL: 30 * time.Second, Value: "10.0.0.2"},
	}, RCodeNoError)
	if err != nil {
		t.Fatalf("EncodeResponse failed: %v", err)
	}
	msg, err := ParseMessageResponse(resp)
	if err != nil {
		t.Fatalf("ParseMessageResponse failed: %v", err)
	}
	if len(msg.Answers) != 2 {
		t.Fatalf("unexpected answers count: %d", len(msg.Answers))
	}
	if msg.Answers[0].Value != "10.0.0.1" || msg.Answers[1].Value != "10.0.0.2" {
		t.Fatalf("unexpected answers: %+v", msg.Answers)
	}
}

func TestNameCompressionInResponse(t *testing.T) {
	req := MustParseQuery(buildQueryPacket(t, 0x7777, "ptr.example.com", QTypeA, ClassIN))
	resp, err := BuildAResponse(req, "8.8.8.8", time.Minute)
	if err != nil {
		t.Fatalf("BuildAResponse failed: %v", err)
	}
	msg, err := ParseMessageResponse(resp)
	if err != nil {
		t.Fatalf("ParseMessageResponse failed: %v", err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("expected one answer")
	}
}

func TestParseMessageResponseUnsupported(t *testing.T) {
	_, err := ParseMessageResponse([]byte{0x00, 0x01})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func buildHeaderOnlyPacket(id uint16, qdcount uint16) []byte {
	p := make([]byte, dnsHeaderSize)
	binary.BigEndian.PutUint16(p[0:2], id)
	binary.BigEndian.PutUint16(p[4:6], qdcount)
	return p
}

func buildQueryPacket(t *testing.T, id uint16, name string, qtype QType, qclass Class) []byte {
	return buildQueryPacketWithFlags(t, id, 0, name, qtype, qclass)
}

func buildQueryPacketWithFlags(t *testing.T, id uint16, flags uint16, name string, qtype QType, qclass Class) []byte {
	t.Helper()
	p := buildHeaderOnlyPacket(id, 1)
	binary.BigEndian.PutUint16(p[2:4], flags)
	var err error
	p, err = appendName(p, name)
	if err != nil {
		t.Fatalf("appendName failed: %v", err)
	}
	p = appendUint16(p, uint16(qtype))
	p = appendUint16(p, uint16(qclass))
	return p
}

func ParseMessageResponse(raw []byte) (*Message, error) {
	if len(raw) < dnsHeaderSize {
		return nil, ErrShortPacket
	}
	hdr := decodeHeader(raw[:dnsHeaderSize])
	off := dnsHeaderSize
	msg := &Message{Header: hdr}
	for i := 0; i < int(hdr.QDCount); i++ {
		name, next, err := readName(raw, off, 0)
		if err != nil {
			return nil, err
		}
		off = next
		if off+4 > len(raw) {
			return nil, ErrShortPacket
		}
		msg.Questions = append(msg.Questions, Question{
			QName:  name,
			QType:  QType(binary.BigEndian.Uint16(raw[off : off+2])),
			QClass: Class(binary.BigEndian.Uint16(raw[off+2 : off+4])),
		})
		off += 4
	}
	for i := 0; i < int(hdr.ANCount); i++ {
		name, next, err := readName(raw, off, 0)
		if err != nil {
			return nil, err
		}
		off = next
		if off+10 > len(raw) {
			return nil, ErrShortPacket
		}
		typ := QType(binary.BigEndian.Uint16(raw[off : off+2]))
		class := Class(binary.BigEndian.Uint16(raw[off+2 : off+4]))
		ttl := time.Duration(binary.BigEndian.Uint32(raw[off+4:off+8])) * time.Second
		rdlen := int(binary.BigEndian.Uint16(raw[off+8 : off+10]))
		off += 10
		if off+rdlen > len(raw) {
			return nil, ErrShortPacket
		}
		value := ""
		if typ == QTypeA && rdlen == 4 {
			value = net.IP(raw[off : off+4]).String()
		}
		msg.Answers = append(msg.Answers, Record{
			Name:  name,
			Type:  typ,
			Class: class,
			TTL:   ttl,
			Value: value,
		})
		off += rdlen
	}
	return msg, nil
}
