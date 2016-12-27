package rawmdns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

type DNSMessage struct {
	Hdr        DNSHeader
	Questions  []DNSQuestion
	Answers    []DNSResourceRecord // any XYZRecord from this package
	Additional []DNSResourceRecord // any XYZRecord from this package
	//NameServers []DNSNSRecord
}

func (dm DNSMessage) ToBytes() ([]byte, error) {
	ret, err := dm.Hdr.toBytes()
	if err != nil {
		return nil, fmt.Errorf("DNSHeader.ToBytes: %s", err)
	}

	for _, dq := range dm.Questions {
		qb, err := dq.toBytes()
		if err != nil {
			return nil, fmt.Errorf("DNSQuestion.ToBytes: %s", err)
		}
		ret = append(ret, qb...)
	}

	for _, answer := range dm.Answers {
		rrr, err := answer.toRawDNSResourceRecord()
		if err != nil {
			return nil, fmt.Errorf("DNSResourceRecord.torawDNSResourceRecord: %s", err)
		}
		ab, err := rrr.toBytes()
		ret = append(ret, ab...)
	}

	for _, addl := range dm.Additional {
		rrr, err := addl.toRawDNSResourceRecord()
		if err != nil {
			return nil, fmt.Errorf("DNSResourceRecord.torawDNSResourceRecord: %s", err)
		}
		ab, err := rrr.toBytes()
		ret = append(ret, ab...)
	}

	return ret, nil
}

type rawDNSHeader struct {
	Id      uint16
	Flag    [2]byte
	QdCount uint16
	AnCount uint16
	NSCount uint16
	ArCount uint16
}

func (rdh rawDNSHeader) toDNSHeader() DNSHeader {
	dh := DNSHeader{}
	dh.ID = rdh.Id
	dh.NumQuestions = rdh.QdCount
	dh.NumAnswers = rdh.AnCount
	dh.NumNameServers = rdh.NSCount
	dh.NumAddlRecords = rdh.ArCount

	if rdh.Flag[0]>>7 == 1 {
		dh.IsResponse = true
	}
	dh.OpCode = OpCode((rdh.Flag[0] >> 3) &^ 0x10)
	if (rdh.Flag[0]&0x4)>>2 == 1 {
		dh.Authoritative = true
	}
	if (rdh.Flag[0]&0x2)>>1 == 1 {
		dh.Truncated = true
	}
	if rdh.Flag[0]&0x1 == 1 {
		dh.RecursionDesired = true
	}
	if rdh.Flag[1]>>7 == 1 {
		dh.RecursionAvailable = true
	}
	dh.ResponseCode = ResponseCode(rdh.Flag[1] & 0xF)

	return dh
}

func (rdh rawDNSHeader) toBytes() ([]byte, error) {
	buf := bytes.Buffer{}
	err := binary.Write(&buf, binary.BigEndian, rdh)
	if err != nil {
		return nil, fmt.Errorf("binary.Write(): %s", err)
	}
	return buf.Bytes(), nil
}

type DNSHeader struct {
	ID                 uint16
	IsResponse         bool
	OpCode             OpCode
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Reserved           bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	// This actually contains two fields we should decode:
	// Authenticated Data (on response)
	// Checking Disabled (on query)
	// These are defined in RFC 2065 section 6.1
	// http://freesoft.org/CIE/RFC/2065/40.htm
	ResponseCode   ResponseCode
	NumQuestions   uint16
	NumAnswers     uint16
	NumNameServers uint16
	NumAddlRecords uint16
}

func (dh DNSHeader) toRaw() rawDNSHeader {
	var rdh rawDNSHeader
	rdh.Id = uint16(dh.ID)
	rdh.QdCount = uint16(dh.NumQuestions)
	rdh.AnCount = uint16(dh.NumAnswers)
	rdh.NSCount = uint16(dh.NumNameServers)
	rdh.ArCount = uint16(dh.NumAddlRecords)

	if dh.IsResponse {
		rdh.Flag[0] |= 0x80
	}
	rdh.Flag[0] |= uint8(dh.OpCode) << 3
	if dh.Authoritative {
		rdh.Flag[0] |= 0x4
	}
	if dh.Truncated {
		rdh.Flag[0] |= 0x2
	}
	if dh.RecursionDesired {
		rdh.Flag[0] |= 0x1
	}
	if dh.RecursionAvailable {
		rdh.Flag[1] |= 0x80
	}
	rdh.Flag[1] |= byte(dh.ResponseCode & 0xF)

	return rdh
}

func (dh DNSHeader) toBytes() ([]byte, error) {
	return dh.toRaw().toBytes()
}

type rawDNSQuestion struct {
	domainLabels rawLabels
	static       rawQuestionStatic
}

type rawQuestionStatic struct {
	Type  RecordType
	Class RecordClass
}

func (rq rawDNSQuestion) toBytes() ([]byte, error) {
	var buf bytes.Buffer
	terminusLabel := rawLabel{length: 0, content: ""}
	outLabels := append(rq.domainLabels, terminusLabel)
	for _, l := range outLabels {
		_, err := buf.Write(l.toBytes())
		if err != nil {
			return nil, fmt.Errorf("bytes.Buffer.Write: %s", err)
		}
	}

	err := binary.Write(&buf, binary.BigEndian, rq.static)
	if err != nil {
		return nil, fmt.Errorf("binary.Write: %s", err)
	}
	return buf.Bytes(), nil
}

func (rq rawDNSQuestion) toQuestion() DNSQuestion {
	q := DNSQuestion{}
	for _, s := range rq.domainLabels {
		if len(q.Domain) > 0 {
			q.Domain += "."
		}
		q.Domain += s.content
	}
	q.Type = rq.static.Type
	q.Class = rq.static.Class & 0x7FFF
	if rq.static.Class&0x8000 == 0x8000 {
		q.AcceptUnicastResponse = true
	}

	return q
}

type DNSQuestion struct {
	Domain                string
	Type                  RecordType
	Class                 RecordClass
	AcceptUnicastResponse bool
}

func (q DNSQuestion) toRaw() rawDNSQuestion {
	var rq rawDNSQuestion
	for _, s := range strings.Split(q.Domain, ".") {
		l := rawLabel{
			length:  uint8(len(s)),
			content: s,
		}
		rq.domainLabels = append(rq.domainLabels, l)
	}
	rq.static.Type = q.Type
	rq.static.Class = q.Class
	if q.AcceptUnicastResponse {
		rq.static.Class = rq.static.Class | 0x8000
	}
	return rq
}

func (q DNSQuestion) toBytes() ([]byte, error) {
	return q.toRaw().toBytes()
}
