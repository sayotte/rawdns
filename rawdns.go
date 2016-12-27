package rawdns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

type DNSMessage struct {
	Hdr       DNSHeader
	Questions []DNSQuestion
	//Answers []DNSAnswer
	//NameServers []DNSNSRecord
	//Addl []DNSAddlRecord
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

	return ret, nil
}

func DNSMessageFromBytes(rdr *bytes.Reader) (DNSMessage, error) {
	var dm DNSMessage

	rdh, err := rawDNSHeaderFromBytes(rdr)
	if err != nil {
		return DNSMessage{}, fmt.Errorf("rawDNSHeaderFromBytes: %s\n", err)
	}
	dm.Hdr = rdh.toDNSHeader()

	var labelRecords []labelRecord
	for i := 0; i < int(dm.Hdr.numQuestions); i++ {
		var rq rawDNSQuestion
		rq, labelRecords, err = rawQuestionFromBytes(rdr, labelRecords)
		if err != nil {
			return DNSMessage{}, fmt.Errorf("rawQueryFromBytes: %s\n", err)
		}
		dm.Questions = append(dm.Questions, rq.toQuestion())
	}

	return dm, nil
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
	dh.id = rdh.Id
	dh.numQuestions = rdh.QdCount
	dh.numAnswers = rdh.AnCount
	dh.numNameServers = rdh.NSCount
	dh.numAddlRecords = rdh.ArCount

	if rdh.Flag[0]>>7 == 1 {
		dh.isResponse = true
	}
	dh.opCode = uint((rdh.Flag[0] >> 3) &^ 0x10)
	if (rdh.Flag[0]&0x4)>>2 == 1 {
		dh.authoritative = true
	}
	if (rdh.Flag[0]&0x2)>>1 == 1 {
		dh.truncated = true
	}
	if rdh.Flag[0]&0x1 == 1 {
		dh.recursionDesired = true
	}
	if rdh.Flag[1]>>7 == 1 {
		dh.recursionAvailable = true
	}
	dh.responseCode = uint(rdh.Flag[1] & 0xF)

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

func rawDNSHeaderFromBytes(r io.ReadSeeker) (rawDNSHeader, error) {
	rdh := rawDNSHeader{}
	err := binary.Read(r, binary.BigEndian, &rdh)
	return rdh, err
}

type DNSHeader struct {
	id                 uint16
	isResponse         bool
	opCode             uint
	authoritative      bool
	truncated          bool
	recursionDesired   bool
	recursionAvailable bool
	alwaysZero         bool
	responseCode       uint
	numQuestions       uint16
	numAnswers         uint16
	numNameServers     uint16
	numAddlRecords     uint16
}

func (dh DNSHeader) toRaw() rawDNSHeader {
	var rdh rawDNSHeader
	rdh.Id = uint16(dh.id)
	rdh.QdCount = uint16(dh.numQuestions)
	rdh.AnCount = uint16(dh.numAnswers)
	rdh.NSCount = uint16(dh.numNameServers)
	rdh.ArCount = uint16(dh.numAddlRecords)

	if dh.isResponse {
		rdh.Flag[0] |= 0x80
	}
	rdh.Flag[0] |= uint8(dh.opCode) << 3
	if dh.authoritative {
		rdh.Flag[0] |= 0x4
	}
	if dh.truncated {
		rdh.Flag[0] |= 0x2
	}
	if dh.recursionDesired {
		rdh.Flag[0] |= 0x1
	}
	if dh.recursionAvailable {
		rdh.Flag[1] |= 0x80
	}
	rdh.Flag[1] |= byte(dh.responseCode & 0xF)

	return rdh
}

func (dh DNSHeader) toBytes() ([]byte, error) {
	return dh.toRaw().toBytes()
}

type rawDNSQuestion struct {
	domainLabels []rawLabel
	static       rawQuestionStatic
}

type rawQuestionStatic struct {
	Type  uint16
	Class uint16
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
		if len(q.domain) > 0 {
			q.domain += "."
		}
		q.domain += s.content
	}
	q.typ = rq.static.Type
	q.class = rq.static.Class & 0x7FFF
	if rq.static.Class&0x8000 == 0x8000 {
		q.acceptUnicastResponse = true
	}

	return q
}

func rawQuestionFromBytes(r *bytes.Reader, labelRecords []labelRecord) (rawDNSQuestion, []labelRecord, error) {
	rq := rawDNSQuestion{}
	var err error

	// Populate labels
	rq.domainLabels, labelRecords, err = rawLabelsFromBytes(r, labelRecords)
	if err != nil {
		return rawDNSQuestion{}, nil, fmt.Errorf("rawLabelsFromBytes: %s", err)
	}

	// Populate rest of the query header
	lr := io.LimitReader(r, int64(binary.Size(rq.static)))
	err = binary.Read(lr, binary.BigEndian, &rq.static)
	if err != nil {
		return rawDNSQuestion{}, nil, fmt.Errorf("binary.Read: %s", err)
	}

	return rq, labelRecords, nil
}

type DNSQuestion struct {
	domain                string
	typ                   uint16
	class                 uint16
	acceptUnicastResponse bool
}

func (q DNSQuestion) toRaw() rawDNSQuestion {
	var rq rawDNSQuestion
	for _, s := range strings.Split(q.domain, ".") {
		l := rawLabel{
			length:  uint8(len(s)),
			content: s,
		}
		rq.domainLabels = append(rq.domainLabels, l)
	}
	rq.static.Type = q.typ
	rq.static.Class = q.class
	if q.acceptUnicastResponse {
		rq.static.Class = rq.static.Class | 0x8000
	}
	return rq
}

func (q DNSQuestion) toBytes() ([]byte, error) {
	return q.toRaw().toBytes()
}

type labelRecord struct {
	offset  int64
	length  int64
	content string
	isPtr   bool
}

type rawLabel struct {
	length  uint8
	content string
}

func (rl rawLabel) toBytes() []byte {
	ret := make([]byte, len(rl.content)+1)
	ret[0] = byte(rl.length)
	copy(ret[1:], []byte(rl.content))
	return ret
}

func rawLabelsFromBytes(r *bytes.Reader, labelRecords []labelRecord) ([]rawLabel, []labelRecord, error) {
	var rlList []rawLabel
	for {
		lRec := labelRecord{}
		rl := rawLabel{}

		var err error
		lRec.offset, err = getCurrentOffset(r)
		if err != nil {
			return nil, nil, fmt.Errorf("getCurrentOffset: %s", err)
		}

		b, err := r.ReadByte()
		if err != nil {
			return nil, nil, fmt.Errorf("bytes.Reader.ReadByte: %s", err)
		}
		lRec.length = int64(b)

		if lRec.length == 0 {
			labelRecords = append(labelRecords, lRec)
			break
		}
		if lRec.length>>6 == 3 {
			lRec.isPtr = true
			// consume second byte
			nextByte, err := r.ReadByte()
			if err != nil {
				return nil, nil, err
			}
			lRec.length = ((lRec.length & 0x3F) << 8) + int64(nextByte)

			labelRecords = append(labelRecords, lRec)
			rlList = append(rlList, rawLabelsFromOffset(labelRecords, lRec.length)...)
			break
		}

		lr := io.LimitReader(r, lRec.length)
		buf := make([]byte, lRec.length)
		_, err = lr.Read(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("io.LimitReader.Read: %s", err)
		}

		lRec.content = string(buf)
		labelRecords = append(labelRecords, lRec)
		rl.length = uint8(lRec.length)
		rl.content = lRec.content
		rlList = append(rlList, rl)
	}
	return rlList, labelRecords, nil
}

func rawLabelsFromOffset(labelRecords []labelRecord, off int64) []rawLabel {
	var rawLabels []rawLabel
	for _, lr := range labelRecords {
		if lr.offset < off {
			continue
		}
		if lr.length == 0 {
			break
		}
		if lr.length>>6 == 3 {
			break
		}
		rawLabels = append(rawLabels, rawLabel{length: uint8(lr.length), content: lr.content})
	}
	return rawLabels
}

func getCurrentOffset(s io.Seeker) (int64, error) {
	return s.Seek(0, os.SEEK_CUR)
}
