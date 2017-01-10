package rawmdns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
)

type readCounter struct {
	reader io.Reader
	offset int
}

func (rc *readCounter) Read(buf []byte) (int, error) {
	off, err := rc.reader.Read(buf)
	rc.offset += off
	return off, err
}

type Decoder struct {
	rdr          *readCounter
	labelRecords []labelRecord
}

func NewDecoder(r io.Reader) Decoder {
	return Decoder{rdr: &readCounter{reader: r}}
}

func (d *Decoder) DecodeDNSMessage() (DNSMessage, error) {
	var dm DNSMessage

	rdh, err := d.nextRawDNSHeader()
	if err != nil {
		// If we get an EOF while still building the header, then
		// we started with an empty stream and can forward the EOF
		// up. If we get an EOF from any subsequent calls, we've
		// probably parsed some broken bits and it needs to be
		// treated as something other than just EOF.
		if err != io.EOF {
			return dm, fmt.Errorf("d.nextRawDNSHeader: %s\n", err)
		}
		return dm, err
	}
	dm.Hdr = rdh.toDNSHeader()

	for i := 0; i < int(dm.Hdr.NumQuestions); i++ {
		var rq rawDNSQuestion
		rq, err = d.nextRawQuestion()
		if err != nil {
			return dm, fmt.Errorf("rawQueryFromBytes: %s\n", err)
		}
		dm.Questions = append(dm.Questions, rq.toQuestion())
	}

	for i := 0; i < int(dm.Hdr.NumAnswers); i++ {
		var drr DNSResourceRecord
		var err error
		drr, err = d.nextResourceRecord()
		if err != nil {
			return dm, fmt.Errorf("nextResourceRecord: %s\n", err)
		}
		dm.Answers = append(dm.Answers, drr)
	}

	for i := 0; i < int(dm.Hdr.NumAddlRecords); i++ {
		var drr DNSResourceRecord
		var err error
		drr, err = d.nextResourceRecord()
		if err != nil {
			return dm, fmt.Errorf("resourceRecordFromBytes: %s\n", err)
		}
		dm.Additional = append(dm.Additional, drr)
	}

	return dm, nil
}

func (d *Decoder) nextRawDNSHeader() (rawDNSHeader, error) {
	rdh := rawDNSHeader{}
	err := binary.Read(d.rdr, binary.BigEndian, &rdh)
	return rdh, err
}

func (d *Decoder) nextRawLabels() (rawLabels, error) {
	return d._nextRawLabelsFromReaderWithBaseOffset(d.rdr, d.rdr.offset)
}

func (d *Decoder) _nextRawLabelsFromReaderWithBaseOffset(rdr io.Reader, baseOffset int) (rawLabels, error) {
	var rlList rawLabels
	var cursor int
	for {
		var (
			lRec      labelRecord
			rl        rawLabel
			bytesRead int
			err       error
		)

		lRec.offset = uint16(baseOffset + cursor)

		buf := make([]byte, 1)
		bytesRead, err = rdr.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("rdr.Read: %s", err)
		}
		cursor += bytesRead
		lRec.length = buf[0]

		if lRec.length == 0 {
			d.labelRecords = append(d.labelRecords, lRec)
			break
		}
		if lRec.length>>6 == 3 {
			lRec.isPtr = true
			// consume second byte
			bytesRead, err = rdr.Read(buf)
			if err != nil {
				return nil, fmt.Errorf("rdr.Read: %s", err)
			}
			cursor += bytesRead
			lRec.targetOffset = uint16(((uint16(lRec.length) & 0x3F) << 8) + uint16(buf[0]))
			rlList = append(rlList, d.rawLabelsFromOffset(lRec.targetOffset)...)

			lRec.length = 0
			d.labelRecords = append(d.labelRecords, lRec)
			break
		}
		// first two bits may be 00 or 11, but not 01 or 10
		if lRec.length&0x80 == 0x80 || lRec.length&0x40 == 0x40 {
			err := fmt.Errorf("Illegal length: 0x%X", lRec.length)
			return nil, err
		}

		buf = make([]byte, lRec.length)
		bytesRead, err = rdr.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("rdr.Read: %s", err)
		}
		cursor += bytesRead

		lRec.content = string(buf)
		d.labelRecords = append(d.labelRecords, lRec)
		rl.length = uint8(lRec.length)
		rl.content = lRec.content
		rlList = append(rlList, rl)
	}
	return rlList, nil
}

func (d Decoder) rawLabelsFromOffset(off uint16) rawLabels {
	var rawLabels rawLabels
	for _, lr := range []labelRecord(d.labelRecords) {
		if lr.offset < off {
			continue
		}
		if lr.isPtr {
			rawLabels = append(rawLabels, d.rawLabelsFromOffset(lr.targetOffset)...)
			break
		}
		if lr.length == 0 {
			break
		}
		rawLabels = append(rawLabels, rawLabel{length: uint8(lr.length), content: lr.content})
	}
	return rawLabels
}

func (d *Decoder) nextRawQuestion() (rawDNSQuestion, error) {
	rq := rawDNSQuestion{}
	var err error

	// Populate labels
	rq.domainLabels, err = d.nextRawLabels()
	if err != nil {
		return rawDNSQuestion{}, fmt.Errorf("d.nextRawLabels: %s", err)
	}

	// Populate rest of the query header
	err = binary.Read(d.rdr, binary.BigEndian, &rq.static)
	if err != nil {
		return rawDNSQuestion{}, fmt.Errorf("binary.Read: %s", err)
	}

	return rq, nil
}

func (d *Decoder) nextRawDNSResourceRecord() (rawResourceRecord, error) {
	var rdrr rawResourceRecord
	var err error

	rdrr.domainLabels, err = d.nextRawLabels()
	if err != nil {
		return rdrr, fmt.Errorf("nextRawLabels: %s", err)
	}

	err = binary.Read(d.rdr, binary.BigEndian, &rdrr.static)
	if err != nil {
		return rdrr, fmt.Errorf("binary.Read: %s", err)
	}

	rdrr.rDataOffsetInMsg = d.rdr.offset
	rdrr.rData = make([]byte, rdrr.static.RDataLength)
	_, err = d.rdr.Read(rdrr.rData)
	if err != nil {
		return rdrr, fmt.Errorf("r.Read: %s", err)
	}

	return rdrr, nil
}

func (d *Decoder) nextResourceRecord() (DNSResourceRecord, error) {
	var rdrr rawResourceRecord
	rdrr, err := d.nextRawDNSResourceRecord()
	if err != nil {
		return nil, fmt.Errorf("nextRawDNSResourceRecord: %s\n", err)
	}

	var drr DNSResourceRecord
	drr, err = d.rawRRtoDNSResourceRecord(rdrr)
	if err != nil {
		return nil, fmt.Errorf("rawRRtoDNSResourceRecord: %s", err)
	}

	return drr, nil
}

func (d *Decoder) rawRRtoDNSResourceRecord(rdrr rawResourceRecord) (DNSResourceRecord, error) {
	switch rdrr.static.Type {
	case TypeA:
		return d.newARecordFromRawRR(rdrr), nil
	case TypeAAAA:
		return d.newAAAARecordFromRawRR(rdrr), nil
	case TypeSRV:
		return d.newSRVRecordFromRawRR(rdrr)
	case TypePTR:
		return d.newPTRRecordFromRawRR(rdrr)
	case TypeTXT:
		return d.newTXTRecordFromRawRR(rdrr), nil
	case TypeNSEC:
		return d.newNSECRecordFromRawRR(rdrr)
	case TypeOPT:
		return d.newOPTRecordFromRawRR(rdrr), nil
	default:
		return nil, fmt.Errorf("Unhandled RR type: %d", rdrr.static.Type)
	}
}

func (d *Decoder) newARecordFromRawRR(rdrr rawResourceRecord) ARecord {
	a := ARecord{Common: commonFromRawRR(rdrr)}
	a.Addr = net.IP(rdrr.rData[0:4])
	return a
}

func (d *Decoder) newAAAARecordFromRawRR(rdrr rawResourceRecord) AAAARecord {
	a := AAAARecord{Common: commonFromRawRR(rdrr)}
	a.Addr = net.IP(rdrr.rData[0:16])
	return a
}

func (d *Decoder) newSRVRecordFromRawRR(rdrr rawResourceRecord) (SRVRecord, error) {
	s := SRVRecord{Common: commonFromRawRR(rdrr)}
	s.Priority = binary.BigEndian.Uint16(rdrr.rData[0:2])
	s.Weight = binary.BigEndian.Uint16(rdrr.rData[2:4])
	s.Port = binary.BigEndian.Uint16(rdrr.rData[4:6])
	var rlList rawLabels
	var err error
	rdr := bytes.NewReader(rdrr.rData[6:])
	// "target" field starts at byte 6 in the RDATA section; to ensure we
	// store the label record properly (so others can reference it) we have to
	// account for that correctly here
	targetOffsetInMsg := rdrr.rDataOffsetInMsg + 6
	rlList, err = d._nextRawLabelsFromReaderWithBaseOffset(rdr, targetOffsetInMsg)
	if err != nil {
		return s, fmt.Errorf("TypeSRV: _nextRawLabelsFromReaderWithBaseOffset: %s", err)
	}
	s.Target = rlList.toDomain()

	return s, nil
}

func (d *Decoder) newPTRRecordFromRawRR(rdrr rawResourceRecord) (PTRRecord, error) {
	p := PTRRecord{Common: commonFromRawRR(rdrr)}
	var rlList rawLabels
	var err error
	rdr := bytes.NewReader(rdrr.rData)
	rlList, err = d._nextRawLabelsFromReaderWithBaseOffset(rdr, rdrr.rDataOffsetInMsg)
	if err != nil {
		return p, fmt.Errorf("TypePTR: _nextRawLabelsFromReaderWithBaseOffset: %s", err)
	}
	p.PtrDName = rlList.toDomain()
	return p, nil
}

func (d *Decoder) newTXTRecordFromRawRR(rdrr rawResourceRecord) TXTRecord {
	t := TXTRecord{Common: commonFromRawRR(rdrr)}
	r := bytes.NewReader(rdrr.rData)
	for {
		length, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Sprintf("Error calling ReadByte on a bytes.Reader?!: %s", err))
		}
		buf := make([]byte, int(length))
		_, err = r.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Sprintf("Error calling ReadByte on a bytes.Reader?!: %s", err))
		}
		t.texts = append(t.texts, string(buf))
	}
	return t
}

func (d *Decoder) newNSECRecordFromRawRR(rdrr rawResourceRecord) (NSECRecord, error) {
	n := NSECRecord{Common: commonFromRawRR(rdrr)}

	var rlList rawLabels
	var err error
	rdr := bytes.NewReader(rdrr.rData)
	rlList, err = d._nextRawLabelsFromReaderWithBaseOffset(rdr, rdrr.rDataOffsetInMsg)
	if err != nil {
		return n, fmt.Errorf("TypePTR: _nextRawLabelsFromReaderWithBaseOffset: %s", err)
	}
	n.NextDomainName = rlList.toDomain()

StopLoop:
	for {
		b, err := rdr.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Sprintf("Error from bytes.Reader.ReadByte?!: %s", err))
		}
		typeGroup := int(b)

		b, err = rdr.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Sprintf("Error from bytes.Reader.ReadByte?!: %s", err))
		}
		numOctets := int(b)

		for octetNum := 0; octetNum < numOctets; octetNum++ {
			b, err := rdr.ReadByte()
			if err != nil {
				if err == io.EOF {
					break StopLoop
				}
				panic(fmt.Sprintf("Error from bytes.Reader.ReadByte?!: %s", err))
			}
			octet := uint(b)
			var bitNum uint
			for bitNum = 0; bitNum < 8; bitNum++ {
				if (octet<<bitNum)&0x80 == 0x80 {
					typ := RecordType((typeGroup * 256) + (octetNum * 8) + int(bitNum))
					n.NextDomainTypes = append(n.NextDomainTypes, typ)
				}
			}
		}
	}

	sort.Sort(recordTypes(n.NextDomainTypes))

	return n, nil
}

func (d *Decoder) newOPTRecordFromRawRR(rdrr rawResourceRecord) OPTRecord {
	o := OPTRecord{Common: commonFromRawRR(rdrr)}
	o.Options = make(map[uint16][]byte)

	r := bytes.NewReader(rdrr.rData)

	for {
		buf := make([]byte, 2)

		_, err := r.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Sprintf("Error from bytes.Reader.ReadByte?!: %s", err))
		}
		code := binary.BigEndian.Uint16(buf)

		_, err = r.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Sprintf("Error from bytes.Reader.ReadByte?!: %s", err))
		}
		optLen := binary.BigEndian.Uint16(buf)

		buf = make([]byte, optLen)
		_, err = r.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Sprintf("Error from bytes.Reader.ReadByte?!: %s", err))
		}

		o.Options[code] = buf
	}

	return o
}

type labelRecord struct {
	offset       uint16
	length       uint8
	content      string
	isPtr        bool
	targetOffset uint16
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

type rawLabels []rawLabel

func (rlList rawLabels) toDomain() string {
	var labelStrings []string
	for _, rl := range []rawLabel(rlList) {
		labelStrings = append(labelStrings, rl.content)
	}
	return strings.Join(labelStrings, ".")
}

func (rlList rawLabels) toBytes() []byte {
	var ret []byte
	for _, rl := range rlList {
		ret = append(ret, rl.toBytes()...)
	}
	// Append terminating 0-length label
	ret = append(ret, 0x00)
	return ret
}

type domain string

func (d domain) toRawLabels() rawLabels {
	var rlList rawLabels
	for _, s := range strings.Split(string(d), ".") {
		rlList = append(rlList, rawLabel{
			length:  uint8(len(s)),
			content: s,
		})
	}
	return rlList
}
