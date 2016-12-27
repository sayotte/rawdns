package rawmdns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
)

// bufWriteAttempter is used to cut down on boilerplate error-handling in code
// that attempts a bunch of io.Write or binary.Write calls to a single
// bytes.Buffer
type bufWriteAttempter struct {
	buf *bytes.Buffer
	err error
}

func (bwa *bufWriteAttempter) attemptWrite(b []byte) {
	if bwa.err != nil {
		return
	}
	_, bwa.err = bwa.buf.Write(b)
}
func (bwa *bufWriteAttempter) attemptBinaryWrite(order binary.ByteOrder, i interface{}) {
	if bwa.err != nil {
		return
	}
	bwa.err = binary.Write(bwa.buf, order, i)
}
func newBufWriteAttempter() bufWriteAttempter {
	return bufWriteAttempter{
		buf: &bytes.Buffer{},
	}
}

type rawResourceRecord struct {
	domainLabels     rawLabels
	static           rawResourceRecordStatic
	rDataOffsetInMsg int
	rData            []byte
}

func (rrr rawResourceRecord) toBytes() ([]byte, error) {
	b := rrr.domainLabels.toBytes()
	buf := bytes.NewBuffer(b)

	err := binary.Write(buf, binary.BigEndian, rrr.static)
	if err != nil {
		return nil, fmt.Errorf("binary.Write: %s", err)
	}
	return append(buf.Bytes(), rrr.rData...), nil
}

func newRawResourceRecordFromCommon(rrc ResourceRecordCommon) rawResourceRecord {
	var rrr rawResourceRecord
	rrr.static = rawResourceRecordStatic{
		Type:  rrc.Type,
		Class: rrc.Class,
		TTL:   rrc.TTL,
	}
	if rrc.CacheFlush {
		rrr.static.Class |= 0x8000
	}
	rrr.domainLabels = domain(rrc.Domain).toRawLabels()

	return rrr
}

func commonFromRawRR(rdrr rawResourceRecord) ResourceRecordCommon {
	common := ResourceRecordCommon{
		Type:  rdrr.static.Type,
		Class: rdrr.static.Class & 0x7FFF,
		TTL:   rdrr.static.TTL,
	}
	if rdrr.static.Class&0x8000 == 0x8000 {
		common.CacheFlush = true
	}
	common.Domain = rdrr.domainLabels.toDomain()

	return common
}

type rawResourceRecordStatic struct {
	Type        RecordType
	Class       RecordClass
	TTL         uint32
	RDataLength uint16
}

type ResourceRecordCommon struct {
	Domain     string
	Type       RecordType
	Class      RecordClass
	CacheFlush bool
	TTL        uint32
}

type ARecord struct {
	Common ResourceRecordCommon
	Addr   net.IP
}

func (ar ARecord) toRawDNSResourceRecord() (rawResourceRecord, error) {
	rrr := newRawResourceRecordFromCommon(ar.Common)
	rrr.static.RDataLength = 4
	rrr.rData = []byte(ar.Addr.To4())
	return rrr, nil
}

func (ar ARecord) GetCommon() ResourceRecordCommon {
	return ar.Common
}

type AAAARecord struct {
	Common ResourceRecordCommon
	Addr   net.IP
}

func (aaaar AAAARecord) toRawDNSResourceRecord() (rawResourceRecord, error) {
	rrr := newRawResourceRecordFromCommon(aaaar.Common)
	rrr.static.RDataLength = 16
	rrr.rData = []byte(aaaar.Addr.To16())
	return rrr, nil
}

func (aaaar AAAARecord) GetCommon() ResourceRecordCommon {
	return aaaar.Common
}

type SRVRecord struct {
	Common   ResourceRecordCommon
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

func (sr SRVRecord) toRawDNSResourceRecord() (rawResourceRecord, error) {
	rrr := newRawResourceRecordFromCommon(sr.Common)
	bwa := newBufWriteAttempter()
	bwa.attemptBinaryWrite(binary.BigEndian, sr.Priority)
	bwa.attemptBinaryWrite(binary.BigEndian, sr.Weight)
	bwa.attemptBinaryWrite(binary.BigEndian, sr.Port)
	targetBytes := domain(sr.Target).toRawLabels().toBytes()
	bwa.attemptWrite(targetBytes)
	if bwa.err != nil {
		return rrr, fmt.Errorf("bufWriteAttempter.err is %s", bwa.err)
	}

	rrr.static.RDataLength = uint16(bwa.buf.Len())
	rrr.rData = make([]byte, bwa.buf.Len())
	copy(rrr.rData, bwa.buf.Bytes())

	return rrr, nil
}

func (sr SRVRecord) GetCommon() ResourceRecordCommon {
	return sr.Common
}

type PTRRecord struct {
	Common   ResourceRecordCommon
	PtrDName string
}

func (pr PTRRecord) toRawDNSResourceRecord() (rawResourceRecord, error) {
	rrr := newRawResourceRecordFromCommon(pr.Common)
	ptrDNameBytes := domain(pr.PtrDName).toRawLabels().toBytes()
	rrr.static.RDataLength = uint16(len(ptrDNameBytes))
	rrr.rData = make([]byte, rrr.static.RDataLength)
	copy(rrr.rData, ptrDNameBytes)

	return rrr, nil
}

func (pr PTRRecord) GetCommon() ResourceRecordCommon {
	return pr.Common
}

type TXTRecord struct {
	Common ResourceRecordCommon
	texts  []string
}

func (tr TXTRecord) toRawDNSResourceRecord() (rawResourceRecord, error) {
	rrr := newRawResourceRecordFromCommon(tr.Common)

	rDataBuf := newBufWriteAttempter()
	for _, t := range tr.texts {
		rDataBuf.attemptWrite([]byte{uint8(len(t))})
		rDataBuf.attemptWrite([]byte(t))
	}

	rrr.static.RDataLength = uint16(rDataBuf.buf.Len())
	rrr.rData = rDataBuf.buf.Bytes()

	return rrr, rDataBuf.err
}

func (tr TXTRecord) GetCommon() ResourceRecordCommon {
	return tr.Common
}

type NSECRecord struct {
	Common          ResourceRecordCommon
	NextDomainName  string
	NextDomainTypes []RecordType
}

func (nsr NSECRecord) toRawDNSResourceRecord() (rawResourceRecord, error) {
	rrr := newRawResourceRecordFromCommon(nsr.Common)

	////// Fill a buffer with the RDATA section //////
	rDataBuf := newBufWriteAttempter()
	// Write the Next Domain Name field and terminating NULL
	rDataBuf.attemptWrite(domain(nsr.NextDomainName).toRawLabels().toBytes())
	// Write the Type Bit maps field
	nsr._writeBitMap(&rDataBuf)

	if rDataBuf.err != nil {
		return rrr, fmt.Errorf("bytes.Buffer.Write(): %s", rDataBuf.err)
	}

	rrr.static.RDataLength = uint16(rDataBuf.buf.Len())
	rrr.rData = rDataBuf.buf.Bytes()

	return rrr, nil
}
func (nsr NSECRecord) _writeBitMap(rDataBuf *bufWriteAttempter) {
	/* NSEC records' RDATA contains a bitmap of all the types declared as
	present by the NSEC record. The format is described in section 4.1.2
	of the RFC: https://www.ietf.org/rfc/rfc4034.txt .

	The example in section 4.3 of that same RFC is a great explanation; I
	won't waste space repeating it here.

	This implementation could probably be simpler, but it makes sense in
	MY head and it's correct, so it's good enough for now (and likely
	forever, unless someone wants to contribute a better version).
	*/

	// Create a list of all types that will go into the bitmap, precomputing
	// which group, octet, and bit numbers will be used to represent them
	type domainTypeDecl struct {
		group uint8
		octet uint8
		bit   uint8
	}
	var typeDecls []domainTypeDecl
	for _, typ := range nsr.NextDomainTypes {
		typeDecls = append(typeDecls, domainTypeDecl{
			group: uint8(typ / 256),
			octet: uint8((typ % 256) / 8),
			bit:   uint8(typ % 8),
		})
	}

	// Build a representation of the octet-groups and octets in the bitmap
	type octetDecl struct {
		octetNum uint8
		value    uint8
	}
	type groupDecl struct {
		groupNum uint8
		octets   []octetDecl
	}
	var groups []groupDecl
	for len(typeDecls) > 0 {
		// Find the subset of typeDecls in same group as first item, this is a
		// "group"
		first := typeDecls[0]
		typeDecls = typeDecls[1:]
		inGroup := []domainTypeDecl{first}
		for len(typeDecls) > 0 {
			if typeDecls[0].group == first.group {
				inGroup = append(inGroup, typeDecls[0])
				typeDecls = typeDecls[1:]
			} else {
				break
			}
		}
		group := groupDecl{groupNum: first.group}

		// Build list of octets in this group
		for len(inGroup) > 0 {
			// Build a list of domainTypes flagged in the same octet
			inOctet := []domainTypeDecl{inGroup[0]}
			inGroup = inGroup[1:]
			for len(inGroup) > 0 {
				if inGroup[0].octet == inOctet[0].octet {
					inOctet = append(inOctet, inGroup[0])
					inGroup = inGroup[1:]
				} else {
					break
				}
			}
			// Build the octet to represent those domainTypes
			var octetValue uint8
			for _, flag := range inOctet {
				octetValue |= 0x80 >> flag.bit
			}
			group.octets = append(group.octets, octetDecl{
				octetNum: inOctet[0].octet,
				value:    octetValue,
			})
		}

		groups = append(groups, group)
	}

	// Write the groups, with 0-bytes in between them as needed/required,
	// into the buffer provided.
	for _, g := range groups {
		// Write the group number
		rDataBuf.attemptWrite([]byte{g.groupNum})
		// Write the number of octets used to represent this group
		highOctetNum := g.octets[len(g.octets)-1].octetNum + 1
		rDataBuf.attemptWrite([]byte{highOctetNum})
		// Write out the octets representing this group
		var i uint8
		for i = 0; i < highOctetNum; i++ {
			// Is i the index of the next non-zero octet?
			if g.octets[0].octetNum != i {
				// No: write a zero octet
				rDataBuf.attemptWrite([]byte{0x00})
			} else {
				// Yes: write the value of that non-zero octet
				rDataBuf.attemptWrite([]byte{g.octets[0].value})
				// Pop it from the front of the list
				g.octets = g.octets[1:]
			}
		}
	}
}

func (nsr NSECRecord) GetCommon() ResourceRecordCommon {
	return nsr.Common
}

type OPTRecord struct {
	Common  ResourceRecordCommon
	Options map[uint16][]byte
}

func (or OPTRecord) toRawDNSResourceRecord() (rawResourceRecord, error) {
	rrr := newRawResourceRecordFromCommon(or.Common)

	var keys []uint16
	for key, _ := range or.Options {
		keys = append(keys, key)
	}
	sort.Sort(UInt16Slice(keys))
	rDataBuf := newBufWriteAttempter()
	for _, key := range keys {
		rDataBuf.attemptBinaryWrite(binary.BigEndian, key)
		optLen := uint16(len(or.Options[key]))
		rDataBuf.attemptBinaryWrite(binary.BigEndian, optLen)
		rDataBuf.attemptWrite(or.Options[key])
	}

	rrr.static.RDataLength = uint16(rDataBuf.buf.Len())
	rrr.rData = rDataBuf.buf.Bytes()

	return rrr, rDataBuf.err
}

func (or OPTRecord) GetCommon() ResourceRecordCommon {
	return or.Common
}

type DNSResourceRecord interface {
	toRawDNSResourceRecord() (rawResourceRecord, error)
	GetCommon() ResourceRecordCommon
}

type UInt16Slice []uint16

func (us UInt16Slice) Len() int {
	return len(us)
}
func (us UInt16Slice) Less(i, j int) bool {
	return us[i] < us[j]
}
func (us UInt16Slice) Swap(i, j int) {
	us[i], us[j] = us[j], us[i]
}
