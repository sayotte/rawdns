package rawmdns

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"net"
)

////// Below cut/pasted from RFC 4034 section 4.3: //////
// alfa.example.com. 86400 IN NSEC host.example.com. ( A MX RRSIG NSEC TYPE1234 )
//
// The first four text fields specify the name, TTL, Class, and RR type
// (NSEC).  The entry host.example.com. is the next authoritative name
// after alfa.example.com. in canonical order.  The A, MX, RRSIG, NSEC,
// and TYPE1234 mnemonics indicate that there are A, MX, RRSIG, NSEC,
// and TYPE1234 RRsets associated with the name alfa.example.com.
//
// The RDATA section of the NSEC RR above would be encoded as:
//
// 0x04 'h'  'o'  's'  't'
// 0x07 'e'  'x'  'a'  'm'  'p'  'l'  'e'
// 0x03 'c'  'o'  'm'  0x00
// 0x00 0x06 0x40 0x01 0x00 0x00 0x00 0x03
// 0x04 0x1b 0x00 0x00 0x00 0x00 0x00 0x00
// 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
// 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
// 0x00 0x00 0x00 0x00 0x20
func TestNSECRecord_toRawDNSResourceRecord(t *testing.T) {
	expectedRData := []byte{
		0x04, 'h', 'o', 's', 't',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03,
		0x04, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20,
	}

	nsr := NSECRecord{
		Common: ResourceRecordCommon{
			Domain:     "alfa.example.com",
			Type:       TypeNSEC,
			Class:      ClassINET,
			CacheFlush: false,
			TTL:        86400,
		},
		NextDomainName:  "host.example.com",
		NextDomainTypes: []RecordType{TypeA, TypeMX, TypeRRSIG, TypeNSEC, 1234},
	}

	rdrr, err := nsr.toRawDNSResourceRecord()
	if err != nil {
		t.Errorf("Unexpected error from toRawDNSResourceRecord: %s", err)
	}
	if !bytes.Equal(expectedRData, rdrr.rData) {
		t.Error("expectedRData != rdrr.rData")
	}
}

func TestOPTRecord_toRawDNSResourceRecord(t *testing.T) {
	/* This expected data was pulled from a packet cap. The only parts we're
	actually interested are the leading 4 bytes: the code and the length.
	The rest is left in here because it might somehow be interesting, but
	the code doesn't actually understand it.
	*/
	expectedRData := []byte{
		0x00, 0x04, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x70, 0x31, 0xfe, 0xb7,
		0x00, 0x00,
	}

	or := OPTRecord{
		Common: ResourceRecordCommon{
			Domain:     "",
			Type:       TypeOPT,
			Class:      ClassINET,
			CacheFlush: true,
		},
		Options: map[uint16][]uint8{
			4: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x70, 0x31, 0xfe, 0xb7, 0x00, 0x00},
		},
	}

	rdrr, err := or.toRawDNSResourceRecord()
	if err != nil {
		t.Errorf("Unexpected error from toRawDNSResourceRecord: %s", err)
	}
	if !bytes.Equal(expectedRData, rdrr.rData) {
		t.Error("expectedRData != rdrr.rData")
	}
}

func TestTXTRecord_toRawDNSResourceRecord(t *testing.T) {
	expectedRData := []byte{
		0x03, 0x30, 0x3d, 0x31, 0x03, 0x61, 0x3d, 0x62,
	}
	tr := TXTRecord{
		texts: []string{
			"0=1",
			"a=b",
		},
	}
	rdrr, err := tr.toRawDNSResourceRecord()
	if err != nil {
		t.Errorf("Unexpected error from toRawDNSResourceRecord: %s", err)
	}
	if !bytes.Equal(expectedRData, rdrr.rData) {
		t.Error("expectedRData != rdrr.rData")
	}
}

func TestARecord_roundtrip(t *testing.T) {
	a := ARecord{
		Common: ResourceRecordCommon{
			Domain: "foo.bar",
			Type: TypeA,
			Class: ClassINET,
			CacheFlush: true,
			TTL: 120,
		},
		Addr: net.ParseIP("1.2.3.4"),
	}
	dm := DNSMessage{
		Hdr: DNSHeader{
			NumAnswers: 1,
		},
		Answers: []DNSResourceRecord{
			a,
		},
	}

	b, err := dm.ToBytes()
	if err != nil {
		t.Fatalf("Unexpected error from dm.ToBytes: %s", err)
	}

	decoder := NewDecoder(bytes.NewReader(b))
	dm2,err := decoder.DecodeDNSMessage()
	if err != nil {
		t.Fatalf("Unexpected error from DecodeDNSMessage: %s", err)
	}
	a2 := dm2.Answers[0].(ARecord)
	same, reasons := a.equal(a2)
	if !same {
		t.Error("Before/after not the same:")
		for _,reason := range reasons {
			t.Log(reason)
		}
	}
}

func TestAAAARecord_roundtrip(t *testing.T) {
	a := AAAARecord{
		Common: ResourceRecordCommon{
			Domain: "foo.bar",
			Type: TypeAAAA,
			Class: ClassINET,
			CacheFlush: true,
			TTL: 120,
		},
		Addr: net.ParseIP("2600::1"),
	}
	dm := DNSMessage{
		Hdr: DNSHeader{
			NumAnswers: 1,
		},
		Answers: []DNSResourceRecord{
			a,
		},
	}

	b, err := dm.ToBytes()
	if err != nil {
		t.Fatalf("Unexpected error from dm.ToBytes: %s", err)
	}

	decoder := NewDecoder(bytes.NewReader(b))
	dm2,err := decoder.DecodeDNSMessage()
	if err != nil {
		t.Fatalf("Unexpected error from DecodeDNSMessage: %s", err)
	}
	a2 := dm2.Answers[0].(AAAARecord)
	same, reasons := a.equal(a2)
	if !same {
		t.Error("Before/after not the same:")
		for _,reason := range reasons {
			t.Log(reason)
		}
	}
}

func TestSRVRecord_roundtrip(t *testing.T) {
	s := SRVRecord{
		Common: ResourceRecordCommon{
			Domain: "_kerberos._udp.foo.bar",
			Type: TypeSRV,
			Class: ClassINET,
			CacheFlush: true,
			TTL: 120,
		},
		Priority: 9,
		Weight: 0x70,
		Port: 88,
		Target: "kdc.foo.bar",
	}
	dm := DNSMessage{
		Hdr: DNSHeader{
			NumAnswers: 1,
		},
		Answers: []DNSResourceRecord{
			s,
		},
	}

	b, err := dm.ToBytes()
	if err != nil {
		t.Fatalf("Unexpected error from dm.ToBytes: %s", err)
	}

	decoder := NewDecoder(bytes.NewReader(b))
	dm2,err := decoder.DecodeDNSMessage()
	if err != nil {
		t.Fatalf("Unexpected error from DecodeDNSMessage: %s", err)
	}
	s2 := dm2.Answers[0].(SRVRecord)
	same, reasons := s.equal(s2)
	if !same {
		t.Error("Before/after not the same:")
		for _,reason := range reasons {
			t.Log(reason)
		}
	}
}

func TestPTRRecord_roundtrip(t *testing.T) {
	p := PTRRecord{
		Common: ResourceRecordCommon{
			Domain: "_airplay._tcp.local",
			Type: TypePTR,
			Class: ClassINET,
			CacheFlush: true,
			TTL: 120,
		},
		PtrDName: "display._airplay._tcp.local",
	}
	dm := DNSMessage{
		Hdr: DNSHeader{
			NumAnswers: 1,
		},
		Answers: []DNSResourceRecord{
			p,
		},
	}

	b, err := dm.ToBytes()
	if err != nil {
		t.Fatalf("Unexpected error from dm.ToBytes: %s", err)
	}

	decoder := NewDecoder(bytes.NewReader(b))
	dm2,err := decoder.DecodeDNSMessage()
	if err != nil {
		t.Fatalf("Unexpected error from DecodeDNSMessage: %s", err)
	}
	p2 := dm2.Answers[0].(PTRRecord)
	same, reasons := p.equal(p2)
	if !same {
		t.Error("Before/after not the same:")
		for _,reason := range reasons {
			t.Log(reason)
		}
	}
}

func TestTXTRecord_roundtrip(t *testing.T) {
	tr := TXTRecord{
		Common: ResourceRecordCommon{
			Domain: "display._airplay._tcp.local",
			Type: TypeTXT,
			Class: ClassINET,
			CacheFlush: true,
			TTL: 120,
		},
		texts: []string{"deviceid=00:11:22:33:44:55"},
	}
	dm := DNSMessage{
		Hdr: DNSHeader{
			NumAnswers: 1,
		},
		Answers: []DNSResourceRecord{
			tr,
		},
	}

	b, err := dm.ToBytes()
	if err != nil {
		t.Fatalf("Unexpected error from dm.ToBytes: %s", err)
	}

	decoder := NewDecoder(bytes.NewReader(b))
	dm2,err := decoder.DecodeDNSMessage()
	if err != nil {
		t.Fatalf("Unexpected error from DecodeDNSMessage: %s", err)
	}
	tr2 := dm2.Answers[0].(TXTRecord)
	same, reasons := tr.equal(tr2)
	if !same {
		t.Error("Before/after not the same:")
		for _,reason := range reasons {
			t.Log(reason)
		}
	}
}

func TestNSECRecord_roundtrip(t *testing.T) {
	n := NSECRecord{
		Common: ResourceRecordCommon{
			Domain: "_airplay._tcp.local",
			Type: TypeNSEC,
			Class: ClassINET,
			CacheFlush: true,
			TTL: 120,
		},
		NextDomainName: "_airplay._tcp.local",
		NextDomainTypes: []RecordType{TypePTR, TypeSRV},
	}
	dm := DNSMessage{
		Hdr: DNSHeader{
			NumAnswers: 1,
		},
		Answers: []DNSResourceRecord{
			n,
		},
	}

	b, err := dm.ToBytes()
	if err != nil {
		t.Fatalf("Unexpected error from dm.ToBytes: %s", err)
	}

	decoder := NewDecoder(bytes.NewReader(b))
	dm2,err := decoder.DecodeDNSMessage()
	if err != nil {
		t.Fatalf("Unexpected error from DecodeDNSMessage: %s", err)
	}
	n2 := dm2.Answers[0].(NSECRecord)
	same, reasons := n.equal(n2)
	if !same {
		t.Error("Before/after not the same:")
		for _,reason := range reasons {
			t.Log(reason)
		}
	}
}

type equaler interface {
	equal(other equaler) (bool, []string)
}

func (rrc ResourceRecordCommon) equal(orrc equaler) (bool, []string) {
	other := orrc.(ResourceRecordCommon)
	same := true
	var reasons []string
	if rrc.Domain != other.Domain {
		same = false
		reason := fmt.Sprintf("Domain: %q != %q", rrc.Domain, other.Domain)
		reasons = append(reasons, reason)
	}
	if rrc.Type != other.Type {
		same = false
		reason := fmt.Sprintf("Type: %d != %d", rrc.Type, other.Type)
		reasons = append(reasons, reason)
	}
	if rrc.Class != other.Class {
		same = false
		reason := fmt.Sprintf("Class: %d != %d", rrc.Class, other.Class)
		reasons = append(reasons, reason)
	}
	if rrc.CacheFlush != other.CacheFlush {
		same = false
		reason := fmt.Sprintf("CacheFlush: %t != %t", rrc.CacheFlush, other.CacheFlush)
		reasons = append(reasons, reason)
	}
	if rrc.TTL != other.TTL {
		same = false
		reason := fmt.Sprintf("TTL: %d != %d", rrc.TTL, other.TTL)
		reasons = append(reasons, reason)
	}
	return same, reasons
}

func (ar ARecord) equal(oar equaler) (bool, []string) {
	other := oar.(ARecord)
	same, reasons := ar.Common.equal(other.Common)
	if !ar.Addr.Equal(other.Addr) {
		same = false
		reason := fmt.Sprintf("Addr: %v != %v", []byte(ar.Addr), []byte(other.Addr))
		reasons = append(reasons, reason)
	}
	return same, reasons
}

func (aaaar AAAARecord) equal(oaaaar equaler) (bool, []string) {
	other := oaaaar.(AAAARecord)
	same, reasons := aaaar.Common.equal(other.Common)
	if !aaaar.Addr.Equal(other.Addr) {
		same = false
		reason := fmt.Sprintf("Addr: %s != %s", aaaar.Addr, other.Addr)
		reasons = append(reasons, reason)
	}
	return same, reasons
}

func (sr SRVRecord) equal(osr equaler) (bool, []string) {
	other := osr.(SRVRecord)
	same, reasons := sr.Common.equal(other.Common)
	if sr.Priority != other.Priority {
		same = false
		reason := fmt.Sprintf("Priority: %d != %d", sr.Priority, other.Priority)
		reasons = append(reasons, reason)
	}
	if sr.Weight != other.Weight {
		same = false
		reason := fmt.Sprintf("Weight: %d != %d", sr.Weight, other.Weight)
		reasons = append(reasons, reason)
	}
	if sr.Port != other.Port {
		same = false
		reason := fmt.Sprintf("Port: %d != %d", sr.Port, other.Port)
		reasons = append(reasons, reason)
	}
	if sr.Target != other.Target {
		same = false
		reason := fmt.Sprintf("Target: %q != %q", sr.Target, other.Target)
		reasons = append(reasons, reason)
	}
	return same, reasons
}

func (pr PTRRecord) equal(opr equaler) (bool, []string) {
	other := opr.(PTRRecord)
	same, reasons := pr.Common.equal(other.Common)
	if pr.PtrDName != other.PtrDName {
		same = false
		reason := fmt.Sprintf("PtrDName: %q != %q", pr.PtrDName, other.PtrDName)
		reasons = append(reasons, reason)
	}
	return same, reasons
}

func (tr TXTRecord) equal(otr equaler) (bool, []string) {
	other := otr.(TXTRecord)
	same, reasons := tr.Common.equal(other.Common)
	if len(tr.texts) != len(other.texts) {
		same = false
		reason := fmt.Sprintf("len(tr.texts): %d != %d", len(tr.texts), len(other.texts))
		reasons = append(reasons, reason)
		return same, reasons
	}
	for i, text := range tr.texts {
		if text != other.texts[i] {
			same = false
			reason := fmt.Sprintf("texts[i]: %s != %s", text, other.texts[i])
			reasons = append(reasons, reason)
		}
	}
	return same, reasons
}

func (nsr NSECRecord) equal(onsr equaler) (bool, []string) {
	other := onsr.(NSECRecord)
	same, reasons := nsr.Common.equal(other.Common)
	if nsr.NextDomainName != other.NextDomainName {
		same = false
		reason := fmt.Sprintf("NextDomainName: %q != %q", nsr.NextDomainName, other.NextDomainName)
		reasons = append(reasons, reason)
	}
	if !reflect.DeepEqual(nsr.NextDomainTypes, other.NextDomainTypes) {
		same = false
		reason := fmt.Sprintf("NextDomainTypes: %v != %v", nsr.NextDomainTypes, other.NextDomainTypes)
		reasons = append(reasons, reason)
	}
	return same, reasons
}

func (or OPTRecord) equal(oor equaler) (bool, []string) {
	other := oor.(OPTRecord)
	same, reasons := or.Common.equal(other.Common)
	if !reflect.DeepEqual(or.Options, other.Options) {
		same = false
		reason := fmt.Sprintf("Options: %v != %v", or.Options, other.Options)
		reasons = append(reasons, reason)
	}
	return same, reasons
}
