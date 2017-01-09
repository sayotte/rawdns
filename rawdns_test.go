package rawmdns

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

var rnd = rand.New(rand.NewSource(time.Now().UnixNano()))

func TestHeaderRoundtrip(t *testing.T) {
	checkFunc := func() bool {
		val, ok := quick.Value(reflect.TypeOf(DNSHeader{}), rnd)
		if !ok {
			t.Fatal("quick.Value returned !ok")
		}
		h := val.Interface().(DNSHeader)

		hb, err := h.toBytes()
		if err != nil {
			t.Fatalf("Unexpected error from h.toBytes: %s", err)
		}
		rdr := bytes.NewReader(hb)

		d := NewDecoder(rdr)
		rawH, err := d.nextRawDNSHeader()
		if err != nil {
			t.Fatalf("Unexpected error from rawDNSHeaderFromBytes: %s", err)
		}

		same, reasons := h.equal(rawH.toDNSHeader())
		if !same {
			t.Error("h != round-tripped h")
			for _, reason := range reasons {
				t.Log(reason)
			}
			t.FailNow()
		}

		return true
	}
	cfg := quick.Config{
		MaxCount: 10000,
		Rand:     rnd,
	}
	quick.Check(checkFunc, &cfg)
}

func (dh DNSHeader) equal(odh equaler) (bool, []string) {
	other := odh.(DNSHeader)
	same := true
	var reasons []string

	if dh.ID != other.ID {
		same = false
		reason := fmt.Sprintf("id: %d != %d", dh.ID, other.ID)
		reasons = append(reasons, reason)
	}
	if dh.IsResponse != other.IsResponse {
		same = false
		reason := fmt.Sprintf("isResponse: %t != %t", dh.IsResponse, other.IsResponse)
		reasons = append(reasons, reason)
	}
	if dh.OpCode != other.OpCode {
		same = false
		reason := fmt.Sprintf("opCode: %d != %d", dh.OpCode, other.OpCode)
		reasons = append(reasons, reason)
	}
	if dh.Authoritative != other.Authoritative {
		same = false
		reason := fmt.Sprintf("authoritative: %t != %t", dh.Authoritative, other.Authoritative)
		reasons = append(reasons, reason)
	}
	if dh.Truncated != other.Truncated {
		same = false
		reason := fmt.Sprintf("truncated: %t != %t", dh.Truncated, other.Truncated)
		reasons = append(reasons, reason)
	}
	if dh.RecursionDesired != other.RecursionDesired {
		same = false
		reason := fmt.Sprintf("recursionDesired: %t != %t", dh.RecursionDesired, other.RecursionDesired)
		reasons = append(reasons, reason)
	}
	if dh.RecursionAvailable != other.RecursionAvailable {
		same = false
		reason := fmt.Sprintf("recursionAvailable: %t != %t", dh.RecursionAvailable, other.RecursionAvailable)
		reasons = append(reasons, reason)
	}
	if dh.ResponseCode != other.ResponseCode {
		same = false
		reason := fmt.Sprintf("responseCode: %d != %d", dh.ResponseCode, other.ResponseCode)
		reasons = append(reasons, reason)
	}
	if dh.NumQuestions != other.NumQuestions {
		same = false
		reason := fmt.Sprintf("numQuestions: %d != %d", dh.NumQuestions, other.NumQuestions)
		reasons = append(reasons, reason)
	}
	if dh.NumAnswers != other.NumAnswers {
		same = false
		reason := fmt.Sprintf("numAnswers: %d != %d", dh.NumAnswers, other.NumAnswers)
		reasons = append(reasons, reason)
	}
	if dh.NumNameServers != other.NumNameServers {
		same = false
		reason := fmt.Sprintf("numNameServers: %d != %d", dh.NumNameServers, other.NumNameServers)
		reasons = append(reasons, reason)
	}
	if dh.NumAddlRecords != other.NumAddlRecords {
		same = false
		reason := fmt.Sprintf("numAddlRecords: %d != %d", dh.NumAddlRecords, other.NumAddlRecords)
		reasons = append(reasons, reason)
	}

	return same, reasons
}

func (typ DNSHeader) Generate(rand *rand.Rand, size int) reflect.Value {
	dh := DNSHeader{}

	var typUint uint
	var typUint16 uint16
	var typBool bool

	val, _ := quick.Value(reflect.TypeOf(typUint16), rand)
	dh.ID = val.Interface().(uint16)
	val, _ = quick.Value(reflect.TypeOf(typBool), rand)
	dh.IsResponse = val.Bool()

	val, _ = quick.Value(reflect.TypeOf(typUint), rand)
	dh.OpCode = OpCode(val.Interface().(uint) & 0xF)

	val, _ = quick.Value(reflect.TypeOf(typBool), rand)
	dh.Authoritative = val.Bool()
	val, _ = quick.Value(reflect.TypeOf(typBool), rand)
	dh.Truncated = val.Bool()
	val, _ = quick.Value(reflect.TypeOf(typBool), rand)
	dh.RecursionDesired = val.Bool()
	val, _ = quick.Value(reflect.TypeOf(typBool), rand)
	dh.RecursionAvailable = val.Bool()

	val, _ = quick.Value(reflect.TypeOf(typUint), rand)
	dh.ResponseCode = ResponseCode(val.Interface().(uint) & 0xF)

	val, _ = quick.Value(reflect.TypeOf(typUint16), rand)
	dh.NumQuestions = val.Interface().(uint16)
	val, _ = quick.Value(reflect.TypeOf(typUint16), rand)
	dh.NumAnswers = val.Interface().(uint16)
	val, _ = quick.Value(reflect.TypeOf(typUint16), rand)
	dh.NumNameServers = val.Interface().(uint16)
	val, _ = quick.Value(reflect.TypeOf(typUint16), rand)
	dh.NumAddlRecords = val.Interface().(uint16)

	return reflect.ValueOf(dh)
}

func TestDecoder_DecodeDNSMessage(t *testing.T) {
	expected := DNSMessage{
		Answers: []DNSResourceRecord{
			PTRRecord{
				Common: ResourceRecordCommon{
					Domain:     "4.5.9.10.in-addr.arpa",
					Type:       TypePTR,
					Class:      ClassINET,
					CacheFlush: true,
					TTL:        120,
				},
				PtrDName: "10-9-5-4.local",
			},
			TXTRecord{
				Common: ResourceRecordCommon{
					Domain:     "7475482BF2C9@AFTB-4._raop._tcp.local",
					Type:       TypeTXT,
					Class:      ClassINET,
					CacheFlush: true,
					TTL:        4500,
				},
				texts: []string{
					"pk=339060cd47b8d71a8d1b09263a42ab7feb44d85252c928a4bf0c9c74cc263e64",
					"ss=16",
					"sr=44100",
					"cn=0,1,2,3",
					"da=true",
					"rmodel=AirReceiver3,1",
					"et=0,3,5",
					"ch=2",
					"sf=0x4",
					"vn=65537",
					"am=AppleTV3,1",
					"sv=false",
					"md=0,1,2",
					"ft=0x527FFEF7",
					"txtvers=1",
					"pw=false",
					"vs=211.3",
					"tp=UDP",
					"sm=false"},
			},
			PTRRecord{
				Common: ResourceRecordCommon{
					Domain:     "_services._dns-sd._udp.local",
					Type:       TypePTR,
					Class:      ClassINET,
					CacheFlush: false,
					TTL:        4500,
				},
				PtrDName: "_raop._tcp.local",
			},
			PTRRecord{
				Common: ResourceRecordCommon{
					Domain:     "_raop._tcp.local",
					Type:       TypePTR,
					Class:      ClassINET,
					CacheFlush: false,
					TTL:        4500,
				},
				PtrDName: "7475482BF2C9@AFTB-4._raop._tcp.local",
			},
			TXTRecord{
				Common: ResourceRecordCommon{
					Domain:     "AFTB-4._airplay._tcp.local",
					Type:       TypeTXT,
					Class:      ClassINET,
					CacheFlush: true,
					TTL:        4500,
				},
				texts: []string{
					"pk=339060cd47b8d71a8d1b09263a42ab7feb44d85252c928a4bf0c9c74cc263e64",
					"srcvers=211.3",
					"rmodel=AirReceiver3,1",
					"features=0x527FFEF7",
					"flags=0x4",
					"pw=0",
					"deviceid=74:75:48:2B:F2:C9",
					"model=AppleTV3,1",
				},
			},
			PTRRecord{
				Common: ResourceRecordCommon{
					Domain:     "_services._dns-sd._udp.local",
					Type:       TypePTR,
					Class:      ClassINET,
					CacheFlush: false,
					TTL:        4500,
				},
				PtrDName: "_airplay._tcp.local",
			},
			PTRRecord{
				Common: ResourceRecordCommon{
					Domain:     "_airplay._tcp.local",
					Type:       TypePTR,
					Class:      ClassINET,
					CacheFlush: false,
					TTL:        4500,
				},
				PtrDName: "AFTB-4._airplay._tcp.local",
			},
			ARecord{
				Common: ResourceRecordCommon{
					Domain:     "10-9-5-4.local",
					Type:       TypeA,
					Class:      ClassINET,
					CacheFlush: true,
					TTL:        120,
				},
				Addr: net.IP([]byte{10, 9, 5, 4}),
			},
			SRVRecord{
				Common: ResourceRecordCommon{
					Domain:     "7475482BF2C9@AFTB-4._raop._tcp.local",
					Type:       TypeSRV,
					Class:      ClassINET,
					CacheFlush: true,
					TTL:        120,
				},
				Priority: 0,
				Weight:   0,
				Port:     5000,
				Target:   "10-9-5-4.local",
			},
			SRVRecord{
				Common: ResourceRecordCommon{
					Domain:     "AFTB-4._airplay._tcp.local",
					Type:       TypeSRV,
					Class:      ClassINET,
					CacheFlush: true,
					TTL:        120,
				},
				Priority: 0,
				Weight:   0,
				Port:     7000,
				Target:   "10-9-5-4.local",
			},
		},
		Additional: []DNSResourceRecord{
			NSECRecord{
				Common: ResourceRecordCommon{
					Domain:     "4.5.9.10.in-addr.arpa",
					Type:       TypeNSEC,
					Class:      ClassINET,
					CacheFlush: true,
					TTL:        120,
				},
				NextDomainName:  "4.5.9.10.in-addr.arpa",
				NextDomainTypes: []RecordType{TypePTR},
			},
			NSECRecord{
				Common: ResourceRecordCommon{
					Domain:     "7475482BF2C9@AFTB-4._raop._tcp.local",
					Type:       TypeNSEC,
					Class:      ClassINET,
					CacheFlush: true,
					TTL:        4500,
				},
				NextDomainName:  "7475482BF2C9@AFTB-4._raop._tcp.local",
				NextDomainTypes: []RecordType{TypeTXT, TypeSRV},
			},
			NSECRecord{
				Common: ResourceRecordCommon{
					Domain:     "AFTB-4._airplay._tcp.local",
					Type:       TypeNSEC,
					Class:      ClassINET,
					CacheFlush: true,
					TTL:        4500,
				},
				NextDomainName:  "AFTB-4._airplay._tcp.local",
				NextDomainTypes: []RecordType{TypeTXT, TypeSRV},
			},
			NSECRecord{
				Common: ResourceRecordCommon{
					Domain:     "10-9-5-4.local",
					Type:       TypeNSEC,
					Class:      ClassINET,
					CacheFlush: true,
					TTL:        120,
				},
				NextDomainName:  "10-9-5-4.local",
				NextDomainTypes: []RecordType{TypeA},
			},
			OPTRecord{
				Common: ResourceRecordCommon{
					Domain:     "",
					Type:       TypeOPT,
					Class:      1440,
					CacheFlush: false,
					TTL:        4500,
				},
				Options: map[uint16][]uint8{
					4: []uint8{
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x70, 0x31, 0xfe, 0xb7, 0x00, 0x00},
				},
			},
		},
	}

	// contents of this file were pulled from a packet cap, so we know they're
	// correct at least in some other implementation's mind (Wireshark agrees)
	fd, err := os.Open("testdata/airplay-answer.cap")
	if err != nil {
		t.Fatalf("os.Open() error: %s\n", err)
	}
	defer fd.Close()

	b, err := ioutil.ReadAll(fd)
	if err != nil {
		t.Fatalf("ioutil.ReadAll() error: %s\n", err)
	}

	rdr := bytes.NewReader(b)
	d := NewDecoder(rdr)
	dm, err := d.DecodeDNSMessage()
	if err != nil {
		if err != io.EOF {
			t.Fatalf("Unexpected error from Decoder.DecodeDNSMessage: %s\n", err)
		}
	}

	if len(dm.Answers) != len(expected.Answers) {
		t.Fatalf("len(dm.Answers) is %d, expected %d", len(dm.Answers), len(expected.Answers))
	}
	for i, answer := range dm.Answers {
		answerEq := answer.(equaler)
		expectedEq := expected.Answers[i].(equaler)
		same, reasons := answerEq.equal(expectedEq)
		if !same {
			t.Errorf("Answers[%d]:", i)
			for _, reason := range reasons {
				t.Log(reason)
			}
		}
	}
	if len(dm.Additional) != len(expected.Additional) {
		t.Fatalf("len(dm.Additional) is %d, expected %d", len(dm.Additional), len(expected.Additional))
	}
	for i, addl := range dm.Additional {
		addlEq := addl.(equaler)
		expectedEq := expected.Additional[i].(equaler)
		same, reasons := addlEq.equal(expectedEq)
		if !same {
			t.Errorf("Additional[%d]:", i)
			for _, reason := range reasons {
				t.Log(reason)
			}
		}
	}
}

func TestQuestionRoundtrip(t *testing.T) {
	checkFunc := func() bool {
		val, ok := quick.Value(reflect.TypeOf(DNSQuestion{}), rnd)
		if !ok {
			t.Fatal("quick.Value returned !ok")
		}
		dq := val.Interface().(DNSQuestion)

		dqb, err := dq.toBytes()
		if err != nil {
			t.Fatalf("Unexpected error from dq.toBytes: %s", err)
		}
		rdr := bytes.NewReader(dqb)

		d := NewDecoder(rdr)
		rawDq, err := d.nextRawQuestion()
		if err != nil {
			t.Fatalf("Unexpected error from rawQuestionFromBytes: %s", err)
		}
		dqrt := rawDq.toQuestion()

		same, reasons := dq.equal(dqrt)
		if !same {
			t.Error("dq != dqrt")
			for _, reason := range reasons {
				t.Log(reason)
			}
			t.FailNow()
		}

		return true
	}
	cfg := quick.Config{
		MaxCount: 10000,
		Rand:     rnd,
	}
	quick.Check(checkFunc, &cfg)
}

func (dq DNSQuestion) equal(odq equaler) (bool, []string) {
	other := odq.(DNSQuestion)
	same := true
	var reasons []string
	if dq.Domain != other.Domain {
		same = false
		reasons = []string{fmt.Sprintf("domain: %q != %q", dq.Domain, other.Domain)}
	}
	if dq.Type != other.Type {
		same = false
		reason := fmt.Sprintf("typ: %d != %d", dq.Type, other.Type)
		reasons = append(reasons, reason)
	}
	if dq.Class != other.Class {
		same = false
		reason := fmt.Sprintf("class: %d != %d", dq.Class, other.Class)
		reasons = append(reasons, reason)
	}
	if dq.AcceptUnicastResponse != other.AcceptUnicastResponse {
		same = false
		reason := fmt.Sprintf("acceptUnicastResponse: %t != %t", dq.AcceptUnicastResponse, other.AcceptUnicastResponse)
		reasons = append(reasons, reason)
	}

	return same, reasons
}

func (typ DNSQuestion) Generate(rand *rand.Rand, size int) reflect.Value {
	var dq DNSQuestion
	var labels []string

	var nameLen int
	for nameLen < 255 {
		var labelLen int
		if 255-nameLen < 64 {
			labelLen = 255 - nameLen - 1
		} else {
			labelLen = rand.Intn(64)
		}
		if labelLen == 0 {
			labelLen = 1
		}
		labels = append(labels, randString(labelLen))
		nameLen += labelLen + 1
	}
	dq.Domain = strings.Join(labels, ".")

	var val reflect.Value
	var ok bool
	val, ok = quick.Value(reflect.TypeOf(dq.Type), rand)
	if !ok {
		panic("quick.Value(reflect.TypeOf(dq.typ)")
	}
	dq.Type = val.Interface().(RecordType)

	val, ok = quick.Value(reflect.TypeOf(dq.Class), rand)
	if !ok {
		panic("quick.Value(reflect.TypeOf(dq.class)")
	}
	dq.Class = val.Interface().(RecordClass) & 0x7FFF

	val, ok = quick.Value(reflect.TypeOf(dq.AcceptUnicastResponse), rand)
	if !ok {
		panic("quick.Value(reflect.TypeOf(dq.acceptUnicastResponse)")
	}
	dq.AcceptUnicastResponse = val.Bool()

	return reflect.ValueOf(dq)
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Int63()%int64(len(letters))]
	}
	return string(b)
}

//func TestBullshit(t *testing.T) {
//	fd, err := os.Open("testdata/addl-records-2.bin")
//	if err != nil {
//		t.Fatalf("os.Open() error: %s\n", err)
//	}
//	defer fd.Close()
//
//	b, err := ioutil.ReadAll(fd)
//	if err != nil {
//		t.Fatalf("ioutil.ReadAll() error: %s\n", err)
//	}
//
//	rdr := bytes.NewReader(b)
//	d := NewDecoder(rdr)
//	dm, err := d.DecodeDNSMessage()
//	spew.Dump(dm)
//	t.Fail()
//}
