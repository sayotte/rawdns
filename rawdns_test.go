package rawdns

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

var rnd = rand.New(rand.NewSource(time.Now().UnixNano()))

func TestDNSMessage_roundtrip(t *testing.T) {
	// Source from file
	fd, err := os.Open("testdata/airplay-question.cap")
	if err != nil {
		t.Fatalf("os.Open() error: %s\n", err)
	}
	defer fd.Close()

	b, err := ioutil.ReadAll(fd)
	if err != nil {
		t.Fatalf("ioutil.ReadAll() error: %s\n", err)
	}

	rdr := bytes.NewReader(b)
	dm, err := DNSMessageFromBytes(rdr)
	if err != nil {
		t.Errorf("Unexpected error from DNSMessageFromBytes: %s\n", err)
	}

	// Back to []byte
	b, err = dm.ToBytes()
	if err != nil {
		t.Errorf("Unexpected error from dm.ToBytes: %s\n", err)
	}

	// Back to memory
	rdr = bytes.NewReader(b)
	dm, err = DNSMessageFromBytes(rdr)
	if err != nil {
		t.Errorf("Unexpected error from DNSMessageFromBytes(2): %s\n", err)
	}
}

func TestHeader_roundtrip(t *testing.T) {
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

		rawH, err := rawDNSHeaderFromBytes(rdr)
		if err != nil {
			t.Fatalf("Unexpected error from rawDNSHeaderFromBytes: %s", err)
		}

		same, reasons := h.equals(rawH.toDNSHeader())
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

func (dh DNSHeader) equals(other DNSHeader) (bool, []string) {
	same := true
	var reasons []string

	if dh.id != other.id {
		same = false
		reason := fmt.Sprintf("id: %d != %d", dh.id, other.id)
		reasons = append(reasons, reason)
	}
	if dh.isResponse != other.isResponse {
		same = false
		reason := fmt.Sprintf("isResponse: %t != %t", dh.isResponse, other.isResponse)
		reasons = append(reasons, reason)
	}
	if dh.opCode != other.opCode {
		same = false
		reason := fmt.Sprintf("opCode: %d != %d", dh.opCode, other.opCode)
		reasons = append(reasons, reason)
	}
	if dh.authoritative != other.authoritative {
		same = false
		reason := fmt.Sprintf("authoritative: %t != %t", dh.authoritative, other.authoritative)
		reasons = append(reasons, reason)
	}
	if dh.truncated != other.truncated {
		same = false
		reason := fmt.Sprintf("truncated: %t != %t", dh.truncated, other.truncated)
		reasons = append(reasons, reason)
	}
	if dh.recursionDesired != other.recursionDesired {
		same = false
		reason := fmt.Sprintf("recursionDesired: %t != %t", dh.recursionDesired, other.recursionDesired)
		reasons = append(reasons, reason)
	}
	if dh.recursionAvailable != other.recursionAvailable {
		same = false
		reason := fmt.Sprintf("recursionAvailable: %t != %t", dh.recursionAvailable, other.recursionAvailable)
		reasons = append(reasons, reason)
	}
	if dh.responseCode != other.responseCode {
		same = false
		reason := fmt.Sprintf("responseCode: %d != %d", dh.responseCode, other.responseCode)
		reasons = append(reasons, reason)
	}
	if dh.numQuestions != other.numQuestions {
		same = false
		reason := fmt.Sprintf("numQuestions: %d != %d", dh.numQuestions, other.numQuestions)
		reasons = append(reasons, reason)
	}
	if dh.numAnswers != other.numAnswers {
		same = false
		reason := fmt.Sprintf("numAnswers: %d != %d", dh.numAnswers, other.numAnswers)
		reasons = append(reasons, reason)
	}
	if dh.numNameServers != other.numNameServers {
		same = false
		reason := fmt.Sprintf("numNameServers: %d != %d", dh.numNameServers, other.numNameServers)
		reasons = append(reasons, reason)
	}
	if dh.numAddlRecords != other.numAddlRecords {
		same = false
		reason := fmt.Sprintf("numAddlRecords: %d != %d", dh.numAddlRecords, other.numAddlRecords)
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
	dh.id = val.Interface().(uint16)
	val, _ = quick.Value(reflect.TypeOf(typBool), rand)
	dh.isResponse = val.Bool()

	val, _ = quick.Value(reflect.TypeOf(typUint), rand)
	dh.opCode = uint(val.Interface().(uint) & 0xF)

	val, _ = quick.Value(reflect.TypeOf(typBool), rand)
	dh.authoritative = val.Bool()
	val, _ = quick.Value(reflect.TypeOf(typBool), rand)
	dh.truncated = val.Bool()
	val, _ = quick.Value(reflect.TypeOf(typBool), rand)
	dh.recursionDesired = val.Bool()
	val, _ = quick.Value(reflect.TypeOf(typBool), rand)
	dh.recursionAvailable = val.Bool()

	val, _ = quick.Value(reflect.TypeOf(typUint), rand)
	dh.responseCode = uint(val.Interface().(uint) & 0xF)

	val, _ = quick.Value(reflect.TypeOf(typUint16), rand)
	dh.numQuestions = val.Interface().(uint16)
	val, _ = quick.Value(reflect.TypeOf(typUint16), rand)
	dh.numAnswers = val.Interface().(uint16)
	val, _ = quick.Value(reflect.TypeOf(typUint16), rand)
	dh.numNameServers = val.Interface().(uint16)
	val, _ = quick.Value(reflect.TypeOf(typUint16), rand)
	dh.numAddlRecords = val.Interface().(uint16)

	return reflect.ValueOf(dh)
}

func TestQuestion_roundtrip(t *testing.T) {
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

		rawDq, _, err := rawQuestionFromBytes(rdr, nil)
		if err != nil {
			t.Fatalf("Unexpected error from rawQuestionFromBytes: %s", err)
		}
		dqrt := rawDq.toQuestion()

		same, reasons := dq.equals(dqrt)
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

func (dq DNSQuestion) equals(other DNSQuestion) (bool, []string) {
	same := true
	var reasons []string
	if dq.domain != other.domain {
		same = false
		reasons = []string{fmt.Sprintf("domain: %q != %q", dq.domain, other.domain)}
	}
	if dq.typ != other.typ {
		same = false
		reason := fmt.Sprintf("typ: %d != %d", dq.typ, other.typ)
		reasons = append(reasons, reason)
	}
	if dq.class != other.class {
		same = false
		reason := fmt.Sprintf("class: %d != %d", dq.class, other.class)
		reasons = append(reasons, reason)
	}
	if dq.acceptUnicastResponse != other.acceptUnicastResponse {
		same = false
		reason := fmt.Sprintf("acceptUnicastResponse: %t != %t", dq.acceptUnicastResponse, other.acceptUnicastResponse)
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
	dq.domain = strings.Join(labels, ".")

	var val reflect.Value
	var ok bool
	val, ok = quick.Value(reflect.TypeOf(dq.typ), rand)
	if !ok {
		panic("quick.Value(reflect.TypeOf(dq.typ)")
	}
	dq.typ = val.Interface().(uint16)

	val, ok = quick.Value(reflect.TypeOf(dq.class), rand)
	if !ok {
		panic("quick.Value(reflect.TypeOf(dq.class)")
	}
	dq.class = val.Interface().(uint16) & 0x7FFF

	val, ok = quick.Value(reflect.TypeOf(dq.acceptUnicastResponse), rand)
	if !ok {
		panic("quick.Value(reflect.TypeOf(dq.acceptUnicastResponse)")
	}
	dq.acceptUnicastResponse = val.Bool()

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
