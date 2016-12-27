[![Build Status](https://travis-ci.org/sayotte/rawmdns.svg?branch=master)](https://travis-ci.org/sayotte/rawmdns)
# rawmdns
DNS datatypes for Golang, including marshalling code to/from []byte

## Installation
`go get github.com/sayotte/rawmdns`

## Example Usage
``` go
package main

import "github.com/sayotte/rawmdns"

func main() {
    /* Receive and decode a message */
    msgReader := getMulticastMessage()
    d := rawmdns.NewDecoder(msgReader)
    dm, _ := d.DecodeDNSMessage()

    /* Send a new message */
    dm = DNSMessage{
        Hdr: DNSHeader{
            IsResponse: true,
            OpCode: rawmdns.OpCodeQuery,
            Authoritative: true,
            NumAnswers: 1,
        },
        Answers: []DNSResourceRecord{
            ARecord{
                Common: ResourceRecordCommon{
                    Domain: "foo.example.com",
                    Type: rawmdns.TypeA,
                    Class: rawmdns.ClassINET,
                    CacheFlush: true,
                    TTL: 120,
                },
                Addr: net.ip([]byte{1,2,3,4}),
            },
        },
    }
    sendMulticastMessage(dm.toBytes())
}

func getMulticastMessage() io.Reader {
    /* Not implemented by this package */
}

func sendMulticastMessage(b []byte) {
    /* Not implemented by this package */
}
```
