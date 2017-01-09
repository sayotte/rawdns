[![Build Status](https://travis-ci.org/sayotte/rawmdns.svg?branch=master)](https://travis-ci.org/sayotte/rawmdns)
# rawmdns
Low-level multicast-DNS (mDNS) datatypes for Golang.

Use this for encoding/decoding wire-format messages in mDNS applications and
libraries.

If you just want mDNS discovery / advertisement *a la* Avahi or mDNS-Responder,
one of these libraries may interest you:
* https://github.com/hashicorp/mdns
* https://github.com/oleksandr/bonjour
* https://github.com/davecheney/mdns

Note: all three of the above use `github.com/miekg/dns` which encodes/decodes only
RFC-1035 formats, which are different in small but possibly important ways from
RFC-6762 formats. This was actually the driving force for the creation of this
library. If since this writing mDNS support has been added to that library, you're
probably better off using that as it's widely adopted and covers more record types.

## Installation
`go get github.com/sayotte/rawmdns`

OR

`git clone --recursive https://github.com/sayotte/rawmdns.git; cd rawmdns; go install`

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

## Implementation notes
### TXT record format
Because the primary use-case for mDNS is service discovery, the TXT record format
implemented here conforms to
[Section 6.3 of RFC-6763 (DNS-SD)](https://tools.ietf.org/html/rfc6763#section-6.3),
rather than the original TXT record format from RFC-1035/6762.
This shouldn't come as a surprise if you're using mDNS, but it bears calling out.

### Asymmetric encoding/decoding API: why?
DNS' wire format provides for compression of domain-name components (called "labels")
by using pointers to identical strings earlier in the overall DNS message. Because
of this, a decoder has to remember the offsets and contents of every label it's
encountered in the message until the message is fully decoded, after which they
can (should) be forgotten in lieu of the fully-decoded domain-names.

Maintaining this context begs for an object, so I gave it one: `rawmdns.Decoder`.

Encoding, on the other hand, doesn't *require* use of this compression. It might
be a neat feature to add, but the use-cases driving me to create this library
didn't need it. Without compression, no context needs to be kept and there is no
need for an `Encoder`-type object, so I didn't create one.

Instead, as in the example above, you'll just build a `DNSMessage` object and then
call its `.ToBytes()` method, which does what you'd expect.
