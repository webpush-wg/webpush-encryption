---
title: Message Encryption for Web Push
abbrev: Web Push Encryption
docname: draft-ietf-webpush-encryption-latest
date: 2015
category: std
ipr: trust200902

stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]

author:
 -
    ins: M. Thomson
    name: Martin Thomson
    org: Mozilla
    email: martin.thomson@gmail.com


normative:
  I-D.thomson-webpush-protocol:
  I-D.thomson-http-encryption:
  RFC2119:
  RFC4086:
  DH:
    title: "New Directions in Cryptography"
    author:
      - ins: W. Diffie
      - ins: M. Hellman
    date: 1977-06
    seriesinfo: IEEE Transactions on Information Theory, V.IT-22 n.6
  ECDH:
    title: "Elliptic Curve Cryptography"
    author:
      - org: SECG
    date: 2000
    seriesinfo: SEC 1
    target: "http://www.secg.org/"
  FIPS186:
    title: "Digital Signature Standard (DSS)"
    author:
      - org: National Institute of Standards and Technology (NIST)
    date: July 2013
    seriesinfo: NIST PUB 186-4
  X.692:
     title: "Public Key Cryptography For The Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
     author:
       - org: ANSI
     date: 1998
     seriesinfo: ANSI X9.62

informative:
  RFC2818:
  RFC4648:
  RFC7230:
  API:
     title: "Web Push API"
     author:
       - ins: M. van Ouwerkerk
       - ins: M. Thomson
     target: "https://w3c.github.io/push-api/"
     date: 2015


--- abstract

A message encryption scheme is described for the Web Push protocol.  This scheme
provides confidentiality and integrity for messages sent from an Application
Server to a User Agent.


--- middle

# Introduction

The Web Push protocol [I-D.thomson-webpush-protocol] is an intermediated
protocol by necessity.  Messages from an Application Server are delivered to a
User Agent via a Push Service.

~~~
 +-------+           +--------------+       +-------------+
 |  UA   |           | Push Service |       | Application |
 +-------+           +--------------+       +-------------+
     |                      |                      |
     |        Setup         |                      |
     |<====================>|                      |
     |           Provide Subscription              |
     |-------------------------------------------->|
     |                      |                      |
     :                      :                      :
     |                      |     Push Message     |
     |    Push Message      |<---------------------|
     |<---------------------|                      |
     |                      |                      |
~~~

This document describes how messages sent using this protocol can be secured
against inspection, modification and falsification by a Push Service.

Web Push messages are the payload of an HTTP message [RFC7230].  These messages
are encrypted using an encrypted content encoding
[I-D.thomson-http-encryption].  This document describes how this
content encoding is applied and describes a recommended key management scheme.

For efficiency reasons, multiple users of Web Push often share a central agent
that aggregates push functionality.  This agent can enforce the use of this
encryption scheme by applications that use push messaging.  An agent that only
delivers messages that are properly encrypted strongly encourages the end-to-end
protection of messages.

A web browser that implements the Web Push API [API] can enforce the use of
encryption by forwarding only those messages that were properly encrypted.


## Notational Conventions

The words "MUST", "MUST NOT", "SHOULD", and "MAY" are used in this document.
It's not shouting, when they are capitalized, they have the special meaning
described in [RFC2119].


# Key Generation and Agreement

For each new subscription that the User Agent generates for an application, it
also generates an asymmetric key pair for use in Diffie-Hellman (DH) [DH] or
elliptic-curve Diffie-Hellman (ECDH) [ECDH].  The public key for this key pair
can then be distributed by the application to the Application Server along with
the URI of the subscription.  The private key MUST remain secret.

This key pair is used with the Diffie-Hellman key exchange as described in
Section 4.2 of [I-D.thomson-http-encryption].

A User Agent MUST generate and provide a public key for the scheme described in
{{mti}}.

The public key MUST be accompanied by a key identifier that can be used in the
"keyid" parameter to identify which key is in use.  Key identifiers need only be
unique within the context of a subscription.


## Diffie-Hellman Group Information

As described in [I-D.thomson-http-encryption], use of Diffie-Hellman
for key agreement requires that the receiver provide clear information about
its chosen group and the format for the "dh" parameter with each potential
sender.

This document only describes a single ECDH group and point format, described in
{{mti}}.  A specification that defines alternative groups or formats MUST
provide a means of indicating precisely which group and format is in use for
every public key that is provided.


## Key Distribution

The application using the subscription distributes the key identifier and public
key along with other subscription information, such as the subscription URI and
expiration time.

The communication medium by which an application distributes the key identifier
and public key MUST be confidentiality protected for the reasons described in
[I-D.thomson-webpush-protocol].  Most applications that use push messaging have
a pre-existing relationship with an Application Server.  Any existing
communication mechanism that is authenticated and provides confidentiality and
integrity, such as HTTPS [RFC2818], is sufficient.


## Push Message Authentication {#auth}

To ensure that push messages are correctly authenticated, a symmetric
authentication secret is added to the information generated by a User Agent.
The authentication secret is mixed into the key derivation process described in
[I-D.thomson-http-encryption].

The authentication secret ensures that exposure or leakage of the DH public
key - which, as a public key, is not necessarily treated as a secret - does not
enable an adversary to generate valid push messages.

A User Agent MUST generate and provide a hard to guess sequence of octets that
is used for authentication of push messages.  This SHOULD be generated by a
cryptographically strong random number generator [RFC4086] and be at least 16
octets long.


# Message Encryption {#encryption}

An Application Server that has the public key, group and format information plus
the authentication secret can encrypt a message for the User Agent.


## Key Derivation {#derivation}

The Application Server generates a new DH or ECDH key pair in the same group as
the value generated by the User Agent.

From the newly generated key pair, the Application Server performs a DH or ECDH
computation with the public key provided by the User Agent to find the input
keying material for key derivation.  The Application Server then generates 16
octets of salt that is unique to the message.  A random [RFC4086] salt is
acceptable.

Web push uses the authentication secret defined in Section 4.3 of
[I-D.thomson-http-encryption].  This authentication secret (see {{auth}}) is
generated by the user agent and shared with the application server.


## Push Message Content Encryption {#c-e}

The Application Server then encrypts the payload.  Header fields are populated
with URL-safe base-64 encoded [RFC4648] values:

* the salt is added to the `salt` parameter of the Encryption header field; and

* the public key for its DH or ECDH key pair is placed in the `dh` parameter of
  the Crypto-Key header field.

An application server MUST encrypt a push message with a single record.  This
allows for a minimal receiver implementation that handles a single record.  If
the message is 4096 octets or longer, the `rs` parameter MUST be set to a value
that is longer than the encrypted push message length.

Note that a push service is not required to support more than 4096 octets of
payload body, which equates to 4080 octets of cleartext, so the `rs` parameter
can be omitted for messages that fit within this limit.

An application server MUST NOT use other content encodings for push messages.
In particular, content encodings that compress could result in leaking of push
message contents.  The Content-Encoding header field therefore has exactly one
value, which is `aesgcm128`.  Multiple `aesgcm128` values are not permitted.

An application server MUST include exactly one entry in each of the Encryption
and Crypto-Key header fields.  This allows the `keyid` parameter to be omitted
from both header fields.

An application server MUST NOT include an `aesgcm128` parameter in the
Encryption header field.


# Message Decryption

A User Agent decrypts messages are decrypted as described in
[I-D.thomson-http-encryption].  The authentication secret described in
{{derivation}} is used in key derivation.

Note that the value of the "keyid" parameter is used to identify the correct
share, if there are multiple values for the Crypto-Key header field.

A receiver is not required to support multiple records.  Such a receiver MUST
check that the record size is large enough to contain the entire payload body in
a single record.  The `rs` parameter MUST NOT be exactly equal to the length of
the payload body minus the length of the authentication tag (16 octets); that
length indicates that the message has been truncated.


# Mandatory Group and Public Key Format {#mti}

User Agents MUST expose an elliptic curve Diffie-Hellman share on the P-256
curve [FIPS186].

Public keys, such as are encoded into the "dh" parameter, MUST be in the form of
an uncompressed point as described in [X.692] (that is, a 65 octet sequence that
starts with a 0x04 octet).

The label for this curve is the string "P-256" encoded in ASCII (that is, the
octet sequence 0x50, 0x2d, 0x32, 0x35, 0x36).


# IANA Considerations

This document has no IANA actions.


# Security Considerations

The security considerations of [I-D.thomson-http-encryption]
describe the limitations of the content encoding.  In particular, any HTTP
header fields are not protected by the content encoding scheme.  A User Agent
MUST consider HTTP header fields to have come from the Push Service.  An
application on the User Agent that uses information from header fields to alter
their processing of a push message is exposed to a risk of attack by the Push
Service.

The timing and length of communication cannot be hidden from the Push Service.
While an outside observer might see individual messages intermixed with each
other, the Push Service will see what Application Server is talking to which
User Agent, and the subscription they are talking about.  Additionally, the
length of messages could be revealed unless the padding provided by the content
encoding scheme is used to obscure length.
