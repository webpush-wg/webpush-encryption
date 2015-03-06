---
title: Message Encryption for Web Push
abbrev: Web Push Encryption
docname: draft-thomson-webpush-encryption-latest
date: 2015
category: std
ipr: trust200902

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: M. Thomson
    name: Martin Thomson
    org: Mozilla
    email: martin.thomson@gmail.com


normative:
  I-D.thomson-webpush-http2:
  I-D.nottingham-http-encryption-encoding:
  RFC2119:
  RFC4492:
  DH:
    title: "New Directions in Cryptography"
    author:
      - ins: W. Diffie
      - ins: M. Hellman
    date: 1977-06
    seriesinfo: IEEE Transactions on Information Theory, V.IT-22 n.6
  FIPS186:
    title: "Digital Signature Standard (DSS)"
    author:
      - org: National Institute of Standards and Technology (NIST)
    date: July 2013
    seriesinfo: NIST PUB 186-4

informative:
  RFC7230:
  X.692:
     title: "Public Key Cryptography For The Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
     author:
       - org: ANSI
     date: 1998
     seriesinfo: ANSI X9.62
  API:
     title: "Web Push API"
     author:
       - ins: B. Sullivan
       - ins: E. Fullea
       - ins: M. van Ouwerkerk
     target: "https://w3c.github.io/push-api/"
     date: 2015


--- abstract

A message encryption scheme is described for the Web Push protocol.  This scheme
provides confidentiality and integrity for messages sent from an Application
Server to a User Agent.


--- middle

# Introduction

The Web Push protocol [I-D.thomson-webpush-http2] is an intermediated protocol
by necessity.  Messages from an Application Server are delivered to a User Agent
via a Push Service.

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
against inspection or modification by a Push Service.

Web Push messages are the payload of an HTTP message [RFC7230].  These messages
are encrypted using an encrypted content encoding
[I-D.nottingham-http-encryption-encoding].  This document describes how this
content encoding is applied and describes a recommended key management scheme.

For efficiency reasons, multiple users of Web Push often share a central agent
that aggregates push functionality.  This agent can enforce the use of this
encryption scheme by applications that use push messaging.  An agent that only
delivers messages that are properly encrypted strongly encourages the end-to-end
protection of messages.

For a web browser that implements the Web Push API [API], the browser can
enforce the use of encryption to the browser.


# Key Generation and Agreement

For each new subscription that the User Agent generates for an application, it
also generates an asymmetric key pair for use in Diffie-Hellman [DH] or
elliptic-curve Diffie-Hellman [ECDH].  The public key for this key pair can then
be distributed by the application to the Application Server along with the URI
of the subscription.

This key pair is used with the Diffie-Hellman key exchange as described in
Section 4.2 of [I-D.nottingham-http-encryption-encoding].

The means by which an application distributes the key identifier and public key
SHOULD be secured for the reasons described in [I-D.thomson-webpush-http2]; the
public key does not need additional protection.

A User Agent MUST generate and provide a public key for the scheme described in
{{mti}}.

Each public key MUST be accompanied by a key identifier that can be used in the
"keyid" parameter to identify which key is in use.  Key identifiers need only be
unique within the context of a subscription.


## Diffie-Hellman Group Information

As defined in [I-D.nottingham-http-encryption-encoding], use of Diffie-Hellman
for key agreement requires that the receiver share information about the group
and the format for the "dh" parameter with each potential sender.

BIG FAT TBD HERE.

### OPTION A

If we are to offer choice here, and we probably need to, we will need to provide
a way to identify a specific usage profile, likely with a registry of
identifiers, so that this can be done in an interoperable fashion.

### OPTION B

Personally, I'd prefer to just restrict this to {{mti}} and use the parameter
name in the API to steer toward alternative schemes.  I.e., expose the P-256
share as "p256dh" and let new schemes expose their shares under different names.


# Message Encryption


A User Agent decrypts messages are decrypted as described in
[I-D.nottingham-http-encryption-encoding].  The "keyid" parameter identifies the
specific key pair.


# Mandatory Elliptic Curve and Point Format {#mti}

User Agents that enforce encryption MUST expose an elliptic curve Diffie-Hellman
share on the P-256 curve [FIPS180].  For this key pair, the format for the "dh"
is an uncompressed point in the form described in [X.692].


# IANA Considerations

This document has no IANA actions.


# Security Considerations

The security considerations of [I-D.nottingham-http-encryption-encoding]
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
