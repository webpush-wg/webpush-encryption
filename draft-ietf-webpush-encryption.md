---
title: Message Encryption for Web Push
abbrev: Web Push Encryption
docname: draft-ietf-webpush-encryption-latest
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
  X9.62:
     title: "Public Key Cryptography For The Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
     author:
       - org: ANSI
     date: 1998
     seriesinfo: ANSI X9.62
  FIPS180-4:
    title: NIST FIPS 180-4, Secure Hash Standard
    author:
      name: NIST
      ins: National Institute of Standards and Technology, U.S. Department of Commerce
    date: 2012-03
    target: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

informative:
  API:
     title: "Web Push API"
     author:
       - ins: P. Beverloo
       - ins: M. Thomson
     target: "https://w3c.github.io/push-api/"
     date: 2015


--- abstract

A message encryption scheme is described for the Web Push protocol.  This scheme
provides confidentiality and integrity for messages sent from an Application
Server to a User Agent.


--- middle

# Introduction

The Web Push protocol {{!RFC8030}} is an intermediated protocol by necessity.
Messages from an Application Server are delivered to a User Agent (UA) via a
Push Service.

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
against inspection, modification and forgery by a Push Service.

Web Push messages are the payload of an HTTP message {{?RFC7230}}.  These
messages are encrypted using an encrypted content encoding {{!RFC8188}}.  This
document describes how this content encoding is applied and describes a
recommended key management scheme.

For efficiency reasons, multiple users of Web Push often share a central agent
that aggregates push functionality.  This agent can enforce the use of this
encryption scheme by applications that use push messaging.  An agent that only
delivers messages that are properly encrypted strongly encourages the end-to-end
protection of messages.

A web browser that implements the Web Push API {{API}} can enforce the use of
encryption by forwarding only those messages that were properly encrypted.


## Notational Conventions

The words "MUST", "MUST NOT", "SHOULD", and "MAY" are used in this document.
It's not shouting, when they are capitalized, they have the special meaning
described in {{!RFC2119}}.

This document uses the terminology from {{RFC8030}}, primarily User Agent, Push
Service, and Application Server.


# Push Message Encryption Overview {#overview}

Encrypting a push message uses elliptic-curve Diffie-Hellman (ECDH) {{ECDH}} on
the P-256 curve {{FIPS186}} to establish a shared secret (see {{dh}}) and a
symmetric secret for authentication (see {{auth}}).

A User Agent generates an ECDH key pair and authentication secret that it
associates with each subscription it creates.  The ECDH public key and the
authentication secret are sent to the Application Server with other details of
the push subscription.

When sending a message, an Application Server generates an ECDH key pair and a
random salt.  The ECDH public key is encoded into the `keyid` parameter of the
encrypted content coding header, the salt in the `salt` parameter of that same
header (see Section 2.1 of {{!RFC8188}}).  The ECDH key pair can be discarded
after encrypting the message.

The content of the push message is encrypted or decrypted using a content
encryption key and nonce that is derived using all of these inputs and the
process described in {{encryption}}.


## Key and Secret Distribution

The application using the subscription distributes the subscription public key
and authentication secret to an authorized Application Server.  This could be
sent along with other subscription information that is provided by the User
Agent, such as the push subscription URI.

An application MUST use an authenticated, confidentiality protected
communications medium for this purpose.  In addition to the reasons described in
{{!RFC8030}}, this ensures that the authentication secret is not revealed to
unauthorized entities, which can be used to generate push messages that will be
accepted by the User Agent.

Most applications that use push messaging have a pre-existing relationship with
an Application Server that can be used for distribution of subscription data.
An authenticated communication mechanism that provides adequate confidentiality
and integrity protection, such as HTTPS {{?RFC2818}}, is sufficient.


# Push Message Encryption {#encryption}

Push message encryption happens in four phases:

* A shared secret is derived using elliptic-curve Diffie-Hellman {{ECDH}}
  ({{dh}}).

* The shared secret is then combined with the authentication secret to produce
  the input keying material used in {{!RFC8188}} ({{combine}}).

* A content encryption key and nonce are derived using the process in
  {{!RFC8188}}.

* Encryption or decryption follows according to {{!RFC8188}}.

The key derivation process is summarized in {{summary}}.  Restrictions on the
use of the encrypted content coding are described in {{restrict}}.


## Diffie-Hellman Key Agreement {#dh}

For each new subscription that the User Agent generates for an Application, it
also generates a P-256 {{FIPS186}} key pair for use in elliptic-curve
Diffie-Hellman (ECDH) {{ECDH}}.

When sending a push message, the Application Server also generates a new ECDH
key pair on the same P-256 curve.

The ECDH public key for the Application Server is included as the "keyid"
parameter in the encrypted content coding header (see Section 2.1 of
{{!RFC8188}}.

An Application Server combines its ECDH private key with the public key provided
by the User Agent using the process described in {{ECDH}}; on receipt of the
push message, a User Agent combines its private key with the public key provided
by the Application Server in the `keyid` parameter in the same way.  These
operations produce the same value for the ECDH shared secret.


## Push Message Authentication {#auth}

To ensure that push messages are correctly authenticated, a symmetric
authentication secret is added to the information generated by a User Agent.
The authentication secret is mixed into the key derivation process shown in
{{combine}}.

A User Agent MUST generate and provide a hard to guess sequence of 16 octets that
is used for authentication of push messages.  This SHOULD be generated by a
cryptographically strong random number generator {{!RFC4086}}.


## Combining Shared and Authentication Secrets {#combine}

The shared secret produced by ECDH is combined with the authentication secret
using the Hashed Message Authentication Code (HMAC)-based key derivation
function (HKDF) {{!RFC5869}}.  This produces the input keying material used by
{{!RFC8188}}.

The HKDF function uses SHA-256 hash algorithm {{FIPS180-4}} with the following
inputs:

salt:
: the authentication secret

IKM:
: the shared secret derived using ECDH

info:

: the concatenation of the ASCII-encoded string "WebPush: info", a zero octet,
  and the User Agent ECDH public key and the Application Server ECDH public key,
  both in the uncompressed point form defined in {{X9.62}}; that is

  ~~~
  key_info = "WebPush: info" || 0x00 || ua_public || as_public
  ~~~

L:
: 32 octets (i.e., the output is the length of the underlying SHA-256 HMAC
  function output)


## Encryption Summary {#summary}

This results in a the final content encryption key and nonce generation using
the following sequence, which is shown here in pseudocode with HKDF expanded
into separate discrete steps using HMAC with SHA-256:

~~~ inline
   -- For a User Agent:
   ecdh_secret = ECDH(ua_private, as_public)
   auth_secret = random(16)
   salt = <from content coding header>

   -- For an Application Server:
   ecdh_secret = ECDH(as_private, ua_public)
   auth_secret = <from User Agent>
   salt = random(16)

   -- For both:

   ## Use HKDF to combine the ECDH and authentication secrets
   # HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
   PRK_key = HMAC-SHA-256(auth_secret, ecdh_secret)
   # HKDF-Expand(PRK_key, key_info, L_key=32)
   key_info = "WebPush: info" || 0x00 || ua_public || as_public
   IKM = HMAC-SHA-256(PRK_key, key_info || 0x01)

   ## HKDF calculations from RFC 8188
   # HKDF-Extract(salt, IKM)
   PRK = HMAC-SHA-256(salt, IKM)
   # HKDF-Expand(PRK, cek_info, L_cek=16)
   cek_info = "Content-Encoding: aes128gcm" || 0x00
   CEK = HMAC-SHA-256(PRK, cek_info || 0x01)[0..15]
   # HKDF-Expand(PRK, nonce_info, L_nonce=12)
   nonce_info = "Content-Encoding: nonce" || 0x00
   NONCE = HMAC-SHA-256(PRK, nonce_info || 0x01)[0..11]
~~~

Note that this omits the exclusive OR of the final nonce with the record
sequence number, since push messages contain only a single record (see
{{restrict}}) and the sequence number of the first record is zero.


# Restrictions on Use of "aes128gcm" Content Coding {#restrict}

An Application Server MUST encrypt a push message with a single record.  This
allows for a minimal receiver implementation that handles a single record.  An
application server MUST set the `rs` parameter in the `aes128gcm` content coding
header to a size that is greater than the sum of the lengths of the plaintext,
the padding delimiter (1 octet), any padding, and the authentication tag (16
octets).

A push message MUST include the application server ECDH public key in the
`keyid` parameter of the encrypted content coding header.  The uncompressed
point form defined in {{X9.62}} (that is, a 65 octet sequence that starts with a
0x04 octet) forms the entirety of the `keyid`.  Note that this means that the
`keyid` parameter will not be valid UTF-8 as recommended in {{!RFC8188}}.

A push service is not required to support more than 4096 octets of payload body
(see Section 7.2 of {{!RFC8030}}).  Absent header (86 octets), padding (minimum
1 octet), and expansion for AEAD_AES_128_GCM (16 octets), this equates to at
most 3993 octets of plaintext.

An Application Server MUST NOT use other content encodings for push messages.
In particular, content encodings that compress could result in leaking of push
message contents.  The Content-Encoding header field therefore has exactly one
value, which is `aes128gcm`.  Multiple `aes128gcm` values are not permitted.

A User Agent is not required to support multiple records.  A User Agent MAY
ignore the `rs` field.  If a record size is unchecked, decryption will fail with
high probability for all valid cases.  The padding delimiter octet MUST be
checked, values other than 0x02 MUST cause the message to be discarded.


# Push Message Encryption Example {#example}

The following example shows a push message being sent to a push service.

~~~ example
POST /push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV HTTP/1.1
Host: push.example.net
TTL: 10
Content-Length: 145
Content-Encoding: aes128gcm

DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml
mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT
pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN
~~~

This example shows the ASCII encoded string, "When I grow up, I want to be a
watermelon". The content body is shown here with line wrapping and URL-safe
base64url {{?RFC4648}} encoding to meet presentation constraints.

The keys used are shown below using the uncompressed form {{X9.62}} encoded
using base64url.

~~~ example
   Authentication Secret: BTBZMqHH6r4Tts7J_aSIgg
   Receiver:
      private key: q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94
      public key: BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx
                  aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4
   Sender:
      private key: yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw
      public key: BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg
                  Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8
~~~

Intermediate values for this example are included in {{ex-intermediate}}.


# IANA Considerations {#iana}

\[\[RFC EDITOR: please remove this section before publication.]]
This document makes no request of IANA.

# Security Considerations

The privacy and security considerations of {{!RFC8030}} all apply to the use of
this mechanism.

The security considerations of {{!RFC8188}} describe the limitations of the
content encoding.  In particular, any HTTP header fields are not protected by
the content encoding scheme.  A User Agent MUST consider HTTP header fields to
have come from the Push Service.  Though header fields might be necessary for
processing an HTTP response correctly, they are not needed for correct operation
of the protocol.  An application on the User Agent that uses information from
header fields to alter their processing of a push message is exposed to a risk
of attack by the Push Service.

The timing and length of communication cannot be hidden from the Push Service.
While an outside observer might see individual messages intermixed with each
other, the Push Service will see which Application Server is talking to which
User Agent, and the subscription that is used.  Additionally, the length of
messages could be revealed unless the padding provided by the content encoding
scheme is used to obscure length.

The User Agent and Application MUST verify that the public key they receive is
on the P-256 curve.  Failure to validate a public key can allow an attacker to
extract a private key.


--- back

# Intermediate Values for Encryption {#ex-intermediate}

The intermediate values calculated for the example in {{example}} are shown
here.  The base64url values in these examples include whitespace that can be
removed.

The following are inputs to the calculation:

Plaintext:

: V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24

Application Server public key (as_public):

: BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg
  Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8

Application Server private key (as_private):

: yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw

User Agent public key (ua_public):

: BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx
  aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4

User Agent private key (ua_private):

: q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94

Salt:

: DGv6ra1nlYgDCS1FRnbzlw

Authentication secret (auth_secret):

: BTBZMqHH6r4Tts7J_aSIgg

Note that knowledge of just one of the private keys is necessary.  The
Application Server randomly generates the salt value, whereas salt is input to
the receiver.

This produces the following intermediate values:

Shared ECDH secret (ecdh_secret):

: kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs

Pseudorandom key (PRK) for key combining (PRK_key):

: Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k

Info for key combining (key_info):

: V2ViUHVzaDogaW5mbwAEJXGyvs3942BVGq8e0PTNNmwR
  zr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3
  ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0Ew
  bZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAv
  MBKiiujwa7t45ewP

Input keying material for content encryption key derivation (IKM):

: S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg

PRK for content encryption (PRK):

: 09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc

Info for content encryption key derivation (cek_info):

: Q29udGVudC1FbmNvZGluZzogYWVzMTI4Z2NtAA

Content encryption key (CEK):

: oIhVW04MRdy2XN9CiKLxTg

Info for content encryption nonce derivation (nonce_info):

: Q29udGVudC1FbmNvZGluZzogbm9uY2UA

Nonce (NONCE):

: 4h_95klXJ5E_qnoN

The salt, record size of 4096, and application server public key produce an 86
octet header of DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z
9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml mlMoZIIgDll6e3vCYLocInmYWAmS6Tlz
AC8wEqKK6PBru3jl7A8.

The push message plaintext has the padding delimiter octet (0x02) appended to
produce V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0 byBiZSBhIHdhdGVybWVsb24C.  The
plaintext is then encrypted with AES-GCM, which emits ciphertext of
8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs
bI_0LpXMuGvnzQ.

The header and cipher text are concatenated and produce the result shown in
{{example}}.
