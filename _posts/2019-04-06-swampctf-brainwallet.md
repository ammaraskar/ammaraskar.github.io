--- 
layout: post
title: SwampCTF 2019 Brainwallet (Crypto) Writeup
categories: []

tags: [ctf, swampctf, writeup, diffie-hellman, tls, crypto]

status: publish
type: post
published: true
meta: 
  _edit_last: "1"
  _syntaxhighlighter_encoded: "1"
---

# Problem Description

> Ever since their hella successful ICO, the crypto experts at VapeCoinIO have 
put  developers first with their simple, intuitive, and, most importantly,
secure API.  Once you've created your account and set up your wallet, you can
access it programmatically using your VapeID by sending a GET request to 
`/api/login?key=<HASH>` where `<HASH>` is your VapeID. Your wallet is 
transferred to you over TLS, so don't worry---it's really, really secure. In 
fact, it's so secure that the founder and CEO of VapeCoinIO uses the API for his 
personal Brainwallet.
>
> One of your contacts is a site-reliability engineer at VapeCoinIO. He has
obtained a PCAP of a TLS session with a client originating from an IP he 
suspects to be used by CEO's personal laptop. Perhaps he accessed his wallet! 
Can you find a way to recover its contents?

[traffic.png](/assets/misc_files/transcript.pcapng)

# Inspecting the packet capture

As the problem description says, the first thing we notice in the PCAP is that
the data is transferred exclusively over a TLS connection. Thus the first thing
we need to look for is something amiss in the TLS exchange such as the use of a
weak cipher.

We can see in the PCAP that the TLS connection is using: 
`TLS_DHE_RSA_WITH_AES_128_GCM_SHA256`

DHE stands for "Diffie-Hellman ephemeral" which is where the RSA key is used to
sign the server's Diffie-Hellman public number to provide authenticity and
every TLS session uses a new set of public numbers.

Looking at the Diffie-Hellman numbers in wireshark, we notice something very
interesting:

![Wireshark Disection TLS Exchange](/images/brainwallet/wireshark.png)

Those numbers look absolutely tiny! Diffie-Hellman's security is based on the
difficulty of the [Discrete Logarithm](https://en.wikipedia.org/wiki/Discrete_logarithm)
problem. Ordinarily the **p** (prime) for DH is a 2048 bit number, here it's
an abysmal 32 bits making it trivial to compute discrete logarithms
on. [SageMath](http://www.sagemath.org/) has several algorithms built in to
compute discrete logs so we wrote up a quick script to recover the client's
secret number.

```python
p = 0xf661398b
g = 0x02
client_public = 0x42b2769b
server_public = 0x916ddb94

k = GF(p)
client_secret = discrete_log_lambda(k(client_public), k(g), (1,2**32))
hex(int(client_secret))
# 0x5ec3d070
```

The client secret is then enough to compute the shared secret. This is known as
the [pre-master secret](https://tools.ietf.org/html/rfc5246#section-8.1.2) in
TLS terms which is all wireshark needs to decrypt TLS traffic.

```python
premaster_secret = pow(server_public, client_secret, p)
hex(int(premaster_secret))
# 0xf5ca9f85
```

# Decrypting with Wireshark

In order to let Wireshark utilize this, it needs a file mapping TLS sessions to
the master or pre-master secrets. So we made a file called `keylogfile.txt`
containing:

```
PMS_CLIENT_RANDOM 358970edf3544c1181cecf3369cd4c0e69be2c3605662ba1288b251161eba51e f5ca9f85
```

PMS stands for Pre-Master Secret and the giant number in the middle is the
client random, sent as part of the `Client Hello` packet which is what 
wireshark uses to map the PMS to the right TLS session.

_(Note: wireshark displays the timestamp and random bytes seperately if you
expand the `Random` portion in the TLS packet, the client random is the
timestamp and random bytes together.)_

We set up Wireshark's TLS protocol settings to use the log file:

![Wireshark TLS Preferences](/images/brainwallet/wireshark-pref.png)

and boom, follow the TLS stream in Wireshark for the flag:

![Wireshark TLS Stream](/images/brainwallet/wireshark-follow.png)