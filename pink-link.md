Pink Link is an encryption layer for UDP messaging between peers. It provides:

 * Message payload protected by Curve25519-XSalsa20-Poly1305 from NaCL library
 * Packet over network resembles random data, frustrating DPI
 * Tracks remote peer IP changes as peers move to different networks
 *

Pink Link transmits all data through "ID Packets", named for the identifying public key included

ID packets take the following form:

```
[24 byte random nonce] [32 byte cloaked public key] [nacl.box encrypted content]
```

### Public Key cloaking in ID packets ###

Public Keys are obscured in ID Packets to make them appear random to network equipment doing deep packet inspection, and general snoops. The following algorithm is used:

```
nonce = 24 random bytes - also used for nacl.box encryption of content
sender_pubkey = 32 bytes
receiver_pubkey = 32 bytes
cloak_bytes = blake2s(nonce + receiver_pubkey)
for idx in range 0 to 31 inclusive:
  sender_cloaked_key[idx] = sender_pubkey[idx] xor cloak_bytes[idx]
```

Cloaking the sender's public key hides it from passive observers who don't already know the receiver's public key. The primary goal is to make packet data appear random to casual observers, so applications built on Pink Link are protected from traffic shaping attacks by internet providers, strengthening network neutrality.

The secondary goal of cloaking is to make tracking users more difficult for people outside the network. Without knowing the recipient's public key, a passive network observer won't discover the sender's public key from the ID packet data.

If an observer does know the public key of the peer you are sending messages to, it still cannot verify you sent your real public key without the recipients private key to attempt decrypting the payload.


### Extra Considerations ###

This document doesn't specify any mechanism to hide the length of packets. Pink Link has a constant overhead, so you can implement that in the encrypted payload.

Pink project wants to make private p2p technologies available to kids and beginner coders, so they will learn p2p networking instead of servers. Projects implementing these protocols should try to make their interfaces friendly to beginners and encourage play. If we want to change the future, we should start with the people who will be building it.

  -- <3 Raina
