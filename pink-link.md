Pink Link is a low level link layer for networking between peers. It provides the backbone to the Pink network library. It does a few things:

 * Keep track of local IP, and peer IP changes as peers move between different networks
 * Reliable unordered delivery of packets
 * All traffic is as close to indistinguishable from random bytes as possible
 * All content is always encrypted using TweetNaCL constructs
 * Congestion control using LEDBAT, with each peer getting a fair share of uplink traffic with a 100ms target latency, allowing heavy syncing and sharing tasks without making interactive traffic like web browsing feel slow on asymmetric home internet connections.

Pink Link has two types of packet: ID and Compact. Both can contain messages.

ID packets take the following form:

```
[24 byte nonce] [32 byte cloaked public key] [nacl.box encrypted content]
```

Compact packets follow this form:

```
[24 byte nonce] [nacl.box encrypted content]
```

### When to use ID Packets ###

Compact Packets are used for most bulk traffic. ID Packets are used occasionally to establish who is sending. This allows the local peer to keep sending to a remote peer when the local peer has changed to a different network address. It also updates the remote peer's records so they can transmit back.

A packet should be encoded as an ID packet whenever:

 * More than 1 second elapsed since the last ID Packet was sent, and the data is short enough to fit under the network protocol's MTU with an extra 32 bytes. For IPv4 this MTU is presumed to be 512, for IPv6 it is 1024.
 * At the start of application, until remote peer has sent decryptable requests or acks to local peer.
 * If a packet has timed out (no ack received in time) it should be retransmitted as an ID packet if possible, or if it cannot fit, a keepalive packet should be scheduled to recover from local network address change.
 * Application detects the local address changed somehow.

### Encrypted Content ###

The encrypted content is an array encoded with MessagePack, with this form:

```json
[message_id, sender_time, data]
```

sender_time is the number of milliseconds since unix epoch or some other arbitrary point. sender_time is a double precision floating point number. ack_id is an integer, and data is whatever the application chooses.

acks take this form:

```json
[message_id, delta_time]
```

delta_time is the recipient's time in milliseconds minus the sender_time from the original packet. When packets are retransmitted, the sender_time should be updated. delta_time is used for LEDBAT congestion control.

Request packets may set their data field to null to send a keep alive. Applications shouldn't be notified about keep alive messages. Peers should send a keep alive more frequently than once every 60 seconds, to maintain mapping in NAT devices. Keep Alive messages follow the one ID packet every second rule and are very short, ensuring at least one ID packet is transmitted every 60 seconds.


### Public Key cloaking in ID packets ###

Public Keys are obscured in ID Packets to make them appear random to network equipment doing deep packet inspection, and general snoops. The following algorithm is used:

```
nonce = 24 bytes - also used for nacl.box encryption of content
sender_pubkey = 32 bytes
receiver_pubkey = 32 bytes
sender_cloaked_key = 32 byte buffer
cloak_bytes = blake2s(nonce + receiver_pubkey)
for idx in range 0 to 31 inclusive:
  sender_cloaked_key[idx] = sender_pubkey[idx] xor cloak_bytes[idx]
```

Cloaking the sender's public key hides it from passive observers who don't already know the receiver's public key. The primary goal is to make packet data appear purely random to casual observers, so applications built on Pink Link are protected from traffic shaping attacks by internet providers, strengthening network neutrality.

The secondary goal of cloaking is to make tracking users more difficult. If the public key was not cloaked, a system of mass surveillance could use it to uniquely identify a particular device as it moves around the internet. With cloaking this is much more complicated, and if all the peers keep their public keys secret, only sharing them via secure or offline channels, it seems unlikely to be useful in any way to track and uniquely identify users.

If a passive observer does know the public key of the peer you are sending messages to, it still cannot verify you sent the real key unless it also knows the recipients private key and can decrypt the data block. This is all sufficiently complicated that it is unlikely any deep packet inspection device would bother for untargeted surveillance.

### Suggested Decryption Order ###

Pink Link does not identify what type of packet it is sending, so a receiver must attempt to decode it multiple ways until one succeeds. The nacl.box operation includes a message authenticator which gives an indication if the message decrypted successfully.

 * If we know the sender's public key, attempt to decrypt it as a Compact Packet
 * Next, attempt to decrypt it as an ID Packet

Whenever the sender decrypts an ID Packet, it should update that sender's network address record, and send all future packets to that network address. Applications should address peers by their public key.

### Extra Considerations ###

This document doesn't specify any mechanism to hide the length of packets. If this is important, you can pad the encrypted section with random bytes at the end. MessagePack seems to ignore extra data.

Peers routinely share their clock with high precision, and could be a way to fingerprint peers who are trying to stay anonymous. Implementations may choose a random epoch for each connection to avoid this. A better epoch maybe the time when the first packet was sent to or received from that peer, keeping numbers lower and preserving sub-millisecond precision.

Implementations should try to keep their API simple and choose sensible defaults. Pink aims to be friendly to beginner coders, like kids who want to add a multiplayer aspect to a game they made, to take away the incentive to learn complicated centralised solutions and perpetuate the status quo in future generations. P2P networking can potentially be much easier and cheaper, and for kids it is especially worthwhile because kids often have no access to servers, or only dodgy shell accounts gifted by strangers.

  -- <3 Raina
