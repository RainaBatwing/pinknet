## Pink Network (draft)

WARNING: This document is a crazy stream of consciousness. As pink gets implemented it is changing to track the discoveries and changes made through implementation. The only aspect unlikely to change is the raw message encoding and pulse encoding - e.g. the ciphertext stuff - which I think is a pretty cool mechanism.

Pink is a low level protocol and library for building toy p2p networks. Project aims:

 1. Provide a simple interface which beginner coders can use to create social apps safely and securely
 2. Discourage the use of servers by providing an easier and free p2p alternative for app builders
 3. Keep all content private using strong encryption built on curve25519 and xsalsa20 through the tweetnacl library
 4. All packets should be indistinguishable from random bytes to passive observers for net neutrality resilience
 5. Cleanly transition between network addresses as peers move between cellular and wired networks with minimal interuption

Pink Network runs entirely over IPv4 UDP, with a goal of supporting IPv6 in the future, and maybe other transports like Bluetooth 4 or WiFi Direct. Pink is inspired in some ways by Telehash, but is not an implementation of it.

Pink encodes packets as compact binary blobs, and uses MessagePack where possible, enabling compact transmission of binary including crypto keys, nonces, and chunks of files. All references to JSON in this document are illustrative, and are always transmitted using msgpack encoding.


## Draft V1 Protocol

### Pulse Request

Peers use pulses to discover their public IP address to that peer, and as a keep-alive to keep NAT port mappings open. Peers should pulse each other at a rate of about *once per 30 seconds* generally. Pulses can measure latency and compare local clocks via the "respond" mechanism, allowing consensus-based shared timekeeping.

If a peer is unresponsive to other types of requests, the requesting peer should send the destination peer a Request Pulse. This helps recover from situations where the sending peer has changed to a different network or otherwise switched to a different network address, and the recipient has no idea who they are and cannot decrypt their packets.

```
[24 byte nonce] [32 byte cloaked public key]
[MsgPack bytes encrypted with nacl.box with specified nonce]
```

MsgPack bytes must encode an object. This object must contain a superset of:

```json
{
  "time": local time in milliseconds
  "you": CompactAddress of intended recipient, without publicKey included
  // optionally:
  "respond": non-null value
  // or:
  "response": value from "respond" in request pulse
}
```

If a pulse contains a `"respond"` key and it's value is not null, the receiver should immediately send a pulse back containing the same object `"respond"` contained. Implementations can use that value to transmit anything, like an object, or a numeric request id.


### Public Key Cloaking

Public keys are transmitted unencrypted in pulse packets. To increase difficulty profiling pink user traffic, 32 byte curve25519 public keys are cloaked by XORing the public key bytes in the plaintext part of a pulse packet with a 32 byte BLAKE2s digest of the packet's nonce concatenated with the intended recipient's public key. A casual observer who knows no members's public key will not be able to determine anyone's public key purely from their PinkNet traffic.

Cloaking is not intended to provide total privacy. It's primary use is to help frustrate network admins attempting to profile PinkNet traffic and filter or delay it by keeping packet appearance random-like. Planning for a future with poor net neutrality. Implementations may choose to pad their pulse packets with random data to further frustrate packet length based profiling.


### Compact IP Buffer Format

When the network needs to transmit an IP address, it uses a format designed to compactly encode in MsgPack:

```javascript
// IPv4 address
[
  4, // address type
  Buffer(1, 2, 3, 4), // each of the 4 octets in an ipv4 address 1.2.3.4
  5678 // port number
]
// IPv6 address
[
  6, // address type
  [false, 1, 2, 3, 4, 5, 6], // each of the 4 octets in an ipv4 address ::1:2:3:4:5:6
  5678 // port number
]
```

Different address types maybe implemented in the future. Implementations should skip over address types they don't understand where possible. IPv6 addresses are stored as plain arrays, with the `false` special value to indicate a :: section. IPv6 encoding is experimental and not being actively tested yet. Both types can have an additional Buffer after the port, containing a publicKey for that address.

### Unreliable Raw Message

Raw messages are used for all other types of communication and take this form:

```
[24 byte nonce] [nacl.box of packet body using specified nonce]
```

Packet Body plaintext is a MsgPack array with two elements. First element is a numeric message type, like 11. Second element is any MsgPack item. The second element maybe null. Applications are generally discouraged from using raw messages. Unreliable notifications are a better option.


### Reliable Notification

Notifications are messages with a type, and a JSON attachment. They receive an acknowledgement in reply. They are implemented on top of unreliable raw messages. Raw message type is 10 and message body is an array:

```json
[
  (anything) ID, // nonce to identify this unique notification
  (string) type, // name of notification
  (anything) body, // any msgpackable data
]
```

Acks are message type 11. Message body is the value of ID. Notifications maybe redelivered if an Ack is not received promptly.

### Unreliable Notification

Notifications containing no "i" property or an "i" property whose value is null must not be acknowledged.


### RPC Request

Pink supports very simple compact RPC. Data in request and response must fit within a single UDP packet each. Coffeescript pseudocode:

```coffeescript
nonce = # random compact id value to tie response to request
notification 'rpc.req', [method_name, nonce, named_args_object], (err)->
  if err
    # timeout or something like that
  else
    # delivered and we can expect a response notification soon
```

Reply:

```coffeescript
pink.on 'rpc.req', ([method_name, nonce, args_object])->
  error = null
  try
    reply = rpc_methods[method_name](args_object)
  catch err
    error = err.toString()
    reply = null
  reply_object = [error, reply]
  notification 'rpc.res', [nonce, reply_object], (err)->
    # timeout or something like that if err isn't null
```


### Long form RPC

When RPC requests or responses are too large to fit in a UDP4 packet we transport the the args_object, reply, or both using Streams. When request arguments are too long, the request args_object is msgpacked and written to a Stream, and that stream is passed as the args_object. Responder similarly replies using a stream containing a msgpack of reply_object when it would otherwise be too long.

Users should try not to use RPC to deliver large pieces of data like this, because the request and response is buffered entirely in to memory during transmission. Implementations may impose a limit on size, with a suggested limit of 64kb. Library users should instead pass streams directly as arguments and responses in their application logic.


### Invite Codes

When building decentralised darknets, invite codes are a familiar way for users to provide some preshared information. Pink includes a built in format for invite codes to make this easy.

Invite codes are the Base58 encoded string result of `checksum + msgpack(compact ip with publicKey)`. The checksum is a Blake2s digest of the msgpack part, with a length of 1 byte.

When unpacking a code, the checksum is verified and used to provide UI feedback as the code is entered correctly. Invite codes contain enough information to Pulse request the inviter. Once pulsed, the two nodes can communicate freely, if they choose to. Applications can then organise longer term friendships or announce their new friend to the local mesh.


### Stream

Streams transmit in a single direction and are used to reliably transmit long pieces of information in order. They are intended to run at low priority similar to uTP, for background sync tasks and general low priority file transmission.

#### Stream Setup

Streams must be fully setup before any chunks can be transmitted. This is done via RPC using a msgpack extension. Extension code is 0x1 and data is a uint8, uint16be, or uint32be integer containing a unique `stream_id` number. `stream_id` can be transmitted again to reference the same stream. Stream ID's must not be reused until the recipient has acked every chunk.

Streams can be included in RPC requests and responses, but  be used in notifications or pulses.

#### Stream Closing

Receiver peer may request a stream be ended early by notifying sender, which requests all chunks not yet transmitted be cleared and the next chunk be made the final false chunk. Receiver peer must still ack all chunks received after sending this request, even if it doesn't do anything with them.

```coffeescript
notify sender, "stream.end", {id: stream_id}
```

#### Stream Chunk

Chunks of up to around 450* bytes are sent as a raw message of type
20 with a msgpacked array message:

```json
[
  stream_id (integer),
  sequence_id (integer),
  time (integer), // milliseconds since unix epoch
  chunk_data (octets buffer)
]
```

which are acknowledged by a raw message type 21

```json
[
  stream_id,
  read_length (integer), // flow control: how many more bytes would recipient like
  [[sequence_id, timediff], [sequence_id, timediff], ...] // sequence ids to ack
]
```

Recipient can transmit a `read_length < 1` to tell sender to pause transmission. Recipient may then transmit another ack with no sequence_ids to update read_length with a positive integer to restart transmission. See section Stream Delivery Rules. `read_length` informs sender how many free bytes are in recipient's buffer, for simple flow control. Each ack includes a timediff value which is Local Time - Chunk `time` in milliseconds. This value maybe negative due to peer computers having different inaccurate time. Timediff is used for delay-based congestion control.

When the stream is complete, the sender finally sends a packet where chunk_data is `false`.

#### Stream Delivery Rules

Simple flow and congestion control by a combination of recipient read buffer remaining size, and delay-based congestion control similar to uTP. Pink streams are designed for low priority traffic like background file syncing.

... TBC


### Get Peers

Request to peer of type "pink.getpeers" with named arguments `max` and optionally `ids`. When ID is omitted, network responds with an array of compact addresses including public keys. When `ids` is included, it is an array of publicKeys (as buffers) of peers you are specifically interested in. In both cases the responder should sort it's response list so the earlier elements are more up to date.

### Security considerations

Pink packets are protected from tampering and corruption by the MAC on their encrypted bodies, which verify the message integrity as well as providing some proof the sender did possess their curve25519 secret key.

Pink does not make any effort to disguise the length of packets. Passive network traffic observers maybe able to infer the type of packet or some aspects of user activity by observing the timing, frequency, and length of packets. A paranoid implementation might include extra garbage data in msgpacked parts, and/or intentionally send extra corrupt packets to confuse passive observers.

Pink does not prevent replay attacks, so apps built on pink should take care to do this themselves if it is necessary.

The tweetnacl-js library used in this reference implementation has not been independently reviewed and may contain bugs.
