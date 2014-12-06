## Pink Network

Pink Network provides a common medium through which darknet peers can send each other notifications and streams (files) with optional reliability and transmission of small app-specific metadata inside ACKs for RPC-like messaging.

Peers are addressed by their curve25519 public key (Uint8Array or base58 string) and the network layer manages keeping track of those users internet address.

Pink Network runs entirely over IPv4 UDP, with a goal of supporting IPv6 in the future, and maybe other transports like Bluetooth 4 or WiFi Direct.

Pink Network encodes packets as compact binary blobs, and uses MessagePack where convenient, enabling compact transmission of binary like crypto keys and nonces, when compared to JSON. In the protocol below some structures are represented as JSON - but in the real protocol these are encoded with MsgPack, not JSON.


## Draft V1 Protocol

### Pulse Request

Peers send each other pulse packets to keep NAT holes open, and keep each other updated on their current IP address and port. Pulses also measure latency and compare local clocks, allowing consensus-based shared time to be implemented in the future. A successful pulse must occur before peers communicate using any other packet type, effectively authenticating the connection. Peers should pulse any others they intend to communicate actively with at least once per minute. Peers should also pulse each other if their packets aren't being acked promptly, to recover from IP changes when shifting between different networks.

```
[24 byte nonce] [32 byte cloaked public key]
[MsgPack bytes encrypted with nacl.box with specified nonce]
```

MsgPack bytes must encode an object. This object can be empty, but a reasonable implementation might include packet creation time for latency measurement, and a unique identifier to track the pulse response to a specific pulse request.


### Pulse Response

Pulse response includes a new random 24 byte nonce, and the responder's
curve25519 public key.

```
[24 byte nonce] [32 byte cloaked public key]
[MsgPack bytes encrypted with nacl.box with specified nonce]
```

Pulse response contains the same object sent in the request, merged with:

```json
{
  "time": (integer) time in milliseconds since unix epoch
  "origin": (compact ip buffer) internet address of original pulse, in compact ip format
}
```

Peers must not respond to pulses which contain an `origin` property or don't have a valid JSON object attached, to avoid loops.


### Public Key Cloaking

Public keys are transmitted unencrypted in pulse packets. To increase difficulty profiling PinkNet user traffic, public keys are cloaked by XORing the public key bytes in the plaintext part of a pulse packet with a 32 byte BLAKE2s digest of the packet's nonce concatenated with
the intended recipient's public key. A casual observer who knows no members's public key will not be able to determine anyone's public key purely from their PinkNet traffic.

Cloaking is not intended to provide total privacy. It's primary use is to help frustrate network admins attempting to profile PinkNet traffic and filter or delay it by keeping packet appearance random-like. Planning for a future with poor net neutrality. Implementations may choose to pad their pulse packets with random data to further frustrate packet length based profiling.


### Compact IP Buffer Format

When the network needs to transmit an IP address, it uses a byte buffer with binary data stored compactly.

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
  [false, 1, 2, 3, 4, 5], // each of the 4 octets in an ipv4 address ::1:2:3:4:5
  5678 // port number
]
```

Different address types maybe implemented in the future. Implementations should skip over address types they don't understand where possible. IPv6 addresses are stored as plain arrays, with the `false` special value to indicate a :: section. IPv6 encoding is experimental and not being actively tested yet. Both types can have an additional Buffer after the port, containing a publicKey for that address.

### Unreliable Raw Message

Raw messages are used for all other types of communication and take this form:

```
[24 byte nonce] [nacl.box of packet body using specified nonce]
```

Packet Body plaintext is a MsgPack array with two elements. First element is a string message type, like "appname.poke". Second element is any MsgPack item. The second element maybe null.


### Reliable Notification

Notifications are messages with a type, and a JSON attachment. They receive an acknowledgement in reply. They are implemented on top of unreliable raw messages. Raw message type is "N" and message body is an object:

```json
{
  "i":msgpack compatible value - a unique nonce for this notification,
  "t":"notification type name",
  "a":attachment value
}
```

Acknowledgments are message type "NAck". Message body is the value of "i" packed with MsgPack. Notifications maybe redelivered if a NAck is not received promptly. PinkNet implementations should keep track of recent id nonce strings to avoid repeating notifications to higher levels.

### Unreliable Notification

Notifications containing no "i" property or an "i" property whose value is null must not be acknowledged.


### RPC Request

Pink supports very simple compact RPC. Data in request and response must fit within a single UDP packet each. Coffeescript psuedocode:

```coffeescript
nonce = # random compact id value to tie response to request
notification 'rpc.req', [method_name, nonce, arguments...], (err)->
  if err
    # timeout or something like that
  else
    # delivered and we can expect a response notification soon
```

Reply:

```coffeescript
pink.on 'rpc.req', (method_name, nonce, args...)->
  reply = call_method(method_name, args...)
  notification 'rpc.res', [nonce, reply], (err)->
    # timeout or something like that if err isn't null
```

TBA: spec out streams as arguments and return values in RPC, so node apps can
pass around Readable, Writable, and Duplex streams easily.


### Invite Codes

When building decentralised darknets, invite codes are a familiar way for users to provide some preshared information. Pink includes an official format for invite codes, so you can simply and easily build toy p2p apps.

Generating an invite code:

```json
[
  (compact ip format) internet address of creator,
  (buffer) creator's network public key
]
```

This code is encoded with MsgPack, then the result is hashed with Blake2s digest length set as 1 byte. This byte is then prepended to the invite code bytes as a checksum.

When unpacking a code, the checksum is verified and used to provide UI feedback as the code is entered correctly. Invite codes contain enough information to Pulse request the inviter. Once pulsed, the two nodes can communicate freely. Applications can then organise longer term friendships or announce their new friend to the local mesh.


### Stream

Streams are single directional and used to reliably transmit long pieces of information in order. They implement simple delay-based congestion control similar to uTP.

#### Stream Setup

```coffeescript
# stream_info is any information being passed to the recipient to explain
# the purpose or contents of the stream
request "stream.open", stream_info, (err, response)->
  unless err
    stream_id = response.id # unique identifier for this stream
    # stream is open now
  else
    # endpoint refused stream
```

TODO: decide if stream setup should be a feature of RPC requests

#### Stream Closing

When there is no more data to send to a recipient, stream should be closed:

```coffeescript
notification "stream.close", {id: stream_id}
```

Recipient may also send a pink.stream.close notification to source if no longer interested.

#### Stream Chunk

Chunks of up to around 450* bytes are sent as a raw message of type
'stream.chk' with an array message:

```json
[
  stream_id (integer),
  sequence_id (integer),
  time (integer), // milliseconds since unix epoch
  chunk_data (octets buffer)
]
```

which are acknowledged by a raw message type 'stream.ack'

```json
[
  stream_id,
  read_length (integer), // flow control: how many more bytes would recipient like
  [[sequence_id, timediff], [sequence_id, timediff], ...] // sequence ids to ack
]
```

Recipient can transmit a `read_length < 1` to tell sender to pause transmission. Recipient may then transmit another ack with no sequence_ids to update read_length with a positive integer to restart transmission. See section Stream Delivery Rules. `read_length` informs sender how many free bytes are in recipient's buffer, for simple flow control. Each ack includes a timediff value which is Local Time - Chunk `time` in milliseconds. This value maybe negative due to peer computers having different inaccurate time.

#### Stream Delivery Rules

Simple flow and congestion control by a combination of recipient read buffer remaining size, and delay-based congestion control similar to uTP. Pink streams are designed for low priority traffic like background file syncing.




### Get Peers

Request to peer of type "pink.getpeers" with a numeric attachment. Attachment indicates maximum number of peers requestor would like in response. Response is a base64 encoded binary blob:

```
4 [4 octets ipv4 address] [uint16be port number]
4 [4 octets ipv4 address] [uint16be port number]
4 [4 octets ipv4 address] [uint16be port number]
...
```


### Get Peer

Request to peer of type "pink.getpeer" with public key of target peer as attachment, ...


### Security considerations

Pink messages are protected by the MAC on their encrypted bodies, which verify the message integrity as well as providing proof the sender did possess your peer's curve25519 secret key.

Pink does not prevent replay attacks, so peers built on Pink should implement suitable protections in their application logic.
