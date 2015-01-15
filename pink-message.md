Pink Messages are transmitted through Pink Link. This document specifies the higher level messages carried through Pink's lower link layer.

Messages take this form:

```json
[label,data,data,data,...]
```

`label` is a string, data can be anything, and there can be zero data elements. This is the basic structure of all standard messages. Implementations should silently ignore anything which doesn't follow this format.

### RPC ###

RPC requests use label "rpc" and form:

```json
["rpc", unique callback id, "method-name", [argument-list] or Stream]
```

RPC responses use label "ret" and form:

```json
["ret", unique callback id from request, [error, return value] or Stream]
```

If either the request arguments or the return array are Streams, they should be read and parsed with msgpack, and should contain the same data it would replace. This form should only be used when the values would be too large to fit in a single packet. Users who wish to transmit large data should instead return or pass in Streams themselves, so they can stream data instead of buffering the entire object in to memory.

### Notifications ###

Notifications use label "notify" and have this format:

```json
["notify", "notification-label", [argument-list] or Stream]
```

### Streams ###

#### Stream Setup ####

Streams are implemented as msgpack5 extensions, with extension id 1. The data in the extension chunk is itself a msgpacked value, like a number or string, which is the stream-id value used in later packets, and is specific to that peer's implementation. Streams are uni-directional, transmitting data from whoever sent the stream to whoever received it in an RPC or Notification. To setup a bidirectional channel, use an RPC request, pass an outgoing stream as an argument and have it return another stream to send back data.

#### Stream Keepalive and Timeout ####

Implementations may expire streams after one hour of inactivity by default, though some applications may want to configure this for shorter or longer durations, to enable long running apps where devices maybe switched off or disconnected for long periods, without special reconnection logic. Servers might want shorter periods to conserve ram, though nobody should write servers because servers are trash.

Receivers should send one keepalive state update at least every 10 seconds to keep alive connections and recover from stalls.

#### Formats ####

Stream Data Chunk:

```json
["chunk", stream_id, sequence_id, chunk_data]
```

Sent from sender to receiver, sequence_id is an integer beginning with 0 and going up by 1 for each data chunk. Chunks are reassembled in order of sequence id and converted to a stream-like interface. When the stream is complete, a chunk is sent where the chunk_data is set to null `null`. All chunks with data are represented as a Buffer type.

Receiver state update:

```json
["notify", "stream-state", [stream_id, {read: int, seq: number}]]
```

`read` defines the buffer size on the receiver in bytes - how many more bytes would the receiver like to receive. This is advisory. Peers must not ack packets for data they cannot buffer. `seq` can be any incrementing number, with the current time being a sensible option.

Sender peer will subtract bytes from the `read` length as chunks are acked until it reaches zero, and stop sending at that point. The receiver should provide a reasonably large buffer and update the read value frequently enough to keep data flowing.

`"stream-state"` are used as keepalives from receiver to sender peer. The acks for those messages provide reverse keepalives.

```json
["notify", "stream.close", [stream_id]]
```

sent from receiver peer to sender peer to immediately close the stream.

  -- <3 Raina
