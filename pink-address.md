## Pink Addresses and Invite Codes ##

Pink defines an address scheme for internal use within apps, as well as an invite code encoding. Pink Addresses have 3 formats: URI, Invite Code, and Binary.

### URI ###

```
udp4://publickey@ip:port/
udp6://publickey@ip:port/
```

`publickey` is hex encoded. The public key is essential to the operation of Pink Link and should not be omitted.

### Invite Code ###

```
base58 encode (
  [1b checksum] [address binary encoded]
)
```

Invite Codes are an address representation which is designed to be more compact to enter than a URI, and error-resistent. They are base58 encoded, so they care case sensitive, but they do not use characters that appear similar like zero and capital o, or 1 and lowercase L. The checksum is a blake2s digest of the address binary encoded, with a digest length of 1. User interfaces are encouraged to check the validity of entered invites as the user types them, and provide feedback if part is mistyped.

UX considerations:

Invite Codes are designed to resemble the codes used by webapps like Gmail and small social networks. When used wisely, they create a sense of exclusivity which can get people excited about a new app. Invite Codes provide a way to introduce a new user to a network without needing any centralised bootstrap infrastructure.

Apps using invite codes may want to consider putting an artificial limit on how frequently users can invite friends, to encourage users to spend them wisely, on people likely to be excited about your project, and to announce to friends that they have invites available.

### Binary ###

```coffee
# IPv4 address
[
  4, # address type
  Buffer(1, 2, 3, 4), # each of the 4 octets in an ipv4 address 1.2.3.4
  5678 # port number
]
# IPv6 address
[
  6, # address type
  [false, 1, 2, 3, 4, 5, 6], # each of the groups in an ipv6 address ::1:2:3:4:5:6
  5678 # port number
]
```

The above structures are MessagePacked, and designed to pack compactly for the types of data most often represented. IPv6 addresses are represented as plain arrays because they often contain low numbers, which can pack to a single byte, while ipv4 addresses contain more evenly distributed numbers and are most compactly stored in a Buffer / byte array. In IPv6 the special false value unpacks to an empty double colon, which is part of the IPv6 textual address spec. :: expands out in to as many ...0:0:0:0... sections as needed to create a full length address. false packs to a single byte.

  -- <3 Raina
