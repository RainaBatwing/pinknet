## Pink Network

WARNING: This project is a crazy work in progress and is not suitable for use in any way yet.

Pink is a protocol and library for building networked apps using p2p technologies and no centralised servers. Project Goals:

 1. Provide a simple interface which beginner coders can use to create social apps safely and securely
 2. Discourage the use of servers by providing an easier and free p2p alternative for app builders
 3. Keep all content private using strong encryption built on curve25519 and xsalsa20 through the tweetnacl library
 resilience
 4. Cleanly transition between network addresses as peers move between cellular and wired networks with minimal interuption
 5. All packets should be indistinguishable from random bytes to passive observers for net neutrality

Pink Network runs entirely over IPv4 UDP, with a goal of supporting IPv6 in the future, and maybe other transports like Bluetooth 4 or WiFi Direct. Pink is inspired in some ways by Telehash, but is not an implementation of it.

Pink encodes packets as compact binary blobs, and uses MessagePack where possible, enabling compact transmission of binary including crypto keys, nonces, and chunks of files. All references to JSON in this document are illustrative, and are always transmitted using msgpack encoding.

For information on the protocols planned to be implemented, check out the other .md files in this folder.


### Security considerations

Pink packets are protected from tampering and corruption by the MAC on their encrypted bodies, which verify the message integrity as well as providing some proof the sender did possess their curve25519 secret key.

Pink does not make any effort to disguise the length of packets. Passive network traffic observers maybe able to infer the type of packet or some aspects of user activity by observing the timing, frequency, and length of packets. A paranoid implementation might include extra garbage data in msgpacked parts, and/or intentionally send extra corrupt packets to confuse network observers.

Pink does not prevent replay attacks, so apps built on pink should take care to do this themselves if it is necessary.

The tweetnacl-js library used in this reference implementation has not been independently reviewed and may contain bugs.
