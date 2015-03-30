# collection of codecs for encoding and decoding network packets
help = require './helpers'
address = require './address'
nacl = help.nacl

codecs = {}

# apply cloak to input using nonce and key to generate cloak
applyCloak = (input, nonce, key)->
  cloak = help.blake(Buffer.concat([nonce, key], nonce.length + key.length), input.length)
  # author pubkey needs to be uncloaked via xor
  output = new Buffer(input.length)
  # author obscured via xor using digest as an awful one time pad
  output[idx] = input[idx] ^ cloakByte for cloakByte, idx in cloak
  return output

# codec to encode and decode pulse packets
codecs.id =
  # encode a new pulse in to a packet to send over UDP directly
  encode:({contents, identity, peer})->
    # to = address.parse(to)
    throw new Error("cannot encode id packet without peer publicKey") unless peer.publicKey
    throw new Error("contents must be a buffer") unless Buffer.isBuffer(contents)
    nonce = help.randomBytes(nacl.box.nonceLength)
    cloakedKey = applyCloak(identity.publicKey, nonce, peer.publicKey)
    ciphertext = nacl(nacl.box, contents.slice(0), nonce, peer.publicKey, identity.secretKey)
    Buffer.concat([nonce, cloakedKey, ciphertext])

  # decode a UDP packet pulse object, if it is a valid one, otherwise returns false
  decode:({packet, identity})->
    # fail if not long enough to be decodable
    return false if packet.length <= nacl.box.nonceLength + nacl.box.publicKeyLength

    nonce = packet[0... nacl.box.nonceLength]
    cloakedKey = packet[nacl.box.nonceLength... nacl.box.nonceLength + nacl.box.publicKeyLength]
    ciphertext = packet[nacl.box.nonceLength + nacl.box.publicKeyLength...]
    # uncloak sender's publicKey
    senderPublicKey = applyCloak(cloakedKey, nonce, identity.publicKey)
    # use their specified publicKey to try and decode message
    plaintext = nacl(nacl.box.open, ciphertext, nonce, senderPublicKey, identity.secretKey)
    return false if plaintext is false
    return { contents: plaintext, author: senderPublicKey }

# raw message packet format
# codecs.compact =
#   # encode a raw message
#   encode:({peer, type, contents, identity})->
#     to = address.parse(peer)
#     nonce = help.randomBytes(nacl.box.nonceLength)
#     throw new Error("contents must be a buffer") unless Buffer.isBuffer(contents)
#     throw new Error("peer publicKey incorrect length") unless peer.publicKey.length is nacl.box.publicKeyLength
#     throw new Error("network secretKey incorrect length") unless identity.secretKey.length is nacl.box.secretKeyLength
#     ciphertext = nacl(nacl.box, contents.slice(0), nonce, peer.publicKey, identity.secretKey)
#     Buffer.concat([nonce, ciphertext])
#
#   # decode a raw message
#   decode:({packet, identity, author})->
#     return false unless author.publicKey
#     nonce = packet.slice(0, nacl.box.nonceLength)
#     ciphertext = packet.slice(nacl.box.nonceLength)
#     plaintext = nacl(nacl.box.open, ciphertext, nonce, author.publicKey, identity.secretKey)
#     return false unless plaintext
#     return { contents: plaintext, author: author }

module.exports = codecs
