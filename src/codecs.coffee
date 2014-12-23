# collection of codecs for encoding and decoding network packets
help = require './helpers'
address = require './address'
nacl = help.nacl
msgpack = help.msgpack

# install msgpack extensions
address.extendMsgpack(msgpack)

codecs = {}

# apply cloak to some data up to 32 bytes
pulseCloak = (input, nonce, destinationPublicKey)->
  cloak = help.blake(Buffer.concat([nonce, destinationPublicKey]), input.length)
  # author pubkey needs to be uncloaked via xor
  output = new Buffer(input.length)
  # author obscured via xor using digest as an awful one time pad
  output[idx] = input[idx] ^ cloakByte for cloakByte, idx in cloak
  return output

# codec to encode and decode pulse packets
codecs.pulse =
  # encode a new pulse in to a packet to send over UDP directly
  encode:({meta, network, to})->
    to = address.parse(to)
    meta = {} if meta is null
    throw new Error("cannot encode pulse to address with no publicKey") unless to.publicKey
    throw new Error("meta must be an object") unless typeof(meta) is 'object'
    nonce = help.randomBytes(nacl.box.nonceLength)
    cloakedKey = pulseCloak(network.publicKey, nonce, to.publicKey)
    plaintext = msgpack.encode(meta).slice(0)
    ciphertext = nacl(nacl.box, plaintext, nonce, to.publicKey, network.secretKey)
    packet = Buffer.concat([nonce, cloakedKey, ciphertext])
    return packet

  # decode a UDP packet pulse object, if it is a valid one, otherwise returns false
  decode:(buffer, {network, sender})->
    # fail if not long enough to be decodable
    return false if buffer.length <= nacl.box.nonceLength + nacl.box.publicKeyLength

    nonce = buffer[0... nacl.box.nonceLength]
    cloakedKey = buffer[nacl.box.nonceLength... nacl.box.nonceLength + nacl.box.publicKeyLength]
    ciphertext = buffer[nacl.box.nonceLength + nacl.box.publicKeyLength...]
    # uncloak sender's publicKey
    senderPublicKey = pulseCloak(cloakedKey, nonce, network.publicKey)
    # use their specified publicKey to try and decode message
    plaintext = nacl(nacl.box.open, ciphertext, nonce, sender.publicKey, network.secretKey)
    return false if plaintext is false
    try
      meta = msgpack.decode(plaintext)
      if sender.publicKey.toString('hex') isnt senderPublicKey.toString('hex')
        sender = sender.copy()
        sender.publicKey = senderPublicKey
      return { meta, sender }
    catch err
      return false

# raw message packet format
codecs.message =
  # encode a raw message
  encode:({to, type, data, network})->
    to = address.parse(to)
    nonce = help.randomBytes(nacl.box.nonceLength)
    plaintext = msgpack.encode([type, data]).slice(0)
    ciphertext = nacl(nacl.box, plaintext, nonce, to.publicKey, network.secretKey)
    Buffer.concat([nonce, ciphertext])

  # decode a raw message
  decode:(buffer, {network, sender})->
    return false unless sender.publicKey
    nonce = buffer.slice(0, nacl.box.nonceLength)
    ciphertext = buffer.slice(nacl.box.nonceLength)
    plaintext = nacl(nacl.box.open, ciphertext, nonce, sender.publicKey, network.secretKey)
    return false unless plaintext
    obj = msgpack.decode(plaintext)
    return false unless obj.length >= 2
    return {
      type: obj[0]
      data: obj[1]
      sender: sender
    }

module.exports = codecs
