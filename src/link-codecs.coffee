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
  encode:({data, network, to})->
    to = address.parse(to)
    throw new Error("cannot encode id packet without to.publicKey") unless to.publicKey
    throw new Error("data must be a buffer") unless Buffer.isBuffer(data)
    nonce = help.randomBytes(nacl.box.nonceLength)
    cloakedKey = applyCloak(network.publicKey, nonce, to.publicKey)
    ciphertext = nacl(nacl.box, data.slice(0), nonce, to.publicKey, network.secretKey)
    Buffer.concat([nonce, cloakedKey, ciphertext])

  # decode a UDP packet pulse object, if it is a valid one, otherwise returns false
  decode:(buffer, {network, sender})->
    # fail if not long enough to be decodable
    return false if buffer.length <= nacl.box.nonceLength + nacl.box.publicKeyLength

    nonce = buffer[0... nacl.box.nonceLength]
    cloakedKey = buffer[nacl.box.nonceLength... nacl.box.nonceLength + nacl.box.publicKeyLength]
    ciphertext = buffer[nacl.box.nonceLength + nacl.box.publicKeyLength...]
    # uncloak sender's publicKey
    senderPublicKey = applyCloak(cloakedKey, nonce, network.publicKey)
    # use their specified publicKey to try and decode message
    plaintext = nacl(nacl.box.open, ciphertext, nonce, senderPublicKey, network.secretKey)
    return false if plaintext is false
    try
      if sender.publicKey.toString('hex') isnt senderPublicKey.toString('hex')
        sender = sender.copy()
        sender.publicKey = senderPublicKey
      return { data: plaintext, sender }
    catch err
      return false

# raw message packet format
codecs.compact =
  # encode a raw message
  encode:({to, type, data, network})->
    to = address.parse(to)
    nonce = help.randomBytes(nacl.box.nonceLength)
    throw new Error("data must be a buffer") unless Buffer.isBuffer(data)
    throw new Error("to publicKey incorrect length") unless to.publicKey.length is nacl.box.publicKeyLength
    throw new Error("network secretKey incorrect length") unless network.secretKey.length is nacl.box.secretKeyLength
    ciphertext = nacl(nacl.box, data.slice(0), nonce, to.publicKey, network.secretKey)
    Buffer.concat([nonce, ciphertext])

  # decode a raw message
  decode:(buffer, {network, sender})->
    return false unless sender.publicKey
    nonce = buffer.slice(0, nacl.box.nonceLength)
    ciphertext = buffer.slice(nacl.box.nonceLength)
    plaintext = nacl(nacl.box.open, ciphertext, nonce, sender.publicKey, network.secretKey)
    return false unless plaintext
    return { data: plaintext, sender }

module.exports = codecs
