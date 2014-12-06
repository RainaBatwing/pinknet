nacl = require('tweetnacl')
base58 = require('bs58')
msgpack = require('msgpack5')()
blake2s = require('blake2s-js')
udp = require('dgram')
util = require('util')
url = require('url')
crypto = require('crypto')

# quick shortcut version of blake2s digest
blakeDigest = (data, args...)->
  digestor = new blake2s(args...)
  digestor.update(new Buffer(data))
  return new Buffer(digestor.digest())
# convert buffers to Uint8Array - useful for feeding tweetnacl-js
asByteArray = (input)->
  if Buffer.isBuffer(input)
    new Uint8Array(input)
  else
    input
# convert Uint8Array to node Buffer - useful for everything except tweetnacl-js
asBuffer = (input)->
  if input and (input.BYTES_PER_ELEMENT? or input.map)
    new Buffer(input)
  else
    input

# Generate and parse base58 encoded invite codes, encoding an IP and Port and
# optionally also a publicKey. Invite codes provide an easy way to bootstrap
# purely p2p networks, without resorting to any centralised system.
class PinkInvite
  constructor:(opts)->
    @address = opts.address or new PinkAddress(opts)
  toString:()->
    addr = @address.toBuffer()
    check = blakeDigest(addr, 1)
    base58.encode(Buffer.concat([check, addr]))
# checks if PinkInvite code is valid
PinkInvite.verify = (inviteCode)->
  try
    bytes = base58.decode(inviteCode)
  catch err
    return false # decode failed - probably invalid characters
  return blakeDigest(bytes.slice(1), 1)[0] == bytes[0]
# parse a PinkInvite
PinkInvite.parse = (inviteCode)->
  bytes = base58.decode(inviteCode)
  return false unless blakeDigest(bytes.slice(1), 1)[0] == bytes[0]
  addr = PinkAddress.parse(asBuffer bytes.slice(1))
  # console.log msgpack.decode(bytes.slice(1))
  # console.log addr
  return false unless addr
  new PinkInvite(address: addr)


# Contactable Pink Network Address
# Represents an IP:Port combination with optional public key both as friendly
# URIs and as a compact binary representation for wire protocols
class PinkAddress
  constructor:(opts)->
    #console.log "construct:", opts
    if typeof(opts) is 'string'
      {hostname: @ip, port: @port, protocol: @protocol, auth: @publicKey} = url.parse(opts)
      throw new Error("unsupported protocol #{@protocol} in #{opts}") unless @protocol is 'udp:'
    else if opts.ip and opts.port
      {@ip, @port, @publicKey} = opts
      @protocol = 'udp:'
    else
      throw new Error("Cannot parse #{Object.prototype.toString.call(opts)}")
    # convert types where needed
    @port = parseInt(@port) if typeof(@port) isnt 'number'
    if @publicKey
      @publicKey = asBuffer(base58.decode(@publicKey)) if typeof(@publicKey) is 'string'
      throw new Error("publicKey cannot be #{Object.prototype.toString.call(@publicKey)}") unless Buffer.isBuffer(@publicKey)

  # copy address
  copy:({includePublicKey})->
    new @constructor({@ip, @port, @publicKey})

  # convert to a compact msgpacked representation
  toBuffer:()->
    if @ip.indexOf(':') isnt -1
      type = 6
      compact_ip = []
      for segment in @ip.split(/\:\./)
        num = if segment == ""
          false
        else
          parseInt(segment, 16)
        compact_ip.push num
    else
      type = 4
      digits = []
      digits[idx] = parseInt(octet) % 256 for octet, idx in @ip.split(/\./, 4)
      compact_ip = new Buffer(digits)
    data = [type, compact_ip, @port]
    throw new Error("publicKey must be a Buffer or null") unless @publicKey is null or Buffer.isBuffer(@publicKey)
    data.push(@publicKey) if @publicKey
    msgpack.encode(data).slice()

  # URI form
  toString:()->
    auth = base58.encode(@publicKey) if @publicKey
    url.format(slashes:true, protocol: @protocol, hostname: @ip, port: @port, auth: auth)

  # test equality
  equals:(other)->
    other = PinkAddress.parse(other) unless other.constructor is @constructor
    return false if @publicKey and other.publicKey and @publicKey.toJSON().toString() != other.publicKey.toJSON().toString()
    return @ip == other.ip and @port == other.port and @protocol == other.protocol

# parse compact binary representation
PinkAddress.parse = (buffer)->
  return buffer if buffer.constructor is PinkAddress
  return new PinkAddress(buffer) unless Buffer.isBuffer(buffer)
  [type, ip_data, port, publicKey] = msgpack.decode(buffer)
  # reconsititute IP string
  seperator = {4: '.', 6: ':'}[type]
  base = {4: 10, 6: 16}[type]
  return false unless seperator # unknown type
  # convert compact_ip_buffer from whatever it is to an array
  compact_ip = []
  compact_ip[idx] = digit for digit, idx in ip_data
  ip = compact_ip.map((num)->
    if num is false
      ''
    else
      num.toString(base)
  ).join(seperator)
  #console.log {ip, port, publicKey}
  new PinkAddress({ip, port, publicKey})


# Pink Pulse packet interface
# Constructor accepts
# class PinkPulse
#   constructor:({@source, @destination, @meta, @origin, noInit, packetNonce})->
#     now = Date.now()
#     @meta = {} unless typeof(meta) is 'object'
#     @nonce = packetNonce || new Buffer(nacl.randomBytes(nacl.box.nonceLength))
#     unless noInit
#       @meta.ot = now
#       @meta.id = new Buffer(nacl.randomBytes(PinkPulse.idLength))
#     @isReply = @meta.origin != null
#     if @isReply
#       # roundtrip latency in milliseconds
#       @latency = now - @meta.ot
#       # time difference between local and remote peer
#       @outgoingLatency = @meta.time - @meta.ot
#       # try to very roughly guess time difference between local and remote peer
#       # this would only work if latency was symetrical. it's not.
#       # maybe useful to alert users if their clock seems extremely wrong
#       @timeOffset = @outgoingLatency - (@latency / 2)
#
#   # generate buffer version ready for transmission
#   toBuffer:(network)->
#     return false unless @source and @destination
#     return false if nacl.verify(asByteArray(network.publicKey), asByteArray(@destination))
#     cipherMeta = asBuffer(nacl.box(
#       asByteArray(msgpack.encode(@meta)),
#       asByteArray(@nonce),
#       asByteArray(network.secretKey),
#       asByteArray(@destination)
#     ))
#     # originators public key is cloaked to make traffic more random-looking
#     cloakedSource = PinkPulse.cloak(@source, @nonce, @destination)
#     Buffer.concat([@nonce, cloakedSource, cipherMeta])
#
#   # generate a reply packet
#   reply:(metaOverrides)->
#     return false if @isReply # replying to a reply is not allowed
#     replyMeta = {}
#     replyMeta[key] = value for key, value of @meta
#     replyMeta.origin = @origin.compact()
#     replyMeta.time = Date.now()
#     replyMeta[key] = value for key, value of metaOverrides
#     new PinkPulse(
#       source: @destination, destination: @source,
#       meta: replyMeta, noInit: true)
#
#   # debug helper
#   inspect:()->
#     source = base58.encode(new Buffer(@source))[0...8]
#     dest = base58.encode(new Buffer(@destination))[0...8]
#     meta = util.inspect(@meta)
#     "<Pulse #{source}... -> #{dest}... #{meta}>"
# PinkPulse.idLength = 8
# # apply cloak to some data up to 32 bytes
# PinkPulse.cloak = (input, nonce, pubkey)->
#   cloak = blakeDigest(Buffer.concat([nonce, pubkey]), input.length)
#   # author pubkey needs to be uncloaked via xor
#   output = new Buffer(input.length)
#   # author obscured via xor using digest as an awful one time pad
#   output[idx] = input[idx] ^ cloakByte for cloakByte, idx in cloak
#   return output
# # parse a received pulse
# PinkPulse.parse = (data, network)->
#   # fails if not long enough to plausably be a pulse
#   return false if data.length < nacl.box.nonceLength + nacl.box.publicKeyLength + nacl.box.overheadLength + 1
#   nonce = data.slice(0, nacl.box.nonceLength)
#   authorCloakedKey = data.slice(nacl.box.nonceLength, nacl.box.publicKeyLength)
#   metaCiphertext = data.slice(nacl.box.nonceLength + nacl.box.publicKeyLength)
#   authorKey = PinkPulse.cloak(authorCloakedKey, nonce, network.publicKey)
#
#   # TODO: Cache shared key for these box operations
#   meta = nacl.box.open(new Uint8Array(metaCiphertext), new Uint8Array(nonce), authorKey, network.secretKey)
#   return false unless meta # if decrypt failed, give up - it's not for us or not a pulse
#   try
#     meta = msgpack.decode(meta)
#   catch err
#     return false # if msgpack fails it's corrupt
#   return false unless typeof(meta) is 'object'
#   return new PinkPulse(
#     source: authorKey, destination: network.publicKey,
#     noInit: true, meta: meta, packetNonce: nonce)

# Parser, Generator, and other utilities for Pulse packets
PinkPulseUtils =
  # apply cloak to some data up to 32 bytes
  cloak:(input, nonce, pubkey)->
    cloak = blakeDigest(Buffer.concat([nonce, pubkey]), input.length)
    # author pubkey needs to be uncloaked via xor
    output = new Buffer(input.length)
    # author obscured via xor using digest as an awful one time pad
    output[idx] = input[idx] ^ cloakByte for cloakByte, idx in cloak
    return output
PinkPulse =
  decode:(buffer, {network, sender})->
    ba = asByteArray; buff = asBuffer
    # fail if not long enough to be plausable
    return false if buffer.length <= nacl.box.nonceLength + nacl.box.publicKeyLength

    nonce = buffer[0... nacl.box.nonceLength]
    cloakedKey = buffer[nacl.box.nonceLength... nacl.box.nonceLength + nacl.box.publicKeyLength]
    ciphertext = buffer[nacl.box.nonceLength + nacl.box.publicKeyLength...]
    # uncloak sender's publicKey
    sender.publicKey = PinkPulseUtils.cloak(cloakedKey, nonce, network.publicKey)
    # use their specified publicKey to try and decode message
    plaintext = buff nacl.box.open(
      ba ciphertext, ba nonce, ba sender.publicKey, ba network.secretKey
    )
    return false unless plaintext
    try
      meta = msgpack.decode(plaintext)
      return { sender, meta }
    catch err
      return false
  encode:({meta, network, destination})->
    ba = asByteArray; buff = asBuffer
    throw new Error("meta must be an object") unless typeof(meta) is 'object'
    nonce = crypto.randomBytes(nacl.box.nonceLength)
    publicKey = buff network.publicKey
    cloakedKey = PinkPulseUtils.cloak(publicKey, nonce, destination.publicKey)
    plaintext = msgpack.encode(meta)
    ciphertext = buff nacl.box(
      ba plaintext, ba nonce, ba destination.publicKey, ba network.secretKey
    )
    Buffer.concat([nonce, cloakedKey, ciphertext])

  reply:(originalPulse, constructorOptions)->
    newMeta = {}
    newMeta[key] = value for key, value of originalPulse.meta
    newMeta.origin = originalPulse.sender.copy(includePublicKey: no).toBuffer()
    newMeta.time = Date.now() # local epoch time in milliseconds
    constructorOptions.to = originalPulse.from
    PinkPulse.encode(newMeta, constructorOptions)


module.exports =
  Invite: PinkInvite
  Address: PinkAddress
  Pulse: PinkPulse
