nacl = require('tweetnacl')
base58 = require('bs58')
msgpack = require('msgpack5')()
blake2s = require('blake2s-js')
udp = require('dgram')
util = require('util')
url = require('url')

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
  copy:({includePublicKey} = {includePublicKey: true})->
    new @constructor({@ip, @port, publicKey: includePublicKey})

  # convert to a compact msgpacked representation
  toBuffer:({includePublicKey} = {includePublicKey: true})->
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
    data.push(@publicKey) if @publicKey and includePublicKey
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
  # encode a new pulse in to a packet to send over UDP directly
  encode:({meta, network, to})->
    ba = asByteArray; buff = asBuffer
    to = PinkAddress.parse(to)
    meta = {} if meta is null
    throw new Error("cannot encode pulse to address with no publicKey") unless to.publicKey
    throw new Error("meta must be an object") unless typeof(meta) is 'object'
    nonce = buff nacl.randomBytes(nacl.box.nonceLength)
    publicKey = buff network.publicKey
    cloakedKey = PinkPulseUtils.cloak(publicKey, nonce, to.publicKey)
    plaintext = msgpack.encode(meta)
    ciphertext = buff nacl.box(
      ba plaintext, nonce, ba to.publicKey, ba network.secretKey
    )
    Buffer.concat([buff(nonce), cloakedKey, ciphertext])

  # decode a UDP packet pulse object, if it is a valid one, otherwise returns false
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

  # generate an encoded reply to a decoded pulse
  reply:(originalPulse, constructorOptions)->
    newMeta = {}
    newMeta[key] = value for key, value of originalPulse.meta
    newMeta.origin = originalPulse.sender.toBuffer(includePublicKey: no)
    newMeta.time = Date.now() # local epoch time in milliseconds
    constructorOptions.to = originalPulse.sender
    PinkPulse.encode(newMeta, constructorOptions)


module.exports =
  Invite: PinkInvite
  Address: PinkAddress
  Pulse: PinkPulse
