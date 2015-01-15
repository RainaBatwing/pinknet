url = require 'url'
help = require './helpers'
msgpack = help.msgpack
base58 = help.base58

# address represents an IP, Port, and optionally publicKey of a remote peer.

# address provides two encodings. A string form, and a buffer format. String is
# a valid URL in the format udp4://pubkey@ip:port, and a buffer format encodes
# ipv4, ipv6, and public keys very compactly for network transmission
class PinkAddress
  constructor:(opts)->
    if typeof(opts) is 'string'
      {hostname: @ip, port: @port, protocol: @protocol, auth: @publicKey} = url.parse(opts)
      throw new Error("unsupported protocol #{@protocol} in #{opts}") unless @protocol is 'udp4:'
    else if opts.ip != undefined
      {@ip, @port, @publicKey} = opts
      @protocol = 'udp4:'
    else
      throw new Error("Cannot parse #{Object.prototype.toString.call(opts)}")
    # convert types where needed
    @port = parseInt(@port) if typeof(@port) isnt 'number'
    if @publicKey
      @publicKey = help.asBuffer(base58.decode(@publicKey)) if typeof(@publicKey) is 'string'
      throw new Error("publicKey cannot be #{Object.prototype.toString.call(@publicKey)}") unless Buffer.isBuffer(@publicKey)

  # copy address
  copy:({includePublicKey} = {includePublicKey: true})->
    new @constructor({@ip, @port, publicKey: if includePublicKey then @publicKey else null})

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
  toString:({includePublicKey} = {includePublicKey: true})->
    auth = base58.encode(@publicKey) if @publicKey and includePublicKey
    url.format(slashes:true, protocol: @protocol, hostname: @ip, port: @port, auth: auth)

  # test equality
  equals:(other)->
    return false unless other
    other = PinkAddress.parse(other) unless other.constructor is @constructor
    return false if @publicKey and other.publicKey and @publicKey.toString('hex') != other.publicKey.toString('hex')
    return @ip == other.ip and @port == other.port and @protocol == other.protocol

# parse compact binary representation
PinkAddress.parse = (input)->
  #return false if input is null or input is false or input is ''
  return input if input.constructor is PinkAddress
  unless Buffer.isBuffer(input)
    try
      return new PinkAddress(input)
    catch err
      return false
  try
    arr = msgpack.decode(input)
    return false if arr.length < 3
    [type, ip_data, port, publicKey] = arr
  catch err
    return false
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

# register Pink Address as a msgpack extension
PinkAddress.extendMsgpack = (packer, extensionID = 16)->
  encoder = (obj)-> obj.toBuffer()
  packer.register(extensionID, PinkAddress, encoder, PinkAddress.parse)

module.exports = PinkAddress
