help    = require './helpers'
Address = require './address'
codecs  = require './link-codecs'
dgram   = require 'dgram'
events  = require 'events'

internal =
  udp4: null
  routes: null

# Identity is compatible with dgram socket, but ports are always ignored
class Identity extends events.EventEmitter
  constructor:(@secretKey, options = {})->
    if Buffer.isBuffer(@secretKey) and @secretKey.length == help.nacl.box.secretKeyLength
      @publicKey = help.nacl(help.nacl.box.keyPair.fromSecretKey, @secretKey).publicKey
    else
      {@secretKey, @publicKey} = help.nacl(help.nacl.box.keyPair)

    # public mode allows packets from unknown peers
    if options.public
      @publicPeers = {}
      @expire = options.expire or 60*10 # default expiry 10 minutes
      @public = yes
    else
      @publicPeers = {}
      @expire = 0
      @public = no

    # peers we are friends with, who we are always happy to talk with
    @trustedPeers = {}

    @nat = new PeerNAT

    # setup udp4 transport
    @udp4 = dgram.createSocket('udp4')
    @udp4.on "message", (packetdata, rinfo)=>
      packet = codecs.id.decode(packet: packetdata, identity: this)
      source = new Address(ip: rinfo.address, port: rinfo.port, publicKey: packet.author)
      @nat.register source
      messageInfo =
        address: if options.stringify then source.toString() else source
        port: 0
      @emit "message", packet.contents, messageInfo
    @udp4.on "listening", (args...)=> @emit "listening", args...
    @udp4.on "close", (args...)=> @emit "close", args...
    @udp4.on "error", (args...)=> @emit "error", args...
    @udp4.bind()
    @udp4.unref() if options.unref

  # send message to a remote peer, compatible with dgram, arguments can be either:
  #   buf, offset, length, port, address[, callback]
  # or
  #   address, buffer[, callback]
  send:(args...)->
    if args.length <= 3
      [address, contents, callback] = args
    else
      [buffer, offset, length, port, address, callback] = args
      contents = buffer.slice(offset, offset + length)

    peer = Address.parse(address)
    throw new Error("Address unparsable: #{address}") unless address
    throw new Error("Peer network address must include public key") unless peer.publicKey
    peer = @nat.lookup(peer) # lookup peer nat to handle peer address changes

    packet = codecs.id.encode({identity: this, contents, peer})
    @udp4.send(packet, 0, packet.length, peer.port, peer.ip, callback)

  close:-> @udp4.close()

  # fetch address info
  address:->
    udp4info = @udp4.address()
    addr = new Address(publicKey: @publicKey, ip: udp4info.address, port: udp4info.port)

# Keep track of peer network address changes
class PeerNAT extends events.EventEmitter
  constructor:->
    @data = {}
    @duration = 10*60 # ten minutes

  register:(newAddress)->
    newAddress = Address.parse(newAddress) unless newAddress instanceof Address
    index = newAddress.publicKey.toString('hex')
    if @data[index]
      clearTimeout(@data[index].expire)
      @emit("change", @data[index].address, newAddress) unless @data[index].address.equals(newAddress)
    @data[index] =
      address: newAddress
      expire: setTimeout((=> delete @data[index]), @duration)

  lookup:(lookupAddress)->
    hashname = Address.parse(lookupAddress).publicKey.toString('hex')
    if @data[hashname]
      return @data[hashname].address
    else
      lookupAddress


# PortRouter implements a ports system compatible with system UDP sockets, for
# compatibility with apps opening sockets on different ports for different
# services or peers
class PortRouter extends events.EventEmitter
  constructor:(@id)->
    @id.on "message", (data, author)=>
      author.port = data.readUInt16BE(0)
      destinationPort = data.readUInt16BE(2)
      data = data.slice(4)
      receiver = @ports[destinationPort.toString(36)]
      receiver.emit("message", data, author) if receiver
    @ports = {}

  # options are ignored for now
  createSocket:(args...)->
    new Port(this, args...)

# Port behaves like a udp socket, including binding to ports via the portrouter
class Port extends events.EventEmitter
  constructor:(@pr, type, opts={})->
    @bound = no
    @id = @pr.id

  # bind this port in the PortRouter
  bind:(args...)->
    if @bound isnt no
      delete @pr.ports[@bound.toString(36)]
      @_bound = no

    if typeof(args[0]) is 'number'
      [port, address, callback] = args
      options = {port, address}
    else if typeof(args[0]) is 'object'
      [options, callback] = args
    else
      options =
        port: parseInt(help.uniqueIndex(@pr.ports, 2), 36)

    throw new Error("Port must be a number") unless typeof options.port is 'number'
    throw new Error("Port not available") if @pr.ports[options.port.toString(36)]

    @bound = options.port
    @pr.ports[@bound.toString(36)] = this

    setImmediate(callback) if callback

  # send message to a remote peer, compatible with dgram, arguments can be either:
  #   buffer, offset, length, port, address[, callback]
  # or
  #   address, port, buffer[, callback]
  send:(args...)->
    if args.length <= 4
      [address, port, contents, callback] = args
    else
      [buffer, offset, length, port, address, callback] = args
      contents = buffer.slice(offset, offset + length)

    # bind to a random local port if we haven't bound yet
    @bind() if @bound is no

    # construct packet data with source and destination port prefixed
    data = new Buffer(contents.length + 4)
    data.writeUInt16BE(@bound, 0)
    data.writeUInt16BE(port, 2)
    contents.copy(data, 4)
    # transmit at lower level
    @pr.id.send(address, data, callback)

  # close port, unbinding it
  close:->
    delete @pr.ports[@bound.toString(36)]
    @bound = no
    @emit "close"

  # get local address
  address:-> @pr.id.address()

  # implement remaining dgram api
  setBroadcast:(flag)-> throw new Error("Not Implemented") if flag
  setTTL:(ttl)-> throw new Error("Not Implemented") if ttl != 64
  setMulticastTTL:-> throw new Error("Not Implemented")
  setMulticastLoopback:-> throw new Error("Not Implemented")
  addMembership:-> throw new Error("Not Implemented")
  dropMembership:-> throw new Error("Not Implemented")
  unref:-> throw new Error("Not Implemented")
  ref:-> throw new Error("Not Implemented")


module.exports = {
  Identity
  PortRouter
}
