nacl = require('tweetnacl')
base58 = require('bs58')
msgpack = require('msgpack5')()
blake2s = require('blake2s-js')
udp = require('dgram')

# quick shortcut version of blake2s digest
blakeDigest = (data, args...)->
  digestor = new blake2s(args...)
  digestor.update(new Buffer(data))
  return digestor.digest()

# Pink Invite - a human friendly way to introduce two peers by having them share
# something that looks like an invite code
class PinkInvite
  constructor: (arg)->
    if typeof(arg) is 'string'
      @_parse arg
    else if typeof(arg) is 'object'
      this[key] = arg[key] for key in ['address', 'port', 'publicKey']


  _parse: (inviteCode)->
    inviteBytes = base58.decode(inviteCode)
    datachunk = inviteBytes.slice(1)
    unless blakeDigest(datachunk, 1)[0] == inviteBytes[0]
      throw new Error('Invite mistyped or incomplete')
    try
      data = msgpack.decode(datachunk)
    catch e
      throw new Error('Invite mistyped or incomplete')
    # check type is array, otherwise maybe datachunk is corrupt
    throw new Error('Invite mistyped or incomplete') unless data.map
    throw new Error('Unknown invite type') unless data[0] == 4
    # unpack address
    @address = (data[1].readUInt8(idx) for idx in [0...4]).join('.')
    @port = data[1].readUInt16BE(4)
    @publicKey = data[2]

  toString:()->
    publicKey = @publicKey
    publicKey = base58.decode(publicKey) if typeof(publicKey) is 'string'
    compactAddress = new Buffer(6)
    for digit, index in @address.split('.')
      compactAddress.writeUInt8 parseInt(digit), index
    compactAddress.writeUInt16BE parseInt(@port), 4
    datachunk = msgpack.encode([4, compactAddress, new Buffer(publicKey)]).slice(0)
    checksum = blakeDigest(datachunk, 1)
    #console.log "checksum:", checksum[0].toString(16)
    #console.log "datachunk:", datachunk
    bytes = Buffer.concat([new Buffer(checksum), datachunk])
    #console.log "concat:", bytes
    base58.encode(bytes)

  inspect:()->
    "udp://#{base58.encode(@publicKey)}@#{@address}:#{@port}"

# checks if PinkInvite code is valid
PinkInvite.verify = (inviteCode)->
  try
    bytes = base58.decode(inviteCode)
  catch err
    return false # decode failed - probably invalid characters
  return blakeDigest(bytes.slice(1), 1)[0] == bytes[0]


module.exports =
  Invite: PinkInvite
