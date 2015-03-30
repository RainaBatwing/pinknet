vows = require 'vows'
assert = require 'assert'
# internal libraries
help = require '../lib/helpers'
codecs = require '../lib/link-codecs'
address = require '../lib/address'

# generate some random mock data
srcKeyPair = help.nacl(help.nacl.box.keyPair)
dstKeyPair = help.nacl(help.nacl.box.keyPair)
srcAddress = new address(ip: '1.2.3.4', port: 1234, publicKey: srcKeyPair.publicKey)
dstAddress = new address(ip: '10.11.12.13', port: 9876, publicKey: dstKeyPair.publicKey)
srcPacket =
  peer: dstAddress
  contents: new Buffer("moshi moshi")
  identity: srcKeyPair
packetInfo =
  identity: dstKeyPair
  author: srcAddress
srcSender = srcAddress.copy(includePublicKey: no)

suite = vows.describe "Pink Link Codecs"
suite.addBatch
  # verify pulse codec
  "ID Packet - encode":
    topic: codecs.id.encode(srcPacket)
    "is buffer":(obj)-> assert.isTrue Buffer.isBuffer(obj)

    "is long enough":(obj)-> assert.isTrue obj.length > 24 + 32 # nonce + pubkey
    "pubkey hidden":(obj)-> assert.equal obj.toString('hex').indexOf(srcKeyPair.publicKey.toString('hex')), -1
    "nonce unique":(obj)->
      two = codecs.id.encode(srcPacket) # generate again - new nonce
      # check ignoring the nonce prefix part to check nonce is actually being used for the encrypted body
      assert.notEqual obj.slice(24).toString('hex'), two.slice(24).toString('hex')
      # check for actual nonce data as well
      assert.notEqual obj.toString('hex'), two.toString('hex')
    "decode":
      topic: (packet)-> codecs.id.decode(packet: packet, identity: dstKeyPair)
      "decoded":       (obj)-> assert.notEqual obj, false
      "data lossless": (obj)-> assert.equal obj.contents.toString(), srcPacket.contents.toString()
      "author pubkey": (obj)-> assert.equal srcKeyPair.publicKey.toString('hex'), obj.author.toString('hex')
    "corrupt decode":
      topic: (packet)->
        p = new Buffer(packet.toJSON())
        p[3] ^= 1 # flip a single bit
        return p
      "false output": (obj)-> assert.isFalse codecs.id.decode(packet: obj, identity: dstKeyPair)

# suite.addBatch
#   # verify compact codec
#   "Compact Packet - encode":
#     topic: codecs.compact.encode(srcPacket)
#     "is buffer":(obj)-> assert.isTrue Buffer.isBuffer(obj)
#     "is long enough":(obj)-> assert.isTrue obj.length > 24 + 16 # nonce + box overhead
#     "nonce unique":(obj)->
#       two = codecs.compact.encode(srcPacket) # generate again - new nonce
#       # check ignoring the nonce prefix part to check nonce is actually being used for the encrypted body
#       assert.notEqual obj.slice(24).toString('hex'), two.slice(24).toString('hex')
#       assert.notEqual obj.toString('hex'), two.toString('hex') # check for actual nonce data as well
#     "decode":
#       topic: (packet)-> codecs.compact.decode(packet, packetInfo)
#       "success": (obj)-> assert.notEqual obj, false
#       "data lossless": (obj)-> assert.equal obj.data.a, srcPacket.data.a
#       "sender":        (obj)-> assert.isTrue srcAddress.equals obj.author
#     "corrupt decode":
#       topic: (packet)->
#         p = new Buffer(packet.toJSON())
#         p[3] ^= 1 # flip a single bit
#         return p
#       "false output": (obj)-> assert.isFalse codecs.compact.decode(obj, packetInfo)

suite.run() # Run tests
