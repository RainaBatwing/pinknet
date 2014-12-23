vows = require 'vows'
assert = require 'assert'
# internal libraries
help = require '../lib/helpers'
codecs = require '../lib/codecs'
address = require '../lib/address'

# generate some random mock data
srcKeyPair = help.nacl(help.nacl.box.keyPair)
dstKeyPair = help.nacl(help.nacl.box.keyPair)
srcAddress = new address(ip: '1.2.3.4', port: 1234, publicKey: srcKeyPair.publicKey)
dstAddress = new address(ip: '10.11.12.13', port: 9876, publicKey: dstKeyPair.publicKey)
srcPulse =
  to: dstAddress
  meta: {abc: 123}
  network: srcKeyPair
srcMessage =
  to: dstAddress
  type: 5
  data: {a:1}
  network: srcKeyPair
packetInfo =
  network: dstKeyPair
  sender: srcAddress
srcSender = srcAddress.copy(includePublicKey: no)

suite = vows.describe "Pink Wire Codecs"
suite.addBatch
  # verify pulse codec
  "pulse codec - encode":
    topic: codecs.pulse.encode(srcPulse)
    "is buffer":(obj)-> assert.isTrue Buffer.isBuffer(obj)

    "is long enough":(obj)-> assert.isTrue obj.length > 24 + 32 # nonce + pubkey
    "pubkey hidden":(obj)-> assert.equal obj.toJSON().join(',').indexOf(srcKeyPair.publicKey.toJSON().join(',')), -1
    "nonce unique":(obj)->
      two = codecs.pulse.encode(srcPulse) # generate again - new nonce
      # check ignoring the nonce prefix part to check nonce is actually being used for the encrypted body
      assert.notEqual obj.slice(24).toString('hex'), two.slice(24).toString('hex')
      assert.notEqual obj.toString('hex'), two.toString('hex') # check for actual nonce data as well
    "decode":
      topic: (packet)-> codecs.pulse.decode(packet, packetInfo)
      "meta lossless": (obj)-> assert.equal JSON.stringify(obj.meta), JSON.stringify(srcPulse.meta)
      "sender pubkey": (obj)-> assert.equal srcKeyPair.publicKey.toString('hex'), obj.sender.publicKey.toString('hex')
    "corrupt decode":
      topic: (packet)->
        p = new Buffer(packet.toJSON())
        p[3] ^= 1 # flip a single bit
        return p
      "false output": (obj)-> assert.isFalse codecs.pulse.decode(obj, packetInfo)

suite.addBatch
  # verify message codec
  "message codec - encode":
    topic: codecs.message.encode(srcMessage)
    "is buffer":(obj)-> assert.isTrue Buffer.isBuffer(obj)
    "is long enough":(obj)-> assert.isTrue obj.length > 24 + 16 # nonce + box overhead
    "nonce unique":(obj)->
      two = codecs.message.encode(srcMessage) # generate again - new nonce
      # check ignoring the nonce prefix part to check nonce is actually being used for the encrypted body
      assert.notEqual obj.slice(24).toString('hex'), two.slice(24).toString('hex')
      assert.notEqual obj.toString('hex'), two.toString('hex') # check for actual nonce data as well
    "decode":
      topic: (packet)-> codecs.message.decode(packet, packetInfo)
      "success": (obj)-> assert.notEqual obj, false
      "data lossless": (obj)-> assert.equal obj.data.a, srcMessage.data.a
      "type correct":  (obj)-> assert.equal obj.type, srcMessage.type
      "sender":        (obj)-> assert.isTrue srcAddress.equals obj.sender
    "corrupt decode":
      topic: (packet)->
        p = new Buffer(packet.toJSON())
        p[3] ^= 1 # flip a single bit
        return p
      "false output": (obj)-> assert.isFalse codecs.message.decode(obj, packetInfo)

suite.run() # Run tests
