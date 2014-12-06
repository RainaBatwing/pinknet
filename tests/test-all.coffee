pink = require '../pinknet'
vows = require 'vows'
assert = require 'assert'
nacl = require 'tweetnacl/nacl-fast'
base58 = require 'bs58'

randomNetwork =->
  keypair = nacl.box.keyPair()
  {
    secretKey: new Buffer(keypair.secretKey)
    publicKey: new Buffer(keypair.publicKey)
  }

suite = vows.describe "Pink Network Library"
mockNetwork1 = randomNetwork()
mockNetwork2 = randomNetwork()
mockAddress = "udp://1.2.3.4:5678"

suite.addBatch
  "pink.Address without pubkey":
    topic: "udp://123.134.221.4:17892"
    "parses url":(url)->
      assert.notEqual pink.Address.parse(url), false
    "encodes a buffer":(url)->
      assert.isTrue Buffer.isBuffer(pink.Address.parse(url).toBuffer())
    "restores compact binary buffer":(url)->
      assert.equal pink.Address.parse(pink.Address.parse(url).toBuffer()).toString(), url

  "pink.Address with public key":
    topic: "udp://#{base58.encode(new Buffer(mockNetwork1.publicKey))}@123.134.221.4:17892"
    "restores compact binary buffer":(url)->
      assert.equal pink.Address.parse(pink.Address.parse(url).toBuffer()).toString(), url
    "publicKey unpacks accurately":(url)->
      addr = pink.Address.parse(pink.Address.parse(url).toBuffer())
      assert.notEqual addr.publicKey, null
      assert.equal addr.publicKey.length, mockNetwork1.publicKey.length
      assert.equal JSON.stringify(addr.publicKey.toJSON()), JSON.stringify((new Buffer(mockNetwork1.publicKey)).toJSON())


  # test invite code functionality
  "pink.Invite":
    topic: new pink.Invite(ip: "1.2.3.4", port: 5678, publicKey: mockNetwork1.publicKey)
    "constructs something":(invite)->
      assert.isString invite.toString()
      assert.isTrue invite.toString().length != 0
    "verifies":(invite)->
      #console.log invite.toString()
      assert.isTrue pink.Invite.verify(invite.toString())
    "corrupted doesn't verify":(invite)->
      assert.isFalse pink.Invite.verify(invite.toString() + "a")
     "parsing works":(invite1)->
      invite2 = pink.Invite.parse(invite1.toString())
      # console.log invite1
      # console.log invite2
      assert.equal invite1.address.toString(), invite2.address.toString()


  # test pulse packet abstractions
  # "pink.Pulse.encode()":
  #   topic: pink.Pulse.encode(
  #     network: mockNetwork1
  #     recipient: mockNetwork2
  #     meta: { ein: "data dog" }
  #   )
  #   "creates a buffer":(output)->
  #     assert.isTrue Buffer.isBuffer(output)
    # "pink.Pulse.decode()":
    #   topic:(buffer)-> pink.Pulse.decode(buffer, network: mockNetwork2)
    #   "returns an object":(output)->
    #     assert.equal typeof(output), 'object'
    #   "object is valid":(output)->
    #     assert.isTrue output.sender?
    #     assert.isTrue output.meta?
    #   "from publicKey is correct":(output)->
    #     assert.equal output.sender.publicKey.toJSON().join(','), mockNetwork1.publicKey.toJSON().join(',')
    #   "to publicKey is correct":(output)->
    #     assert.equal output.to.publicKey.toJSON().join(','), mockNetwork2.publicKey.toJSON().join(',')
    #   "pink.Pulse.reply(decoded object)":
    #     topic:(pulse)-> pink.Pulse.reply(pulse, {sender: mockAddress, network: mockNetwork2})
    #     "returns buffer":(buffer)-> assert.isTrue Buffer.isBuffer(buffer)
    #     "can decode buffer":(buffer)-> assert.notEqual pink.Pulse.decode(buffer, mockNetwork1), false
    #     "time field added correctly":(buffer)->
    #       pulse = pink.Pulse.decode(buffer, mockNetwork1)
    #       assert.equal typeof(pulse.time), 'number'
    #     "origin field added correctly":(buffer)->
    #       pink.Address.parse(mockAddress).equal(pulse.origin)


suite.run() # Run tests
