pink = require '../pink-net'
vows = require 'vows'
assert = require 'assert'
nacl = require 'tweetnacl/nacl-fast'
base58 = require 'bs58'

suite = vows.describe('Pink Network Utilities')
#pubkey = new Uint8Array(32)
pubkey = nacl.randomBytes(32)
suite.addBatch
  "Pink Invite Generation":
    topic: new pink.Invite(address: "1.2.3.4", port: 5678, publicKey: pubkey)
    "constructs something":(invite)->
      assert.isString invite.toString()
      assert.isTrue invite.toString().length != 0
    "verifies":(invite)->
      #console.log invite.toString()
      assert.isTrue pink.Invite.verify(invite.toString())
    "corrupted doesn't verify":(invite)->
      assert.isFalse pink.Invite.verify(invite.toString() + "a")
    "parsing works":(invite1)->
      invite2 = new pink.Invite(invite1.toString())
      assert.equal invite1.inspect(), invite2.inspect()

suite.run() # Run tests
