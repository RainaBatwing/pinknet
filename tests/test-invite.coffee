vows = require 'vows'
assert = require 'assert'
# internal libraries
help = require '../lib/helpers'
invite = require '../lib/invite'
address = require '../lib/address'

ip = "1.2.3.4"
port = 5678
pubkey = help.randomBytes(help.nacl.box.publicKeyLength)
address = new address(ip: ip, port: port, publicKey: pubkey)

suite = vows.describe "Pink Invite"
suite.addBatch
  # test general parsing and generation
  "generate":
    topic: new invite(address)
    "makes string":(obj)-> assert.equal typeof(obj.toString()), 'string'
    "parse":
      topic: (obj)-> invite.parse(obj.toString())
      "lossless": (obj)-> assert.equal address, obj.address.toString()
    "parse failure":
      topic: (obj)-> invite.parse("#{obj}a")
      "false output": (obj)-> assert.isFalse obj
  # test verify function
  "verify":
    "empty":   -> assert.isFalse invite.verify('')
    "words":   -> assert.isFalse invite.verify('i like you')
    "valid":   -> assert.isTrue  invite.verify("#{new invite(address)}")
    "number":  -> assert.isFalse invite.verify(5)
    "buffer":  -> assert.isFalse invite.verify(new Buffer("#{new invite(address)}"))
    "append":  -> assert.isFalse invite.verify("#{new invite(address)}4")
    "prepend": -> assert.isFalse invite.verify("5#{new invite(address)}")


suite.run() # Run tests
