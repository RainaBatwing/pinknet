vows = require 'vows'
assert = require 'assert'
help = require '../lib/helpers'
address = require '../lib/address'

suite = vows.describe "Pink Address"
suite.addBatch
  "address without pubkey":
    topic: "udp://123.134.221.4:17892"
    "parses url":(url)->
      assert.notEqual address.parse(url), false
    "encodes a buffer":(url)->
      assert.isTrue Buffer.isBuffer(address.parse(url).toBuffer())
    "restores compact binary buffer":(url)->
      assert.equal address.parse(address.parse(url).toBuffer()).toString(), url

  "address with public key":
    topic: "udp://Dp1iRcubw2bcvSBhrff9EtRXYDXnHQBqcL2wEM5ViSek@4.3.2.1:5678"
    "buffer and string encoding is lossless":(url)->
      assert.equal address.parse(address.parse(url).toBuffer()).toString(), url
    "publicKey is a buffer":(url)->
      addr = address.parse(address.parse(url).toBuffer())
      assert.notEqual addr.publicKey, null
      assert.isTrue Buffer.isBuffer(addr.publicKey)
      assert.equal addr.publicKey.length, help.nacl.box.publicKeyLength
    "can encode buffer without a publicKey":(url)->
      addr = address.parse(address.parse(url).toBuffer(includePublicKey: false))
      assert.equal addr.publicKey, null

suite.run() # Run tests
