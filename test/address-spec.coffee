vows = require 'vows'
assert = require 'assert'
help = require '../lib/helpers'
address = require '../lib/address'

suite = vows.describe "Pink Address"
suite.addBatch
  "address without pubkey":
    topic: "udp4://123.134.221.4:17892"
    "parses url":(url)->
      assert.notEqual address.parse(url), false
    "encodes a buffer":(url)->
      assert.isTrue Buffer.isBuffer(address.parse(url).toBuffer())
    "restores compact binary buffer":(url)->
      assert.equal address.parse(address.parse(url).toBuffer()).toString(), url

  "address with public key":
    topic: "udp4://eadaa66a1e9100ca2fbf350430d667872e855aafe4f84506ae314cb806613354@4.3.2.1:5678"
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
    "copy works":(url)->
      assert.equal address.parse(url).copy(includePublicKey: yes).toString(), url
      assert.equal address.parse(url).copy(includePublicKey: no).toString(), "udp4://4.3.2.1:5678"
    "equals()":(url)->
      a1 = address.parse(url)
      assert.isTrue a1.equals url
      assert.isTrue a1.equals "udp4://4.3.2.1:5678"
      assert.isTrue a1.equals a1.copy(includePublicKey: yes)
      assert.isTrue a1.equals a1.copy(includePublicKey: no)
      assert.isTrue a1.equals a1.copy(includePublicKey: yes).toBuffer()
      assert.isTrue a1.equals a1.copy(includePublicKey: no).toBuffer()
      assert.isFalse a1.equals ''
      assert.isFalse a1.equals {}
      assert.isFalse a1.equals false
      assert.isFalse a1.equals "udp4://"
      assert.isFalse a1.equals new Buffer([])
suite.run() # Run tests
