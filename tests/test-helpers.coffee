vows = require 'vows'
assert = require 'assert'
help = require '../lib/helpers'


suite = vows.describe "Pink Helpers Library"
suite.addBatch
  "blake":
    topic: help.blake(new Buffer('e85c06a80a62d65e', 'hex'), 3)
    "correct output":(output)->
      assert.equal output.toString('hex').toLowerCase(), 'badca7'

  "asByteArray with Buffer input":
    topic: help.asByteArray(new Buffer([1,2]))
    converts:(out)-> assert.isTrue out.constructor is Uint8Array
    correct:(out)-> assert.equal out[1], 2
    length:(out)-> assert.equal out.length, 2
  "asByteArray with Uint8Array input":
    topic: help.asByteArray(new Uint8Array([1,2]))
    converts:(out)-> assert.isTrue out.constructor is Uint8Array
    correct:(out)-> assert.equal out[1], 2
    length:(out)-> assert.equal out.length, 2

  "randomID":
    topic: help.randomID(16)
    "is string":(out)-> assert.equal typeof(out), 'string'
    "contains something":(out)-> assert.isTrue out.length > 0
    "is unique":(out)-> assert.notEqual out, help.randomID(16)

  "uniqueIndex":
    topic:->
      obj = {}
      obj[i.toString(36)] = 'used' for i in [0...500]
      return obj
    "unused":(obj)-> assert.equal obj[help.uniqueIndex(obj)], undefined
    "returns string":(obj)-> assert.equal typeof(help.uniqueIndex(obj)), 'string'
    "ouputs something":(obj)-> assert.isTrue help.uniqueIndex(obj).length > 0

  "erase":
    topic: [1,2]
    "works":(test)->
      arr = new Uint8Array(test)
      buf = new Buffer(test)
      assert.equal arr[0], 1
      assert.equal arr[1], 2
      assert.equal buf[0], 1
      assert.equal buf[1], 2
      help.erase(arr, buf)
      assert.equal arr[0], 0
      assert.equal arr[1], 0
      assert.equal buf[0], 0
      assert.equal buf[1], 0

  # test the nacl buffer/uint8array translator function is working
  # can't test memory leakage easily, so I just hope that works! :<
  "nacl.randomBytes":
    topic: help.nacl(help.nacl.randomBytes, 5)
    "returned buffer":(ret)-> assert.isTrue Buffer.isBuffer(ret)
    "correct length":(ret)-> assert.equal ret.length, 5

  "nacl.util.decodeBase64":
    topic: help.nacl(help.nacl.util.decodeBase64, '44GL44KP44GE44GE')
    "returns buffer":(ret)-> assert.isTrue Buffer.isBuffer(ret)
    "is correct":(ret)-> assert.equal ret.toString(), "かわいい"

  "nacl.secretbox.open":
    topic:->
      key = new Buffer('Bkiuwce/zjTus6IBqb5z5ZaiTbnHNLqZgvoCy8sInhA=', 'base64')
      nonce = new Buffer('LGs1eABctUsXLFlbmQ4gZOXT5HlegqW4', 'base64')
      box = new Buffer('43q6DOmCaVm0ex5C8gnGySt0lvFQaVE5', 'base64')
      help.nacl(help.nacl.secretbox.open, box, nonce, key)
    "returns buffer":(ret)-> assert.isTrue Buffer.isBuffer(ret)
    "correct length":(ret)-> assert.equal ret.length, 8





suite.run() # Run tests
