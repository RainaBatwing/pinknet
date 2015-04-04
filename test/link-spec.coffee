vows = require 'vows'
assert = require 'assert'
# internal libraries
help = require '../lib/helpers'
link = require '../lib/link'
Address = require '../lib/address'
util = require 'util'

suite = vows.describe "Pink Link Identity"
suite.addBatch
  "Link Identity":
    topic:->
      {
        id1: new link.Identity(null, public: true, unref: true)
        id2: new link.Identity(null, public: true, unref: true)
      }
    "created":({id1, id2})->
      assert.isTrue !!id1
      assert.isTrue !!id2
    ".address()":
      "returns Address":({id1, id2})-> assert.isTrue id1.address() instanceof Address
      "includes publicKey":({id1, id2})-> assert.isTrue Buffer.isBuffer(id1.address().publicKey)
    "transmit id1 to id2":
      topic:({id1, id2})->
        id2.on "message", @callback
        id1.send(id2.address(), new Buffer("Mr. Watson--Come here--I want to see you."))
        return
      "decode":(message, rinfo)->
        assert.equal message.toString(), "Mr. Watson--Come here--I want to see you."

suite.addBatch
  "Link PortRouter":
    topic:->
      subjects =
        id1: new link.Identity(null, public: true, unref: true)
        id2: new link.Identity(null, public: true, unref: true)
      subjects.pr1 = new link.PortRouter(subjects.id1)
      subjects.pr2 = new link.PortRouter(subjects.id2)
      return subjects
    "create socket pair":
      topic:({pr1, pr2, id1, id2})->
        {
          socketA: pr1.createSocket()
          socketB: pr2.createSocket()
          pr1, pr2, id1, id2
        }
      "success":({socketA, socketB})->
        assert.notEqual socketA, false
        assert.notEqual socketB, false
      "sockets bound":
        topic: (subjects)->
          subjects.socketA.bind()
          subjects.socketB.bind()
          return subjects
        "bind success":({socketA, socketB})->
          assert.notEqual socketA.bound, false
          assert.notEqual socketB.bound, false
        "message A to B":
          topic:(subjects)->
            subjects.socketB.on "message", @callback
            subjects.socketA.send(subjects.socketB.address(), subjects.socketB.bound, new Buffer("nyan!"))
            return
          "contents":(contents, rinfo)->
            assert.equal contents.toString(), "nyan!"


suite.run() # Run tests
