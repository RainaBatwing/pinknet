blake2s = require 'blake2s-js'
crypto = require 'crypto'
base58 = require 'bs58'
msgpack = require 'msgpack5'
nacl   = require 'tweetnacl/nacl-fast'

# helpers module
# collection of useful functions
helpers =
  # expose some generally useful things
  base58: base58
  msgpack: msgpack

  # quick shortcut to make a blake2s digest from whatever
  # to have a specific digest length: help.blake(string/buffer, 16) for 16 bytes
  blake: (data, args...)->
    digestor = new blake2s(args...)
    digestor.update(helpers.asTempBuffer(data))
    return helpers.asBuffer digestor.digest()

  # convert buffers to Uint8Array - useful for feeding tweetnacl-js
  asByteArray: (input)->
    if Buffer.isBuffer(input)
      new Uint8Array(input)
    else
      input

  # convert Uint8Array or Array to node Buffer - useful for everything except tweetnacl-js
  asBuffer: (input)->
    unless Buffer.isBuffer(input)
      new Buffer(input)
    else
      input

  # identical to asByteArray, but erases returned typed array on next tick if copy was required
  asTempByteArray: (input)->
    if Buffer.isBuffer(input)
      arr = new Uint8Array(input)
      setImmediate -> helpers.erase(out)
      return arr
    else
      input

  # identical to asBuffer, but erases returned buffer on next tick if copy was required
  asTempBuffer: (input)->
    unless Buffer.isBuffer(input)
      out = new Buffer(input)
      setImmediate -> helpers.erase(out)
      return out
    else
      input

  # alias
  randomBytes: crypto.randomBytes

  # generate a random ID string with a number of octets worth of randomness
  randomID: (octets)-> base58.encode(crypto.randomBytes(octets))

  # generate an unique random index id for an object
  # attempts short indexes, getting progressively longer
  uniqueIndex: (hashmap, maxlength = 8)->
    length = 1
    loop
      id = helpers.randomID(length)
      return id if hashmap[id] is undefined
      length += 1 if length < maxlength

  # fill typed arrays and buffers with zeros to attempt to securely erase crypto secrets from memory
  erase: (arrays...)->
    for arg, argidx in arrays
      if Buffer.isBuffer(arg)
        arg.fill(0, 0, arg.length)
      else if arg.BYTES_PER_ELEMENT?
        arg[i] = 0 for i in [0...arg.length]
      else
        throw new Error("Argument #{argidx} isn't Buffer or Typed Array. Cannot be securely erased!")

  # wrap a call to tweetnacl, converting arguments from buffers to Uint8Arrays
  # securely, and converting back to buffer when call returns
  # hopefully this can die in a fire if this issue is fixed:
  #   https://github.com/dchest/tweetnacl-js/issues/59
  nacl: (method, args...)->
    callArgs = []
    eraseList = []
    # convert any buffers to Uint8Arrays and note them down for erasure after
    for arg in args
      if Buffer.isBuffer(arg)
        arg = new Uint8Array(arg)
        eraseList.push arg
      callArgs.push arg

    # call the method supplied
    ret = method.apply(nacl, callArgs)

    # returned value is a Uint8Array
    if ret.BYTES_PER_ELEMENT
      eraseList.push ret # schedule it for secure erasure
      ret = new Buffer(ret)

    helpers.erase(eraseList...)

    return ret

# make nacl library available through the nacl function here
helpers.nacl[key] = value for key, value of nacl

module.exports = helpers
