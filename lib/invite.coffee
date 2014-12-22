# external dependencies
base58 = require 'bs58'
# internal dependencies
help    = require './helpers'
address = require './address'

# Generate and parse base58 encoded invite codes, encoding an IP, Port and
# publicKey. Invite codes provide an easy way to create new isolated p2p
# networks without any hard coded central initial peers or trackers.
class invite
  constructor:(opts)->
    @address = opts.address or new address(opts)
  toString:()->
    addr = @address.toBuffer()
    check = help.blake(addr, 1)
    base58.encode(Buffer.concat([check, addr]))
# checks if pink invite code is valid
invite.verify = (inviteCode)->
  try
    bytes = base58.decode(inviteCode)
  catch err
    return false # decode failed - probably invalid characters
  return help.blake(bytes.slice(1), 1)[0] == bytes[0]
# parse a pink invite
invite.parse = (inviteCode)->
  bytes = base58.decode(inviteCode)
  return false unless help.blake(bytes.slice(1), 1)[0] == bytes[0]
  addr = address.parse(help.asBuffer bytes.slice(1))
  return false unless addr
  new invite(address: addr)

module.exports = invite
