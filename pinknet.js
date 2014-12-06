// Generated by CoffeeScript 1.8.0
(function() {
  var PinkAddress, PinkInvite, PinkPulse, PinkPulseUtils, asBuffer, asByteArray, base58, blake2s, blakeDigest, crypto, msgpack, nacl, udp, url, util,
    __slice = [].slice;

  nacl = require('tweetnacl');

  base58 = require('bs58');

  msgpack = require('msgpack5')();

  blake2s = require('blake2s-js');

  udp = require('dgram');

  util = require('util');

  url = require('url');

  crypto = require('crypto');

  blakeDigest = function() {
    var args, data, digestor;
    data = arguments[0], args = 2 <= arguments.length ? __slice.call(arguments, 1) : [];
    digestor = (function(func, args, ctor) {
      ctor.prototype = func.prototype;
      var child = new ctor, result = func.apply(child, args);
      return Object(result) === result ? result : child;
    })(blake2s, args, function(){});
    digestor.update(new Buffer(data));
    return new Buffer(digestor.digest());
  };

  asByteArray = function(input) {
    if (Buffer.isBuffer(input)) {
      return new Uint8Array(input);
    } else {
      return input;
    }
  };

  asBuffer = function(input) {
    if (input && ((input.BYTES_PER_ELEMENT != null) || input.map)) {
      return new Buffer(input);
    } else {
      return input;
    }
  };

  PinkInvite = (function() {
    function PinkInvite(opts) {
      this.address = opts.address || new PinkAddress(opts);
    }

    PinkInvite.prototype.toString = function() {
      var addr, check;
      addr = this.address.toBuffer();
      check = blakeDigest(addr, 1);
      return base58.encode(Buffer.concat([check, addr]));
    };

    return PinkInvite;

  })();

  PinkInvite.verify = function(inviteCode) {
    var bytes, err;
    try {
      bytes = base58.decode(inviteCode);
    } catch (_error) {
      err = _error;
      return false;
    }
    return blakeDigest(bytes.slice(1), 1)[0] === bytes[0];
  };

  PinkInvite.parse = function(inviteCode) {
    var addr, bytes;
    bytes = base58.decode(inviteCode);
    if (blakeDigest(bytes.slice(1), 1)[0] !== bytes[0]) {
      return false;
    }
    addr = PinkAddress.parse(asBuffer(bytes.slice(1)));
    if (!addr) {
      return false;
    }
    return new PinkInvite({
      address: addr
    });
  };

  PinkAddress = (function() {
    function PinkAddress(opts) {
      var _ref;
      if (typeof opts === 'string') {
        _ref = url.parse(opts), this.ip = _ref.hostname, this.port = _ref.port, this.protocol = _ref.protocol, this.publicKey = _ref.auth;
        if (this.protocol !== 'udp:') {
          throw new Error("unsupported protocol " + this.protocol + " in " + opts);
        }
      } else if (opts.ip && opts.port) {
        this.ip = opts.ip, this.port = opts.port, this.publicKey = opts.publicKey;
        this.protocol = 'udp:';
      } else {
        throw new Error("Cannot parse " + (Object.prototype.toString.call(opts)));
      }
      if (typeof this.port !== 'number') {
        this.port = parseInt(this.port);
      }
      if (this.publicKey) {
        if (typeof this.publicKey === 'string') {
          this.publicKey = asBuffer(base58.decode(this.publicKey));
        }
        if (!Buffer.isBuffer(this.publicKey)) {
          throw new Error("publicKey cannot be " + (Object.prototype.toString.call(this.publicKey)));
        }
      }
    }

    PinkAddress.prototype.copy = function(_arg) {
      var includePublicKey;
      includePublicKey = _arg.includePublicKey;
      return new this.constructor({
        ip: this.ip,
        port: this.port,
        publicKey: this.publicKey
      });
    };

    PinkAddress.prototype.toBuffer = function() {
      var compact_ip, data, digits, idx, num, octet, segment, type, _i, _j, _len, _len1, _ref, _ref1;
      if (this.ip.indexOf(':') !== -1) {
        type = 6;
        compact_ip = [];
        _ref = this.ip.split(/\:\./);
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          segment = _ref[_i];
          num = segment === "" ? false : parseInt(segment, 16);
          compact_ip.push(num);
        }
      } else {
        type = 4;
        digits = [];
        _ref1 = this.ip.split(/\./, 4);
        for (idx = _j = 0, _len1 = _ref1.length; _j < _len1; idx = ++_j) {
          octet = _ref1[idx];
          digits[idx] = parseInt(octet) % 256;
        }
        compact_ip = new Buffer(digits);
      }
      data = [type, compact_ip, this.port];
      if (!(this.publicKey === null || Buffer.isBuffer(this.publicKey))) {
        throw new Error("publicKey must be a Buffer or null");
      }
      if (this.publicKey) {
        data.push(this.publicKey);
      }
      return msgpack.encode(data).slice();
    };

    PinkAddress.prototype.toString = function() {
      var auth;
      if (this.publicKey) {
        auth = base58.encode(this.publicKey);
      }
      return url.format({
        slashes: true,
        protocol: this.protocol,
        hostname: this.ip,
        port: this.port,
        auth: auth
      });
    };

    PinkAddress.prototype.equals = function(other) {
      if (other.constructor !== this.constructor) {
        other = PinkAddress.parse(other);
      }
      if (this.publicKey && other.publicKey && this.publicKey.toJSON().toString() !== other.publicKey.toJSON().toString()) {
        return false;
      }
      return this.ip === other.ip && this.port === other.port && this.protocol === other.protocol;
    };

    return PinkAddress;

  })();

  PinkAddress.parse = function(buffer) {
    var base, compact_ip, digit, idx, ip, ip_data, port, publicKey, seperator, type, _i, _len, _ref;
    if (buffer.constructor === PinkAddress) {
      return buffer;
    }
    if (!Buffer.isBuffer(buffer)) {
      return new PinkAddress(buffer);
    }
    _ref = msgpack.decode(buffer), type = _ref[0], ip_data = _ref[1], port = _ref[2], publicKey = _ref[3];
    seperator = {
      4: '.',
      6: ':'
    }[type];
    base = {
      4: 10,
      6: 16
    }[type];
    if (!seperator) {
      return false;
    }
    compact_ip = [];
    for (idx = _i = 0, _len = ip_data.length; _i < _len; idx = ++_i) {
      digit = ip_data[idx];
      compact_ip[idx] = digit;
    }
    ip = compact_ip.map(function(num) {
      if (num === false) {
        return '';
      } else {
        return num.toString(base);
      }
    }).join(seperator);
    return new PinkAddress({
      ip: ip,
      port: port,
      publicKey: publicKey
    });
  };

  PinkPulseUtils = {
    cloak: function(input, nonce, pubkey) {
      var cloak, cloakByte, idx, output, _i, _len;
      cloak = blakeDigest(Buffer.concat([nonce, pubkey]), input.length);
      output = new Buffer(input.length);
      for (idx = _i = 0, _len = cloak.length; _i < _len; idx = ++_i) {
        cloakByte = cloak[idx];
        output[idx] = input[idx] ^ cloakByte;
      }
      return output;
    }
  };

  PinkPulse = {
    decode: function(buffer, _arg) {
      var ba, buff, ciphertext, cloakedKey, err, meta, network, nonce, plaintext, sender;
      network = _arg.network, sender = _arg.sender;
      ba = asByteArray;
      buff = asBuffer;
      if (buffer.length <= nacl.box.nonceLength + nacl.box.publicKeyLength) {
        return false;
      }
      nonce = buffer.slice(0, nacl.box.nonceLength);
      cloakedKey = buffer.slice(nacl.box.nonceLength, nacl.box.nonceLength + nacl.box.publicKeyLength);
      ciphertext = buffer.slice(nacl.box.nonceLength + nacl.box.publicKeyLength);
      sender.publicKey = PinkPulseUtils.cloak(cloakedKey, nonce, network.publicKey);
      plaintext = buff(nacl.box.open(ba(ciphertext, ba(nonce, ba(sender.publicKey, ba(network.secretKey))))));
      if (!plaintext) {
        return false;
      }
      try {
        meta = msgpack.decode(plaintext);
        return {
          sender: sender,
          meta: meta
        };
      } catch (_error) {
        err = _error;
        return false;
      }
    },
    encode: function(_arg) {
      var ba, buff, ciphertext, cloakedKey, destination, meta, network, nonce, plaintext, publicKey;
      meta = _arg.meta, network = _arg.network, destination = _arg.destination;
      ba = asByteArray;
      buff = asBuffer;
      if (typeof meta !== 'object') {
        throw new Error("meta must be an object");
      }
      nonce = crypto.randomBytes(nacl.box.nonceLength);
      publicKey = buff(network.publicKey);
      cloakedKey = PinkPulseUtils.cloak(publicKey, nonce, destination.publicKey);
      plaintext = msgpack.encode(meta);
      ciphertext = buff(nacl.box(ba(plaintext, ba(nonce, ba(destination.publicKey, ba(network.secretKey))))));
      return Buffer.concat([nonce, cloakedKey, ciphertext]);
    },
    reply: function(originalPulse, constructorOptions) {
      var key, newMeta, value, _ref;
      newMeta = {};
      _ref = originalPulse.meta;
      for (key in _ref) {
        value = _ref[key];
        newMeta[key] = value;
      }
      newMeta.origin = originalPulse.sender.copy({
        includePublicKey: false
      }).toBuffer();
      newMeta.time = Date.now();
      constructorOptions.to = originalPulse.from;
      return PinkPulse.encode(newMeta, constructorOptions);
    }
  };

  module.exports = {
    Invite: PinkInvite,
    Address: PinkAddress,
    Pulse: PinkPulse
  };

}).call(this);