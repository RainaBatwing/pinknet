// Generated by CoffeeScript 1.8.0
(function() {
  var PinkAddress, base58, help, msgpack, url;

  url = require('url');

  help = require('./helpers');

  msgpack = help.msgpack;

  base58 = help.base58;

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
          this.publicKey = help.asBuffer(base58.decode(this.publicKey));
        }
        if (!Buffer.isBuffer(this.publicKey)) {
          throw new Error("publicKey cannot be " + (Object.prototype.toString.call(this.publicKey)));
        }
      }
    }

    PinkAddress.prototype.copy = function(_arg) {
      var includePublicKey;
      includePublicKey = (_arg != null ? _arg : {
        includePublicKey: true
      }).includePublicKey;
      return new this.constructor({
        ip: this.ip,
        port: this.port,
        publicKey: includePublicKey ? this.publicKey : null
      });
    };

    PinkAddress.prototype.toBuffer = function(_arg) {
      var compact_ip, data, digits, idx, includePublicKey, num, octet, segment, type, _i, _j, _len, _len1, _ref, _ref1;
      includePublicKey = (_arg != null ? _arg : {
        includePublicKey: true
      }).includePublicKey;
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
      if (this.publicKey && includePublicKey) {
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
      if (other === false) {
        return false;
      }
      if (this.publicKey && other.publicKey && this.publicKey.toString('hex') !== other.publicKey.toString('hex')) {
        return false;
      }
      return this.ip === other.ip && this.port === other.port && this.protocol === other.protocol;
    };

    return PinkAddress;

  })();

  PinkAddress.parse = function(input) {
    var arr, base, compact_ip, digit, err, idx, ip, ip_data, port, publicKey, seperator, type, _i, _len;
    if (input.constructor === PinkAddress) {
      return input;
    }
    if (!Buffer.isBuffer(input)) {
      try {
        return new PinkAddress(input);
      } catch (_error) {
        err = _error;
        return false;
      }
    }
    try {
      arr = msgpack.decode(input);
      if (arr.length < 3) {
        return false;
      }
      type = arr[0], ip_data = arr[1], port = arr[2], publicKey = arr[3];
    } catch (_error) {
      err = _error;
      return false;
    }
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

  PinkAddress.extendMsgpack = function(packer, extensionID) {
    var encoder;
    if (extensionID == null) {
      extensionID = 16;
    }
    encoder = function(obj) {
      return obj.toBuffer();
    };
    return packer.register(extensionID, PinkAddress, encoder, PinkAddress.parse);
  };

  module.exports = PinkAddress;

}).call(this);