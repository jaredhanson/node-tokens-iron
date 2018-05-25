var Iron = require('iron')
  , clone = require('clone')
  , ALGORITHMS = require('./constants').ALGORITHMS
  , ALGORITHM_MAP = require('./constants').ALGORITHM_MAP;

/**
 * Seal a security token in an Iron envelope.
 *
 * Iron is a message security format that provides encryption with integrity
 * protection of JSON data structures.  The encryption is conducted using
 * either AES-256 in CBC mode or AES-128 in CTR mode, with integrity provided
 * by a SHA-256 HMAC.  The key used for signing and encryption is derived from
 * a password using PBKDF2.
 *
 * Due to the fact that symmetric encryption is utilized, it is not necessary
 * to indicate the intended audience within the token itself.  The secret shared
 * between the issuer and the audience is sufficient to prove that the token
 * has been received by the intended party, provided that the token is indeed
 * valid.
 *
 * References:
 *  - [iron](https://github.com/hueniverse/iron)
 */
module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  
  return function iron(claims, audience, options, cb) {
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    options.encryption = options.encryption || {};
    options.signature = options.signature || {};
    audience = audience || [];
    
    //var audience = options.audience || [];
    if (audience.length > 1) {
      return cb(new Error('Unable to seal iron tokens for multiple recipients'));
    }
    
    var ealg = 'aes256-cbc'
      , rcptSupported;
    if (options.encryption.algorithms) {
      rcptSupported = options.encryption.algorithms;
      ealg = ALGORITHMS.find(function(a) { return rcptSupported.indexOf(a) != -1 });
      if (!ealg) {
        return cb(new Error('Unsupported encryption algorithm: ' + rcptSupported[0]));
      }
    }
    
    
    var query  = {
      usage: 'deriveKey',
      recipient: audience[0],
      algorithms: [ 'pbkdf2' ]
    }
    
    keying(query, function(err, keys) {
      if (err) { return cb(err); }
      
      var key = keys[0];
      var password = key.secret;
      if (key.id) {
        password = {
          id: key.id,
          secret: key.secret
        }
      }
      
      var opts = clone(Iron.defaults);
      opts.encryption.algorithm = ALGORITHM_MAP[ealg];
      opts.encryption.saltBits = options.encryption.saltLength || 256;
      opts.encryption.iterations = options.encryption.iterations || 1;
      
      Iron.seal(claims, password, opts, function(err, sealed) {
        if (err) { return cb(err); }
        return cb(null, sealed);
      });
    });
  };
};
