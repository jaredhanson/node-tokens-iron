var Iron = require('iron')
  , clone = require('clone')
  , constants = require('./constants');

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
  
  
  return function iron(claims, options, cb) {
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    
    var audience = options.audience || [];
    if (audience.length > 1) {
      return cb(new Error('Unable to seal iron tokens for multiple recipients'));
    }
    
    var encopts = options.encryption || {};
    var sigopts = options.signing || {};
    encopts.algorithms = encopts.algorithms || [ 'aes256-cbc' ];
    
    var encalg = constants.ENCRYPTION_ALGORITHM_MAP[encopts.algorithms[0]];
    if (!encalg) {
      return cb(new Error('Unsupported algorithm: ' + encopts.algorithms[0]));
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
      opts.encryption.algorithm = encalg;
      opts.encryption.saltBits = options.saltLength || 256;
      
      Iron.seal(claims, password, opts, function(err, sealed) {
        if (err) { return cb(err); }
        return cb(null, sealed);
      });
    });
  };
};
