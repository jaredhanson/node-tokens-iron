var Iron = require('iron')
  , clone = require('clone')
  , constants = require('./constants');

/**
 * Seal a security token in an Iron envelope.
 *
 * Iron is a message security format that provides encryption with integrity
 * protection of JSON data structures.  The encryption is conducted using
 * symmetric key algorithms.
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
    
    
    // TODO: Implement functionality to get separate encryption and integrity
    //       keys.
    var query  = {
      usage: 'encrypt',
      recipient: audience[0],
      algorithms: [ 'aes256-cbc', 'aes128-ctr' ]
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
      
      var opts = clone(Iron.defaults)
        , eopts
      if (key.algorithm) {
        eopts = constants.ENCRYPTION_ALGORITHM_OPTIONS[key.algorithm];
        if (!eopts) {
          return cb(new Error('Unsupported encryption algorithm: ' + key.algorithm));
        }
        opts.encryption = eopts;
      }
      
      Iron.seal(claims, password, opts, function(err, sealed) {
        if (err) { return cb(err); }
        return cb(null, sealed);
      });
    });
  };
};
