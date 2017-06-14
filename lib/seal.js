var Iron = require('iron')
  , clone = require('clone');

var internals = {};

/**
 * Seal a security token in an Iron envelope.
 *
 * Iron is a message security format that provides encryption with integrity
 * protection of JSON data structures.  The encryption is conducted using
 * symmentric key algorithms.
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
    // TODO: Lack of audience claim in ticket??
    //       Requires non audience-qualified scope values, perhaps?
    // NOTE: encryptionPassword is effectively a resource server and audience check.
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
      var secret = key.secret;
      if (key.id) {
        secret = {
          id: key.id,
          secret: key.secret
        }
      }
      
      var opts = clone(Iron.defaults)
        , eopts
      if (key.algorithm) {
        eopts = internals.ENCRYPTION_ALGORITHM_OPTIONS[key.algorithm];
        if (!eopts) {
          return cb(new Error('Unsupported encryption algorithm: ' + key.algorithm));
        }
        opts.encryption = eopts;
      }
      
      Iron.seal(claims, secret, opts, function(err, sealed) {
        if (err) { return cb(err); }
        return cb(null, sealed);
      });
    });
  };
};


internals.ENCRYPTION_ALGORITHM_OPTIONS = {
  'aes128-ctr': {  // TODO: Verify that these options make sense
    saltBits: 128,
    algorithm: 'aes-128-ctr',
    iterations: 1,
    minPasswordlength: 16
  },
  'aes256-cbc': {
    saltBits: 256,
    algorithm: 'aes-256-cbc',
    iterations: 1,
    minPasswordlength: 32
  }
}
