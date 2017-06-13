var Iron = require('iron');


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
    
    var query  = {
      recipient: audience[0],
      usage: 'encrypt',
      algorithms: [ 'aes256-cbc' ]
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
      
      var opts = Iron.defaults;
      
      Iron.seal(claims, secret, opts, function(err, sealed) {
        if (err) { return cb(err); }
        return cb(null, sealed);
      });
    });
  };
};
