var Iron = require('iron');


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
    
    var query  = {
      recipients: options.audience,
      usage: 'encrypt',
      algorithms: [ 'aes256-cbc' ]
    }
    
    keying(query, function(err, keys) {
      var ticket = claims;
      var opts = Iron.defaults;
      
      var key = keys[0];
      var secret = key.secret;
      if (key.id) {
      //if (1) {
        secret = {
          id: key.id || '123',
          secret: key.secret
        }
      }
      
      
      
      Iron.seal(ticket, secret, opts, function(err, sealed) {
        if (err) { return cb(err); }
        return cb(null, sealed);
      });
    });
  };
};
