var Iron = require('iron');


module.exports = function(options) {
  options = options || {};
  
  var key = options.key;
  
  
  return function iron(claims, options, cb) {
    console.log('ENCODE CLAIMS INTO OZ TICKET');
    console.log(claims);
    console.log(options);
    
    // TODO: Lack of audience claim in ticket??
    //       Requires non audience-qualified scope values, perhaps?
    // NOTE: encryptionPassword is effectively a resource server and audience check.
    
    var ticket = {
      exp: claims.expiresAt.getTime(),
      app: claims.authorizedParty || claims.authorizedPresenter,
      scope: claims.scope || []
    }
    
    if (claims.subject) {
      ticket.user = claims.subject;
    }
    
    
    // TODO: Implement support for "grant", which identifies the authorization grant
    //       Useful for immediate, stateful revocation checks
    
    // TODO: Implement support for delegatiable tickets
    ticket.delegate = false;
    
    if (claims.confirmation) {
      // TODO: Generalize this...
      ticket.key = claims.confirmation.key;
      ticket.algorithm = 'sha256';
    }
    
    
    // TODO: Call a keying function to obtain a symmetric key for the intended audience
    // TODO: Support options for algorithm, etc?  This potentially has to be negotiated
    //       with the resource server.  Maybe keying funciton should supply such things.
    
    function didKey(err, key, info) {
      console.log('ON KEYEED!');
      console.log(err);
      console.log(key);
      console.log(info);
    
      //var opts = {};
      var opts = Iron.defaults;
      // TODO: Change options base in `info`
      
      var secret = key;
      if (info.id) {
        secret = {
          id: info.id,
          secret: key
        }
      }
    
      // TODO: Can use `Iron` directly to avoid having a `key` be generated, which appears
      //       only necessary in the Hawk authentication scheme.
      // NOTE: If `key` is present, any use of `Bearer` authentication should be rejected.
    
      Iron.seal(ticket, secret, opts, function(err, sealed) {
        console.log(err);
        console.log(sealed);
      
      
        if (err) { return cb(err); }
        return cb(null, sealed);
      });
    }
    
    options.use = 'encryption';
    key(options, didKey);
  }
}
