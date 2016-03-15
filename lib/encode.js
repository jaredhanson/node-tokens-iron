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
    
    
    function didKey(err, key, info) {
      var ticket = {
        exp: claims.expiresAt.getTime(),
        app: claims.authorizedParty || claims.authorizedPresenter,
        scope: claims.scope || []
      }
    
      if (claims.subject) {
        ticket.user = claims.subject;
      }
      if (claims.grant) {
        ticket.grant = claims.grant;
      }
    
    
      // TODO: Implement support for "grant", which identifies the authorization grant
      //       Useful for immediate, stateful revocation checks
    
      // TODO: Implement support for delegatiable tickets
      ticket.delegate = false;
    
      // TODO: `key` is options, which appears
      //       only necessary in the Hawk authentication scheme, or other pop-type
      //       schemes, such as OAuth
      if (claims.confirmation) {
        // TODO: Generalize this...
        ticket.key = claims.confirmation.key;
        ticket.algorithm = 'sha256';
      }
    
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
      
      Iron.seal(ticket, secret, opts, function(err, sealed) {
        if (err) { return cb(err); }
        return cb(null, sealed);
      });
    }
    
    options.use = 'encryption';
    keying(options, didKey);
  }
}
