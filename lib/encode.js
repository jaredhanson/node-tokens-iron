var Oz = require('oz')


module.exports = function(options) {
  options = options || {};
  
  return function oz(claims, cb) {
    console.log('ENCODE CLAIMS INTO OZ TICKET');
    console.log(claims);
    
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
    
    
    // TODO: Call a keying function to obtain a symmetric key for the intended audience
    // TODO: Support options for algorithm, etc?  This potentially has to be negotiated
    //       with the resource server.  Maybe keying funciton should supply such things.
    
    var opts = {};
    
    //var secret = 's3cr1t-asdfasdfaieraadsfiasdfasd';
    var secret = {
      id: '123', // NOTE: This is similar to a key ID in JWKS
      secret: 's3cr1t-asdfasdfaieraadsfiasdfasd'
    };
    
    // TODO: Can use `Iron` directly to avoid having a `key` be generated, which appears
    //       only necessary in the Hawk authentication scheme.
    // NOTE: If `key` is present, any use of `Bearer` authentication should be rejected.
    
    Oz.ticket.generate(ticket, secret, opts, function(err, ticket) {
      console.log(err);
      console.log(ticket);
      
      
      if (err) { return cb(err); }
      return cb(null, ticket.id);
    });
    
    
  }
}
