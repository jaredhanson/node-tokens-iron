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
      user: claims.subject,
      app: claims.authorizedParty || claims.authorizedPresenter
    }
    
    var opts = {};
    
    
    Oz.ticket.generate(ticket, 's3cr1t-asdfasdfaieraadsfiasdfasd', opts, function(err, ticket) {
      console.log(err);
      console.log(ticket);
      
      
      if (err) { return cb(err); }
      return cb(null, ticket.id);
      
    })
    
    
  }
}
