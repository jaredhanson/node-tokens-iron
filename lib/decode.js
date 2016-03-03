var Oz = require('oz')


module.exports = function(options, keying) {
  
  // TODO: Allow application to supply this.
  keying = function(cb) {
    return cb(null, 's3cr1t-asdfasdfaieraadsfiasdfasd')
  }
  
  return function oz(id, cb) {
    console.log('DECODE OZ TOKEN');
    console.log(id);
    
    function keyed(err, key) {
      if (err) { return cb(err); }
    
    
      var opts = {};
    
      // TODO: Need to extend Oz/Iron with ability to call a callback to obtain the password
      //  (aka encryption secret), based on the password/key id.
    
      // TODO: Switch to Iron directly
    
      Oz.ticket.parse(id, 's3cr1t-asdfasdfaieraadsfiasdfasd', opts, function(err, ticket) {
        console.log(err);
        console.log(ticket);
      
        // TODO: Make sure crypto errors are treated as 4xx, not 5xx
        if (err) { return cb(err); }
      
        var claims = {};
        claims.subject = ticket.user || ticket.app;
        claims.authorizedParty =
        claims.authorizedPresenter = ticket.app;
        claims.scope = ticket.scope;
        
        return cb(null, claims);
      
      });
    }
    
    // TODO: Must have a well-known issuer that is expected to have generated this ticket,
    //       since shared secrets are in use.   Could be determined from key id, if multiple
    //       parties are expected.
    keying(keyed);
  }
  
}
