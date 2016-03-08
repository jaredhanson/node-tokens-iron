var Iron = require('iron')


module.exports = function(options, keying) {
  
  // TODO: Allow application to supply this.
  keying = function(cb) {
    return cb(null, 's3cr1t-asdfasdfaieraadsfiasdfasd')
  }
  
  return function oz(sealed, cb) {
    console.log('DECODE OZ TOKEN');
    console.log(sealed);
    
    function keyed(err, key) {
      if (err) { return cb(err); }
    
    
      //var opts = {};
      var opts = Iron.defaults;
    
      // TODO: Need to extend Oz/Iron with ability to call a callback to obtain the password
      //  (aka encryption secret), based on the password/key id.  This can be done by just
      //  splitting the data on * and parsing it out first.
    
      // TODO: Switch to Iron directly
    
      Iron.unseal(sealed, 'some-shared-with-rs-s3cr1t-asdfasdfaieraadsfiasdfasd', opts, function(err, ticket) {
        console.log(err);
        console.log(ticket);
      
        // TODO: Make sure crypto errors are treated as 4xx, not 5xx
        if (err) { return cb(err); }
      
        var claims = {};
        claims.subject = ticket.user || ticket.app;
        claims.authorizedParty =
        claims.authorizedPresenter = ticket.app;
        claims.scope = ticket.scope;
        
        if (ticket.key) {
          claims.confirmation = {
            type: 'symmetric',
            use: 'encryption',
            key: ticket.key
          }
        }
        
        return cb(null, claims);
      
      });
    }
    
    // TODO: Must have a well-known issuer that is expected to have generated this ticket,
    //       since shared secrets are in use.   Could be determined from key id, if multiple
    //       parties are expected.
    keying(keyed);
  }
  
}
