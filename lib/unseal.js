var Iron = require('iron')

var internals = {};


module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  return function iron(sealed, cb) {
    console.log('UNSEAL IRON!');
    console.log(sealed);
    
    var parsed;
    
    try {
      parsed = internals.parse(sealed)
    } catch(ex) {
      // not a JWT, attempt other parsing
      return cb(null);
    }
    
    console.log(parsed);
    
    
    function keyed(err, keys) {
      //if (err) { return cb(err); }
      
      console.log('GOT KEYS!');
      console.log(err);
      console.log(keys)
      
      var opts = Iron.defaults;
      var key = keys[0].secret;
      
      Iron.unseal(sealed, key, opts, function(err, claims) {
        console.log('UNSEALED');
        console.log(err);
        console.log(claims);
        
        if (err) { return cb(err); }
        
        var tok = {
          issuer: query.sender,
          headers: {
            issuer: claims.iss
          },
          claims: claims
        }
      
        return cb(null, tok);
      });
    }
    
    
    // NOTE: There is no sender present in they key query, due to the fact that
    //       no acceptably standardized mechanism exists to indicate the issuer
    //       of an Iron token.  Iron's constraints assume that a receipient of a
    //       token has a pre-arranged relationship with a single token issuer,
    //       and therefor the issuer is implied.
    var query  = {
      usage: 'decrypt',
      id: parsed.passwordId,
      algorithms: [ 'aes256-cbc' ]
    }
    
    console.log('QUERY WILL BE');
    console.log(query);
    
    keying(query, keyed);
    return;
    
    
    return;
    
    function didKey(err, key, info) {
      if (err) { return cb(err); }
      
      //var opts = {};
      var opts = Iron.defaults;
      // TODO: Change options base in `info`
      
      Iron.unseal(sealed, key, opts, function(err, ticket) {
        console.log(err);
        console.log(ticket);
      
        // TODO: Make sure crypto errors are treated as 4xx, not 5xx (wrong key, etc)
        if (err) { return cb(err); }
      
        var claims = {};
        claims.subject = ticket.user || ticket.app;
        claims.authorizedParty =
        claims.authorizedPresenter = ticket.app;
        claims.scope = ticket.scope;
        // TODO: Parse expiration, make sure it is checked by `Iron` internall, if not do it here
        if (ticket.grant) {
          claims.grant = ticket.grant;
        }
        
        if (ticket.key) {
          claims.confirmation = {
            use: 'signing',
            key: ticket.key
          }
          // TODO: Set confimation algorithm key in normalized form
        }
        
        // TODO: Set delegation claim in normalized form
        
        return cb(null, claims);
      
      });
    }
    
      // TODO: Need to extend Oz/Iron with ability to call a callback to obtain the password
      //  (aka encryption secret), based on the password/key id.  This can be done by just
      //  splitting the data on * and parsing it out first.  This will also help with format
      //  detection, so we don't throw errors and continue other token types.
    
    // TODO: Ensure that only symmetric algs are used for encrypting this token, unless
    //       there is some other way to indicate an issuer and audience.  As is, trust needs
    //       to be pre-configured, in order to avoid confused deputy problems.
    
    // TODO: Must have a well-known issuer that is expected to have generated this ticket,
    //       since shared secrets are in use.   Could be determined from key id, if multiple
    //       parties are expected.
    
    var opts = {};
    opts.use = 'decryption';
    opts.issuer = options.issuer;
    // TODO: Add key id (password ID in Oz/Hawk/Iron terminology)
    
    keying(opts, didKey);
  }
  
}


internals.parse = function(sealed) {
  var parts = sealed.split('*');
  if (parts.length !== 8) {
    throw new Error('Invalid Iron serialization');
  }
  if (parts[0] !== Iron.macPrefix) {
    throw new Error('Invalid Iron serialization');
  }
  
  console.log(parts);
  
  var passwordId = (parts[1].length ? parts[1] : undefined);
  
  return {
    passwordId: passwordId
  };
};
