var Iron = require('iron')
  , clone = require('clone')
  , constants = require('./constants');

var internals = {};

/**
 * Unseal a security token from an Iron envelope.
 *
 * Iron is a message security format that provides encryption with integrity
 * protection of JSON data structures.  The encryption is conducted using
 * either AES-256 in CBC mode or AES-128 in CTR mode, with integrity provided
 * by a SHA-256 HMAC.  The key used for signing and encryption is derived from
 * a password using PBKDF2.
 *
 * Iron tokens do not provide a standardized means of indicating the issuer
 * of a token.  As such, it is assumed that the receipient of an Iron token
 * has a pre-arranged relationship with a single trusted issuer with which
 * it shares an encryption secret (referred to as a password in Iron) used to
 * decrypt and verify tokens.
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
  
  return function iron(sealed, cb) {
    var parsed;
    
    try {
      parsed = internals.parse(sealed)
    } catch(ex) {
      // not an iron token
      return cb(null);
    }
    
    // NOTE: There is no sender present in they key query, due to the fact that
    //       no (standardized) mechanism to indicate the issuer.
    var query  = {
      usage: 'decrypt',
      id: parsed.passwordId,
      algorithms: [ 'aes256-cbc', 'aes128-ctr' ]
    }
    
    keying(query, function(err, keys) {
      if (err) { return cb(err); }
      
      // TODO: Implement support for checking multiple keys
      
      var key = keys[0];
      var password = key.secret;
      var opts = clone(Iron.defaults);
      if (key.algorithm) {
        eopts = constants.ENCRYPTION_ALGORITHM_OPTIONS[key.algorithm];
        if (!eopts) {
          return cb(new Error('Unsupported encryption algorithm: ' + key.algorithm));
        }
        opts.encryption = eopts;
      }
      
      Iron.unseal(sealed, password, opts, function(err, claims) {
        if (err) { return cb(err); }
        
        var tkn = {
          headers: {
            keyID: parsed.passwordId
          },
          claims: claims
        }
        return cb(null, tkn);
      });
    });
    
    // TODO: Add an interpreter for Oz-based tickets.
    /*
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
    */
  };
};


internals.parse = function(sealed) {
  var parts = sealed.split('*');
  if (parts.length !== 8) {
    throw new Error('Invalid Iron serialization');
  }
  if (parts[0] !== Iron.macPrefix) {
    throw new Error('Invalid Iron serialization');
  }
  
  var passwordId = (parts[1].length ? parts[1] : undefined);
  
  return {
    passwordId: passwordId
  };
};
