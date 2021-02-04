var Iron = require('iron')
  , clone = require('clone')
  , ALGORITHMS = require('./constants').ALGORITHMS
  , ALGORITHM_MAP = require('./constants').ALGORITHM_MAP;

/**
 * Seal a security token in an Iron envelope.
 *
 * Iron is a message security format that provides encryption with integrity
 * protection of JSON data structures.  The encryption is conducted using
 * either AES-256 in CBC mode or AES-128 in CTR mode, with integrity provided
 * by a SHA-256 HMAC.  The key used for signing and encryption is derived from
 * a password using PBKDF2.
 *
 * Due to the fact that symmetric encryption is utilized, it is not necessary
 * to indicate the intended audience within the token itself.  The secret shared
 * between the issuer and the audience is sufficient to prove that the token
 * has been received by the intended party, provided that the token is indeed
 * valid.
 *
 * Furthermore, because the issuer is not indicated within the unecrypted
 * portion of the token, applications are expected to be able to determine the
 * trusted issuer based on context specific to the application itself.  For
 * example, this could be configuration that sets a single, static trusted
 * issuer.
 *
 * References:
 *  - [iron](https://github.com/hueniverse/iron)
 */
module.exports = function iron(claims, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  options.encryption = options.encryption || {};
  options.signature = options.signature || {};
  
  var ealg = 'aes256-cbc'
    , rcptSupported;
  if (options.encryption.algorithms) {
    rcptSupported = options.encryption.algorithms;
    ealg = ALGORITHMS.find(function(a) { return rcptSupported.indexOf(a) != -1 });
    if (!ealg) {
      return cb(new Error('Unsupported encryption algorithm: ' + rcptSupported[0]));
    }
  }
  
  
  var password = options.secret;
  if (options.id) {
    password = {
      id: options.id,
      secret: options.secret
    }
  }

  var opts = clone(Iron.defaults);
  opts.encryption.algorithm = ALGORITHM_MAP[ealg];
  opts.encryption.saltBits = options.encryption.saltLength || 256;
  opts.encryption.iterations = options.encryption.iterations || 1;

  Iron.seal(claims, password, opts, function(err, token) {
    if (err) { return cb(err); }
    return cb(null, token);
  });
};
