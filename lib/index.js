var Iron = require('iron');

exports.seal = require('./seal');
exports.unseal = require('./unseal');

exports.parse = function(token) {
  var parts = token.split('*');
  if (parts.length !== 8) {
    throw new Error('Invalid Iron token');
  }
  if (parts[0] !== Iron.macPrefix) {
    throw new Error('Invalid Iron token');
  }
  
  var passwordId = (parts[1].length ? parts[1] : undefined);
  
  return {
    key: {
      usage: 'decrypt',
      id: passwordId
    }
  };
};
