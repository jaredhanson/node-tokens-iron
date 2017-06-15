exports.ENCRYPTION_ALGORITHM_OPTIONS = {
  'aes128-ctr': {  // TODO: Verify that these options make sense
    saltBits: 128,
    algorithm: 'aes-128-ctr',
    iterations: 1,
    minPasswordlength: 16
  },
  'aes256-cbc': {
    saltBits: 256,
    algorithm: 'aes-256-cbc',
    iterations: 1,
    minPasswordlength: 32
  }
};


exports.ENCRYPTION_ALGORITHMS = [ 'aes256-cbc', 'aes128-ctr' ];

exports.ENCRYPTION_ALGORITHM_MAP = {
  'aes128-ctr': 'aes-128-ctr',
  'aes256-cbc': 'aes-256-cbc'
};
