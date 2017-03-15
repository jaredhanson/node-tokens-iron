/* global describe, it */

var pkg = require('..');
var expect = require('chai').expect;


describe('tokens-iron', function() {
  
  it('should export functions', function() {
    expect(pkg.seal).to.be.a('function');
    expect(pkg.unseal).to.be.a('function')
  });
  
});
