/* global describe, it */

var Iron = require('iron');
var setup = require('../lib/unseal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('unseal', function() {
  
  describe('defaults', function() {
    
    describe('decrypting', function() {
      var claims, conditions;
      
      var keying = sinon.stub().yields(null, { secret: 'API-12abcdef7890abcdef7890abcdef' });
      
      before(function(done) {
        var token = 'Fe26.2**a26b6f7d7ea3e27e43d19e39323e6c71a5b48d92391a152e7ad4b251329886d6*POBMxPB55ziWCaTDrYrKIw*RAtJEMSA4zaRL0_opM-r1g**83fa7e47602b919b42e3d2f65e0e86e776ff251747c04d2b8c8ae2358dc98408*xDBJInWQNdFGKIxFaDCJRGpYoMO9xYYLFv27BYl-LDQ';
        
        var unseal = setup(keying);
        unseal(token, function(err, c, co) {
          claims = c;
          conditions = co;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          id: undefined,
          usage: 'deriveKey',
          algorithms: [ 'pbkdf2' ]
        });
      });
      
      it('should yield claims', function() {
        expect(claims).to.deep.equal({
          foo: 'bar'
        });
      });
      
      it('should yield conditions', function() {
        expect(conditions).to.deep.equal({
        });
      });
    }); // decrypting
    
    describe('decrypting with issuer', function() {
      var claims, conditions;
      
      var keying = sinon.stub().yields(null, { secret: 'API-12abcdef7890abcdef7890abcdef' });
      
      before(function(done) {
        var token = 'Fe26.2**a26b6f7d7ea3e27e43d19e39323e6c71a5b48d92391a152e7ad4b251329886d6*POBMxPB55ziWCaTDrYrKIw*RAtJEMSA4zaRL0_opM-r1g**83fa7e47602b919b42e3d2f65e0e86e776ff251747c04d2b8c8ae2358dc98408*xDBJInWQNdFGKIxFaDCJRGpYoMO9xYYLFv27BYl-LDQ';
        
        var unseal = setup(keying);
        unseal(token, { issuer: { identifier: 'https://server.example.com' } }, function(err, c, co) {
          claims = c;
          conditions = co;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({ identifier: 'https://server.example.com' });
        expect(call.args[1]).to.deep.equal({
          id: undefined,
          usage: 'deriveKey',
          algorithms: [ 'pbkdf2' ]
        });
      });
      
      it('should yield claims', function() {
        expect(claims).to.deep.equal({
          foo: 'bar'
        });
      });
      
      it('should yield conditions', function() {
        expect(conditions).to.deep.equal({
        });
      });
    }); // decrypting with issuer
    
    describe('decrypting with specific key', function() {
      var claims, conditions;
      
      var keying = sinon.stub().yields(null, { secret: '12abcdef7890abcdef7890abcdef7890' });
      
      before(function(done) {
        var token = 'Fe26.2*k1*d07707532253175ab08dd0c852daa869788e27e09cb3357fcd81f099c3d2dc91*SnwigF0hAiavmOZmOSJBAw*xuthZNzot190oBfOOlEcwA**adda380704c56029f5f95abd14ccd8a31c4426a54ce2d31eb885426ca7336cec*iRBd9muS5WQ3_cvcmedjujPX7lWKuABoyGwLXhwN0lU';
        
        var unseal = setup(keying);
        unseal(token, function(err, c, co) {
          claims = c;
          conditions = co;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          id: 'k1',
          usage: 'deriveKey',
          algorithms: [ 'pbkdf2' ]
        });
      });
      
      it('should yield claims', function() {
        expect(claims).to.deep.equal({
          foo: 'bar'
        });
      });
      
      it('should yield conditions', function() {
        expect(conditions).to.deep.equal({
        });
      });
    }); // decrypting with specific key
    
  }); // defaults
  
  describe('using AES-128 in CTR mode', function() {
    var unseal, keying;
    
    describe('decrypting', function() {
      var claims, conditions;
      
      var keying = sinon.stub().yields(null, { secret: 'RS1-12abcdef7890abcdef7890abcdef' });
      
      before(function(done) {
        var token = 'Fe26.2*rs1*53ec68594e9a1cce7d218204a057b8a4*axVXk6wymK23icn-tV8QsA*na07AthWC4sQHlDlXg**53840cce2a1c9c31e6395c121c7727c80891f440022b2abcd5b81e4a3bbbbbc9*9xzbl80Ih12hzu_tcFAjFdcAlOAGvSBZtw9kZt3pcCM';
        
        var unseal = setup({ encryption: { algorithm: 'aes128-ctr' } }, keying);
        unseal(token, function(err, c, co) {
          claims = c;
          conditions = co;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[1]).to.deep.equal({
          id: 'rs1',
          usage: 'deriveKey',
          algorithms: [ 'pbkdf2' ]
        });
      });
      
      it('should yield claims', function() {
        expect(claims).to.deep.equal({
          foo: 'bar'
        });
      });
      
      it('should yield conditions', function() {
        expect(conditions).to.deep.equal({
        });
      });
    }); // decrypting
    
  }); // using AES-128 in CTR mode
  
}); // unseal
