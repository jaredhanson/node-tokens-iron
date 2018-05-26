/* global describe, it */

var Iron = require('iron');
var setup = require('../lib/seal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('seal', function() {
  
  describe('defaults', function() {
    
    describe('encrypting to self', function() {
      var token;
      
      var keying = sinon.stub().yields(null, { id: 'k1', secret: '12abcdef7890abcdef7890abcdef7890' });
      
      before(function(done) {
        var seal = setup(keying);
        seal({ foo: 'bar' }, { identifier: 'https://self-issued.me' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({ identifier: 'https://self-issued.me' });
        expect(call.args[1]).to.deep.equal({
          usage: 'deriveKey',
          algorithms: [ 'pbkdf2' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.be.above(0);
        expect(token.substr(0, 10)).to.equal('Fe26.2*k1*');
      });
      
      describe('verifying claims', function() {
        var claims;
        before(function(done) {
          Iron.unseal(token, '12abcdef7890abcdef7890abcdef7890', Iron.defaults, function(err, c) {
            claims = c;
            done(err);
          });
        });
        
        it('should be correct', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to self
    
    describe('encrypting to recipient', function() {
      var token;
      
      var keying = sinon.stub().yields(null, { secret: 'API-12abcdef7890abcdef7890abcdef' });
      
      before(function(done) {
        var recipients = [ {
          id: 'https://api.example.com/'
        } ];
        
        var seal = setup(keying);
        seal({ foo: 'bar' }, recipients, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          id: 'https://api.example.com/'
        });
        expect(call.args[1]).to.deep.equal({
          usage: 'deriveKey',
          algorithms: [ 'pbkdf2' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.be.above(0);
        expect(token.substr(0, 8)).to.equal('Fe26.2**');
      });
      
      describe('verifying claims', function() {
        var claims;
        before(function(done) {
          Iron.unseal(token, 'API-12abcdef7890abcdef7890abcdef', Iron.defaults, function(err, c) {
            claims = c;
            done(err);
          });
        });
        
        it('should be correct', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to recipient
    
    describe('encrypting to recipient with AES-128 in CTR mode and 128-bit encryption salt', function() {
      var token;
      
      var keying = sinon.stub().yields(null, { secret: 'API-12abcdef7890abcdef7890abcdef' });
      
      before(function(done) {
        var recipients = [ {
          id: 'https://api.example.com/'
        } ];
        
        var options = {
          encryption: { algorithms: [ 'aes128-ctr' ], saltLength: 128 }
        }
        
        var seal = setup(keying);
        seal({ foo: 'bar' }, recipients, options, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          id: 'https://api.example.com/'
        });
        expect(call.args[1]).to.deep.equal({
          usage: 'deriveKey',
          algorithms: [ 'pbkdf2' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.be.above(0);
        expect(token.substr(0, 8)).to.equal('Fe26.2**');
      });
      
      describe('verifying claims', function() {
        var claims;
        before(function(done) {
          var opts = {
            encryption: {
              saltBits: 128,
              algorithm: 'aes-128-ctr',
              iterations: 1,
              minPasswordlength: 32
            },
            integrity: {
              saltBits: 256,
              algorithm: 'sha256',
              iterations: 1,
              minPasswordlength: 32
            },
            ttl: 0,
            timestampSkewSec: 60,
            localtimeOffsetMsec: 0
          }
          
          Iron.unseal(token, 'API-12abcdef7890abcdef7890abcdef', opts, function(err, c) {
            claims = c;
            done(err);
          });
        });
        
        it('should be correct', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to audience with AES-128 in CTR mode and 128-bit encryption salt
    
    describe('encrypting to multiple recipients', function() {
      var error, token;
      
      before(function(done) {
        var recipients = [ {
          id: 'https://api.example.com/'
        }, {
          id: 'https://api.example.net/'
        } ];
        
        var seal = setup(function(){});
        seal({ foo: 'bar' }, recipients, function(err, t) {
          error = err;
          token = t;
          done();
        });
      });
      
      it('should error', function() {
        expect(error).to.be.an.instanceOf(Error);
        expect(error.message).to.equal('Unable to seal iron token to multiple recipients');
      });
      
      it('should not generate a token', function() {
        expect(token).to.be.undefined;
      });
    }); // encrypting to multiple recipients
    
  }); // using defaults
  
}); // seal
