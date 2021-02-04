/* global describe, it */

var Iron = require('iron');
var setup = require('../lib/seal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('seal', function() {
  
  describe('defaults', function() {
    
    describe('encrypting to self', function() {
      var token;
      
      before(function(done) {
        var seal = setup();
        seal({ foo: 'bar' }, { id: 'k1', secret: '12abcdef7890abcdef7890abcdef7890' }, function(err, t) {
          token = t;
          done(err);
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
      
      before(function(done) {
        var seal = setup();
        seal({ foo: 'bar' }, { secret: 'API-12abcdef7890abcdef7890abcdef' }, function(err, t) {
          token = t;
          done(err);
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
      
      before(function(done) {
        var options = {
          secret: 'API-12abcdef7890abcdef7890abcdef',
          encryption: { algorithms: [ 'aes128-ctr' ], saltLength: 128 }
        }
        
        var seal = setup();
        seal({ foo: 'bar' }, options, function(err, t) {
          token = t;
          done(err);
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
    
  }); // using defaults
  
}); // seal
