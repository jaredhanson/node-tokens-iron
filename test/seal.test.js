/* global describe, it */

var Iron = require('iron');
var setup = require('../lib/seal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('seal', function() {
  
  describe('using defaults', function() {
    var seal, keying;
    
    before(function() {
      keying = sinon.spy(function(q, cb){
        if (!q.recipient) {
          return cb(null, [ { id: 'k1', secret: '12abcdef7890abcdef7890abcdef7890' } ]);
        }
        
        switch (q.recipient.id) {
        case 'https://api.example.com/':
          return cb(null, [ { secret: 'API-12abcdef7890abcdef7890abcdef' } ]);
        case 'https://rs1.example.com/':
          return cb(null, [ { id: 'rs1', secret: 'RS1-12abcdef7890abcdef7890abcdef', algorithm: 'aes128-ctr' } ]);
        }
      });
      
      seal = setup(keying);
    });
    
    
    describe('encrypting to self', function() {
      var token;
      before(function(done) {
        seal({ foo: 'bar' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          usage: 'encrypt',
          recipient: undefined,
          algorithms: [ 'aes256-cbc', 'aes128-ctr' ]
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
    
    describe('encrypting to audience', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/'
          },
          usage: 'encrypt',
          algorithms: [ 'aes256-cbc', 'aes128-ctr' ]
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
    }); // encrypting to audience
    
    describe('encrypting to audience with aes-128-ctr encryption', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://rs1.example.com/'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipient: {
            id: 'https://rs1.example.com/'
          },
          usage: 'encrypt',
          algorithms: [ 'aes256-cbc', 'aes128-ctr' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.be.above(0);
        expect(token.substr(0, 11)).to.equal('Fe26.2*rs1*');
      });
      
      describe('verifying claims', function() {
        var claims;
        before(function(done) {
          var opts = {
              encryption: {
                saltBits: 128,
                algorithm: 'aes-128-ctr',
                iterations: 1,
                minPasswordlength: 16
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
          
          Iron.unseal(token, 'RS1-12abcdef7890abcdef7890abcdef', opts, function(err, c) {
            claims = c;
            done(err);
          });
        });
        
        it('should be correct', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to audience with aes-128-ctr encryption
    
  });
  
});
