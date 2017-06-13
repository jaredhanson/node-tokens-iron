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
        if (q.recipients) {
          var recipient = q.recipients[0];
          return cb(null, [ { secret: recipient.secret } ]);
        }
        
        return cb(null, [ { id: 'k1', secret: '12abcdef7890abcdef7890abcdef7890' } ]);
      });
      
      seal = setup(keying);
    });
    
    
    describe('encrypting arbitrary claims', function() {
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
          recipients: undefined,
          usage: 'encrypt',
          algorithms: [ 'aes256-cbc' ]
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
    }); // encrypting arbitrary claims
    
    describe('encrypting arbitrary claims to audience', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/',
          secret: 'API-12abcdef7890abcdef7890abcdef'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipients: [ {
            id: 'https://api.example.com/',
            secret: 'API-12abcdef7890abcdef7890abcdef'
          } ],
          usage: 'encrypt',
          algorithms: [ 'aes256-cbc' ]
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
    }); // encrypting arbitrary claims
    
  });
  
});