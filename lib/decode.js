var Oz = require('oz')


module.exports = function(options, keying) {
  
  return function oz(id, cb) {
    console.log('DECODE OZ TOKEN');
    console.log(id);
    
    var opts = {};
    
    Oz.ticket.parse(id, 's3cr1t-asdfasdfaieraadsfiasdfasd', opts, function(err, ticket) {
      console.log(err);
      console.log(ticket);
      
    });
    
    
  }
  
}
