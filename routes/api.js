/**
 * Created by waps12b on 15. 6. 3..
 */
var express = require('express');
var router = express.Router();
var NodeRSA = require('node-rsa');
var fs = require('fs');
//var session = require('express-session');


var key = new NodeRSA(fs.readFileSync('./keys/rsa-private.pem', 'utf8'));

//var cipher = key.encrypt('abcd0900abcd0900','base64','hex');
//console.log(cipher);
//
//var plain = key.decrypt(cipher);
//console.log(plain);

//get public key
router.all('/get_public', function(req, res){
    console.log(req.cookies.last);
    if(req.cookies.last==='a')
    {
        res.clearCookie('last');
    }else
    {
        res.cookie('last','a');

    }


    var data = fs.readFileSync('./keys/rsa-public.pem', 'utf8');
    var rn = req.body.rn;


    console.log(rn);
    res.end(data);
});




module.exports = router;
