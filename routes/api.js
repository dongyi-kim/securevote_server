/**
 * Created by waps12b on 15. 6. 3..
 */
var express = require('express');
var router = express.Router();
var NodeRSA = require('node-rsa');
var crypto = require('crypto');
var fs = require('fs');
var mysql = require('mysql');
var db_info = require('../db_info');
var async = require('async');

//var session = require('express-session');



//var cipher = key.encrypt('abcd0900abcd0900','base64','hex');
//console.log(cipher);
//
//var plain = key.decrypt(cipher);
//console.log(plain);
//
//var key = ursa.createPrivateKey(fs.readFileSync('./keys/rsa-private.pem'));
//var crt = ursa.createPublicKey(fs.readFileSync('./keys/rsa-public.pem'));

var key = new NodeRSA(fs.readFileSync('./keys/rsa-private.pem', 'utf8'));
key.setOptions('pkcs1');
//var text = 'Hello RSA!';
//var encrypted = key.encrypt(text, 'base64');
//console.log('encrypted: ', encrypted);
//var decrypted = key.decrypt(encrypted, 'utf8');
//console.log('decrypted: ', decrypted);

var connection = mysql.createConnection({
    host    :'localhost',
    port : 3306,
    user : db_info.DB_ID,
    password : db_info.DB_PW,
    database:db_info.DB_NAME
});

connection.connect(function(err) {
    if (err) {
        console.error('mysql connection error');
        console.error(err);
        throw err;
    }else
    {
        console.log('db connected.');
    }
});

function get_hashed(pw) {
    var shasum = crypto.createHash('sha256');
    shasum.update(pw);
    return shasum.digest('hex');
}

//get public key
router.all('/get_public', function(req, res){
    var user_id = req.body.user_id;
    var query = "select * from user where user_id = '" + user_id + "'";
    console.log(query);
    connection.query(query,function(err,rows){
        var json = {};
        console.log(err);
        console.log(rows);
        if(err==null && rows.length == 1)
        {//user okay
            json.Result = "TRUE";
            json.Kp = fs.readFileSync('./keys/rsa-public.pem', 'utf8');
            json.RN = crypto.randomBytes(20).toString('hex');
            //res.end(data);
        }else
        {
            json.Result = "FALSE";
        }
        res.end(JSON.stringify(json));
    });

});


router.all('/auth', function(req, res){
    var cipher = req.body.cipher;
    console.log('[cipher] : ' + cipher);
    console.log('[my]' + key.encrypt('hello','base64'));
    ////
    //var buf = new Buffer(cipher,'hex');
    //console.log('[buf] : ' + buf.toString('hex'));
    //var dectext = buf.toString('base64');
    //console.log('[base64]' + dectext);
    try {
        var decrypted = key.decrypt(cipher, 'utf8');
    } catch (e) {
        console.log(e);
    }
    console.log('[plain] : ' + decrypted);
    var json = JSON.parse(decrypted);
    var user_id = json['user_id'];
    var user_pw = json['user_pw'];
    //var rn = json['rn'];
    //var session_key = json['session_key'];
    //var user_id = req.body.user_id;
    //var user_pw = req.body.user_pw;
    var hashed_pw = get_hashed(user_pw);



    console.log('here');
    //if( req.cookies.user_id !== user_id )
    //{ //user_id unmatched
    //    res.end('FALSE');
    //}
    //
    var query = "select * from user where user_id = '" + user_id + "' and user_pw ='" + hashed_pw +"' ";
    connection.query(query,function(err,rows) {
        var json = {};
        if (!err && rows.length == 1) {//auth okay
            console.log(rows);
            json.Result = "TRUE";
        } else
        {
            json.Result = "FALSE";
        }
        res.end(JSON.stringify(json));
    });
});



router.all('/register', function(req,res){
    var user_id = "waps12b";
    var user_pw = "password";
    var hashed_pw = get_hashed(user_pw);

    var query = connection.query('INSERT INTO user(user_id, user_pw) VALUES("' + user_id + '" ,"' + hashed_pw +   '"  )',function(err,rows){
        console.log(rows);
        res.end('okay');
    });
});



module.exports = router;
