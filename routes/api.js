/**
 * Created by waps12b on 15. 6. 3..
 */
var express = require('express');
var router = express.Router();
var NodeRSA = require('node-rsa');
var crypto = require('crypto'),
    algorithm = 'aes-256-cbc';
var fs = require('fs');
var mysql = require('mysql');
var db_info = require('../db_info');
var async = require('async');

var key = new NodeRSA(fs.readFileSync('./keys/rsa-private.pem', 'utf8'));


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
    //console.log('[cipher] : ' + cipher);
    //console.log('[my]' + key.encrypt('hello','base64'));
    ////
    //var buf = new Buffer(cipher,'hex');
    //console.log('[buf] : ' + buf.toString('hex'));
    //var dectext = buf.toString('base64');
    //console.log('[base64]' + dectext);
    //try {
    //    var decrypted = key.decrypt(cipher, 'utf8');
    //} catch (e) {
    //    console.log(e);
    //}
    var decrypted = cipher;
    console.log('[plain] : ' + decrypted);
    var json = JSON.parse(decrypted);
    var user_id = json['user_id'];
    var user_pw = json['user_pw'];
    var session_key = json['session_key'];
    var hashed_pw = get_hashed(user_pw);

    var query = "select * from user where user_id = '" + user_id + "' and user_pw ='" + hashed_pw +"' ";
    connection.query(query,function(err,rows) {
        var json = {};
        if (!err && rows.length == 1) {//auth okay
            console.log(rows);
            json.Result = "TRUE";
            connection.query("insert into session (user_id, session_key) values('"+ user_id +"', '" + session_key+ "')");
        } else
        {
            json.Result = "FALSE";
        }
        json.Cipher = encryptAES( JSON.stringify({RN:crypto.randomBytes(20).toString('hex')}), session_key);
        res.end(JSON.stringify(json));
    });
});

router.all('/vote_info', function(req, res) {
    var cipher = req.body.cipher;
    var user_id = req.body.user_id;
    var hmac = req.body.hmac.toLowerCase();
    var ret = {};
    var json = {};
    var session_key;
    var vote_id;
    async.series([
        function (callback) {
            //query auth
            connection.query("select * from session where user_id = '" + user_id +"' ORDER BY session_id DESC LIMIT 1", function(err,rows) {
                if (!err && rows.length == 1) {//auth okay
                    session_key = rows[0].session_key;
                    var my_hmac =  get_hashed(user_id + session_key).toLowerCase();
                    //console.log('[hmac1]' + hmac);
                    //console.log('[hmac2]' + my_hmac);
                    if( hmac != my_hmac)
                    { // wrong hmac
                        callback(err);
                    }
                } else {
                    callback(err);
                }
                var decrypted = decryptAES(cipher, session_key);
                decrypted = decrypted.replace(/(\r\n|\n|\r|\s|\t)/gm,"");
                console.log('[dec] (' + decrypted +')');

                var req_vote = JSON.parse(decrypted);
                vote_id = req_vote.vote_id;

                callback(null, null);
            });

        },
        function (callback) {
            // get vote info
            console.log('vote table');
            connection.query("select * from vote where vote_id = '" + vote_id +"'", function(err,rows) {
                if (!err && rows.length == 1) {//auth okay
                    json.vote_id = vote_id;
                    json.vote_desc = rows[0].vote_desc;
                    json.vote_item = {};
                } else {
                    callback(err);
                }
                callback(null, null);
            });
        },
        function (callback) {
            console.log('item table');
            connection.query("select * from item where vote_id = '" + vote_id +"'", function(err,rows) {
                if (!err && rows.length >= 1) {//auth okay
                    json.vote_item = rows;
                } else {
                    callback(err);
                }
                callback(null, null);
            });
        },
    ],function(err, results)
    {
        console.log('last function');
        if(err)
        {
            ret.Result = "FALSE";
        }else
        {
            ret.Result = "TRUE";
            ret.cipher = encryptAES( JSON.stringify(json), session_key);
        }
        res.end(JSON.stringify(ret));
    });
});

//router.all('/register', function(req,res){
//    var user_id = "waps12b";
//    var user_pw = "password";
//    var hashed_pw = get_hashed(user_pw);
//
//    var query = connection.query('INSERT INTO user(user_id, user_pw) VALUES("' + user_id + '" ,"' + hashed_pw +   '"  )',function(err,rows){
//        console.log(rows);
//        res.end('okay');
//    });
//});

function encryptAES(text, session_key){
    var cipher = crypto.createCipheriv(algorithm, session_key, new Buffer('00000000000000000000000000000000','hex')).setAutoPadding(false);
    text = customPadding(text);

    var crypted = cipher.update(text,'utf8','hex');
    crypted += cipher.final('hex');
    return crypted;
}

function decryptAES(text, session_key){
    var decipher = crypto.createDecipheriv(algorithm,session_key, new Buffer('00000000000000000000000000000000','hex')).setAutoPadding(false);
    var dec = decipher.update(text,'hex','utf8');
    dec += decipher.final('utf8');
    return dec.trim();
}

function customPadding(str) {
    str = new Buffer(str,"utf8").toString("hex");
    var bitLength = str.length*8;

    if(bitLength < 256) {
        for(var i=bitLength;i<256;i+=8) {
            str += 0x0;
        }
    } else if(bitLength > 256) {
        while((str.length*8)%256 != 0) {
            str+= 0x0;
        }
    }
    return new Buffer(str,"hex").toString("utf8");
}

module.exports = router;
