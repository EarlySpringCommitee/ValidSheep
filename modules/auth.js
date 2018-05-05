const sha256 = require('js-sha256').sha256;
const fs = require('fs');
const crypto = require('crypto')
const jwt = require('jsonwebtoken');
const algorithm = 'aes-256-ctr'
const userPath = x => userFilesMenu + x + '.usr'
const base64 = data => Buffer.from(data).toString("base64")

const jwtPassword = 'test'
const jwtIss = 'ValidSheep API Server'
const jwtExpirePeriod = 600
const userFilesMenu = './users/'

class Auth {
    constructor(){
        this.session = {}
        this.username = undefined;
        this.token = undefined;
    }
    register(username, password, cb){
        if (userExist(username)) throw new Error ("Username occupied.")
        encrypt(username, sha256(password), {
            'username': username,
            'password': sha256(password),
            'servers': {}
        }, cb)
    }

    login(username, password, cb){
        if (!userExist(username)) throw new Error ("User not exist.")
        decrypt(username, password, data => {
            let currentUnixTime = Math.floor(new Date() / 1000)
            this.token = jwt.sign({"data": encryptText(JSON.stringify(data), data.password)}, jwtPassword, {
                expiresIn: jwtExpirePeriod,
                issuer: jwtIss,
                subject: username})
            cb(data)
        });
    }
}

function validate(token){
    jwt.verify(token, jwtPassword, {issuer:jwtIss}, function(err, decoded) {
        if (err) throw err
        console.log(decoded.data)
    });
}

exports.Auth = Auth
exports.validate = validate

function checkFileExistsSync(filepath){
    let flag = true;
    try{
        fs.accessSync(filepath, fs.F_OK);
    }catch(e){
      flag = false;
    }
    return flag;
}

function userExist(username) {
    return checkFileExistsSync(userPath(username))
}

function encrypt(username, password, data, cb){
    let cipher = crypto.createCipher(algorithm, password)
    let crypted = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(data))), cipher.final()]);
    console.log(crypted)
    if (!checkFileExistsSync(userFilesMenu)) fs.mkdirSync(userFilesMenu)
    fs.writeFile(userPath(username), crypted, "binary", err => {
        if (err) throw err
        cb()
    })
}
   
function decrypt(username, password, cb){
    let decipher = crypto.createDecipher(algorithm, password)
    let dec = buffer => Buffer.concat([decipher.update(buffer), decipher.final()]).toString('utf8');
    fs.readFile(userPath(username), (err, data) => {
        if (err) throw err
        cb(JSON.parse(dec(data)));
    })
}
// https://github.com/crypto-browserify/browserify-aes
// https://lollyrock.com/articles/nodejs-encryption/

function encryptText(text, password){
    var cipher = crypto.createCipher(algorithm, password)
    var crypted = cipher.update(text, 'utf8', 'hex')
    crypted += cipher.final('hex');
    return crypted;
}