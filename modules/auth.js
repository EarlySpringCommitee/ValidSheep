const sha256 = require('js-sha256').sha256;
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const jsonfile = require('jsonfile');

const algorithm = 'aes-256-ctr';
const config = jsonfile.readFileSync('config.json');
const jwtPassword = config.jwtPassword || 'test';
const jwtIss = config.jwtIss || 'ValidSheep API Server';
const jwtExpirePeriod = config.jwtExpirePeriod || 600;
const userFilesDir = config.userFilesDir || './users/';

const userPath = x => userFilesDir + x + '.usr';
const base64 = data => Buffer.from(data).toString("base64");
const checkFileExists = s => new Promise(r => fs.access(s, fs.F_OK, e => r(!e)))
const isUserExist = username => checkFileExists(userPath(username))

class Auth {
    constructor() {
        this.init()
    }

    init() {
        this.session = {}
        this.username = undefined;
        this.token = undefined;
    }

    register(username, password) {
        return new Promise(async(resolve, reject) => {
            if (await isUserExist(username)) reject(new Error("Username occupied."))
            else {
                encrypt(username, sha256(password), {
                        'username': username,
                        'servers': {}
                    })
                    .then(_ => this.login(username, sha256(password)))
                    .then(data => resolve(data))
                    .catch(err => reject(err))
                    }
            })
    }

    login(username, password) {
        return new Promise(async(resolve, reject) => {
            if (!(await isUserExist(username))) reject(new Error("User not exist."))
            else {
                decrypt(username, password)
                    .then(data => {
                        this.username = username
                        jwt.sign({ "data": encryptText(JSON.stringify(data), password) }, 
                            jwtPassword, {
                                expiresIn: jwtExpirePeriod,
                                issuer: jwtIss,
                                subject: username
                            }, 
                            (err, data) => {
                                if (err) reject(err);
                                else {
                                    this.token = data;
                                    resolve(data);
                                }
                            })
                    })
                    .catch(e => reject(e))
                }
            })
    }

    verify() {
        return new Promise((resolve, reject) => {
                jwt.verify(this.token, jwtPassword, { issuer: jwtIss }, (err, decoded) => {
                    if (err) this.logout(() => reject(err))
                    else resolve(decoded.data)
                });
            })
    }

    changePassword(oldPassword, newPassword) {
        return new Promise((resolve, reject) => {
                decrypt(this.username, oldPassword)
                    .then(data => {
                        fs.unlink(userPath(this.username), err => {
                            if (err) reject(err);
                            else {
                                encrypt(this.username, newPassword, data)
                                .then(_ => this.login(this.username, newPassword))
                                .then(_ => resolve(true))
                            }
                        })
                    })
                    .catch(err => reject(err))
            })
    }

    modifyData(password, newServer) {
        return new Promise((resolve, reject) => {
                fs.unlink(userPath(this.username), err => {
                    if (err) reject(err);
                    else {
                        data.servers = newServer
                        encrypt(this.username, password, data)
                            .then(_ => this.login(this.username, password))
                            .then(data => resolve(data))
                            .catch(e => reject(e))
                    }
                })
            })
    }

    logout(cb) {
        this.init()
        delete this
        return cb()
    }

    perish(cb) {
        return fs.unlink(userPath(this.username), err => {
            if (err) throw err;
            return this.logout(cb)
        })
    }
}

exports.Auth = Auth

function encrypt(username, password, data) {
    return new Promise(async(resolve, reject) => {
            let cipher = crypto.createCipher(algorithm, password);
            let crypted = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(data))), cipher.final()]);
            if (!(await checkFileExists(userFilesDir))) fs.mkdir(userFilesDir, 0777, err => {
                if (err) reject(err);
            })
            fs.writeFile(userPath(username), crypted, "binary", err => {
                if (err) reject(err);
                else resolve(userPath(username));
            })
        })
}

function decrypt(username, password) {
    return new Promise((resolve, reject) => {
            let decipher = crypto.createDecipher(algorithm, password);
            let dec = buffer => Buffer.concat([decipher.update(buffer), decipher.final()]).toString('utf8');
            fs.readFile(userPath(username), (err, data) => {
                if (err) reject(err);
                else {
                    try {
                        var decryptedData = JSON.parse(dec(data))
                        resolve(decryptedData);
                    } catch (e) {
                        reject(new Error("Password error."))
                    }
                }
            })
        })
}

// https://github.com/crypto-browserify/browserify-aes
// https://lollyrock.com/articles/nodejs-encryption/

function encryptText(text, password) {
    console.log(text)
    let cipher = crypto.createCipher(algorithm, password)
    let crypted = cipher.update(text, 'utf8', 'hex')
    crypted += cipher.final('hex');
    return crypted;
}