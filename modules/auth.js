const sha256 = require('js-sha256').sha256;
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const jsonfile = require('jsonfile');

const algorithm = 'aes-256-ctr';
const config = jsonfile.readFileSync('config.json');
const jwtPassword = config.jwtPassword || 'test';
const jwtIss = config.jwtIss || 'ValidSheep API Server';
const jwtExpirePeriod = config.jwtExpirePeriod || 600;
const userFilesDir = config.userFilesDir || './users/';
const dbType = config.dbType || 'fs';

const base64 = data => Buffer.from(data).toString("base64");
const db = require('./database/' + dbType + '.js').Database(userFilesDir)

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
            if (await db.isUserExist(username)) reject(new Error("Username occupied."))
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
            if (!(await db.isUserExist(username))) reject(new Error("User not exist."))
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
                if (err) this.logout().then(_ => reject(err)).catch(e => reject[e, err])
                else resolve(decoded.data)
            });
        })
    }

    changePassword(oldPassword, newPassword) {
        return new Promise((resolve, reject) => {
            decrypt(this.username, oldPassword)
                .then(data => encrypt(this.username, newPassword, data))
                .then(_ => this.login(this.username, newPassword))
                .then(_ => resolve(true))
                .catch(err => reject(err))
            })
    }

    modifyData(password, newServer) {
        return new Promise((resolve, reject) => {
            decrypt(this.username, password)
                .then(data => encrypt(this.username, password, {...data, ...{servers: newServer}}))
                .then(_ => this.login(this.username, password))
                .then(data => resolve(data))
                .catch(e => reject(e))
            })
    }

    logout() {
        return new Promise((resolve, reject) => {
            try {
                this.init()
                delete this
                resolve(true)
            } catch(e) {
                reject(e)
            }
        })
    }

    perish() {
        return new Promise((resolve, reject) => {
            db.remove(this.username)
                .then(() => this.logout())
                .then(_ => resolve(true))
                .catch(e => reject(e))
        })
    }
}

exports.Auth = Auth

function encrypt(username, password, data) {
    return new Promise(async(resolve, reject) => {
        let cipher = crypto.createCipher(algorithm, password);
        let crypted = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(data))), cipher.final()]);
        db.write(username, crypted)
            .then(() => resolve(true))
            .catch(err => reject(err))
        })
}

function decrypt(username, password) {
    return new Promise((resolve, reject) => {
        let decipher = crypto.createDecipher(algorithm, password);
        let dec = buffer => Buffer.concat([decipher.update(buffer), decipher.final()]).toString('utf8');
        db.read(username)
            .then(data => resolve(JSON.parse(dec(data))))
            .catch(_ => reject(new Error("Password error.")))
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