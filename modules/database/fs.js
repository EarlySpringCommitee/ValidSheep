const fs = require('fs-extra')

class Database {
    constructor(userFilesDir) {
        fs.ensureDir(userFilesDir)
            .then((() => {
                this._userPath = x => userFilesDir + x + '.usr';
                let checkFileExists = s => new Promise(r => fs.access(s, fs.F_OK, e => r(!e)))

                this.isUserExist = username => checkFileExists(this._userPath(username))
                this.remove = username => fs.remove(this._userPath(username))
                this.write = (username, content) => fs.outputFile(this._userPath(username), content, "binary")
                this.read = username => fs.readFile(this._userPath(username))
            }))
            .catch(err => {throw err})
    }
}

exports.Database = x => new Database(x)