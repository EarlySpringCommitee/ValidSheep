const Syno = require('syno');

class Dsm {
    constructor(protocol, host, port, account, passwd, apiVersion) {
        this._syno = new Syno({
            // Requests protocol : 'http' or 'https' (default: http)
            protocol: protocol,
            // DSM host : ip, domain name (default: localhost)
            host: host,
            // DSM port : port number (default: 5000)
            port: port,
            // DSM User account (required)
            account: account,
            // DSM User password (required)
            passwd: passwd,
            // DSM API version (optional, default: 6.0.2)
            apiVersion: apiVersion
        });
    }
    tasks() {
        let tasks = {}
        this._syno.dl.listTasks(resp => resp.tasks.forEach(task => tasks[task.id] = task))
        return tasks

        /*
        {
            "id": {
                "id": "dbid_141",
                "size": 38981861376,
                "status": "paused", // paused, error, finished, downloading, pending
                "title": "TASKNAME",
                "type": "bt", // bt, https, http
                "username": "ESC"
            }
        }
        */
    }

    getInfo() {
        return this._syno.dl.getInfo()

        /*
            {
                "is_manager":true,
                "version":2269,
                "version_string":"3.2-2269"
            }
        */
    }
}