const log = {
    error: async (message, error) => {
        if (!error) return console.error(`[ERROR] ${message}`);
        else return console.error(`[ERROR] ${message} ${error}`);
    },
    warn: async (message, warn) => {
        if (!warn) return console.warn(`[WARN] ${message}`);
        else return console.warn(`[WARN] ${message} ${warn}`);
    },
    info: async (message, info) => {
        if (!info) return console.info(`[INFO] ${message}`);
        else return console.info(`[INFO] ${message} ${info}`);
    },
    debug: async (message, debug) => {
        if (!debug) return console.debug(`[DEBUG] ${message}`);
        else return console.debug(`[DEBUG] ${message} ${debug}`);
    }
};

module.exports = {
    log
};