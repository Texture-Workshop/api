const log = {
    error: async (message, error) => {
        if (!error) return console.error("[ERROR]", message);
        else return console.error("[ERROR]", message, error);
    },
    warn: async (message, warn) => {
        if (!warn) return console.warn("[WARN]", message);
        else return console.warn("[WARN]", message, warn);
    },
    info: async (message, info) => {
        if (!info) return console.info("[INFO]", message);
        else return console.info("[INFO]", message, info);
    },
    debug: async (message, debug) => {
        if (!debug) return console.debug("[DEBUG]", message);
        else return console.debug("[DEBUG]", message, debug);
    }
};

const encode = {
    base64encode: async (string) => {
        if (!string) return;
        try {
            return Buffer.from(string).toString('base64');
        } catch (error) {
            log.error("Error while trying to encode string to base64:", error);
            return;
        }
    },
    base64decode: async (string) => {
        if (!string) return;
        try {
            return Buffer.from(string, 'base64').toString();
        } catch (error) {
            log.error("Error while trying to decode base64 to string:", error);
            return;
        }
    },
    base64urlencode: async (string) => {
        if (!string) return;
        try {
            return Buffer.from(string).toString('base64url');
        } catch (error) {
            log.error("Error while trying to encode string to base64url:", error);
            return;
        }
    },
    base64urldecode: async (string) => {
        if (!string) return;
        try {
            return Buffer.from(string, 'base64url').toString();
        } catch (error) {
            log.error("Error while trying to decode base64url to string:", error);
            return;
        }
    }
}

module.exports = {
    log,
    encode
};