const fs = require("fs").promises;
const bcrypt = require("bcrypt");

// Simplied async functions that are related to console logging.
const log = {
    // Log an error in the console.
    error: async (message, error) => {
        if (!error) return console.error("[ERROR]", message);
        else return console.error("[ERROR]", message, error);
    },

    // Log a warn in the console.
    warn: async (message, warn) => {
        if (!warn) return console.warn("[WARN]", message);
        else return console.warn("[WARN]", message, warn);
    },

    // Log an info in the console.
    info: async (message, info) => {
        if (!info) return console.info("[INFO]", message);
        else return console.info("[INFO]", message, info);
    },

    // Log a debug in the console.
    debug: async (message, debug) => {
        if (!debug) return console.debug("[DEBUG]", message);
        else return console.debug("[DEBUG]", message, debug);
    }
};

// Simplied async functions that are related to base64.
const encode = {
    // Encode an URL using the base64 format.
    base64encode: async (string) => {
        if (!string) return;
        try {
            return Buffer.from(string).toString("base64");
        } catch (error) {
            log.error("Error while trying to encode string to base64:", error);
            return;
        }
    },

    // Decode an URL using the base64 format.
    base64decode: async (string) => {
        if (!string) return;
        try {
            return Buffer.from(string, "base64").toString();
        } catch (error) {
            log.error("Error while trying to decode base64 to string:", error);
            return;
        }
    },

    // Encode an URL using the base64 url format.
    base64urlencode: async (string) => {
        if (!string) return;
        try {
            return Buffer.from(string).toString("base64url");
        } catch (error) {
            log.error("Error while trying to encode string to base64url:", error);
            return;
        }
    },

    // Decode an URL using the base64 url format.
    base64urldecode: async (string) => {
        if (!string) return;
        try {
            return Buffer.from(string, "base64url").toString();
        } catch (error) {
            log.error("Error while trying to decode base64url to string:", error);
            return;
        }
    }
}

// Simplied async functions that, for most, use the bcrypt module.
const encrypt = {
    // Generate a salt and returns it. Returns false if it fails to or one of the values is invalid.
    generateSalt: async (saltRounds) => {
        if (!saltRounds) return false;
        try {
            const salt = await new Promise((resolve, reject) => {
                bcrypt.genSalt(saltRounds, (error, salt) => {
                    if (error) {
                        log.error("Failed generating password salt:", error);
                        reject(error);
                    } else {
                        resolve(salt);
                    }
                });
            });
            return salt;
        } catch (error) {
            log.error("Failed generating password salt:", error);
            return false;
        }
    },

    // Generate an hash and returns it, using a password and a salt. Returns false if it fails to, or one of the values are invalid.
    generateHash: async (password, salt) => {
        if (!password || !salt) return false;
        try {
            const hash = await new Promise((resolve, reject) => {
                bcrypt.hash(password, salt, (error, hash) => {
                    if (error) {
                        log.error("Failed generating password hash:", error);
                        reject(error);
                    } else {
                        resolve(hash);
                    }
                });
            });
            return hash;
        } catch (error) {
            log.error("Failed generating password hash:", error);
            return false;
        }
    },

    // Verify the authenticity of a password compared to an hash. Returns false if it fails to, if one of the values is invalid or if the password is invalid.
    verifyPassword: async (password, hash) => {
        if (!password || !hash) return false;
        try {
            const response = await new Promise((resolve, reject) => {
                bcrypt.compare(password, hash, (error, response) => {
                    if (error) {
                        log.error("Failed checking for password:", error);
                        reject(error);
                    } else {
                        resolve(response);
                    }
                });
            });
            return response;
        } catch (error) {
            log.error("Failed checking for password:", error);
            return false;
        }
    }
}

// Tries deleting a file. If it fails to, returns false.
async function deleteFile(filePath) {
    if (!filePath) return false;
    try {
        await fs.access(filePath);
        await fs.unlink(filePath);
        return true;
    } catch (error) {
        log.error("Failed to delete a file:", error);
        return false;
    }
}

module.exports = {
    log,
    encode,
    encrypt,
    deleteFile
};