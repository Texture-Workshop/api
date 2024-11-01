const fs = require("fs").promises;
const path = require("path");
const bcrypt = require("bcrypt");

// Define log file path
const logFilePath = path.join(__dirname, "..", "logs.txt");

// Delete logs older than one week
async function deleteLogs() {
    try {
        await fs.access(logFilePath);
        
        const stats = await fs.stat(logFilePath);
        
        // Check if file is older than one week
        if (Date.now() - new Date(stats.birthtime).getTime() > (7 * 24 * 60 * 60 * 1000)) {
            await fs.unlink(logFilePath);
            log.info("Logs have been cleaned!");
        }
    } catch (error) {
        if (error.code == "ENOENT") {
            await fs.writeFile(logFilePath, "", "utf8");
        } else {
            log.error("Error checking logs file information:", error);
        }
    }
}

// Simplified async functions that are related to console logging.
const log = {
    error: async (message, error) => {
        await deleteLogs();
        const logMessage = `[ERROR] ${message} ${error || ""}`.trim();
        try {
            await fs.appendFile(logFilePath, `${logMessage}\n`, 'utf8');
            console.error(logMessage);
        } catch (error) {
            console.error("Failed to write error log:", error);
        }
    },

    warn: async (message, warn) => {
        await deleteLogs();
        const logMessage = `[WARN] ${message} ${warn || ""}`.trim();
        try {
            await fs.appendFile(logFilePath, `${logMessage}\n`, 'utf8');
            console.warn(logMessage);
        } catch (error) {
            console.error("Failed to write warn log:", error);
        }
    },

    info: async (message, info) => {
        await deleteLogs();
        const logMessage = `[INFO] ${message} ${info || ""}`.trim();
        try {
            await fs.appendFile(logFilePath, `${logMessage}\n`, 'utf8');
            console.info(logMessage);
        } catch (error) {
            console.error("Failed to write info log:", error);
        }
    },

    debug: async (message, debug) => {
        await deleteLogs();
        const logMessage = `[DEBUG] ${message} ${debug || ""}`.trim();
        try {
            await fs.appendFile(logFilePath, `${logMessage}\n`, 'utf8');
            console.info(logMessage);
        } catch (error) {
            console.error("Failed to write debug log:", error);
        }
    },

    request: async (request, logToConsole) => {
        await deleteLogs();
        if (!request) return;
        const logMessage = `[REQUEST] ${request}`;
        try {
            await fs.appendFile(logFilePath, `${logMessage}\n`, 'utf8');
            if (logToConsole) console.log(logMessage);
        } catch (error) {
            console.error("Failed to write request log:", error);
        }
    }
};

// Simplified async functions that are related to base64.
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

// Simplified async functions that, for most, use the bcrypt module.
const encrypt = {
    generateSalt: (saltRounds) => {
        try {
            return bcrypt.genSaltSync(saltRounds);
        } catch (error) {
            log.error("Failed generating password salt:", error);
            return null;
        }
    },

    // Generate an hash and returns it, using a password and a salt. Returns false if it fails to, or one of the values are invalid.
    generateHash: async (password, salt) => {
        if (!password || !salt) return false;
        try {
            return bcrypt.hashSync(password, salt);
        } catch (error) {
            log.error("Failed generating password hash:", error);
            return null;
        }
    },

    // Verify the authenticity of a password compared to an hash. Returns false if it fails to, if one of the values is invalid or if the password is invalid.
    verifyPassword: async (password, hash) => {
        if (!password || !hash) return false;
        try {
            return bcrypt.compareSync(password, hash);
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

// Tries to verify a user; Will check if they exist and will verify if their password is correct.
async function verifyUser(db, username, password, checkPerm) {
    if (!db || !username || !password) return false;
    try {
        username = encode.base64encode(username);
        const row = db.prepare("SELECT * FROM accounts WHERE userName = ?").get(username);

        if (!row) return false;

        // Password verification
        if (!encrypt.verifyPassword(password, row.hash)) return false;

        // Permission check (if needed)
        if (checkPerm && row[checkPerm.replace(/[^A-Za-z]/g, "")] < 1 && row.permAdmin < 1) return false;

        return true;
    } catch (error) {
        log.error("Failed verifying user:", error);
        return false;
    }
}

module.exports = {
    log,
    encode,
    encrypt,
    deleteFile,
    verifyUser
};
