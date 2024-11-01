require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const validator = require("validator");
const Database = require("better-sqlite3");
const axios = require("axios");
const sharp = require("sharp");
const path = require("path");

const { log, encode, deleteFile, verifyUser, encrypt } = require(path.join(__dirname, "util", "functions.js"));
const { logRequests, countDownloads, convertLogo, tpCache, logoCache, bcryptRounds } = require(path.join(__dirname, "config.json"));

const { version } = require(path.join(__dirname, "package.json"));

const fs = require("fs").promises;

const PORT = process.env.PORT ? process.env.PORT : 3300;

const TOKEN = process.env.TOKEN;
if (!TOKEN) {
    console.error("Please supply a token in your environment variables.");
    return process.exit(1);
}

const API_URL = `${process.env.API_URL ? process.env.API_URL : "http://localhost:3300"}/api/v1/tws`;

// Define the path where data such as texture packs or logos will be stored
const dataPath = path.join(__dirname, "data");

let db;
try {
    db = new Database(path.join(dataPath, "database.db"));
    db.exec(require("fs").readFileSync(path.join(dataPath, "database.sql"), "utf8"));
    log.info("Connected to SQLite and initialized tables if they didn't exist");
} catch (error) {
    log.error("Error initializing SQLite database:", error);
    process.exit(1);
}

const app = express();

if (process.env.TRUST_PROXY) app.set("trust proxy", process.env.TRUST_PROXY); // Number of proxies between user and server

// Log requests
app.use((req, res, next) => {
    try {
        req.time = new Date(Date.now()).toString();
    
        res.on('finish', () => {
            log.request(`(${req.time}) "${req.method} ${req.path} HTTP/${req.httpVersion}" (host: "${req.hostname}", requester: "${req.headers['x-forwarded-for'] || req.socket.remoteAddress}", code: ${res.statusCode}, user-agent: "${req.headers["user-agent"]}")`, logRequests ? true : false);
        });
        
        next();
    } catch(error) {
        log.error("Failed to log request:", error);
        return next();
    }
});

app.use(bodyParser.urlencoded({ extended: false }));

app.get("/favicon.ico", (req, res) => res.sendFile(path.join(__dirname, "app", "assets", "favicon.ico"))); // Texture Workshop icon
app.use("/assets", express.static(path.join(__dirname, "app", "assets"))); // All assets
app.use("/css", express.static(path.join(__dirname, "app", "css"))); // All CSS stuff

app.get("/terms", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "terms.html"))); // Terms of services
app.get("/privacy", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "privacy.html"))); // Privacy policy

app.get("/api/v1/tws/ping", async (req, res) => {
    try {
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
        res.setHeader("Pragma", "no-cache");
        res.setHeader("Expires", "0");
        res.setHeader("Surrogate-Control", "no-store");
    
        res.setHeader("Content-Type", "application/json");
    
        res.json({ timestamp: Date.now() });
    }
    catch (error) {
        log.error("Error while trying to ping (somehow):", error.message);
        return res.status(500).send("Internal Server Error");
    }
});

app.get("/api/v1/tws/getTPs", async (req, res) => {
    let { sort } = req.query;
    res.setHeader("Content-Type", "application/json");

    let result = {};
    let queryOrder = "";

    switch (sort) {
        case "downloads":
            queryOrder = "ORDER BY downloads DESC";
            break;
        case "recent":
            queryOrder = "ORDER BY lastUpdated DESC";
            break;
        case "featured":
            queryOrder = "WHERE feature >= 1 ORDER BY downloads DESC";
            break;
        default:
            queryOrder = "ORDER BY feature DESC, downloads DESC";
            break;
    }

    try {
        const rows = db.prepare(`SELECT * FROM texturepacks ${queryOrder}`).all();
        
        await Promise.all(rows.map(async (row, index) => {
            result[index + 1] = {
                packID: row.ID,
                packName: await encode.base64decode(row.name),
                downloadLink: countDownloads ? `${API_URL}/getPack/${row.ID}.zip` : await encode.base64urldecode(row.download),
                packLogo: convertLogo ? `${API_URL}/getLogo/${row.ID}.png` : await encode.base64urldecode(row.logo),
                packDescription: await encode.base64decode(row.description),
                packCreator: await encode.base64decode(row.creator),
                packVersion: row.version,
                gdVersion: row.gameVersion,
                packFeature: row.feature,
                packDownloads: row.downloads,
                creationDate: row.creationDate,
                lastUpdated: row.lastUpdated
            }
        })).then(async () => {
            res.setHeader("Cache-Control", "public, max-age=3600, immutable"); // Cache for 1 hour
            return res.status(200).json(result);
        }).catch(async error => {
            log.error("Error fetching data from SQLite:", error.message);
            return res.status(500).json({ success: false, cause: "Internal Server Error" });
        });
    } catch (error) {
        log.error("Error fetching data from SQLite:", error.message);
        return res.status(500).json({ success: false, cause: "Internal Server Error" });
    }
});


// Rate limiting (only apply it from here)
if (process.env.RATE_LIMIT) {
    app.use(
        require("express-rate-limit").rateLimit({
        windowMs: 60 * 1000, // 1 minute
        limit: process.env.RATE_LIMIT,
        message: "Temporarily rate limited, please try again later."
    }));
}

app.get("/api/v1/tws/getLogo/:logo", async (req, res) => {
    try {
        if (!convertLogo) return res.status(404).send("Endpoint deactivated");

        let logo = req.params.logo;
        if (!logo) return res.status(400).send("Bad Request");

        if (!logo.endsWith(".png")) return res.status(400).send("Logos can only be .png files");

        // Remove .png extension and sanitize
        logo = logo.replace(/[^0-9]/g, "");
        if (!logo) return res.status(400).send("Invalid logo (some characters have been deleted after security check)");

        const logoCacheFilePath = path.join(dataPath, "logos", `${logo}.png`);

        // Check if the logo is cached locally
        const fileExists = await fs.access(logoCacheFilePath).then(() => true).catch(() => false);
        if (fileExists) {
            // Serve cached file if it exists
            return res.sendFile(logoCacheFilePath, { maxAge: 3600000 });
        }

        // Query the database for the logo if it's not cached
        const row = db.prepare("SELECT logo FROM texturepacks WHERE id = ?").get(logo);
        if (!row) return res.status(404).send("Logo not found");

        // Fetch and process the logo image
        const logoUrl = await encode.base64urldecode(row.logo);
        const logoResponse = await axios.get(logoUrl, {
            responseType: "arraybuffer",
            headers: { "User-Agent": `TextureWorkshopAPI/${version}` }
        });
        
        let logoBuffer = Buffer.from(logoResponse.data, "binary");
        const image = sharp(logoBuffer);
        const metadata = await image.metadata();

        // Resize the image if it’s not 336x336 pixels
        if (metadata.width !== 336 || metadata.height !== 336) {
            logoBuffer = await image.resize(336, 336).toBuffer();
        }

        // Optionally cache the processed image
        if (logoCache) {
            try {
                await fs.writeFile(logoCacheFilePath, logoBuffer);
            } catch (error) {
                log.error("Failed to write logo in cache:", error.message);
            }
        }

        // Send the processed image
        res.setHeader("Cache-Control", "public, max-age=3600, immutable"); // Cache for 1 hour
        res.setHeader("Content-Type", "image/png");
        res.send(logoBuffer);
    } catch (error) {
        log.error("Error while trying to get/return logo:", error.message);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/api/v1/tws/getPack/:pack", async (req, res) => {
    try {
        if (!countDownloads) return res.status(404).send("Endpoint deactivated");

        let pack = req.params.pack;
        if (!pack) return res.status(400).send("Bad Request");

        if (!pack.endsWith(".zip")) return res.status(400).send("Texture Packs can only be .zip files");

        // Remove .zip extension
        pack = pack.replace(/[^0-9]/g, "");
        if (!pack) return res.status(400).send("Invalid pack (some characters have been deleted after security check)");

        const packCacheFilePath = path.join(dataPath, "packs", `${pack}.zip`);

        // If the file is cached locally, serve it and increment download count
        const fileExists = await fs.access(packCacheFilePath).then(() => true).catch(() => false);
        if (fileExists) {
            res.setHeader("Cache-Control", "public, max-age=3600, immutable"); // Cache for 1 hour
            res.sendFile(packCacheFilePath, { maxAge: 3600000 });
            
            // Increment downloads after sending response
            db.prepare("UPDATE texturepacks SET downloads = downloads + 1 WHERE id = ?").run(pack);
            return;
        }

        // Query the database for the pack URL if not cached
        const row = db.prepare("SELECT download FROM texturepacks WHERE id = ?").get(pack);
        if (!row) return res.status(404).send("Pack not found");

        // Fetch the pack and cache it locally if `tpCache` is true
        const packUrl = await encode.base64urldecode(row.download);
        const packResponse = await axios.get(packUrl, { responseType: "arraybuffer", headers: { "User-Agent": `TextureWorkshopAPI/${version}` } });
        const packBuffer = Buffer.from(packResponse.data, "binary");

        if (tpCache) {
            try {
                await fs.writeFile(packCacheFilePath, packBuffer);
            } catch (error) {
                log.error("Failed to write pack in cache:", error.message);
            }
        }

        res.setHeader("Cache-Control", "public, max-age=3600, immutable");
        res.setHeader("Content-Type", "application/octet-stream");
        res.send(packBuffer);

        // Increment downloads after sending response
        db.prepare("UPDATE texturepacks SET downloads = downloads + 1 WHERE id = ?").run(pack);
    } catch (error) {
        log.error("Error while trying to get/return pack:", error.message);
        res.status(500).send("Internal Server Error");
    }
});


/* HTML webpages */
// Everyone endpoints
app.get("/registerUser", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "registerUser.html")));
app.get("/userDelete", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "userDelete.html")));
app.get("/changeUsername", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "changeUsername.html")));
app.get("/changePassword", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "changePassword.html")));
// Mod endpoints
app.get("/mod/addTP", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "addTP.html")));
app.get("/mod/deleteTP", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "deleteTP.html")));
app.get("/mod/featureTP", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "featureTP.html")));
app.get("/mod/updateTP", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "updateTP.html")));
// Admin endpoints
app.get("/admin/deleteUser", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "deleteUser.html")));
app.get("/admin/updateUser", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "updateUser.html")));


// POST method to actually handle the form responses
app.post("/api/v1/tws/addTP", async (req, res) => {
    try {
        let { username, password, name, description, creator, logo, download, version, gameVersion, feature } = req.body;

        // Check for missing parameters
        if (!username || !password || !name || !description || !creator || !logo || !download || !version || !gameVersion || !feature) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the user is not valid
        if (!await verifyUser(db, username, password, "permAddTP")) return res.status(401).json({ success: false, cause: "Unauthorized" });

        if (!validator.isURL(logo, { protocols: ["http", "https"], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Logo URL" });
        if (!validator.isURL(download, { protocols: ["http", "https"], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Download Link" });

        // Security Checks
        version = version.replace(/[^A-Za-z0-9 :\/?.]/g, "");
        gameVersion = gameVersion.replace(/[^A-Za-z0-9 :\/?.]/g, "");

        feature = feature.replace(/[^0-9]/g, "");
        if (!["0", "1"].includes(feature)) return res.status(400).json({ success: false, cause: "Invalid Feature boolean (must be either 0 (false) or 1 (true))" });

        // Make sure the user has the permission to feature a TP, otherwise default to 0
        feature = await verifyUser(db, username, password, "permFeatureTP") ? feature : 0;

        name = await encode.base64encode(name);
        // Check if all fields are here again
        if (!name || !description || !creator || !logo || !download || !version || !gameVersion || !feature) return res.status(400).json({ success: false, cause: "Bad Request (One or multiple fields have been cleared after security check)" });

        // Check if a texture pack with the same name already exists
        const existingPack = db.prepare("SELECT 1 FROM texturepacks WHERE name = ?").get(name);
        if (existingPack) return res.status(409).json({ success: false, cause: "This Texture Pack already exists!" });

        timestamp = Math.floor(Date.now() / 1000);
        db.prepare(`
            INSERT INTO texturepacks 
            (name, description, creator, logo, download, version, gameVersion, feature, creationDate, lastUpdated) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            name,
            await encode.base64encode(description),
            await encode.base64encode(creator),
            await encode.base64urlencode(logo),
            await encode.base64urlencode(download),
            version,
            gameVersion,
            feature,
            timestamp,
            timestamp
        );
        log.info(`${username} added Texture Pack "${await encode.base64decode(name)}" by ${creator} (Featured: ${feature})`);
        return res.status(200).json({ success: true, message: "Texture pack added!" });
    } catch (error) {
        log.error("Error adding a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.patch("/api/v1/tws/featureTP", async (req, res) => {
    try {
        let { username, password, id, feature } = req.body;
        id = id.replace(/[^0-9]/g, "");

        if (!username || !password || !id || !feature) return res.status(400).json({ success: false, cause: "Bad Request" });

        if (!await verifyUser(db, username, password, "permFeatureTP")) return res.status(401).json({ success: false, cause: "Unauthorized" });
        
        const existingPack = db.prepare("SELECT 1 FROM texturepacks WHERE ID = ?").get(id);
        if (!existingPack) return res.status(409).json({ success: false, cause: "This Texture Pack doesn't exist!" });

        const timestamp = Math.floor(Date.now() / 1000);
        db.prepare(`UPDATE texturepacks SET feature = ?, lastUpdated = ? WHERE ID = ?`).run(feature, timestamp, id);

        log.info(`${username} ${feature == 0 ? "unfeatured" : "featured"} Texture Pack #${id}`);
        return res.status(200).json({ success: true, message: feature == 0 ? "Texture pack unfeatured!" : "Texture pack featured!" });
    } catch (error) {
        log.error("Error featuring/unfeaturing a texture pack:", error.message);
        res.status(500).send("Internal Server Error");
    }
});

app.patch("/api/v1/tws/updateTP", async (req, res) => {
    try {
        let { username, password, type, id, name, description, creator, logo, version, gameVersion, download } = req.body;

        // Check for missing parameters
        if (!username || !password || !type || !id) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the user is not valid
        if (!await verifyUser(db, username, password, "permUpdateTP")) return res.status(401).json({ success: false, cause: "Unauthorized" });

        id = id.replace(/[^0-9]/g, "");

        // Check if ID's still there
        if (!id) return res.status(400).json({ success: false, cause: "Bad Request (ID deleted by security check)" });

        const existingPack = db.prepare("SELECT 1 FROM texturepacks WHERE ID = ?").get(id);
        if (!existingPack) return res.status(409).json({ success: false, cause: "This Texture Pack doesn't exist!" });
        
        switch (type) {
            case "version":
                if (version) version = version.replace(/[^A-Za-z0-9 :\/?.]/g, "");
                if (gameVersion) gameVersion.replace(/[^A-Za-z0-9 :\/?.]/g, "");
                if (!download || !version || !gameVersion) return res.status(400).json({ success: false, cause: "Bad Request" });

                if (!validator.isURL(download, { protocols: ["http", "https"], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Download Link" });

                db.prepare(`UPDATE texturepacks SET download = ?, version = ?, gameVersion = ?, lastUpdated = ? WHERE ID = ?`)
                    .run(await encode.base64urlencode(download), version, gameVersion, Date.now(), id);
                await deleteFile(path.join(dataPath, "packs", `${id}.zip`));

                log.info(`${username} updated Texture Pack #${id} to ${version} (${gameVersion})`);
                return res.status(200).json({ success: true, message: "Texture pack updated!" })
                break;

            case "name":
                if (!name) return res.status(400).json({ success: false, cause: "Bad Request" });
                name = await encode.base64encode(name);

                const tpExist = db.prepare("SELECT 1 FROM texturepacks WHERE name = ?").get(name);
                if (tpExist) return res.status(409).json({ success: false, cause: "This texture pack already exists!" });

                db.prepare(`UPDATE texturepacks SET name = ?, lastUpdated = ? WHERE ID = ?`)
                    .run(name, Date.now(), id);

                log.info(`${username} updated Texture Pack #${id}'s name to "${name}"`);
                return res.status(200).json({ success: true, message: "Texture pack's name updated!" })
                break;

            case "description":
                if (!description) return res.status(400).json({ success: false, cause: "Bad Request" });

                db.prepare(`UPDATE texturepacks SET description = ?, lastUpdated = ? WHERE ID = ?`)
                    .run(await encode.base64encode(description), Date.now(), id);

                log.info(`${username} updated Texture Pack #${id}'s description`);
                return res.status(200).json({ success: true, message: "Texture pack's description updated!" })
                break;

            case "creator":
                if (!creator) return res.status(400).json({ success: false, cause: "Bad Request" });

                db.prepare(`UPDATE texturepacks SET creator = ?, lastUpdated = ? WHERE ID = ?`)
                    .run(await encode.base64encode(creator), Date.now(), id);

                log.info(`${username} updated Texture Pack #${id}'s creator(s) to "${creator}"`);
                return res.status(200).json({ success: true, message: "Texture pack's creator(s) updated!" })
                break;

            case "logo":
                if (!logo) return res.status(400).json({ success: false, cause: "Bad Request" });

                if (!validator.isURL(logo, { protocols: ["http", "https"], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Logo URL" });
                
                db.prepare(`UPDATE texturepacks SET logo = ?, lastUpdated = ? WHERE ID = ?`)
                    .run(await encode.base64urlencode(logo), Date.now(), id);
                await deleteFile(path.join(dataPath, "logos", `${id}.png`));

                log.info(`${username} updated Texture Pack #${id}'s logo`);
                return res.status(200).json({ success: true, message: "Texture pack's logo updated!" })
                break;

            default:
                return res.status(400).json({ success: false, cause: "what" });
        }
    } catch (error) {
        log.error("Error updating a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.delete("/api/v1/tws/deleteTP", async (req, res) => {
    try {
        let { username, password, id } = req.body;

        // Check for missing parameters
        if (!username || !password || !id) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the user is not valid
        if (!await verifyUser(db, username, password, "permDeleteTP")) return res.status(401).json({ success: false, cause: "Unauthorized" });

        id = id.replace(/[^0-9]/g, "");

        // Check if ID's still there
        if (!id) return res.status(400).json({ success: false, cause: "Bad Request (ID deleted by security check)" });

        const existingPack = db.prepare("SELECT 1 FROM texturepacks WHERE ID = ?").get(id);
        if (!existingPack) return res.status(409).json({ success: false, cause: "This Texture Pack doesn't exist!" });

        db.prepare(`DELETE FROM texturepacks WHERE ID = ?`).run(id);
        // Delete cached pack
        await deleteFile(path.join(dataPath, "packs", `${id}.zip`));
        // Delete cached logo
        await deleteFile(path.join(dataPath, "logos", `${id}.png`));

        log.info(`${username} deleted Texture Pack #${id}`);
        return res.status(200).json({ success: true, message: "Texture pack deleted!" });
    } catch (error) {
        log.error("Error deleting a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});


app.get("/api/v1/tws/getUsers", async (req, res) => {
    res.setHeader("Content-Type", "application/json");

    let result = {};
    try {
        const rows = db.prepare("SELECT * FROM accounts").all();
        const result = {};

        await Promise.all(rows.map(async (row, index) => {
            result[index + 1] = {
                userID: row.ID,
                userName: await encode.base64decode(row.userName),
                permAdmin: row.permAdmin,
                permAddTP: row.permAddTP,
                permFeatureTP: row.permFeatureTP,
                permUpdateTP: row.permUpdateTP,
                permDeleteTP: row.permDeleteTP,
                registerDate: row.registerDate
            };
        }));

        return res.status(200).json(result);
    } catch (error) {
        log.error("Error fetching data from SQLite:", error.message);
        return res.status(500).json({ success: false, cause: "Internal Server Error" });
    }
});

app.post("/api/v1/tws/registerUser", async (req, res) => {
    try {
        let { username, password } = req.body;

        username = await encode.base64encode(username);

        // Check if user exists
        const userExist = db.prepare("SELECT 1 FROM accounts WHERE userName = ?").get(username);
        if (userExist) return res.status(409).json({ success: false, cause: "This user already exists!" });

        const salt = await encrypt.generateSalt(bcryptRounds);
        const hash = await encrypt.generateHash(password, salt);

        db.prepare(`INSERT INTO accounts (userName, hash, salt, registerDate) VALUES (?, ?, ?, ?)`)
            .run(username, hash, salt, Math.floor(Date.now() / 1000));

        log.info(`Registered user "${await encode.base64decode(username)}"`);
        return res.status(200).json({ success: true, message: "User registered!" })

    } catch (error) {
        log.error("Error registering new user:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.delete("/api/v1/tws/userDelete", async (req, res) => {
    try {
        let { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ success: false, cause: "Bad Request" });
        
        if (!await verifyUser(db, username, password)) return res.status(401).json({ success: false, cause: "Invalid password/username" });

        username = await encode.base64encode(username);

        // Check if the username exists
        const userExist = db.prepare("SELECT 1 FROM accounts WHERE userName = ?").get(username);
        if (!userExist) return res.status(404).json({ success: false, cause: "This user does not exist!" });
        
        // Delete the user
        db.prepare(`DELETE FROM accounts WHERE userName = ?`).run(username);

        log.info(`Deleted user "${await encode.base64decode(username)}"!`);
        return res.status(200).json({ success: true, message: "User deleted!" });
    } catch (error) {
        log.error("Error deleting user:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.patch("/api/v1/tws/changeUsername", async (req, res) => {
    try {
        let { username, password, newUsername } = req.body;

        if (!username || !password || !newUsername) return res.status(400).json({ success: false, cause: "Bad Request" });

        if (!await verifyUser(db, username, password)) return res.status(401).json({ success: false, cause: "Invalid password/username" });

        newUsername = await encode.base64encode(newUsername);
                
        const userExist = db.prepare("SELECT 1 FROM accounts WHERE userName = ?").get(newUsername);
        if (userExist) return res.status(409).json({ success: false, cause: "Someone's already using this name!" });

        db.prepare(`UPDATE accounts SET userName = ? WHERE userName = ?`)
            .run(newUsername, await encode.base64encode(username));

        log.info(`${username} updated their username! ("${await encode.base64decode(newUsername)}")`);
        return res.status(200).json({ success: true, message: "Username updated!" })
    } catch (error) {
        log.error("Error updating user name:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.patch("/api/v1/tws/changePassword", async (req, res) => {
    try {
        let { username, password, newPassword } = req.body;

        if (!username || !password || !newPassword) return res.status(400).json({ success: false, cause: "Bad Request" });

        if (!await verifyUser(db, username, password)) return res.status(401).json({ success: false, cause: "Invalid password/username" });

        const salt = await encrypt.generateSalt(bcryptRounds);
        const hash = await encrypt.generateHash(newPassword, salt);

        db.prepare(`UPDATE accounts SET hash = ?, salt = ? WHERE userName = ?`)
            .run(hash, salt, await encode.base64encode(username));

        log.info(`${username} updated their password!`);
        return res.status(200).json({ success: true, message: "Password updated!" })
    } catch (error) {
        log.error("Error updating user password:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.patch("/api/v1/tws/updateUser", async (req, res) => {
    try {
        let { token, username, adminUser, adminPass, newUsername, newPassword, type, permAdmin, permAddTP, permFeatureTP, permUpdateTP, permDeleteTP } = req.body;

        if (!username || !type) return res.status(400).json({ success: false, cause: "Bad Request" });

        if (!token && (!adminUser && !adminPass)) return res.status(400).json({ success: false, cause: "Bad Request" });
        if (token && token != TOKEN) return res.status(401).json({ success: false, cause: "Unauthorized" });
        if ((adminUser || adminPass) && !await verifyUser(db, adminUser, adminPass, "permAdmin")) return res.status(401).json({ success: false, cause: "Unauthorized" });
    
        username = await encode.base64encode(username);

        // Check if user exists
        const userExistence = db.prepare("SELECT 1 FROM accounts WHERE userName = ?").get(username);
        if (!userExistence) return res.status(404).json({ success: false, cause: "This user does not exist!" });

        switch (type) {
            case "username":
                if (!newUsername) return res.status(400).json({ success: false, cause: "Bad Request" });
                
                newUsername = await encode.base64encode(newUsername);
                
                const userExist = db.prepare("SELECT 1 FROM accounts WHERE userName = ?").get(newUsername);
                if (userExist) return res.status(409).json({ success: false, cause: "This user already exists!" });
        
                db.prepare("UPDATE accounts SET userName = ? WHERE userName = ?")
                    .run(newUsername, username);

                log.info(`${adminUser ? `${adminUser} updated` : "Updated"} ${await encode.base64decode(username)}'s username ("${await encode.base64decode(newUsername)}")`);
                return res.status(200).json({ success: true, message: "Username updated!" })
                break;
            case "password":
                if (!newPassword) return res.status(400).json({ success: false, cause: "Bad Request" });

                const salt = await encrypt.generateSalt(bcryptRounds);
                const hash = await encrypt.generateHash(newPassword, salt);

                db.prepare("UPDATE accounts SET hash = ?, salt = ? WHERE userName = ?")
                    .run(hash, salt, username);

                log.info(`${adminUser ? `${adminUser} updated` : "Updated"} ${await encode.base64decode(username)}'s password`);
                return res.status(200).json({ success: true, message: "Password updated!" })
                break;
            case "permissions":
                // Security Checks
                const cleanBoolean = (booleanInt) => {
                    booleanInt = booleanInt.replace(/[^0-9]/g, "");
                    return ["0", "1"].includes(booleanInt) ? booleanInt : null;
                };
        
                permAdmin = cleanBoolean(permAdmin);
                permAddTP = cleanBoolean(permAddTP);
                permFeatureTP = cleanBoolean(permFeatureTP);
                permUpdateTP = cleanBoolean(permUpdateTP);
                permDeleteTP = cleanBoolean(permDeleteTP);
                if (!permAdmin || !permAddTP || !permFeatureTP || !permUpdateTP || !permDeleteTP) return res.status(400).json({ success: false, cause: "Bad Request" });

                db.prepare(`
                    UPDATE accounts 
                    SET permAdmin = ?, permAddTP = ?, permFeatureTP = ?, permUpdateTP = ?, permDeleteTP = ? 
                    WHERE userName = ?`)
                    .run(permAdmin, permAddTP, permFeatureTP, permUpdateTP, permDeleteTP, username);

                log.info(`${adminUser ? `${adminUser} updated` : "Updated"} ${await encode.base64decode(username)}'s permissions`);
                return res.status(200).json({ success: true, message: "Permissions updated!" })
                break;

            default:
                return res.status(400).json({ success: false, cause: "what" });
            }
    } catch (error) {
        log.error("Error updating user:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.delete("/api/v1/tws/deleteUser", async (req, res) => {
    try {
        let { token, adminUser, adminPass, username } = req.body;

        if (!username) return res.status(400).json({ success: false, cause: "Bad Request" });
        username = await encode.base64encode(username);

        if (!token && (!adminUser && !adminPass)) return res.status(400).json({ success: false, cause: "Bad Request" });
        if (token && token != TOKEN) return res.status(401).json({ success: false, cause: "Unauthorized" });
        if ((adminUser || adminPass) && !await verifyUser(db, adminUser, adminPass, "permAdmin")) return res.status(401).json({ success: false, cause: "Unauthorized" });

        const userExist = db.prepare("SELECT userName FROM accounts WHERE userName = ?").get(username);
        if (!userExist) return res.status(404).json({ success: false, cause: "This user does not exist!" });
        
        db.prepare("DELETE FROM accounts WHERE userName = ?").run(username);

        log.info(`${adminUser ? `${adminUser} deleted` : "Deleted"} user "${await encode.base64decode(username)}"`);
        return res.status(200).json({ success: true, message: "User deleted!" });    
    } catch (error) {
        log.error("Error deleting user:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.get("/*", (req, res) => res.sendFile(path.join(__dirname, "app", "html", "index.html")));

app.listen(PORT, async () => { log.info(`Server is now running on ${PORT}`) });

process.on("unhandledRejection", (reason, promise) => {
    log.error(`Unhandled rejection at ${promise}:`, reason);
});

process.on("uncaughtException", (error) => {
    log.error(`Uncaught exception:`, error);
});