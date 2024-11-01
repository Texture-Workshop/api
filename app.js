require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const validator = require("validator");
const axios = require("axios");
const sharp = require("sharp");
const path = require("path");

const { log, encode, deleteFile, verifyUser, encrypt } = require(path.join(__dirname, "util", "functions.js"));
const { logRequests, countDownloads, convertLogo, tpCache, logoCache, bcryptRounds } = require(path.join(__dirname, "config.json"));

const { version } = require(path.join(__dirname, "package.json"));

const fs = require("fs").promises;
const { Database } = require("sqlite3").verbose();


const PORT = process.env.PORT ? process.env.PORT : 3300;

const TOKEN = process.env.TOKEN;
if (!TOKEN) {
    console.error("Please supply a token in your environment variables.");
    return process.exit(1);
}

const API_URL = `${process.env.API_URL ? process.env.API_URL : "http://localhost:3300"}/api/v1/tws`;

// Define the path where data such as texture packs or logos will be stored
const dataPath = path.join(__dirname, "data");

const db = new Database(path.join(dataPath, "database.db"), async (error) => {
    if (error) {
        log.error("Error opening SQLite:", error.message);
    } else {
        log.info("Connected to SQLite");
        try {
            db.exec(await fs.readFile(path.join(dataPath, "database.sql"), "utf8"), async (error) => { // Execute SQL script
                if (error) {
                    await log.error("Error executing SQL script:", error.message);
                    return process.exit(1);
                } else {
                    log.info("SQLite tables have been created or already exist");
                }
            });
        } catch (error) {
            log.error("Error executing SQL script:", error.message);
        }
    }
});

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
        db.all(`SELECT * FROM texturepacks ${queryOrder}`, async (error, rows) => {
            if (error) {
                log.error("Error fetching data from SQLite:", error.message);
                return res.status(500).json({ success: false, cause: "Internal Server Error" });
            }

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

        // Remove .png extension
        logo = logo.replace(/[^0-9]/g, "");
        if (!logo) return res.status(400).send("Invalid logo (some characters have been deleted after security check)");

        const logoCacheFilePath = path.join(dataPath, "logos", `${logo}.png`);

        // If the logo is already stored locally, return it
        if (await fs.access(logoCacheFilePath).then(() => true).catch(() => false)) {
            try {
                res.setHeader("Cache-Control", "public, max-age=3600, immutable"); // Cache for 1 hour
                return res.sendFile(logoCacheFilePath);
            } catch (error) {
                log.error("Error reading the cached logo file:", error);
                res.status(500).send("Internal Server Error");
            }
        }
    
        // Query the database to check if the logo exists and if so continue the code
        return db.get("SELECT logo FROM texturepacks WHERE id = ?", [logo], async (error, row) => {
            if (error) {
                log.error("Error while trying to check for ID existence in SQLite:", error.message);
                return res.status(500).send("Internal Server Error");
            }
            if (!row) return res.status(404).send("Logo not found");
    
            try {
                let logoResponse = await axios.get(await encode.base64urldecode(row.logo), { responseType: "arraybuffer",
                    headers: {
                      "User-Agent": `TextureWorkshopAPI/${version}`
                    }
                });
                let logoBuffer = Buffer.from(logoResponse.data, "binary")
                const image = sharp(logoBuffer);
                const metadata = await image.metadata();

                // Resize if the logo is not already 336x336 pixels
                if (metadata.width != 336 || metadata.height != 336) logoBuffer = await image.resize(336, 336).toBuffer();
    
                // Logo cache
                try {
                    if (logoCache) await fs.writeFile(logoCacheFilePath, logoBuffer);
                } catch (error) {
                    log.error("Failed to write logo in cache:", error.message);
                }
    
                // Send the resized image
                res.setHeader("Cache-Control", "public, max-age=3600, immutable"); // Cache for 1 hour
                res.setHeader("Content-Type", "image/png");
                return res.send(logoBuffer);
            } catch (error) {
                log.error("Error fetching/resizing logo:", error.message);
                return res.status(500).send("Error processing logo");
            }
        });
    } catch (error) {
        log.error("Error while trying to get/return logo:", error.message);
        return res.status(500).send("Internal Server Error");  
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

        // If the logo is already stored locally, return it
        if (await fs.access(packCacheFilePath).then(() => true).catch(() => false)) {
            try {                
                res.setHeader("Cache-Control", "public, max-age=3600, immutable"); // Cache for 1 hour
                res.sendFile(packCacheFilePath);
                
                // Increment downloads
                try {
                    return db.run("UPDATE texturepacks SET downloads = downloads + 1 WHERE id = ?", [pack]);
                } catch (error) {
                    return log.error("Error updating the \"downloads\" value in SQLite:", error.message);
                }
            } catch (error) {
                log.error("Error reading the cached pack file:", error);
            }
        }
    
        // Query the database to check if the logo exists and if so continue the code
        await db.get("SELECT download FROM texturepacks WHERE id = ?", [pack], async (error, row) => {
            if (error) {
                log.error("Error while trying to check for ID existence in SQLite:", error.message);
                return res.status(500).send("Internal Server Error");
            }
            if (!row) return res.status(404).send("Pack not found");
    
            try {
                let packResponse = await axios.get(await encode.base64urldecode(row.download), { responseType: "arraybuffer",
                    headers: {
                      "User-Agent": `TextureWorkshopAPI/${version}`
                    }
                });
                const packBuffer = Buffer.from(packResponse.data, "binary");

                // Pack cache
                try {
                    if (tpCache) await fs.writeFile(packCacheFilePath, packBuffer);
                } catch (error) {
                    log.error("Failed to write pack in cache:", error.message);
                }
                
                res.setHeader("Cache-Control", "public, max-age=3600, immutable"); // Cache for 1 hour
                res.setHeader("Content-Type", "application/octet-stream");
                res.send(packBuffer);
            } catch (error) {
                log.error("Error fetching pack:", error.message);
                return res.status(500).send("Error while trying to fetch the pack");
            }
        });

        // Increment downloads
        try {
            return db.run("UPDATE texturepacks SET downloads = downloads + 1 WHERE id = ?", [pack]);
        } catch (error) {
            return log.error("Error updating the \"downloads\" value in SQLite:", error.message);
        }
    } catch (error) {
        log.error("Error while trying to get/return pack:", error.message);
        return res.status(500).send("Internal Server Error");  
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

        // Check if all fields are here again
        if (!name || !description || !creator || !logo || !download || !version || !gameVersion || !feature) return res.status(400).json({ success: false, cause: "Bad Request (One or multiple fields have been cleared after security check)" });

        // Check if a texture pack with the same name already exists
        let existingPack = await new Promise(async (resolve, reject) => {
            db.get("SELECT 1 FROM texturepacks WHERE name = ?", [await encode.base64encode(name)], (error, row) => {
                if (error) return reject(error);
                resolve(row);
            });
        });

        if (existingPack) {
            return res.status(409).json({ success: false, cause: "This Texture Pack already exists!" });
        }

        timestamp = Math.floor(Date.now() / 1000);
        return await new Promise(async (resolve, reject) => {
            db.run(
                `INSERT INTO texturepacks (name, description, creator, logo, download, version, gameVersion, feature, creationDate, lastUpdated) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [await encode.base64encode(name), await encode.base64encode(description), await encode.base64encode(creator), await encode.base64urlencode(logo), await encode.base64urlencode(download), version, gameVersion, feature, timestamp, timestamp], async (error) => {
                    if (error) {
                        log.error("Error inserting texture pack into SQLite:", error.message);
                        resolve(res.status(500).json({ success: false, cause: "Internal Server Error" }));

                    }
                    log.info(`${username} added Texture Pack "${name}" by ${creator} (Featured: ${feature})`);
                    resolve(res.status(200).json({ success: true, message: "Texture pack added!" }));
                }
            );
        });
    } catch (error) {
        log.error("Error adding a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.patch("/api/v1/tws/featureTP", async (req, res) => {
    try {
        let { username, password, id, feature } = req.body;

        // Check for missing parameters
        if (!username || !password || !id || !feature) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the user is not valid
        if (!await verifyUser(db, username, password, "permFeatureTP")) return res.status(401).json({ success: false, cause: "Unauthorized" });
        id = id.replace(/[^0-9]/g, "");

        feature = feature.replace(/[^0-9]/g, "");
        if (!["0", "1"].includes(feature)) return res.status(400).json({ success: false, cause: "Invalid Feature boolean (must be either 0 or 1)" });

        // Check if ID's still there
        if (!id || !feature) return res.status(400).json({ success: false, cause: "Bad Request (One or multiple fields have been cleared after security check)" });

        db.run(
            `UPDATE texturepacks SET feature = ?, lastUpdated = ? WHERE ID = ?`, [feature, Math.floor(Date.now() / 1000), id], async (error) => {
                if (error) {
                    log.error("Error featuring/unfeaturing texture pack:", error.message);
                    return res.status(500).json({ success: false, cause: "Internal Server Error" });
                }

                if (feature == 0) {
                    log.info(`${username} unfeatured Texture Pack #${id}`);
                    return res.status(200).json({ success: true, message: "Texture pack unfeatured!" });
                } else {
                    log.info(`${username} featured Texture Pack #${id}`);
                    return res.status(200).json({ success: true, message: "Texture pack featured!" });
                }
            });
    } catch (error) {
        log.error("Error featuring/unfeaturing a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
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

        switch (type) {
            case "version":
                if (!download || !version || !gameVersion) return res.status(400).json({ success: false, cause: "Bad Request" });

                if (!validator.isURL(download, { protocols: ["http", "https"], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Download Link" });

                version = version.replace(/[^A-Za-z0-9 :\/?.]/g, "");
                gameVersion = gameVersion.replace(/[^A-Za-z0-9 :\/?.]/g, "");

                db.run(
                    `UPDATE texturepacks SET download = ?, version = ?, gameVersion = ?, lastUpdated = ? WHERE ID = ?`, [await encode.base64urlencode(download), version, gameVersion, Math.floor(Date.now() / 1000), id], async (error) => {
                        if (error) {
                            log.error("Error updating texture pack:", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`${username} updated Texture Pack #${id} to ${version} (${gameVersion})`);
                        res.status(200).json({ success: true, message: "Texture pack updated!" })

                        // Delete cached pack
                        return await deleteFile(path.join(dataPath, "packs", `${id}.zip`));
                    });
                break;

            case "name":
                if (!name) return res.status(400).json({ success: false, cause: "Bad Request" });

                db.run(
                    `UPDATE texturepacks SET name = ?, lastUpdated = ? WHERE ID = ?`, [await encode.base64encode(name), Math.floor(Date.now() / 1000), id], async (error) => {
                        if (error) {
                            log.error("Error updating texture pack's name:", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`${username} updated Texture Pack #${id}'s name to "${name}"`);
                        return res.status(200).json({ success: true, message: "Texture pack's name updated!" })
                    });
                break;

            case "description":
                if (!description) return res.status(400).json({ success: false, cause: "Bad Request" });

                db.run(
                    `UPDATE texturepacks SET description = ?, lastUpdated = ? WHERE ID = ?`, [await encode.base64encode(description), Math.floor(Date.now() / 1000), id], async (error) => {
                        if (error) {
                            log.error("Error updating texture pack's description:", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`${username} updated Texture Pack #${id}'s description`);
                        return res.status(200).json({ success: true, message: "Texture pack's description updated!" })
                    });
                break;

            case "creator":
                if (!creator) return res.status(400).json({ success: false, cause: "Bad Request" });

                db.run(
                    `UPDATE texturepacks SET creator = ?, lastUpdated = ? WHERE ID = ?`, [await encode.base64encode(creator), Math.floor(Date.now() / 1000), id], async (error) => {
                        if (error) {
                            log.error("Error updating texture pack's creator(s):", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`${username} updated Texture Pack #${id}'s creator(s) to "${creator}"`);
                        return res.status(200).json({ success: true, message: "Texture pack's creator(s) updated!" })
                    });
                break;

            case "logo":
                if (!logo) return res.status(400).json({ success: false, cause: "Bad Request" });

                if (!validator.isURL(logo, { protocols: ["http", "https"], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Logo URL" });
                
                db.run(
                    `UPDATE texturepacks SET logo = ?, lastUpdated = ? WHERE ID = ?`, [await encode.base64urlencode(logo), Math.floor(Date.now() / 1000), id], async (error) => {
                        if (error) {
                            log.error("Error updating texture pack's logo:", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`${username} updated Texture Pack #${id}'s logo`);
                        res.status(200).json({ success: true, message: "Texture pack's logo updated!" })
                        
                        // Delete cached logo
                        return await deleteFile(path.join(dataPath, "logos", `${id}.png`));
                    });
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

        db.run(
            `DELETE FROM texturepacks WHERE ID = ?`, [id], async (error) => {
                if (error) {
                    log.error("Error deleting texture pack:", error.message);
                    return res.status(500).json({ success: false, cause: "Internal Server Error" });
                }

                log.info(`${username} deleted Texture Pack #${id}`);
                res.status(200).json({ success: true, message: "Texture pack deleted!" });

                // Delete cached pack
                await deleteFile(path.join(dataPath, "packs", `${id}.zip`));
                // Delete cached logo
                return await deleteFile(path.join(dataPath, "logos", `${id}.png`));
            });
    } catch (error) {
        log.error("Error deleting a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});


app.get("/api/v1/tws/getUsers", async (req, res) => {
    res.setHeader("Content-Type", "application/json");

    let result = {};
    try {
        db.all("SELECT * FROM accounts", async (error, rows) => {
            if (error) {
                log.error("Error fetching data from SQLite:", error.message);
                return res.status(500).json({ success: false, cause: "Internal Server Error" });
            }

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
                }
            })).then(async () => {
                return res.status(200).json(result);
            }).catch(async error => {
                log.error("Error fetching data from SQLite:", error.message);
                return res.status(500).json({ success: false, cause: "Internal Server Error" });
            });
        });
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
        let userExist = await new Promise(async (resolve, reject) => {
            db.get("SELECT 1 FROM accounts WHERE userName = ?", [username], (error, row) => {
                if (error) return reject(error);
                resolve(row);
            });
        });
        if (userExist) return res.status(409).json({ success: false, cause: "This user already exists!" });

        const salt = await encrypt.generateSalt(bcryptRounds);
        const hash = await encrypt.generateHash(password, salt);

        return await new Promise(async (resolve, reject) => {
            db.run(
                `INSERT INTO accounts (userName, hash, salt, registerDate) 
                VALUES (?, ?, ?, ?)`,
                [username, hash, salt, Math.floor(Date.now() / 1000)], async (error) => {
                    if (error) {
                        log.error("Error inserting user into SQLite:", error.message);
                        reject(res.status(500).json({ success: false, cause: "Internal Server Error" }));
                    }
                    log.info(`Registered user "${await encode.base64decode(username)}"`);
                    resolve(res.status(200).json({ success: true, message: "User registered!" }));
                }
            );
        });
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
        let userExist = await new Promise(async (resolve, reject) => {
            db.get("SELECT 1 FROM accounts WHERE userName = ?", [username], (error, row) => {
                if (error) return reject(error);
                resolve(row);
            });
        });
        if (!userExist) return res.status(404).json({ success: false, cause: "Unknown user" });
        
        // Delete the user
        db.run(
            `DELETE FROM accounts WHERE userName = ?`, [username], async (error) => {
                if (error) {
                    log.error("Error deleting user:", error.message);
                    return res.status(500).json({ success: false, cause: "Internal Server Error" });
                }

                log.info(`Deleted user "${await encode.base64decode(username)}"!`);
                return res.status(200).json({ success: true, message: "User deleted!" });
            });
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
                
        let userExist = await new Promise(async (resolve, reject) => {
            db.get("SELECT 1 FROM accounts WHERE userName = ?", [newUsername], (error, row) => {
                if (error) return reject(error);
                resolve(row);
            });
        });
        if (userExist) return res.status(409).json({ success: false, cause: "Someone's already using this name!" });

        db.run(
            `UPDATE accounts SET userName = ? WHERE userName = ?`, [newUsername, await encode.base64encode(username)], async (error) => {
                if (error) {
                    log.error("Error updating username:", error.message);
                    return res.status(500).json({ success: false, cause: "Internal Server Error" });
                }

                log.info(`${username} updated their username! ("${await encode.base64decode(newUsername)}")`);
                return res.status(200).json({ success: true, message: "Username updated!" })
            });
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

        db.run(
            `UPDATE accounts SET hash = ?, salt = ? WHERE userName = ?`, [hash, salt, await encode.base64encode(username)], async (error) => {
                if (error) {
                    log.error("Error updating password:", error.message);
                    return res.status(500).json({ success: false, cause: "Internal Server Error" });
                }

                log.info(`${username} updated their password!`);
                return res.status(200).json({ success: true, message: "Password updated!" })
            });
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
    
        // Check if user exists
        let userExistence = await new Promise(async (resolve, reject) => {
            db.get("SELECT 1 FROM accounts WHERE userName = ?", [await encode.base64encode(username)], (error, row) => {
                if (error) return reject(error);
                resolve(row);
            });
        });
        if (!userExistence) return res.status(404).json({ success: false, cause: "Not Found" });

        switch (type) {
            case "username":
                if (!newUsername) return res.status(400).json({ success: false, cause: "Bad Request" });
                
                newUsername = await encode.base64encode(newUsername);
                
                let userExist = await new Promise(async (resolve, reject) => {
                    db.get("SELECT 1 FROM accounts WHERE userName = ?", [newUsername], (error, row) => {
                        if (error) return reject(error);
                        resolve(row);
                    });
                });
                if (userExist) return res.status(409).json({ success: false, cause: "This user already exists!" });
        
                db.run(
                    `UPDATE accounts SET userName = ? WHERE userName = ?`, [newUsername, await encode.base64encode(username)], async (error) => {
                        if (error) {
                            log.error("Error updating username:", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`${adminUser ? `${adminUser} updated` : "Updated"} ${username}'s username ("${await encode.base64decode(newUsername)}")`);
                        return res.status(200).json({ success: true, message: "Username updated!" })
                    });
                break;
            case "password":
                if (!newPassword) return res.status(400).json({ success: false, cause: "Bad Request" });

                const salt = await encrypt.generateSalt(bcryptRounds);
                const hash = await encrypt.generateHash(newPassword, salt);

                db.run(
                    `UPDATE accounts SET hash = ?, salt = ? WHERE userName = ?`, [hash, salt, await encode.base64encode(username)], async (error) => {
                        if (error) {
                            log.error("Error updating password:", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`${adminUser ? `${adminUser} updated` : "Updated"} ${username}'s password`);
                        return res.status(200).json({ success: true, message: "Password updated!" })
                    });
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

                db.run(
                    `UPDATE accounts SET permAdmin = ?, permAddTP = ?, permFeatureTP = ?, permUpdateTP = ?, permDeleteTP = ? WHERE userName = ?`, [permAdmin, permAddTP, permFeatureTP, permUpdateTP, permDeleteTP, await encode.base64encode(username)], async (error) => {
                        if (error) {
                            log.error("Error updating permissions:", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`${adminUser ? `${adminUser} updated` : "Updated"} ${username}'s permissions`);
                        return res.status(200).json({ success: true, message: "Permissions updated!" })
                    });
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
        username = await encode.base64encode(username)

        if (!token && (!adminUser && !adminPass)) return res.status(400).json({ success: false, cause: "Bad Request" });
        if (token && token != TOKEN) return res.status(401).json({ success: false, cause: "Unauthorized" });
        if ((adminUser || adminPass) && !await verifyUser(db, adminUser, adminPass, "permAdmin")) return res.status(401).json({ success: false, cause: "Unauthorized" });

        let userExist = await new Promise(async (resolve, reject) => {
            db.get("SELECT 1 FROM accounts WHERE userName = ?", [username], (error, row) => {
                if (error) return reject(error);
                resolve(row);
            });
        });
        if (!userExist) return res.status(404).json({ success: false, cause: "Not Found" });
        
        db.run(
            `DELETE FROM accounts WHERE userName = ?`, [username], async (error) => {
                if (error) {
                    log.error("Error deleting account:", error.message);
                    return res.status(500).json({ success: false, cause: "Internal Server Error" });
                }

                log.info(`${adminUser ? `${adminUser} deleted` : "Deleted"} user "${await encode.base64decode(username)}"`);
                return res.status(200).json({ success: true, message: "User deleted!" });
            });
    
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