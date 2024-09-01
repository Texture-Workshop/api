const express = require("express");
const http = require("http");
const fs = require("fs").promises;
const { Database } = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const validator = require("validator");
const favicon = require("serve-favicon");
const axios = require("axios");
const sharp = require("sharp");
const path = require("path");

const { log, encode, deleteFile } = require(path.join(__dirname, "util", "functions.js"));
const config = require(path.join(__dirname, "config.json"));

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
                    log.warn("Error executing SQL script:", error.message);
                } else {
                    log.info("SQLite: Tables created or already exist.");
                }
            });
        } catch (error) {
            log.error("Error executing SQL script:", error.message);
        }
    }
});

const app = express();

const PORT = config.port;

// Set the favicon
app.use(favicon(path.join(__dirname, "assets", "favicon.ico")));

app.get("/", async (req, res) => {
    res.redirect("https://geode-sdk.org/mods/uproxide.textures");
});

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

app.get("/api/v1/tws/getLogo/:logo", async (req, res) => {
    try {
        if (!config.convertLogo) return res.status(404).send("Endpoint deactivated");

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
                return res.status(500).send("Internal Server Error");
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
                let logoResponse = await axios.get(await encode.base64urldecode(row.logo), { responseType: "arraybuffer" });
                let logoBuffer = Buffer.from(logoResponse.data, "binary")
                const image = sharp(logoBuffer);
                const metadata = await image.metadata();

                // Resize if the logo is not already 336x336 pixels
                if (metadata.width != 336 || metadata.height != 336) logoBuffer = await image.resize(336, 336).toBuffer();
    
                // Logo cache
                try {
                    if (config.logoCache) await fs.writeFile(logoCacheFilePath, logoBuffer);
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
        if (!config.countDownloads) return res.status(404).send("Endpoint deactivated");

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
                // Increment downloads
                try {
                    await db.run("UPDATE texturepacks SET downloads = downloads + 1 WHERE id = ?", [pack]);
                } catch (error) {
                    log.error("Error updating the \"downloads\" value in SQLite:", error.message);
                    return res.status(500).send("Internal Server Error");
                }
                
                res.setHeader("Cache-Control", "public, max-age=3600, immutable"); // Cache for 1 hour
                return res.sendFile(packCacheFilePath);
            } catch (error) {
                log.error("Error reading the cached pack file:", error);
                return res.status(500).send("Internal Server Error");
            }
        }
    
        // Query the database to check if the logo exists and if so continue the code
        return db.get("SELECT download FROM texturepacks WHERE id = ?", [pack], async (error, row) => {
            if (error) {
                log.error("Error while trying to check for ID existence in SQLite:", error.message);
                return res.status(500).send("Internal Server Error");
            }
            if (!row) return res.status(404).send("Pack not found");
    
            try {
                let packResponse = await axios.get(await encode.base64urldecode(row.download), { responseType: "arraybuffer" });
                const packBuffer = Buffer.from(packResponse.data, "binary");

                // Pack cache
                try {
                    if (config.tpCache) await fs.writeFile(packCacheFilePath, packBuffer);
                } catch (error) {
                    log.error("Failed to write pack in cache:", error.message);
                }

                // Increment downloads
                try {
                    await db.run("UPDATE texturepacks SET downloads = downloads + 1 WHERE id = ?", [pack]);
                } catch (error) {
                    log.error("Error updating the \"downloads\" value in SQLite:", error.message);
                    return res.status(500).send("Internal Server Error");
                }
                
                res.setHeader("Cache-Control", "public, max-age=3600, immutable"); // Cache for 1 hour
                res.setHeader("Content-Type", "application/octet-stream");
                return res.send(packBuffer);
            } catch (error) {
                log.error("Error fetching pack:", error.message);
                return res.status(500).send("Error while trying to fetch the pack");
            }
        });
    } catch (error) {
        log.error("Error while trying to get/return pack:", error.message);
        return res.status(500).send("Internal Server Error");  
    }
});

app.get("/api/v1/tws/getTPs", async (req, res) => {
    res.setHeader("Content-Type", "application/json");

    let result = {};
    try {
        db.all("SELECT * FROM texturepacks ORDER BY feature DESC", async (error, rows) => {
            if (error) {
                log.error("Error fetching data from SQLite:", error.message);
                return res.status(500).json({ success: false, cause: "Internal Server Error" });
            }

            await Promise.all(rows.map(async (row, index) => {
                result[index + 1] = {
                    packID: row.ID,
                    packName: await encode.base64decode(row.name),
                    downloadLink: config.countDownloads ? `${config.apiURL}/getPack/${row.ID}.zip` : await encode.base64urldecode(row.download),
                    packLogo: config.convertLogo ? `${config.apiURL}/getLogo/${row.ID}.png` : await encode.base64urldecode(row.logo),
                    packDescription: await encode.base64decode(row.description),
                    packCreator: await encode.base64decode(row.creator),
                    packVersion: row.version,
                    gdVersion: row.gameVersion,
                    packFeature: row.feature
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

// GET method to send the form
app.get("/api/v1/tws/addTP", async (req, res) => {
    try {
        return res.sendFile(path.join(__dirname, "pages", "addTP.html"));
    } catch (error) {
        log.error("Error sending the addTP.html file:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.use(bodyParser.urlencoded({ extended: false }));

// POST method to actually handle the form responses
app.post("/api/v1/tws/addTP", async (req, res) => {
    try {
        let { token, name, description, creator, logo, download, version, gameVersion, feature } = req.body;

        // Check for missing parameters
        if (!token || !name || !description || !creator || !logo || !download || !version || !gameVersion || !feature) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the token is not valid
        if (token != config.token) return res.status(403).json({ success: false, cause: "Forbidden" });

        if (!validator.isURL(logo, { protocols: ["http", "https"], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Logo URL" });
        if (!validator.isURL(download, { protocols: ["http", "https"], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Download Link" });

        // Security Checks
        version = version.replace(/[^A-Za-z0-9 :\/?.]/g, "");
        gameVersion = gameVersion.replace(/[^A-Za-z0-9 :\/?.]/g, "");

        feature = feature.replace(/[^0-9]/g, "");
        if (!["0", "1"].includes(feature)) return res.status(400).json({ success: false, cause: "Invalid Feature boolean (must be either 0 (false) or 1 (true))" });

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

        return await new Promise(async (resolve, reject) => {
            db.run(
                `INSERT INTO texturepacks (name, description, creator, logo, download, version, gameVersion, feature) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [await encode.base64encode(name), await encode.base64encode(description), await encode.base64encode(creator), await encode.base64urlencode(logo), await encode.base64urlencode(download), version, gameVersion, feature], async (error) => {
                    if (error) {
                        log.error("Error inserting texture pack into SQLite:", error.message);
                        resolve(res.status(500).json({ success: false, cause: "Internal Server Error" }));

                    }
                    log.info(`Added Texture Pack "${name}" by ${creator} (Featured: ${feature})`);
                    resolve(res.status(200).json({ success: true, message: "Texture pack added!" }));
                }
            );
        });
    } catch (error) {
        log.error("Error adding a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.get("/api/v1/tws/featureTP", async (req, res) => {
    try {
        return res.sendFile(path.join(__dirname, "pages", "featureTP.html"));
    } catch (error) {
        log.error("Error sending the featureTP.html file:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.post("/api/v1/tws/featureTP", async (req, res) => {
    try {
        let { token, id, feature } = req.body;

        // Check for missing parameters
        if (!token || !id || !feature) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the token is not valid
        if (token != config.token) return res.status(403).json({ success: false, cause: "Forbidden" });

        id = id.replace(/[^0-9]/g, "");

        feature = feature.replace(/[^0-9]/g, "");
        if (!["0", "1"].includes(feature)) return res.status(400).json({ success: false, cause: "Invalid Feature boolean (must be either 0 or 1)" });

        // Check if ID's still there
        if (!id || !feature) return res.status(400).json({ success: false, cause: "Bad Request (One or multiple fields have been cleared after security check)" });

        db.run(
            `UPDATE texturepacks SET feature = ? WHERE ID = ?`, [feature, id], async (error) => {
                if (error) {
                    log.error("Error featuring/unfeaturing texture pack:", error.message);
                    return res.status(500).json({ success: false, cause: "Internal Server Error" });
                }

                if (feature == 0) {
                    log.info(`Unfeatured Texture Pack #${id}`);
                    return res.status(200).json({ success: true, message: "Texture pack unfeatured!" });
                } else {
                    log.info(`Featured Texture Pack #${id}`);
                    return res.status(200).json({ success: true, message: "Texture pack featured!" });
                }
            });
    } catch (error) {
        log.error("Error featuring/unfeaturing a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.get("/api/v1/tws/updateTP", async (req, res) => {
    try {
        return res.sendFile(path.join(__dirname, "pages", "updateTP.html"));
    } catch (error) {
        log.error("Error sending the updateTP.html file:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.post("/api/v1/tws/updateTP", async (req, res) => {
    try {
        let { token, type, id, name, description, creator, logo, version, gameVersion, download } = req.body;

        // Check for missing parameters
        if (!token || !type || !id) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the token is not valid
        if (token != config.token) return res.status(403).json({ success: false, cause: "Forbidden" });

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
                    `UPDATE texturepacks SET download = ?, version = ?, gameVersion = ? WHERE ID = ?`, [await encode.base64urlencode(download), version, gameVersion, id], async (error) => {
                        if (error) {
                            log.error("Error updating texture pack:", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`Updated Texture Pack #${id} to ${version} (${gameVersion})`);
                        res.status(200).json({ success: true, message: "Texture pack updated!" })

                        // Delete cached pack
                        return await deleteFile(path.join(dataPath, "packs", `${id}.zip`));
                    });
                break;

            case "name":
                if (!name) return res.status(400).json({ success: false, cause: "Bad Request" });

                db.run(
                    `UPDATE texturepacks SET name = ? WHERE ID = ?`, [await encode.base64encode(name), id], async (error) => {
                        if (error) {
                            log.error("Error updating texture pack's name:", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`Updated Texture Pack #${id}'s name to "${name}"`);
                        return res.status(200).json({ success: true, message: "Texture pack's name updated!" })
                    });
                break;

            case "description":
                if (!description) return res.status(400).json({ success: false, cause: "Bad Request" });

                db.run(
                    `UPDATE texturepacks SET description = ? WHERE ID = ?`, [await encode.base64encode(description), id], async (error) => {
                        if (error) {
                            log.error("Error updating texture pack's description:", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`Updated Texture Pack #${id}'s description`);
                        return res.status(200).json({ success: true, message: "Texture pack's description updated!" })
                    });
                break;

            case "creator":
                if (!creator) return res.status(400).json({ success: false, cause: "Bad Request" });

                db.run(
                    `UPDATE texturepacks SET creator = ? WHERE ID = ?`, [await encode.base64encode(creator), id], async (error) => {
                        if (error) {
                            log.error("Error updating texture pack's creator(s):", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`Updated Texture Pack #${id}'s creator(s) to "${creator}"`);
                        return res.status(200).json({ success: true, message: "Texture pack's creator(s) updated!" })
                    });
                break;

            case "logo":
                if (!logo) return res.status(400).json({ success: false, cause: "Bad Request" });

                if (!validator.isURL(logo, { protocols: ["http", "https"], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Logo URL" });
                
                db.run(
                    `UPDATE texturepacks SET logo = ? WHERE ID = ?`, [await encode.base64urlencode(logo), id], async (error) => {
                        if (error) {
                            log.error("Error updating texture pack's logo:", error.message);
                            return res.status(500).json({ success: false, cause: "Internal Server Error" });
                        }

                        log.info(`Updated Texture Pack #${id}'s logo`);
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

app.get("/api/v1/tws/deleteTP", async (req, res) => {
    try {
        return res.sendFile(path.join(__dirname, "pages", "deleteTP.html"));
    } catch (error) {
        log.error("Error sending the deleteTP.html file:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.post("/api/v1/tws/deleteTP", async (req, res) => {
    try {
        let { token, id } = req.body;

        // Check for missing parameters
        if (!token || !id) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the token is not valid
        if (token != config.token) return res.status(403).json({ success: false, cause: "Forbidden" });

        id = id.replace(/[^0-9]/g, "");

        // Check if ID's still there
        if (!id) return res.status(400).json({ success: false, cause: "Bad Request (ID deleted by security check)" });

        db.run(
            `DELETE FROM texturepacks WHERE ID = ?`, [id], async (error) => {
                if (error) {
                    log.error("Error deleting texture pack:", error.message);
                    return res.status(500).json({ success: false, cause: "Internal Server Error" });
                }

                log.info(`Deleted Texture Pack #${id}`);
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

const server = http.createServer(app);
server.listen(PORT, async () => { log.info(`Server is now running on ${PORT}`) });
