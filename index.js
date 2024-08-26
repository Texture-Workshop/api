const express = require("express");
const http = require("http");
const fs = require("fs").promises;
const { Database } = require("sqlite3").verbose();
const bodyParser = require('body-parser');
const validator = require('validator');
const path = require('path');
const favicon = require('serve-favicon');

const { log, encode } = require(path.join(__dirname, "util", "functions.js"));
const config = require(path.join(__dirname, "config.json"));


const db = new Database(path.join(__dirname, "data", "database.db"), async (error) => {
    if (error) {
        log.error("Error opening SQLite:", error.message);
    } else {
        log.info("Connected to SQLite");
        try {
            db.exec(await fs.readFile(path.join(__dirname, "data", "database.sql"), "utf8"), async (error) => { // Execute SQL script
                if (error) {
                    log.warn("Error executing SQL script:", error.message);
                } else {
                    log.info("DB: Tables created or already exist.");
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

app.get("/api/v1/tws/ping", async (req, res) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");

    res.setHeader("Content-Type", "application/json");

    res.json({ timestamp: Date.now() });
});

app.get("/api/v1/tws/getTPs", async (req, res) => {
    res.setHeader("Content-Type", "application/json");

    let result = {};
    try {
        db.all("SELECT * FROM texturepacks", async (error, rows) => {
            if (error) {
                log.error("Error fetching data from SQLite:", error.message);
                return res.status(500).json({ success: false, cause: "Internal Server Error" });
            }

            await Promise.all(rows.map(async (row, index) => {
                result[index + 1] = {
                    packID: row.ID,
                    packName: await encode.base64decode(row.name),
                    downloadLink: await encode.base64urldecode(row.download),
                    packLogo: await encode.base64urldecode(row.logo),
                    packDescription: await encode.base64decode(row.description),
                    packCreator: await encode.base64decode(row.creator),
                    packVersion: row.version,
                    packFeature: row.feature
                }
            })).then(async () => {
                res.setHeader("Cache-Control", "public, max-age=1800, immutable"); // Cache for 30 minutes
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
        return res.send(await fs.readFile(path.join(__dirname, "pages", "addTP.html"), "utf8"));
    } catch (error) {
        log.error("Error sending the addTP.html file:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.use(bodyParser.urlencoded({ extended: false }));

// POST method to actually handle the form responses
app.post("/api/v1/tws/addTP", async (req, res) => {
    try {
        // Get variables from body
        let { token, name, description, creator, logo, download, version, gameVersion, feature } = req.body;

        // Check for missing parameters
        if (!token || !name || !description || !creator || !logo || !download || !version || !gameVersion || !feature) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the token is not valid
        if (token != config.token) return res.status(403).json({ success: false, cause: "Forbidden" });
        name = await encode.base64encode(name);
        description = await encode.base64encode(description);
        creator = await encode.base64encode(creator);

        // Cleaning up potential SQL injection prompts
        /*name = name.replace(/[^A-Za-z0-9 ]/g, '');
        description = description.replace(/[^A-Za-z0-9 ]/g, '');
        creator = creator.replace(/[^A-Za-z0-9 ]/g, '');

        // Same for logo and download, additionally check if they actually are URLs
        logo = logo.replace(/[^A-Za-z0-9:\/._\-]/g, '');*/
        if (!validator.isURL(logo, { protocols: ['http', 'https'], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Logo URL" });
        /*download = download.replace(/[^A-Za-z0-9:\/._\-]/g, '');*/
        logo = await encode.base64urlencode(logo);

        if (!validator.isURL(download, { protocols: ['http', 'https'], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Download Link" });
        download = await encode.base64urlencode(download);

        version = version.replace(/[^A-Za-z0-9 :\/?.]/g, '');
        gameVersion = gameVersion.replace(/[^A-Za-z0-9 :\/?.]/g, '');

        feature = feature.replace(/[^0-9]/g, '');
        if (!['0', '1'].includes(feature)) return res.status(400).json({ success: false, cause: "Invalid Feature boolean (must be either 0 or 1)" });

        // Check if all fields are here again
        if (!name || !description || !creator || !logo || !download || !version || !gameVersion || !feature) return res.status(400).json({ success: false, cause: "Bad Request (One or multiple fields have been cleared after security check)" });

        // Check if a texture pack with the same name already exists
        let existingPack = await new Promise((resolve, reject) => {
            db.get("SELECT 1 FROM texturepacks WHERE name = ?", [name], (error, row) => {
                if (error) return reject(error);
                resolve(row);
            });
        });

        if (existingPack) {
            return res.status(409).json({ success: false, cause: "This Texture Pack already exists!" });
        }

        return await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO texturepacks (name, description, creator, logo, download, version, gameVersion, feature) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [name, description, creator, logo, download, version, gameVersion, feature], async (error) => {
                    if (error) {
                        log.error('Error inserting texture pack into SQLite:', error.message);
                        resolve(res.status(500).json({ success: false, cause: 'Internal Server Error' }));

                    }
                    log.info(`Added Texture Pack "${await encode.base64decode(name)}" by ${await encode.base64decode(creator)} (Featured: ${feature})`);
                    resolve(res.status(200).json({ success: true, message: 'Texture pack added!' }));
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
        return res.send(await fs.readFile(path.join(__dirname, "pages", "featureTP.html"), "utf8"));
    } catch (error) {
        log.error("Error sending the featureTP.html file:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.post("/api/v1/tws/featureTP", async (req, res) => {
    try {
        // Get variables from body
        let { token, id, feature } = req.body;

        // Check for missing parameters
        if (!token || !id || !feature) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the token is not valid
        if (token != config.token) return res.status(403).json({ success: false, cause: "Forbidden" });

        id = id.replace(/[^0-9]/g, '');

        feature = feature.replace(/[^0-9]/g, '');
        if (!['0', '1'].includes(feature)) return res.status(400).json({ success: false, cause: "Invalid Feature boolean (must be either 0 or 1)" });

        // Check if ID's still there
        if (!id || !feature) return res.status(400).json({ success: false, cause: "Bad Request (One or multiple fields have been cleared after security check)" });

        db.run(
            `UPDATE texturepacks SET feature = ? WHERE ID = ?`, [feature, id], async (error) => {
                if (error) {
                    log.error('Error featuring/unfeaturing texture pack:', error.message);
                    return res.status(500).json({ success: false, cause: 'Internal Server Error' });
                }

                if (feature == 0) {
                    log.info(`Unfeatured ${id}`);
                    return res.status(200).json({ success: true, message: 'Texture pack unfeatured!' });
                } else {
                    log.info(`Featured ${id}`);
                    return res.status(200).json({ success: true, message: 'Texture pack featured!' });
                }
            });
    } catch (error) {
        log.error("Error featuring/unfeaturing a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.get("/api/v1/tws/updateTP", async (req, res) => {
    try {
        return res.send(await fs.readFile(path.join(__dirname, "pages", "updateTP.html"), "utf8"));
    } catch (error) {
        log.error("Error sending the updateTP.html file:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.post("/api/v1/tws/updateTP", async (req, res) => {
    try {
        // Get variables from body
        let { token, type, id, name, description, creator, logo, version, gameVersion, download } = req.body;

        // Check for missing parameters
        if (!token || !type || !id) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the token is not valid
        if (token != config.token) return res.status(403).json({ success: false, cause: "Forbidden" });

        id = id.replace(/[^0-9]/g, '');

        // Check if ID's still there
        if (!id) return res.status(400).json({ success: false, cause: "Bad Request (ID deleted by security check)" });

        switch (type) {
            case "version":
                if (!download || !version || !gameVersion) return res.status(400).json({ success: false, cause: "Bad Request" });

                if (!validator.isURL(download, { protocols: ['http', 'https'], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Download Link" });
                download = await encode.base64urlencode(download);

                version = version.replace(/[^A-Za-z0-9 :\/?.]/g, '');
                gameVersion = gameVersion.replace(/[^A-Za-z0-9 :\/?.]/g, '');

                db.run(
                    `UPDATE texturepacks SET download = ?, version = ?, gameVersion = ? WHERE ID = ?`, [download, version, gameVersion, id], async (error) => {
                        if (error) {
                            log.error('Error updating texture pack:', error.message);
                            return res.status(500).json({ success: false, cause: 'Internal Server Error' });
                        }

                        log.info(`Updated ${id} to ${version} (${gameVersion})`);
                        return res.status(200).json({ success: true, message: 'Texture pack updated!' })
                    });
                break;

            case "name":
                if (!name) return res.status(400).json({ success: false, cause: "Bad Request" });

                name = await encode.base64encode(name);
                db.run(
                    `UPDATE texturepacks SET name = ? WHERE ID = ?`, [name, id], async (error) => {
                        if (error) {
                            log.error('Error updating texture pack\'s name:', error.message);
                            return res.status(500).json({ success: false, cause: 'Internal Server Error' });
                        }

                        log.info(`Updated ${id}'s name to ${await encode.base64decode(name)}`);
                        return res.status(200).json({ success: true, message: 'Texture pack\'s name updated!' })
                    });
                break;

            case "description":
                if (!description) return res.status(400).json({ success: false, cause: "Bad Request" });

                description = await encode.base64encode(description);
                db.run(
                    `UPDATE texturepacks SET description = ? WHERE ID = ?`, [description, id], async (error) => {
                        if (error) {
                            log.error('Error updating texture pack\'s description:', error.message);
                            return res.status(500).json({ success: false, cause: 'Internal Server Error' });
                        }

                        log.info(`Updated ${id}'s description to ${await encode.base64decode(description)}`);
                        return res.status(200).json({ success: true, message: 'Texture pack\'s description updated!' })
                    });
                break;

            case "creator":
                if (!creator) return res.status(400).json({ success: false, cause: "Bad Request" });

                creator = await encode.base64encode(creator);
                db.run(
                    `UPDATE texturepacks SET creator = ? WHERE ID = ?`, [creator, id], async (error) => {
                        if (error) {
                            log.error('Error updating texture pack\'s creator(s):', error.message);
                            return res.status(500).json({ success: false, cause: 'Internal Server Error' });
                        }

                        log.info(`Updated ${id}'s creator(s) to ${await encode.base64decode(creator)}`);
                        return res.status(200).json({ success: true, message: 'Texture pack\'s creator(s) updated!' })
                    });
                break;

            case "logo":
                if (!logo) return res.status(400).json({ success: false, cause: "Bad Request" });

                if (!validator.isURL(logo, { protocols: ['http', 'https'], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Logo URL" });
                logo = await encode.base64urlencode(logo);
                db.run(
                    `UPDATE texturepacks SET logo = ? WHERE ID = ?`, [logo, id], async (error) => {
                        if (error) {
                            log.error('Error updating texture pack\'s logo:', error.message);
                            return res.status(500).json({ success: false, cause: 'Internal Server Error' });
                        }

                        log.info(`Updated ${id}'s logo`);
                        return res.status(200).json({ success: true, message: 'Texture pack\'s logo updated!' })
                    });
                break;

            default:
                return res.status(400).json({ success: false, cause: 'what' });
        }
    } catch (error) {
        log.error("Error updating a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.get("/api/v1/tws/deleteTP", async (req, res) => {
    try {
        return res.send(await fs.readFile(path.join(__dirname, "pages", "deleteTP.html"), "utf8"));
    } catch (error) {
        log.error("Error sending the deleteTP.html file:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.post("/api/v1/tws/deleteTP", async (req, res) => {
    try {
        // Get variables from body
        let { token, id } = req.body;

        // Check for missing parameters
        if (!token || !id) return res.status(400).json({ success: false, cause: "Bad Request" });

        // Do not continue if the token is not valid
        if (token != config.token) return res.status(403).json({ success: false, cause: "Forbidden" });

        id = id.replace(/[^0-9]/g, '');

        // Check if ID's still there
        if (!id) return res.status(400).json({ success: false, cause: "Bad Request (ID deleted by security check)" });

        db.run(
            `DELETE FROM texturepacks WHERE ID = ?`, [id], async (error) => {
                if (error) {
                    log.error('Error deleting texture pack:', error.message);
                    return res.status(500).json({ success: false, cause: 'Internal Server Error' });
                }

                log.info(`Deleted ${id}`);
                return res.status(200).json({ success: true, message: 'Texture pack deleted!' });
            });
    } catch (error) {
        log.error("Error deleting a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

const server = http.createServer(app);
server.listen(PORT, async () => { log.info(`Server is now running on ${PORT}`) });