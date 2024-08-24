const express = require("express");
const http = require("http");
const fs = require("fs").promises;
const { Database } = require("sqlite3").verbose();
const bodyParser = require('body-parser');
const validator = require('validator');

const { log } = require("./util/functions");
const config = require("./config.json");

const db = new Database("data/database.db", async (error) => {
    if (error) {
        log.error("Error opening SQLite:", error.message);
    } else {
        log.info("Connected to SQLite");
        try {
            db.exec(await fs.readFile("data/database.sql", "utf8"), (error) => { // Execute SQL script
                if (error) {
                    log.error("Error executing SQL script:", error.message);
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

const PORT = 8080;

app.get("/api/v1/tws/ping", async (req, res) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");

    res.setHeader("Content-Type", "application/json");

    res.json({ timestamp: Date.now() });
});

app.get("/api/v1/tws/getTPs", async (req, res) => {
    res.setHeader("Cache-Control", "public, max-age=1800, immutable"); // Cache for 30 minutes
    res.setHeader("Content-Type", "application/json");

    let result = {};
    try {
        db.all("SELECT * FROM texturepacks", (error, rows) => {
            if (error) {
                log.error("Error fetching data from SQLite:", error.message);
                return res.status(500).json({ success: false, cause: "Internal Server Error" });
            }

            rows.forEach((row, index) => {
                result[index + 1] = {
                    packID: row.ID,
                    packName: row.name,
                    downloadLink: row.download,
                    packLogo: row.logo,
                    packDescription: row.description,
                    packCreator: row.creator,
                    packVersion: row.version,
                    packFeature: row.feature
                };
            });
    
            return res.status(200).json(result);
        });
    } catch (error) {
        log.error("Error fetching data from SQLite:", error.message);
        return res.status(500).json({ success: false, cause: "Internal Server Error" });
    }
});

// GET method to send the form
app.get("/api/v1/tws/addTP", async (req, res) => {
    try {
        return res.send(await fs.readFile("pages/addTP.html", "utf8"));
    } catch (error) {
        log.error("Error sending the addTP.html file:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.use(bodyParser.urlencoded({ extended: false }));

// POST method to actually handle the form responses
app.post("/api/v1/tws/addTP", async (req, res) => {
    let { token, name, description, creator, logo, download, version, gameVersion, feature } = req.body;
    try {
        // Check for missing parameters
        if (!token || !name || !description || !creator || !logo || !download || !version || !gameVersion || !feature) return res.status(400).json({ success: false, cause: "Bad Request"});

        // Do not continue if the token is not valid
        if (token != config.token) return res.status(403).json({ success: false, cause: "Forbidden"});

        // Cleaning up potential SQL injection prompts
        name = name.replace(/[^A-Za-z0-9 ]/g, '');
        description = description.replace(/[^A-Za-z0-9 ]/g, '');
        creator = creator.replace(/[^A-Za-z0-9 ]/g, '');

        // Same for logo and download, additionally check if they actually are URLs
        logo = logo.replace(/[^A-Za-z0-9:\/._\-]/g, '');
        if (!validator.isURL(logo, { protocols: ['http', 'https'], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Logo URL"});
        download = download.replace(/[^A-Za-z0-9:\/._\-]/g, '');
        if (!validator.isURL(download, { protocols: ['http', 'https'], require_tld: true })) return res.status(400).json({ success: false, cause: "Invalid Download Link"});
    
        version = version.replace(/[^A-Za-z0-9 :\/?]/g);
        gameVersion = gameVersion.replace(/[^A-Za-z0-9 :\/?]/g);

        feature = feature.replace(/[^0-9]/g, '');
        if (!['0', '1'].includes(feature)) return res.status(400).json({ success: false, cause: "Invalid Feature boolean (must be either 0 or 1)"});

        // Check if all fields are here again
        if (!name || !description || !creator || !logo || !download || !version || !gameVersion || !feature) return res.status(400).json({ success: false, cause: "Bad Request (One or multiple fields have been cleared after security check)"});

        db.run(
            `INSERT INTO texturepacks (name, description, creator, logo, download, version, gameVersion, feature) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [name, description, creator, logo, download, version, gameVersion, feature], function (error) {
            if (error) {
                log.error('Error inserting texture pack into SQLite:', error.message);
                return res.status(500).json({ success: false, cause: 'Internal Server Error' });
            }
            
            log.info(`Added Texture Pack "${name}" by ${creator} (Featured: ${feature})`);
            return res.status(200).json({ success: true, message: 'Texture pack added!' });
        });
    } catch (error) {
        log.error("Error adding a texture pack:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.get("/api/v1/tws/featureTP", async (req, res) => {
    try {
        return res.send(await fs.readFile("pages/featureTP.html", "utf8"));
    } catch (error) {
        log.error("Error sending the featureTP.html file:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.post("/api/v1/tws/featureTP", async (req, res) => {
    let { token, id, feature } = req.body;
    try {
        // Check for missing parameters
        if (!token || !id || !feature) return res.status(400).json({ success: false, cause: "Bad Request"});

        // Do not continue if the token is not valid
        if (token != config.token) return res.status(403).json({ success: false, cause: "Forbidden"});

        id = id.replace(/[^0-9]/g, '');

        feature = feature.replace(/[^0-9]/g, '');
        if (!['0', '1'].includes(feature)) return res.status(400).json({ success: false, cause: "Invalid Feature boolean (must be either 0 or 1)"});

        // Check if ID's still there
        if (!id || !feature) return res.status(400).json({ success: false, cause: "Bad Request (One or multiple fields have been cleared after security check)"});

        db.run(
            `UPDATE texturepacks SET feature = ? WHERE ID = ?`, [feature, id], function (error) {
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

app.get("/api/v1/tws/deleteTP", async (req, res) => {
    try {
        return res.send(await fs.readFile("pages/deleteTP.html", "utf8"));
    } catch (error) {
        log.error("Error sending the deleteTP.html file:", error.message);
        return res.status(500).send("Internal Server Error")
    }
});

app.post("/api/v1/tws/deleteTP", async (req, res) => {
    let { token, id } = req.body;
    try {
        // Check for missing parameters
        if (!token || !id) return res.status(400).json({ success: false, cause: "Bad Request"});

        // Do not continue if the token is not valid
        if (token != config.token) return res.status(403).json({ success: false, cause: "Forbidden"});

        id = id.replace(/[^0-9]/g, '');

        // Check if ID's still there
        if (!id) return res.status(400).json({ success: false, cause: "Bad Request (ID deleted by security check)"});

        db.run(
            `DELETE FROM texturepacks WHERE ID = ?`, [id], function (error) {
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
server.listen(PORT, async () => { await log.info(`Server is now running on ${PORT}`) });