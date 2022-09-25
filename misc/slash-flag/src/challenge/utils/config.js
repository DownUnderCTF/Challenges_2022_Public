require("dotenv").config();

const REQUIRED_KEYS = ["PROD_BOT_TOKEN", "CLIENT_ID", "GUILD_ID", "FILE_LIMIT"];

for (const key of REQUIRED_KEYS) {
    if (!process.env[key]) {
        throw new Error(`Environment variable ${key} is missing or empty`);
    }
}

let BOT_TOKEN = process.env.PROD_BOT_TOKEN;
if (process.env.NODE_ENV === "dev") {
    BOT_TOKEN = process.env.DEV_BOT_TOKEN;
}

const CLIENT_ID = process.env.CLIENT_ID;
const GUILD_ID = process.env.GUILD_ID;
const FILE_LIMIT = parseInt(process.env.FILE_LIMIT);

module.exports = {
    BOT_TOKEN, CLIENT_ID, GUILD_ID, FILE_LIMIT
};
