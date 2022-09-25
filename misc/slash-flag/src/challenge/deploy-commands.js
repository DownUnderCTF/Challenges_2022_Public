const fs = require("node:fs");
const path = require("node:path");
const { REST } = require("@discordjs/rest");
const { Routes } = require("discord.js");
const { CLIENT_ID, GUILD_ID, BOT_TOKEN } = require("./utils/config");

const rest = new REST({ version: "10" }).setToken(BOT_TOKEN);

// Delete previous commands

// for guild-based commands
rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: [] })
    .then(() => console.log("Successfully deleted all guild commands."))
    .catch(console.error);

// for global commands
rest.put(Routes.applicationCommands(CLIENT_ID), { body: [] })
    .then(() => console.log("Successfully deleted all application commands."))
    .catch(console.error);

// Add commands (reset command should only be available to DUCTF Organisers)

const commands = [];
const commandsPath = path.join(__dirname, "commands");
const commandFiles = fs.readdirSync(commandsPath).filter(file => file.endsWith(".js") && !file.includes("reset"));

for (const file of commandFiles) {
    const filePath = path.join(commandsPath, file);
    const command = require(filePath);
    commands.push(command.data.toJSON());
}

rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: [require(path.join(commandsPath, "reset.js")).data.toJSON()] })
    .then(() => console.log("Successfully registered application commands."))
    .catch(console.error);

rest.put(Routes.applicationCommands(CLIENT_ID), { body: commands })
    .then(() => console.log("Successfully registered application commands."))
    .catch(console.error);

