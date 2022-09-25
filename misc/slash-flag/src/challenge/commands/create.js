const { SlashCommandBuilder } = require("discord.js");
const { runCommand } = require("../utils/os");
const { FILE_LIMIT } = require("../utils/config");
const { errorHandler } = require("../utils/helper");
const quote = require("shell-quote").quote;

module.exports = {
    data: new SlashCommandBuilder()
        .setName("create")
        .setDescription("Create file with the given text!")
        .addStringOption(option => option.setName("filename").setDescription("Name of file to store text in").setRequired(true))
        .addStringOption(option => option.setName("text").setDescription("Text to store").setRequired(true)),
    async execute(interaction) {
        const filename = interaction.options.getString("filename").toUpperCase();
        const text = quote(interaction.options.getString("text").split(" "));
        console.log(`user ${interaction.user.id}:${interaction.guildId} ran create on "${filename}" with contents "${text}"`);

        if (text.length > FILE_LIMIT) {
            return await interaction.reply("Sorry your text is too big aka I don't have enough money to give to Google :)");
        }

        try {
            await runCommand(`echo '${text}' > ${filename}`, interaction.guildId);
        }
        catch (e) {
            return await interaction.reply(errorHandler(e));
        }

        await interaction.reply(`File '${filename}' has been created!`);
    },
};

