const { SlashCommandBuilder } = require("discord.js");
const { errorHandler } = require("../utils/helper");
const { runCommand } = require("../utils/os");

module.exports = {
    data: new SlashCommandBuilder()
        .setName("list")
        .setDescription("List files stored"),
    async execute(interaction) {
        let out = "";
        console.log(`user ${interaction.user.id}:${interaction.guildId} ran list`);
        try {
            out = await runCommand("ls", interaction.guildId);
        }
        catch (e) {
            return await interaction.reply(errorHandler(e));
        }

        const nsjailMounts = ["bin", "flag", "lib", "lib64", "lost+found"];
        for (let i = 0; i < nsjailMounts.length; i++) {
            out = out.replace(nsjailMounts[i], "");
        }
        await interaction.reply(`Your files:\n${out}`);
    },
};

