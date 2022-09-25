const { SlashCommandBuilder } = require("discord.js");
const { GUILD_ID } = require("../utils/config");

module.exports = {
    data: new SlashCommandBuilder()
        .setName("reset")
        .setDescription("This command isn't apart of the challenge. It is for the limit of 100 servers.")
        .setDefaultPermission(false),
    async execute(interaction) {
        console.log(`RESET RUN BY: ${interaction.user.tag}`);
        const guilds = await interaction.client.guilds.fetch();

        guilds.forEach(async (g) => {
            const guild = await g.fetch();
            if (g.id != GUILD_ID) {
                guild.leave();
            }
        });

        interaction.reply({ content: "Have left all guilds", ephemeral: true });
    },
};

