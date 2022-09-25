module.exports = {
    name: "ready",
    once: true,
    async execute(client) {
        // Deploy the commands
        require("../deploy-commands");
        console.log(`Ready! Logged in as ${client.user.tag}`);
    },
};