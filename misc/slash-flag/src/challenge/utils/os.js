const fsPromises = require("fs").promises;
const util = require("util");
const execFile = util.promisify(require("child_process").execFile);


async function runCommand(command, guildId) {
    if (isNaN(guildId)) {
        throw new Error("not a valid guild id");
    }

    const { stdout } = await execFile("sudo", ["/usr/src/app/run_lock", guildId, command]);
    return stdout;
}

async function mkdir(folder) {
    try {
        await fsPromises.access(folder);

    }
    catch (e) {
        await fsPromises.mkdir(folder, { recursive: true });
        await fsPromises.chmod(folder, 0o777);
    }
}

module.exports = {
    mkdir, runCommand,
};