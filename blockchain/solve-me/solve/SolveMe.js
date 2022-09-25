const ethers = require('ethers');
const path = require('path');
const fs = require('fs');
const ts = require('typescript');
const fetch = require('node-fetch');


const HOST = "http://localhost:3000"
const ETH_HOST = "http://localhost:8545"

async function main() {
    await solveExampleChallenge();
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

async function solveExampleChallenge() {

    const details = await getChalDetails()

    const privKey = details[0];
    const contractAddr = details[1];

    
    const provider = ethers.getDefaultProvider(ETH_HOST);
    const wallet = new ethers.Wallet(privKey, provider);
    
    const abi = ["function solveChallenge()"];
    const contract = new ethers.Contract(contractAddr, abi, wallet);
    const tx = await contract.solveChallenge();
    await tx.wait();

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