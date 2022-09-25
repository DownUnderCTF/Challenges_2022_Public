from requests import get
from web3 import Web3
from web3.middleware import geth_poa_middleware
import rlp

URL = 'http://0.0.0.0:3000/challenge'
RPC_URL = 'http://0.0.0.0:8545/'

def get_instance():
    r = get(URL)
    dat = r.json()
    player_addr = dat['player_wallet']['address']
    player_privkey = dat['player_wallet']['private_key']
    target_addr = dat['contract_address'][0]['address']
    return player_addr, player_privkey, target_addr

def get_flag():
    r = get(URL + '/solve')
    dat = r.json()
    if dat['flag']:
        return dat['flag']
    elif dat['error']:
        return dat['error']
    elif dat['message']:
        return dat['message']

def deploy_contract(bytecode):
    nonce = web3.eth.get_transaction_count(PLAYER_ADDRESS)
    tx = {
        'chainId': 31337,
        'nonce': nonce,
        'from': PLAYER_ADDRESS,
        'gasPrice': web3.eth.gas_price,
        'data': bytecode,
        'value': web3.toWei(1.01, 'ether')
    }
    gas_estimate = web3.eth.estimate_gas(tx)
    tx['gas'] = 2 * gas_estimate
    signed_tx = web3.eth.account.sign_transaction(tx, private_key=PLAYER_PRIVKEY)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt['contractAddress']
    return contract_address

def send_unlock_tx(target_address, code, inp):
    nonce = web3.eth.get_transaction_count(PLAYER_ADDRESS)
    tx = {
        'chainId': 31337,
        'nonce': nonce,
        'from': PLAYER_ADDRESS,
        'to': target_address,
        'gasPrice': web3.eth.gas_price,
        'data': code.hex() + inp.hex()
    }
    gas_estimate = web3.eth.estimate_gas(tx)
    tx['gas'] = gas_estimate
    signed_tx = web3.eth.account.sign_transaction(tx, private_key=PLAYER_PRIVKEY)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt

def check_solved(contract_address):
    s = web3.eth.get_storage_at(contract_address, 0x1337)
    solved = web3.eth.get_storage_at(contract_address, 0x736f6c766564)
    solved = int.from_bytes(solved, 'big')
    s = int.from_bytes(s, 'big')
    return s, solved

web3 = Web3(Web3.HTTPProvider(RPC_URL))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)

PLAYER_ADDRESS, PLAYER_PRIVKEY, target_address = get_instance()

def unlock_pin_A(target_address):
    inp = ((0x346d81803d471 ^ 0xb3abdcef1f1) // 0x80) - 0x69b135a06c3
    tx_receipt = send_unlock_tx(target_address, b'AAAA', inp.to_bytes(4, 'big'))
    s, _ = check_solved(target_address)
    print('After unlocking pin A, storage[0x1337] =', s)

def unlock_pin_C(target_address):
    # just spam bogus txs until contract address is good
    while True:
        nonce = web3.eth.get_transaction_count(PLAYER_ADDRESS)
        addr = web3.keccak(rlp.encode([bytes.fromhex(PLAYER_ADDRESS[2:]), nonce]))[12:]
        addr_lower = int.from_bytes(addr, 'big') & 0xff
        if addr_lower == 0x77:
            break
        send_unlock_tx('0x' + 40 * '0', b'x', b'x')

    attack_ctor_bytecode = '6025600d60003960256000f3fe60003560601c67434343439266316160c01b60005260006000600860006000855af1005050'
    attack_contract = deploy_contract(attack_ctor_bytecode)
    nonce = web3.eth.get_transaction_count(PLAYER_ADDRESS)
    tx = {
        'chainId': 31337,
        'nonce': nonce,
        'from': PLAYER_ADDRESS,
        'to': attack_contract,
        'gasPrice': web3.eth.gas_price,
        'data': target_address
    }
    gas_estimate = web3.eth.estimate_gas(tx)
    tx['gas'] = 5 * gas_estimate
    signed_tx = web3.eth.account.sign_transaction(tx, private_key=PLAYER_PRIVKEY)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    s, _ = check_solved(target_address)
    print('After unlocking pin C, storage[0x1337] =', s)

def unlock_pin_D(target_address):
    inp = 0x1a001a7f
    tx_receipt = send_unlock_tx(target_address, b'DDDD', inp.to_bytes(4, 'big'))
    s, _ = check_solved(target_address)
    print('After unlocking pin D, storage[0x1337] =', s)

def unlock_pin_E(target_address):
    print('hash of bytecode is:', Web3.keccak(web3.eth.get_code(target_address)).hex())
    inp = 0xb23b606f
    tx_receipt = send_unlock_tx(target_address, b'EEEE', inp.to_bytes(4, 'big'))
    s, _ = check_solved(target_address)
    print('After unlocking pin E, storage[0x1337] =', s)


unlock_pin_A(target_address)
unlock_pin_C(target_address)
unlock_pin_D(target_address)
unlock_pin_E(target_address)
send_unlock_tx(target_address, b'vrfy', b'xxxx')

print(check_solved(target_address))

flag = get_flag()
print(flag)
