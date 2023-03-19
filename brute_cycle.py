#!/usr/bin/python3
from bip_utils import Bip39MnemonicValidator
from bip_utils import Bip32
import codecs, ecdsa, sha3, mnemonic
from smsme import notif_sms
import random, itertools, time, ast, os
def chkmwphrse_old(mwords):
    mobj = mnemonic.Mnemonic("english")
    seed_bytes = mobj.to_seed(mwords)
    bip32_ctx_eth = Bip32.FromSeedAndPath(seed_bytes, "m/44'/60'/0'/0/0")
    hx_pvkey_bytes = bip32_ctx_eth.PrivateKey().Raw().ToBytes()
    key = ecdsa.SigningKey.from_string(hx_pvkey_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    public_key = codecs.encode(key_bytes, 'hex')
    public_key_bytes = codecs.decode(public_key, 'hex')
    keks = sha3.keccak_256()
    keks.update(public_key_bytes)
    keccak_digest = keks.hexdigest()
    address = '0x' + keccak_digest[-40:]
    return address

def chkmwphrse(mwords):
    #mwords = mphrase
    entropy_bytes = Bip39MnemonicValidator(mwords).GetEntropy()
    #is_valid = Bip39MnemonicValidator(mwords).Validate()
    mobj = mnemonic.Mnemonic("english")

    seed_bytes = mobj.to_seed(mwords)
    seed = seed_bytes.hex()

    bip32_ctx = Bip32.FromSeed(seed_bytes)
    # Extended Master Key (Bip32 Root Key)
    mstrkey = bip32_ctx.PrivateKey().ToExtended()

    # Derivation (Bip32 Extended Private Key / Public Key)
    bip32_ctx_eth = Bip32.FromSeedAndPath(seed_bytes, "m/44'/60'/0'/0/0")
    #ext_pvkey = bip32_ctx_eth.PrivateKey().ToExtended()
    #ext_pbkey = bip32_ctx_eth.PublicKey().ToExtended()

    # Derivation Hex Format (Public & Private Keys)
    #hx_pvkey = bip32_ctx_eth.PrivateKey().Raw().ToHex()
    #hx_pbkey = bip32_ctx_eth.PublicKey().RawCompressed().ToHex()
    hx_pvkey_bytes = bip32_ctx_eth.PrivateKey().Raw().ToBytes()
    hx_pbkey_bytes = bip32_ctx_eth.PublicKey().RawCompressed().ToBytes()

    key = ecdsa.SigningKey.from_string(hx_pvkey_bytes, curve=ecdsa.SECP256k1).verifying_key

    key_bytes = key.to_string()
    private_key = codecs.encode(hx_pvkey_bytes, 'hex')
    public_key = codecs.encode(key_bytes, 'hex')

    public_key_bytes = codecs.decode(public_key, 'hex')
    keks = sha3.keccak_256()
    keks.update(public_key_bytes)

    keccak_digest = keks.hexdigest()
    address = '0x' + keccak_digest[-40:]
    #print("Address:",address)
    return address

def wrdlg(phrase):
    lgme = open('try.lg', '+a')
    lgme.write(phrase + '\n')
    lgme.close()

k = 0
open('try.lg', '+a').close()
trylst = open('try.lg', 'r').read().splitlines()

while True:
    # ==========   Variables   ========#
    # get curl here #
    try:
        brtcfg = open('words.cfg','r').read())
    except:
        print("config error")
        brtcfg = {}
        exit()
    # add parse brtcfg #
    switch = brtcfg['switch']
    reference = brtcfg['reference']
    pcount  = int(brtcfg['pcount'])
    plist   = brtcfg['plist']
    vcount  = int(brtcfg['vcount'])
    vlist   = brtcfg['vlist']
    sample  = int(brtcfg['sample'])
    fixed   = brtcfg['fixed']
    combine = brtcfg['combine']
    refaddr = brtcfg['refaddr']

    #============   Parse   ============#
    combi_vlist =  list(itertools.combinations(vlist.split(), vcount))
    combi_plist = list(itertools.combinations(plist.split(), pcount))
    wrdslist = ' '.join(random.choice(combi_vlist)) + ' ' + ' '.join(random.choice(combi_plist)) + ' ' + ' '.join(fixed.split())

    hit = []
    hitfile = open('hit.hit', '+a')
    parsed = wrdslist.split()
    trysort = ' '.join(sorted(parsed))

    # Check if done
    if trysort in trylst:
        print("Skipped: " + trysort)
        skipthis = 'Skipped : ' + trysort
        wrdlg(skipthis)
        time.sleep(5)
        while trysort in trylst:
            combi_vlist = list(itertools.combinations(vlist.split(), vcount))
            combi_plist = list(itertools.combinations(plist.split(), pcount))
            wrdslist = ' '.join(random.choice(combi_vlist)) + ' ' + ' '.join(
                random.choice(combi_plist)) + ' ' + ' '.join(fixed.split())
            parsed = wrdslist.split()
            trysort = ' '.join(sorted(parsed))
    random.shuffle(parsed)
    random.shuffle(parsed)
    random.shuffle(parsed)

    permute_lst = itertools.permutations(parsed,sample)
    i = 0
    print('Start iteration ' + str(k) +  '.' + 'try: ' + str(wrdslist))
    time.sleep(3)
    for line in permute_lst:
        newlist = eval(combine)
        phrase = ' '.join(newlist)
        try:
            myaddr = chkmwphrse(phrase).lower()
            #print(' : '.join([str(i), 'addr', myaddr, phrase]))
        except:
            myaddr = 'invalid'
        if myaddr == refaddr.lower():
            print('HIT!!!!!!!!!!!!!!!!!!!!')
            print(phrase)
            hit.append(phrase)
            tempstr = ''.join(phrase)[1:-1]
            hitfile.write(str(tempstr))
            notif_sms(tempstr, '639208111111')
            time.sleep(30)
            exit()
        i += 1
    k += 1
    hitfile.write(str(k) + ' : ' + str(i) + ' : ' + wrdslist + ' NOLUCK!!! \n')
    hitfile.close()
    # Log attempts
    wrdlg(trysort)
    trylst.append(trysort)