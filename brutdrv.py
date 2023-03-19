#!/usr/bin/python3
from bip_utils import Bip39MnemonicValidator
from bip_utils import Bip32
import codecs, ecdsa, sha3, mnemonic
from ntf import notif_sms
import random, itertools, time, ast, os
import os

def chkmwphrse_wdr(mwords,dlen):
    addrlst = []
    entropy_bytes = Bip39MnemonicValidator(mwords).GetEntropy()
    mobj = mnemonic.Mnemonic("english")
    seed_bytes = mobj.to_seed(mwords)
    seed = seed_bytes.hex()
    bip32_ctx = Bip32.FromSeed(seed_bytes)
    # Extended Master Key (Bip32 Root Key)
    mstrkey = bip32_ctx.PrivateKey().ToExtended()
    dlength = int(dlen)
    for d in range(dlength):
        dpath = "m/44'/60'/0'/0/" + str(d)
        bip32_ctx_eth = Bip32.FromSeedAndPath(seed_bytes, dpath)
        mstrkey = bip32_ctx.PrivateKey().ToExtended()
        hx_pvkey_bytes = bip32_ctx_eth.PrivateKey().Raw().ToBytes()
        hx_pbkey_bytes = bip32_ctx_eth.PublicKey().RawCompressed().ToBytes()
        key_bytes = key.to_string()
        private_key = codecs.encode(hx_pvkey_bytes, 'hex')
        public_key = codecs.encode(key_bytes, 'hex')
        public_key_bytes = codecs.decode(public_key, 'hex')
        keks = sha3.keccak_256()
        keks.update(public_key_bytes)
        keccak_digest = keks.hexdigest()
        address = '0x' + keccak_digest[-40:]
        addrlst.append(address.lower())
    return addrlst

def wrdlg(phrase):
    devtestfile = dtstamp + '_' + hostname + '.tdrv'
    lgme = open(devtestfile, '+a')
    lgme.write(phrase + '\n')
    lgme.close()
hostname = os.popen('hostname').read().lower().strip().replace('-', '_')
dtstamp = os.popen('date +%Y%m%d').read().strip()
devtestfile = dtstamp + '_' + hostname + '.tdrv'

k = 0
open(devtestfile, '+a').close()
trylst = open(devtestfile, 'r').read().splitlines()
time.sleep(1)

while True:
    # ==========   Variables   ========#
    # get curl here #
    try:
        brtcfg = ast.literal_eval(open('words_drv.cfg', 'r').read())

    except:
        print("config error")
        brtcfg = {}
        exit()
    # get try db
    try:
        trydb = open('try.tdrv', 'r').read().strip().splitlines()
    except:
        trydb = []
    trylst_full = trylst + trydb
    print("Current List: " + str(len(trylst_full)))

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
    dlength = brtcfg['dlength']

    #============   Parse   ============#
    combi_vidlist =  list(itertools.combinations(vlist.split(), vcount))
    combi_postlist = list(itertools.combinations(plist.split(), pcount))
    wrdslist = ' '.join(random.choice(combi_vidlist)) + ' ' + ' '.join(random.choice(combi_postlist)) + ' ' + ' '.join(fixed.split())

    hit = []
    hitfile = open('hitdrv.hit', '+a')
    parsed = wrdslist.split()
    trysort = ' '.join(sorted(parsed))

    # Check if done
    if trysort in trylst_full:
        while trysort in trylst_full:
            print("Skipped: " + trysort)
            combi_vidlist = list(itertools.combinations(vlist.split(), vcount))
            combi_postlist = list(itertools.combinations(plist.split(), pcount))
            wrdslist = ' '.join(random.choice(combi_vidlist)) + ' ' + ' '.join(
                random.choice(combi_postlist)) + ' ' + ' '.join(fixed.split())
            parsed = wrdslist.split()
            trysort = ' '.join(sorted(parsed))
    random.shuffle(parsed)
    random.shuffle(parsed)
    random.shuffle(parsed)

    permute_lst = itertools.permutations(parsed,sample)
    i = 0
    print('Start iteration ' + str(k) +  '.' + ' Try: ' + str(wrdslist))
    print('derive length: ' + str(dlength))
    time.sleep(5)
    for line in permute_lst:
        newlist = eval(combine)
        phrase = ' '.join(newlist)
        try:
            addrlist = chkmwphrse_wdr(phrase, dlength)
            print(' : '.join([str(i), 'addr', addrlist[-1], phrase]))
        except:
            addrlist = []
        if refaddr.lower() in addrlist :
            print('HIT!!!!!!!!!!!!!!!!!!!!')
            print(phrase)
            hit.append(phrase)
            tempstr = ''.join(phrase)[1:-1]
            hitfile.write(str(tempstr))
            notif_sms(tempstr, '63920811111111')
            time.sleep(5)
            exit()
        i += 1
    k += 1
    hitfile.write(str(k) + ' : ' + str(i) + ' : ' + wrdslist + ' NOLUCK!!! \n')
    hitfile.close()
    # Log attempts
    wrdlg(trysort)
    trylst.append(trysort)