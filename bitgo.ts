import { BitGo } from 'bitgo';
import { Ecdsa, ECDSA, ECDSAMethodTypes, hexToBigInt, SignatureShareRecord, SignatureShareType, TssUtils } from '@bitgo/sdk-core';
import { EcdsaPaillierProof, EcdsaRangeProof, EcdsaTypes } from '@bitgo/sdk-lib-mpc';
import { Eth } from '@bitgo/sdk-coin-eth';
import { Polygon, PolygonToken } from '@bitgo/sdk-coin-polygon';
import * as ethUtil from 'ethereumjs-util';
import { ethers, utils } from 'ethers';
import createKeccakHash from 'keccak';
import { Hash } from 'crypto';
import { splitSignature } from '@ethersproject/bytes';

const MPC = new Ecdsa();

async function bitgoCreate() {

    // const seed = Buffer.from(
    //     '2b73353a2bdecf9bb4a5305d6cfb231d7f5528c5e45de815d17fd0a091fa7f84778e3f9890ad2a5d03af50b9a69574640afe7be3039d35a7e5824b2d1b59b0c3',
    //     'hex',
    // );
    // const address = '0xc11DDc828Ad53195B2E1ec630Ab2D67b56FFC44f'
    // const path = "m/44'/60'/0'/0/0"

    const A = await MPC.keyShare(1, 2, 3);
    const B = await MPC.keyShare(2, 2, 3);
    const C = await MPC.keyShare(3, 2, 3);

    console.log(JSON.stringify(A, undefined, 1));
    console.log(JSON.stringify(B, undefined, 2));
    console.log(JSON.stringify(C, undefined, 3));

    const aKeyCombine = MPC.keyCombine(A.pShare, [B.nShares[1], C.nShares[1]]);
    const bKeyCombine = MPC.keyCombine(B.pShare, [A.nShares[2], C.nShares[2]]);
    const cKeyCombine = MPC.keyCombine(C.pShare, [A.nShares[3], B.nShares[3]]);

    console.log(`commonPublicKey-a--- ${aKeyCombine.xShare.y}`)
    console.log(`commonPublicKey-b--- ${bKeyCombine.xShare.y}`)
    console.log(`commonPublicKey-c--- ${cKeyCombine.xShare.y}`)

    // const apublicKey = aKeyCombine.xShare.y
    // const aPublicKeyBuffer = Buffer.from(apublicKey, 'hex');
    // const aEthereumAddress = ethUtil.pubToAddress(aPublicKeyBuffer, true).toString('hex');
    // console.log(`a Ethereum Address: 0x${aEthereumAddress}`);

    // const aKeyDerive = MPC.keyDerive(A.pShare, [B.nShares[1], C.nShares[1]], path)
    // const bKeyDerive = MPC.keyDerive(B.pShare, [A.nShares[2], C.nShares[2]], path)
    // const cKeyDerive = MPC.keyDerive(C.pShare, [A.nShares[3], B.nShares[3]], path)

    // const aaKeyCombine: ECDSA.KeyCombined = {
    //     xShare: aKeyDerive.xShare,
    //     yShares: aKeyCombine.yShares,
    // };

    // const bbKeyCombine: ECDSA.KeyCombined = {
    //     xShare: bKeyDerive.xShare,
    //     yShares: bKeyCombine.yShares,
    // };

    // const ccKeyCombine: ECDSA.KeyCombined = {
    //     xShare: cKeyDerive.xShare,
    //     yShares: cKeyCombine.yShares,
    // };

    // const bitgo = new BitGo({
    //     env: 'test',
    // });
    // const options = {
    //     label: 'ETH TSS Wallet',
    //     m: 2,
    //     n: 3,
    //     // Prerequisite is to create keys before hand
    //     keys: ['62fe654e9095600007e92114e6d89e5a', '62fe654e6b4cf70007b343aec0641a31', '62fe654e9095600007e920f7a22590b9'],
    //     multisigType: 'tss',
    //     walletVersion: 3, // Required for ECDSA assets, such as ETH and MATIC
    // };
    // //@ts-ignore
    // const newWallet = await bitgo.coin('tpolygon').wallets().add(options);
    // console.log(JSON.stringify(newWallet, undefined, 2));

    console.log(`commonPublicKey-aa--- ${aKeyCombine.xShare.y}`)
    console.log(`commonPublicKey-bb--- ${bKeyCombine.xShare.y}`)
    console.log(`commonPublicKey-cc--- ${cKeyCombine.xShare.y}`)

    const aapublicKey = aKeyCombine.xShare.y
    const aaPublicKeyBuffer = Buffer.from(aapublicKey, 'hex');
    const aaEthereumAddress = ethUtil.pubToAddress(aaPublicKeyBuffer, true).toString('hex');
    console.log(`aa Ethereum Address: 0x${aaEthereumAddress}`);


    const provider = new ethers.providers.JsonRpcProvider('https://gateway.tenderly.co/public/polygon-mumbai');
    const nonce = 1;
    const maxFeePerGas = ethers.utils.parseUnits('10', 'gwei');
    const gasPriority = ethers.utils.parseUnits('5', 'gwei');
    const toAddress = '0xC3bB09532A3a92376280bCD3bD153f7FA712E6AC'
    const txParams = {
        type: 2,
        nonce: nonce,
        to: toAddress,
        maxPriorityFeePerGas: gasPriority,
        maxFeePerGas: maxFeePerGas.add(gasPriority),
        value: 0,
        gasLimit: '21000',
        data: "0x"
    };

    const txParams1 = {
        to: toAddress,
        nonce: nonce,
        value: 0,
        gasLimit: 21000,
        eip1559: {
            maxPriorityFeePerGas: 5,
            maxFeePerGas: 10
        },
        data: Buffer.from('0x'),
        type: 2
    };

    let tx = Polygon.buildTransaction(txParams1);
    const signableHex = tx.getMessageToSign(true).toString('hex');

    console.log(`signableHex--- ${signableHex}`)

    // const serialize = utils.serializeTransaction(txParams);
    // const signableHex = utils.keccak256(serialize);

    console.log(`unsignedHash--- ${signableHex}`)

    const signature = await bitgoSign(aKeyCombine, bKeyCombine, signableHex, txParams1)
    // const ethCommmon = Eth.getEthCommon(params.eip1559, params.replayProtectionOptions);
    // tx = this.getSignedTxFromSignature(ethCommmon, tx, signature);
    try {
        const status = await provider.sendTransaction(signature);
        console.log(`status--- ${status}`)
    } catch (e) {
        console.log(`broadcast error--- ${JSON.stringify(e)}`)
    }
}

async function bitgoSign(aKeyCombine: ECDSA.KeyCombined, bKeyCombine: ECDSA.KeyCombined, signValue: any, unsignedTransaction: any) {

    console.log(`signValue--- ${signValue}`)

    console.log(`time--- ${Date.parse(new Date().toString()) / 1000}`)
    const [ntilde1, ntilde2] = await Promise.all([
        EcdsaRangeProof.generateNtilde(256),
        EcdsaRangeProof.generateNtilde(256),
    ]);

    console.log(`time0--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step One
    // signerOne, signerTwo have decided to sign the message
    const signerOne = aKeyCombine;
    const signerOneIndex = signerOne.xShare.i;
    const signerTwo = bKeyCombine;
    const signerTwoIndex = signerTwo.xShare.i;
    const [signerOneToTwoPaillierChallenge, signerTwoToOnePaillierChallenge] = await Promise.all([
        EcdsaPaillierProof.generateP(hexToBigInt(signerOne.yShares[signerTwoIndex].n)),
        EcdsaPaillierProof.generateP(hexToBigInt(signerTwo.yShares[signerOneIndex].n)),
    ]);

    console.log(`time1--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Two
    // First signer generates their range proof challenge.
    const signerOneXShare: ECDSA.XShareWithChallenges = MPC.appendChallenge(
        signerOne.xShare,
        EcdsaTypes.serializeNtildeWithProofs(ntilde1),
        EcdsaTypes.serializePaillierChallenge({ p: signerOneToTwoPaillierChallenge }),
    );

    console.log(`time2--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Three
    //  Second signer generates their range proof challenge.
    const signerTwoXShare: ECDSA.XShareWithChallenges = MPC.appendChallenge(
        signerTwo.xShare,
        EcdsaTypes.serializeNtildeWithProofs(ntilde2),
        EcdsaTypes.serializePaillierChallenge({ p: signerTwoToOnePaillierChallenge }),
    );
    const signerTwoChallenge = { ntilde: signerTwoXShare.ntilde, h1: signerTwoXShare.h1, h2: signerTwoXShare.h2 };

    console.log(`time3--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Four
    // First signer receives the challenge from the second signer and appends it to their YShare
    const signerTwoYShare: ECDSA.YShareWithChallenges = MPC.appendChallenge(
        signerOne.yShares[signerTwoIndex],
        signerTwoChallenge,
        EcdsaTypes.serializePaillierChallenge({ p: signerTwoToOnePaillierChallenge }),
    );

    console.log(`time4--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Five
    // Sign Shares are created by one of the participants (signerOne)
    // with its private XShare and YShare corresponding to the other participant (signerTwo)
    // This step produces a private WShare which signerOne saves and KShare which signerOne sends to signerTwo
    const signShares = await MPC.signShare(signerOneXShare, signerTwoYShare);

    console.log(`time5--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Six
    // signerTwo receives the KShare from signerOne and uses it produce private
    // BShare (Beta Share) which signerTwo saves and AShare (Alpha Share)
    // which is sent to signerOne

    const signConvertS21 = await MPC.signConvertStep1({
        xShare: signerTwoXShare,
        yShare: signerTwo.yShares[signerOneIndex], // YShare corresponding to the other participant signerOne
        kShare: signShares.kShare,
    });

    console.log(`time6--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Seven
    // signerOne receives the AShare from signerTwo and signerOne using the private WShare from step two
    // uses it produce private GShare (Gamma Share) and MUShare (Mu Share) which
    // is sent to signerTwo to produce its Gamma Share
    const signConvertS12 = await MPC.signConvertStep2({
        aShare: signConvertS21.aShare,
        wShare: signShares.wShare,
    });

    console.log(`time7--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Eight
    // signerTwo receives the MUShare from signerOne and signerOne using the private BShare from step three
    // uses it produce private GShare (Gamma Share)
    const signConvertS21_2 = await MPC.signConvertStep3({
        muShare: signConvertS12.muShare,
        bShare: signConvertS21.bShare,
    });

    console.log(`time8--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Nine
    // signerOne and signerTwo both have successfully generated GShares and they use
    // the sign combine function to generate their private omicron shares and
    // delta shares which they share to each other

    const [signCombineOne, signCombineTwo] = [
        MPC.signCombine({
            gShare: signConvertS12.gShare,
            signIndex: {
                i: signConvertS12.muShare.i,
                j: signConvertS12.muShare.j,
            },
        }),
        MPC.signCombine({
            gShare: signConvertS21_2.gShare,
            signIndex: {
                i: signConvertS21_2.signIndex.i,
                j: signConvertS21_2.signIndex.j,
            },
        }),
    ];

    const MESSAGE = Buffer.from(signValue, 'hex');

    console.log(`time9--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Ten
    // signerOne and signerTwo shares the delta share from each other
    // and finally signs the message using their private OShare
    // and delta share received from the other signer

    const [signA, signB] = [
        MPC.sign(MESSAGE, signCombineOne.oShare, signCombineTwo.dShare, createKeccakHash('keccak256') as Hash),
        MPC.sign(MESSAGE, signCombineTwo.oShare, signCombineOne.dShare, createKeccakHash('keccak256') as Hash),
    ];

    console.log(`time10--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Eleven
    // Construct the final signature

    const signature = MPC.constructSignature([signA, signB]);
    const finalSigantureBitgoResponse =
        '0x' + signature.r + signature.s + signature.y;
    const signatureShareThreeFromBitgo: SignatureShareRecord = {
        from: SignatureShareType.BITGO,
        to: SignatureShareType.USER,
        share: finalSigantureBitgoResponse,
    };

    // const ethCommmon = PolygonToken.getEthLikeCommon(params.eip1559, params.replayProtectionOptions);
    // tx = Eth.getSignedTxFromSignature(ethCommmon, tx, signature);

    console.log(`signature--- ${JSON.stringify(signature)}`)

    const isValid = MPC.verify(MESSAGE, signature, createKeccakHash('keccak256') as Hash, true);
    console.log(`isValid--- ${isValid}`)


    const chainId = 80001;
    const v = chainId * 2 + 35 + signature.recid;
    const signature11 = {
        r: signature.r,
        s: signature.s,
        v: v, // recid 通常对应于 v 值，但这可能需要根据实际情况调整
    };
    // const combinedSignature = Buffer.from(signature.r + signature.s, 'hex')
    // const vHex = v.toString(16).padStart(2, '0');
    // const combinedSignature = `0x${signature.r.padStart(64, '0')}${signature.s.padStart(64, '0')}${vHex}`;



    // console.log(`Ethereum Signature3: ${combinedSignature}`);

    // const rawTransaction = ethers.utils.serializeTransaction(unsignedTransaction, signature11);

    // console.log(`length--- ${combinedSignature.length}`)

    // const sig = 'b3d5b45dec592d6ca60455f2926e06e5ff1c81cc4115d44d4b4f9953e6260aee55bc80e341977ab77713c80b31d960be01e09bb19014db49484db45859c77fda00';
    // console.log(`sig length--- ${sig.length}`)

    // const r = combinedSignature.substring(0, 64);
    // const s = combinedSignature.substring(64, 128);
    // const v = combinedSignature.substring(128);
    // const signature1 = {
    //     r: '0x' + r,
    //     s: '0x' + s,
    //     recoveryParam: parseInt(v, 16),
    // };
    // const signature2 = splitSignature(signature1);
    // const signedTransaction = utils.serializeTransaction(unsignedTransaction, signature2);

    // console.log(`signature--- ${JSON.stringify(signedTransaction)}`)

    console.log(`time11--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Twelve
    // Verify signature

    // const isValid = MPC.verify(MESSAGE, signature, undefined, true);
    // console.log(`isValid--- ${isValid}`)

    return finalSigantureBitgoResponse
}

bitgoCreate()