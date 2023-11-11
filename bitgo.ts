import { Ecdsa, ECDSA, hexToBigInt, TssUtils } from '@bitgo/sdk-core';
import { EcdsaPaillierProof, EcdsaRangeProof, EcdsaTypes } from '@bitgo/sdk-lib-mpc';
import * as ethUtil from 'ethereumjs-util';

const MPC = new Ecdsa();

async function bitgoCreate() {

    const seed = Buffer.from(
        '2b73353a2bdecf9bb4a5305d6cfb231d7f5528c5e45de815d17fd0a091fa7f84778e3f9890ad2a5d03af50b9a69574640afe7be3039d35a7e5824b2d1b59b0c3',
        'hex',
    );
    const address = '0xc11DDc828Ad53195B2E1ec630Ab2D67b56FFC44f'
    const path = "m/44'/60'/0'/0/0"

    const A = await MPC.keyShare(1, 2, 3, seed);
    const B = await MPC.keyShare(2, 2, 3, seed);
    const C = await MPC.keyShare(3, 2, 3, seed);

    console.log(JSON.stringify(A, undefined, 1));
    console.log(JSON.stringify(B, undefined, 2));
    console.log(JSON.stringify(C, undefined, 3));

    const aKeyCombine = MPC.keyCombine(A.pShare, [B.nShares[1], C.nShares[1]]);
    const bKeyCombine = MPC.keyCombine(B.pShare, [A.nShares[2], C.nShares[2]]);
    const cKeyCombine = MPC.keyCombine(C.pShare, [A.nShares[3], B.nShares[3]]);

    console.log(`commonPublicKey-a--- ${aKeyCombine.xShare.y}`)
    console.log(`commonPublicKey-b--- ${bKeyCombine.xShare.y}`)
    console.log(`commonPublicKey-c--- ${cKeyCombine.xShare.y}`)

    const apublicKey = aKeyCombine.xShare.y
    const aPublicKeyBuffer = Buffer.from(apublicKey, 'hex');
    const aEthereumAddress = ethUtil.pubToAddress(aPublicKeyBuffer, true).toString('hex');
    console.log(`a Ethereum Address: 0x${aEthereumAddress}`);

    const aKeyDerive = MPC.keyDerive(A.pShare, [B.nShares[1], C.nShares[1]], path)
    const bKeyDerive = MPC.keyDerive(B.pShare, [A.nShares[2], C.nShares[2]], path)
    const cKeyDerive = MPC.keyDerive(C.pShare, [A.nShares[3], B.nShares[3]], path)

    const aaKeyCombine: ECDSA.KeyCombined = {
        xShare: aKeyDerive.xShare,
        yShares: aKeyCombine.yShares,
    };

    const bbKeyCombine: ECDSA.KeyCombined = {
        xShare: bKeyDerive.xShare,
        yShares: bKeyCombine.yShares,
    };

    const ccKeyCombine: ECDSA.KeyCombined = {
        xShare: cKeyDerive.xShare,
        yShares: cKeyCombine.yShares,
    };

    console.log(`commonPublicKey-aa--- ${aaKeyCombine.xShare.y}`)
    console.log(`commonPublicKey-bb--- ${bbKeyCombine.xShare.y}`)
    console.log(`commonPublicKey-cc--- ${ccKeyCombine.xShare.y}`)

    const aapublicKey = aaKeyCombine.xShare.y
    const aaPublicKeyBuffer = Buffer.from(aapublicKey, 'hex');
    const aaEthereumAddress = ethUtil.pubToAddress(aaPublicKeyBuffer, true).toString('hex');
    console.log(`aa Ethereum Address: 0x${aaEthereumAddress}`);

    // await bitgoSign(aKeyCombine, bKeyCombine, 'aa')
}

async function bitgoSign(aKeyCombine: ECDSA.KeyCombined, bKeyCombine: ECDSA.KeyCombined, signValue: string) {

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

    const MESSAGE = Buffer.from(signValue);

    console.log(`time9--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Ten
    // signerOne and signerTwo shares the delta share from each other
    // and finally signs the message using their private OShare
    // and delta share received from the other signer

    const [signA, signB] = [
        MPC.sign(
            MESSAGE,
            signCombineOne.oShare,
            signCombineTwo.dShare,
            undefined,
            true,
        ),
        MPC.sign(
            MESSAGE,
            signCombineTwo.oShare,
            signCombineOne.dShare,
            undefined,
            true,
        ),
    ];

    console.log(`time10--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Eleven
    // Construct the final signature

    const signature = MPC.constructSignature([signA, signB]);

    console.log(`signature--- ${JSON.stringify(signature)}`)

    const mumbaiChainId = 80001;
    const v = 35 + signature.recid + (mumbaiChainId * 2);

    // 组合 r, s, 和 v
    const combinedSignature = `0x${signature.r}${signature.s}${v.toString(16)}`;

    console.log(`Ethereum Signature: ${combinedSignature}`);

    console.log(`time11--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Twelve
    // Verify signature

    const isValid = MPC.verify(MESSAGE, signature, undefined, true);
    console.log(`isValid--- ${isValid}`)
}

bitgoCreate()