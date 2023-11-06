import { Ecdsa, ECDSA, hexToBigInt, TssUtils } from '@bitgo/sdk-core';
import { EcdsaPaillierProof, EcdsaRangeProof, EcdsaTypes } from '@bitgo/sdk-lib-mpc';

const MPC = new Ecdsa();

async function bitgoCreate() {

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

    // await bitgoResharing(A, B)

    await bitgoSign(aKeyCombine, bKeyCombine, 'aa')


    const dKeyCombine = MPC.keyCombine(C.pShare, [A.nShares[3], B.nShares[3]]);
    console.log(`commonPublicKey-d--- ${dKeyCombine.xShare.y}`)
}

async function bitgoResharing(aKeyCombine: ECDSA.KeyCombined, bKeyCombine: ECDSA.KeyCombined) {

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

    console.log(`time11--- ${Date.parse(new Date().toString()) / 1000}`)

    // Step Twelve
    // Verify signature

    const isValid = MPC.verify(MESSAGE, signature, undefined, true);
    console.log(`isValid--- ${isValid}`)
}

bitgoCreate()