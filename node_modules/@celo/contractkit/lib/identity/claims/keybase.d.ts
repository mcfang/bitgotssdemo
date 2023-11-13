import { Address } from '@celo/base/lib/address';
import { ContractKit } from '../../kit';
import { KeybaseClaim } from './claim';
export declare const keybaseFilePathToProof = ".well-known/celo/";
export declare const proofFileName: (address: Address) => string;
export declare const targetURL: (username: string, address: Address) => string;
/**
 *
 * @remarks
 * If verification encounters an error, returns the error message as a string
 * otherwise returns undefined when successful
 *
 * @param kit
 * @param claim
 * @param signer
 * @returns a human readable string with claims (non)verifiability or undefined
 */
export declare function verifyKeybaseClaim(kit: ContractKit, claim: KeybaseClaim, signer: Address): Promise<string | undefined>;
export declare const createKeybaseClaim: (username: string) => KeybaseClaim;
