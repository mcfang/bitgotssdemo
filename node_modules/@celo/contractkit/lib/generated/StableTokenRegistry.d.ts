/// <reference types="node" />
import { AbiItem, Callback, CeloTxObject, Contract, EventLog } from '@celo/connect';
import { EventEmitter } from 'events';
import Web3 from 'web3';
import { ContractEvent, EventOptions } from './types';
export interface StableTokenRegistry extends Contract {
    clone(): StableTokenRegistry;
    methods: {
        fiatTickers(arg0: number | string): CeloTxObject<string>;
        initialized(): CeloTxObject<boolean>;
        isOwner(): CeloTxObject<boolean>;
        owner(): CeloTxObject<string>;
        renounceOwnership(): CeloTxObject<void>;
        stableTokens(arg0: string | number[]): CeloTxObject<string>;
        transferOwnership(newOwner: string): CeloTxObject<void>;
        getVersionNumber(): CeloTxObject<{
            0: string;
            1: string;
            2: string;
            3: string;
        }>;
        initialize(fiatTicker: string | number[], stableTokenContractName: string | number[]): CeloTxObject<void>;
        getContractInstances(): CeloTxObject<{
            0: string;
            1: string[];
        }>;
        removeStableToken(fiatTicker: string | number[], index: number | string): CeloTxObject<void>;
        addNewStableToken(fiatTicker: string | number[], stableTokenContractName: string | number[]): CeloTxObject<void>;
        queryStableTokenContractNames(fiatTicker: string | number[]): CeloTxObject<string>;
    };
    events: {
        OwnershipTransferred: ContractEvent<{
            previousOwner: string;
            newOwner: string;
            0: string;
            1: string;
        }>;
        allEvents: (options?: EventOptions, cb?: Callback<EventLog>) => EventEmitter;
    };
}
export declare const ABI: AbiItem[];
export declare function newStableTokenRegistry(web3: Web3, address: string): StableTokenRegistry;
