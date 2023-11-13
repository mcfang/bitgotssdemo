import { StableToken } from '@celo/base';
import { Connection } from '@celo/connect';
import { AddressRegistry } from './address-registry';
import { ContractCacheType } from './basic-contract-cache-type';
import { newAccounts } from './generated/Accounts';
import { newExchange } from './generated/Exchange';
import { newExchangeBrl } from './generated/ExchangeBRL';
import { newExchangeEur } from './generated/ExchangeEUR';
import { newGasPriceMinimum } from './generated/GasPriceMinimum';
import { newGoldToken } from './generated/GoldToken';
import { newStableToken } from './generated/StableToken';
import { newStableTokenBrl } from './generated/StableTokenBRL';
import { newStableTokenEur } from './generated/StableTokenEUR';
import { AccountsWrapper } from './wrappers/Accounts';
import { ExchangeWrapper } from './wrappers/Exchange';
import { GasPriceMinimumWrapper } from './wrappers/GasPriceMinimum';
import { GoldTokenWrapper } from './wrappers/GoldTokenWrapper';
import { StableTokenWrapper } from './wrappers/StableTokenWrapper';
declare const MINIMUM_CONTRACTS: {
    Accounts: {
        newInstance: typeof newAccounts;
        wrapper: typeof AccountsWrapper;
    };
    GasPriceMinimum: {
        newInstance: typeof newGasPriceMinimum;
        wrapper: typeof GasPriceMinimumWrapper;
    };
    GoldToken: {
        newInstance: typeof newGoldToken;
        wrapper: typeof GoldTokenWrapper;
    };
    Exchange: {
        newInstance: typeof newExchange;
        wrapper: typeof ExchangeWrapper;
    };
    ExchangeEUR: {
        newInstance: typeof newExchangeEur;
        wrapper: typeof ExchangeWrapper;
    };
    ExchangeBRL: {
        newInstance: typeof newExchangeBrl;
        wrapper: typeof ExchangeWrapper;
    };
    StableToken: {
        newInstance: typeof newStableToken;
        wrapper: typeof StableTokenWrapper;
    };
    StableTokenBRL: {
        newInstance: typeof newStableTokenBrl;
        wrapper: typeof StableTokenWrapper;
    };
    StableTokenEUR: {
        newInstance: typeof newStableTokenEur;
        wrapper: typeof StableTokenWrapper;
    };
};
export declare type ContractsBroughtBase = typeof MINIMUM_CONTRACTS;
declare type Keys = keyof ContractsBroughtBase;
declare type Wrappers<T extends Keys> = InstanceType<ContractsBroughtBase[T]['wrapper']>;
/**
 * Alternative Contract Cache with Minimal Contracts
 *
 * Provides access to a subset of wrappers: {@link AccountsWrapper},  {@link ExchangeWrapper}, {@link GasPriceMinimumWrapper} and Celo Token contracts
 * Used internally by {@link MiniContractKit}
 *
 * @param connection – {@link Connection}
 * @param registry – {@link AddressRegistry}
 */
export declare class MiniContractCache implements ContractCacheType {
    readonly connection: Connection;
    readonly registry: AddressRegistry;
    private readonly contractClasses;
    private cache;
    constructor(connection: Connection, registry: AddressRegistry, contractClasses?: ContractsBroughtBase);
    getAccounts(): Promise<AccountsWrapper>;
    getExchange(stableToken?: StableToken): Promise<ExchangeWrapper>;
    getGoldToken(): Promise<GoldTokenWrapper>;
    getStableToken(stableToken?: StableToken): Promise<StableTokenWrapper>;
    /**
     * Get Contract wrapper
     */
    getContract<ContractKey extends keyof ContractsBroughtBase>(contract: ContractKey, address?: string): Promise<Wrappers<ContractKey>>;
    private setContract;
    invalidateContract<C extends keyof ContractsBroughtBase>(contract: C): void;
    private isContractAvailable;
}
export {};
