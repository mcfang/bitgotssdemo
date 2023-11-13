import { EIP712TypedData } from '@celo/utils/lib/sign-typed-data-utils';
import { Signature } from '@celo/utils/lib/signatureUtils';
import Web3 from 'web3';
import { AbiCoder } from './abi-types';
import { Address, Block, BlockHeader, BlockNumber, CeloTx, CeloTxObject, CeloTxPending, CeloTxReceipt, Provider } from './types';
import { RpcCaller } from './utils/rpc-caller';
import { TxParamsNormalizer } from './utils/tx-params-normalizer';
import { TransactionResult } from './utils/tx-result';
import { ReadOnlyWallet } from './wallet';
declare type BN = ReturnType<Web3['utils']['toBN']>;
export interface ConnectionOptions {
    gasInflationFactor: number;
    gasPrice: string;
    feeCurrency?: Address;
    from?: Address;
}
/**
 * Connection is a Class for connecting to Celo, sending Transactions, etc
 * @param web3 an instance of web3
 * @optional wallet a child class of {@link WalletBase}
 * @optional handleRevert sets handleRevert on the web3.eth instance passed in
 */
export declare class Connection {
    readonly web3: Web3;
    wallet?: ReadOnlyWallet | undefined;
    private config;
    readonly paramsPopulator: TxParamsNormalizer;
    rpcCaller: RpcCaller;
    /** @deprecated no longer needed since gasPrice is available on minimumClientVersion node rpc */
    private currencyGasPrice;
    constructor(web3: Web3, wallet?: ReadOnlyWallet | undefined, handleRevert?: boolean);
    setProvider(provider: Provider): boolean;
    keccak256: (value: string | BN) => string;
    hexToAscii: (hex: string) => string;
    /**
     * Set default account for generated transactions (eg. tx.from )
     */
    set defaultAccount(address: Address | undefined);
    /**
     * Default account for generated transactions (eg. tx.from)
     */
    get defaultAccount(): Address | undefined;
    set defaultGasInflationFactor(factor: number);
    get defaultGasInflationFactor(): number;
    set defaultGasPrice(price: number);
    get defaultGasPrice(): number;
    /**
     * Set the ERC20 address for the token to use to pay for transaction fees.
     * The ERC20 must be whitelisted for gas.
     *
     * Set to `null` to use CELO
     *
     * @param address ERC20 address
     */
    set defaultFeeCurrency(address: Address | undefined);
    get defaultFeeCurrency(): Address | undefined;
    isLocalAccount(address?: Address): boolean;
    addAccount(privateKey: string): void;
    removeAccount(address: string): void;
    getNodeAccounts(): Promise<string[]>;
    getLocalAccounts(): string[];
    getAccounts(): Promise<string[]>;
    private toChecksumAddresses;
    isListening(): Promise<boolean>;
    isSyncing(): Promise<boolean>;
    /**
     * Send a transaction to celo-blockchain.
     *
     * Similar to `web3.eth.sendTransaction()` but with following differences:
     *  - applies connections tx's defaults
     *  - estimatesGas before sending
     *  - returns a `TransactionResult` instead of `PromiEvent`
     */
    sendTransaction: (tx: CeloTx) => Promise<TransactionResult>;
    sendTransactionObject: (txObj: CeloTxObject<any>, tx?: Omit<CeloTx, 'data'>) => Promise<TransactionResult>;
    signTypedData: (signer: string, typedData: EIP712TypedData, version?: 1 | 3 | 4 | 5) => Promise<Signature>;
    sign: (dataToSign: string, address: Address | number) => Promise<string>;
    sendSignedTransaction: (signedTransactionData: string) => Promise<TransactionResult>;
    /** @deprecated no longer needed since gasPrice is available on minimumClientVersion node rpc */
    fillGasPrice(tx: CeloTx): CeloTx;
    /** @deprecated no longer needed since gasPrice is available on minimumClientVersion node rpc */
    setGasPriceForCurrency(address: Address, gasPrice: string): Promise<void>;
    estimateGas: (tx: CeloTx, gasEstimator?: (tx: CeloTx) => Promise<number>, caller?: (tx: CeloTx) => Promise<string>) => Promise<number>;
    getAbiCoder(): AbiCoder;
    estimateGasWithInflationFactor: (tx: CeloTx, gasEstimator?: ((tx: CeloTx) => Promise<number>) | undefined, caller?: ((tx: CeloTx) => Promise<string>) | undefined) => Promise<number>;
    chainId: () => Promise<number>;
    getTransactionCount: (address: Address) => Promise<number>;
    nonce: (address: Address) => Promise<number>;
    coinbase: () => Promise<string>;
    gasPrice: (feeCurrency?: Address) => Promise<string>;
    getBlockNumber: () => Promise<number>;
    private isBlockNumberHash;
    getBlock: (blockHashOrBlockNumber: BlockNumber, fullTxObjects?: boolean) => Promise<Block>;
    getBlockHeader: (blockHashOrBlockNumber: BlockNumber) => Promise<BlockHeader>;
    getBalance: (address: Address, defaultBlock?: BlockNumber) => Promise<string>;
    getTransaction: (transactionHash: string) => Promise<CeloTxPending>;
    getTransactionReceipt: (txhash: string) => Promise<CeloTxReceipt | null>;
    private fillTxDefaults;
    stop(): void;
}
export {};
