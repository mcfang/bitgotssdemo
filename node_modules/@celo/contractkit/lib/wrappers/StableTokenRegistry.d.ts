import { StableTokenRegistry } from '../generated/StableTokenRegistry';
import { BaseWrapper } from './BaseWrapper';
export declare class StableTokenRegistryWrapper extends BaseWrapper<StableTokenRegistry> {
    fiatTickers: (arg0: string | number) => Promise<string>;
    stableTokens: (arg0: string | number[]) => Promise<string>;
    /**
     * Returns a stringified array of stable token contracts
     * @return string array containing contract names
     */
    getContractInstances(): Promise<string[]>;
    getFiatTickers(): Promise<string[]>;
    /**
     * Queries the mapping using a fiatTicker
     * @return queried stableTokenContractName
     */
    queryStableTokenContractNames(fiatTicker: string): Promise<string>;
}
