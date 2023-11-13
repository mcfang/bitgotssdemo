"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContractKit = exports.MiniContractKit = exports.newKitFromWeb3 = exports.newKitWithApiKey = exports.newKit = void 0;
var connect_1 = require("@celo/connect");
var wallet_local_1 = require("@celo/wallet-local");
var address_registry_1 = require("./address-registry");
var celo_tokens_1 = require("./celo-tokens");
var mini_contract_cache_1 = require("./mini-contract-cache");
var setupForKits_1 = require("./setupForKits");
/**
 * Creates a new instance of `MiniMiniContractKit` given a nodeUrl
 * @param url CeloBlockchain node url
 * @optional wallet to reuse or add a wallet different than the default (example ledger-wallet)
 * @optional options to pass to the Web3 HttpProvider constructor
 */
function newKit(url, wallet, options) {
    var web3 = (0, setupForKits_1.getWeb3ForKit)(url, options);
    return newKitFromWeb3(web3, wallet);
}
exports.newKit = newKit;
/**
 * Creates a new instance of `MiniContractKit` given a nodeUrl and apiKey
 * @param url CeloBlockchain node url
 * @param apiKey to include in the http request header
 * @optional wallet to reuse or add a wallet different than the default (example ledger-wallet)
 */
function newKitWithApiKey(url, apiKey, wallet) {
    var options = (0, setupForKits_1.setupAPIKey)(apiKey);
    return newKit(url, wallet, options);
}
exports.newKitWithApiKey = newKitWithApiKey;
/**
 * Creates a new instance of the `MiniContractKit` with a web3 instance
 * @param web3 Web3 instance
 */
function newKitFromWeb3(web3, wallet) {
    if (wallet === void 0) { wallet = new wallet_local_1.LocalWallet(); }
    (0, setupForKits_1.ensureCurrentProvider)(web3);
    return new MiniContractKit(new connect_1.Connection(web3, wallet));
}
exports.newKitFromWeb3 = newKitFromWeb3;
/**
 * MiniContractKit provides a core subset of {@link ContractKit}'s functionality
 *
 * @remarks
 *
 * It is recommended to use this over ContractKit for dApps as it is lighter
 *
 * @param connection – an instance of @celo/connect {@link Connection}
 */
var MiniContractKit = /** @class */ (function () {
    function MiniContractKit(connection) {
        this.connection = connection;
        this.registry = new address_registry_1.AddressRegistry(connection);
        this.contracts = new mini_contract_cache_1.MiniContractCache(connection, this.registry);
        this.celoTokens = new celo_tokens_1.CeloTokens(this.contracts, this.registry);
    }
    MiniContractKit.prototype.getWallet = function () {
        return this.connection.wallet;
    };
    // Like get Total Balance on MiniContractKit but does not include locked celo or pending
    MiniContractKit.prototype.getTotalBalance = function (address) {
        return __awaiter(this, void 0, void 0, function () {
            var _a;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        _a = [{}];
                        return [4 /*yield*/, this.celoTokens.balancesOf(address)];
                    case 1: return [2 /*return*/, __assign.apply(void 0, _a.concat([(_b.sent())]))];
                }
            });
        });
    };
    return MiniContractKit;
}());
exports.MiniContractKit = MiniContractKit;
// For easy switching from full contractKit to Mini
exports.ContractKit = MiniContractKit;
//# sourceMappingURL=mini-kit.js.map