"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.StableTokenRegistryWrapper = void 0;
var web3_1 = __importDefault(require("web3"));
var BaseWrapper_1 = require("./BaseWrapper");
/**
 * Splits a string with concatenated contract names into each individual name.
 * @param contractHex concatenated contract names
 * @param lengths their lengths
 * @return string array containing contract names
 */
var splitContractNamesByLength = function (contractsHex, lengths) {
    var contracts = web3_1.default.utils.hexToUtf8(contractsHex);
    var currentIndex = 0;
    var contractsArr = [];
    for (var _i = 0, lengths_1 = lengths; _i < lengths_1.length; _i++) {
        var length_1 = lengths_1[_i];
        var contract = contracts.slice(currentIndex, currentIndex + Number(length_1));
        currentIndex += Number(length_1);
        contractsArr.push(contract);
    }
    return contractsArr;
};
var StableTokenRegistryWrapper = /** @class */ (function (_super) {
    __extends(StableTokenRegistryWrapper, _super);
    function StableTokenRegistryWrapper() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.fiatTickers = (0, BaseWrapper_1.proxyCall)(_this.contract.methods.fiatTickers);
        _this.stableTokens = (0, BaseWrapper_1.proxyCall)(_this.contract.methods.stableTokens);
        return _this;
    }
    /**
     * Returns a stringified array of stable token contracts
     * @return string array containing contract names
     */
    StableTokenRegistryWrapper.prototype.getContractInstances = function () {
        return __awaiter(this, void 0, void 0, function () {
            var values, concatenatedContracts, contractLengths;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.contract.methods.getContractInstances().call()];
                    case 1:
                        values = _a.sent();
                        concatenatedContracts = values[0];
                        contractLengths = values[1];
                        return [2 /*return*/, splitContractNamesByLength(concatenatedContracts, contractLengths)];
                }
            });
        });
    };
    StableTokenRegistryWrapper.prototype.getFiatTickers = function () {
        return __awaiter(this, void 0, void 0, function () {
            var convertedToHex, index, fiatTicker, error_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        convertedToHex = [];
                        index = 0;
                        _a.label = 1;
                    case 1:
                        if (!true) return [3 /*break*/, 6];
                        fiatTicker = void 0;
                        _a.label = 2;
                    case 2:
                        _a.trys.push([2, 4, , 5]);
                        return [4 /*yield*/, this.fiatTickers(index)];
                    case 3:
                        fiatTicker = _a.sent();
                        return [3 /*break*/, 5];
                    case 4:
                        error_1 = _a.sent();
                        return [2 /*return*/, convertedToHex];
                    case 5:
                        convertedToHex.push(web3_1.default.utils.hexToUtf8(fiatTicker));
                        index++;
                        return [3 /*break*/, 1];
                    case 6: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Queries the mapping using a fiatTicker
     * @return queried stableTokenContractName
     */
    StableTokenRegistryWrapper.prototype.queryStableTokenContractNames = function (fiatTicker) {
        return __awaiter(this, void 0, void 0, function () {
            var res;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.stableTokens(web3_1.default.utils.utf8ToHex(fiatTicker))];
                    case 1:
                        res = _a.sent();
                        return [2 /*return*/, web3_1.default.utils.hexToUtf8(res)];
                }
            });
        });
    };
    return StableTokenRegistryWrapper;
}(BaseWrapper_1.BaseWrapper));
exports.StableTokenRegistryWrapper = StableTokenRegistryWrapper;
//# sourceMappingURL=StableTokenRegistry.js.map