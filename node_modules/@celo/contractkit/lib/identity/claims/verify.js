"use strict";
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
exports.verifyDomainRecord = exports.verifyAccountClaim = exports.verifyClaim = void 0;
var address_1 = require("@celo/base/lib/address");
var io_1 = require("@celo/base/lib/io");
var dns_1 = require("dns");
var util_1 = require("util");
var metadata_1 = require("../metadata");
var claim_1 = require("./claim");
var keybase_1 = require("./keybase");
var types_1 = require("./types");
/**
 * Verifies a claim made by an account, i.e. whether a claim can be verified to be correct
 * @param kit ContractKit object
 * @param claim The claim to verify
 * @param address The address that is making the claim
 * @returns If valid, returns undefined. If invalid or unable to verify, returns a string with the error
 */
function verifyClaim(kit, claim, address, tries) {
    if (tries === void 0) { tries = 3; }
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (claim.type) {
                case types_1.ClaimTypes.KEYBASE:
                    return [2 /*return*/, (0, keybase_1.verifyKeybaseClaim)(kit, claim, address)];
                case types_1.ClaimTypes.ACCOUNT:
                    return [2 /*return*/, (0, exports.verifyAccountClaim)(kit, claim, address, tries)];
                case types_1.ClaimTypes.DOMAIN:
                    return [2 /*return*/, (0, exports.verifyDomainRecord)(kit, claim, address)];
                default:
                    break;
            }
            return [2 /*return*/];
        });
    });
}
exports.verifyClaim = verifyClaim;
var verifyAccountClaim = function (kit, claim, address, tries) {
    if (tries === void 0) { tries = 3; }
    return __awaiter(void 0, void 0, void 0, function () {
        var metadataURL, metadata, _a, _b, error_1, accountClaims;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0: return [4 /*yield*/, kit.contracts.getAccounts()];
                case 1: return [4 /*yield*/, (_c.sent()).getMetadataURL(claim.address)];
                case 2:
                    metadataURL = _c.sent();
                    if (!(0, io_1.isValidUrl)(metadataURL)) {
                        return [2 /*return*/, "Metadata URL of ".concat(claim.address, " could not be retrieved")];
                    }
                    _c.label = 3;
                case 3:
                    _c.trys.push([3, 6, , 7]);
                    _b = (_a = metadata_1.IdentityMetadataWrapper).fetchFromURL;
                    return [4 /*yield*/, kit.contracts.getAccounts()];
                case 4: return [4 /*yield*/, _b.apply(_a, [_c.sent(), metadataURL,
                        tries])];
                case 5:
                    metadata = _c.sent();
                    return [3 /*break*/, 7];
                case 6:
                    error_1 = _c.sent();
                    return [2 /*return*/, "Metadata could not be fetched for ".concat(claim.address, " at ").concat(metadataURL, ": ").concat(error_1.toString())];
                case 7:
                    accountClaims = metadata.filterClaims(types_1.ClaimTypes.ACCOUNT);
                    if (accountClaims.find(function (x) { return (0, address_1.eqAddress)(x.address, address); }) === undefined) {
                        return [2 /*return*/, "".concat(claim.address, " did not claim ").concat(address)];
                    }
                    return [2 /*return*/];
            }
        });
    });
};
exports.verifyAccountClaim = verifyAccountClaim;
/**
 * It verifies if a DNS domain includes in the TXT records an entry with name
 * `celo-site-verification` and a valid signature in base64
 */
var verifyDomainRecord = function (kit, claim, address, dnsResolver) {
    if (dnsResolver === void 0) { dnsResolver = dns_1.resolveTxt; }
    return __awaiter(void 0, void 0, void 0, function () {
        var getRecords, domainRecords, _i, domainRecords_1, record, _a, record_1, entry, signatureBase64, signature, _b, _c, error_2;
        return __generator(this, function (_d) {
            switch (_d.label) {
                case 0:
                    _d.trys.push([0, 9, , 10]);
                    getRecords = (0, util_1.promisify)(dnsResolver);
                    return [4 /*yield*/, getRecords(claim.domain)];
                case 1:
                    domainRecords = _d.sent();
                    _i = 0, domainRecords_1 = domainRecords;
                    _d.label = 2;
                case 2:
                    if (!(_i < domainRecords_1.length)) return [3 /*break*/, 8];
                    record = domainRecords_1[_i];
                    _a = 0, record_1 = record;
                    _d.label = 3;
                case 3:
                    if (!(_a < record_1.length)) return [3 /*break*/, 7];
                    entry = record_1[_a];
                    if (!entry.startsWith(claim_1.DOMAIN_TXT_HEADER)) return [3 /*break*/, 6];
                    signatureBase64 = entry.substring(claim_1.DOMAIN_TXT_HEADER.length + 1);
                    signature = Buffer.from(signatureBase64, 'base64').toString('binary');
                    _c = (_b = metadata_1.IdentityMetadataWrapper).verifySignerForAddress;
                    return [4 /*yield*/, kit.contracts.getAccounts()];
                case 4: return [4 /*yield*/, _c.apply(_b, [_d.sent(), (0, claim_1.serializeClaim)(claim),
                        signature,
                        address])];
                case 5:
                    if (_d.sent()) {
                        return [2 /*return*/];
                    }
                    _d.label = 6;
                case 6:
                    _a++;
                    return [3 /*break*/, 3];
                case 7:
                    _i++;
                    return [3 /*break*/, 2];
                case 8: return [2 /*return*/, "Unable to verify domain claim with address ".concat(address)];
                case 9:
                    error_2 = _d.sent();
                    return [2 /*return*/, "Unable to fetch domain TXT records: ".concat(error_2.toString())];
                case 10: return [2 /*return*/];
            }
        });
    });
};
exports.verifyDomainRecord = verifyDomainRecord;
//# sourceMappingURL=verify.js.map