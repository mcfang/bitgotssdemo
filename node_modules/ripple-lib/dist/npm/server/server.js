"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const common = __importStar(require("../common"));
function isConnected() {
    return this.connection.isConnected();
}
exports.isConnected = isConnected;
function getLedgerVersion() {
    return this.connection.getLedgerVersion();
}
exports.getLedgerVersion = getLedgerVersion;
function connect() {
    return this.connection.connect();
}
exports.connect = connect;
function disconnect() {
    return this.connection.disconnect();
}
exports.disconnect = disconnect;
function formatLedgerClose(ledgerClose) {
    return {
        baseFeeXRP: common.dropsToXrp(ledgerClose.fee_base),
        ledgerHash: ledgerClose.ledger_hash,
        ledgerVersion: ledgerClose.ledger_index,
        ledgerTimestamp: common.rippleTimeToISO8601(ledgerClose.ledger_time),
        reserveBaseXRP: common.dropsToXrp(ledgerClose.reserve_base),
        reserveIncrementXRP: common.dropsToXrp(ledgerClose.reserve_inc),
        transactionCount: ledgerClose.txn_count,
        validatedLedgerVersions: ledgerClose.validated_ledgers
    };
}
exports.formatLedgerClose = formatLedgerClose;
//# sourceMappingURL=server.js.map