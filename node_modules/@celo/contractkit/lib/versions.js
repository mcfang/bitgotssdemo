"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.newContractVersion = exports.ContractVersion = void 0;
var semverGte = require('semver/functions/gte');
/** @internal */
var ContractVersion = /** @class */ (function () {
    function ContractVersion(storage, major, minor, patch) {
        var _this = this;
        this.storage = storage;
        this.major = major;
        this.minor = minor;
        this.patch = patch;
        this.toSemver = function () { return "".concat(_this.storage, ".").concat(_this.major, ".").concat(_this.minor); };
        this.isAtLeast = function (other) { return semverGte(_this.toSemver(), other.toSemver()); };
        this.toString = function () { return _this.toSemver().concat(".".concat(_this.patch)); };
        this.toRaw = function () { return [_this.storage, _this.major, _this.minor, _this.patch]; };
    }
    ContractVersion.fromRaw = function (raw) {
        return new ContractVersion(raw[0], raw[1], raw[2], raw[3]);
    };
    return ContractVersion;
}());
exports.ContractVersion = ContractVersion;
/** @internal */
var newContractVersion = function (storage, major, minor, patch) {
    return new ContractVersion(storage, major, minor, patch);
};
exports.newContractVersion = newContractVersion;
//# sourceMappingURL=versions.js.map