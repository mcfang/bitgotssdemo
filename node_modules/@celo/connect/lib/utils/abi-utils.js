"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeStringParameter = exports.signatureToAbiDefinition = exports.parseDecodedParams = exports.getAbiByName = void 0;
var address_1 = require("@celo/base/lib/address");
/** @internal */
var getAbiByName = function (abi, methodName) {
    return abi.find(function (entry) { return entry.name === methodName; });
};
exports.getAbiByName = getAbiByName;
/** @internal */
var parseDecodedParams = function (params) {
    var args = new Array(params.__length__);
    Object.keys(params).forEach(function (key) {
        if (key === '__length__') {
            return;
        }
        var argIndex = parseInt(key, 10);
        if (argIndex >= 0) {
            args[argIndex] = params[key];
            delete params[key];
        }
    });
    return { args: args, params: params };
};
exports.parseDecodedParams = parseDecodedParams;
/** @internal */
var signatureToAbiDefinition = function (fnSignature) {
    var matches = /(?<method>[^\(]+)\((?<args>.*)\)/.exec(fnSignature);
    if (matches == null) {
        throw new Error("".concat(fnSignature, " is malformed"));
    }
    var method = matches.groups.method;
    var args = matches.groups.args.split(',');
    return {
        name: method,
        signature: fnSignature,
        type: 'function',
        inputs: args.map(function (type, index) {
            var parts = type
                .trim()
                .split(' ')
                .map(function (p) { return p.trim(); });
            if (parts.length > 2) {
                throw new Error("".concat(fnSignature, " is malformed"));
            }
            return {
                name: parts.length > 1 ? parts[1] : "a".concat(index),
                type: parts[0],
            };
        }),
    };
};
exports.signatureToAbiDefinition = signatureToAbiDefinition;
/** @internal */
var decodeStringParameter = function (ethAbi, str) {
    return ethAbi.decodeParameter('string', (0, address_1.ensureLeading0x)(str));
};
exports.decodeStringParameter = decodeStringParameter;
//# sourceMappingURL=abi-utils.js.map