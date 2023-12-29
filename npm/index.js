// Copyright OracularHades (Josh J)

import { isNullOrWhiteSpace, isNumber } from "./globals.js";
import sign from "./sign.js";
import verify from "./verify.js";

let whoami = null;
let acceptable_registries = null;
let expiry_tolerance = null;
let replay_attack_mitigation = null;

function getCreds() {
    return {
        whoami: whoami,
        acceptable_registries: acceptable_registries,
        expiry_tolerance: expiry_tolerance,
        replay_attack_mitigation: replay_attack_mitigation
    };
}

function Regions(credsObject) {
    // { whoami: { id: "", service: "api", privatekey: "", publickey: "", registry: "dns://example.com" }, acceptable_registries: [ { url: "dns://example.com", cache: 120, publickey: "" } ], replay_attack_mitigation: null, expiry_tolerance: 30000 }
    if (credsObject) {
        if (!credsObject.whoami) {
            throw "credsObject.whoami is null.";
        }
        if (!credsObject.acceptable_registries || Array.isArray(credsObject.acceptable_registries) != true || credsObject.acceptable_registries.length == 0) {
            throw "credsObject.acceptable_registries is null, is not an array or has no items.";
        }

        for (var i = 0; i < credsObject.acceptable_registries.length; i++) {
            const element = credsObject.acceptable_registries[i];
            if (!element.url) {
                throw `acceptable_registries[${i}].url is null or whitespace.`;
            }
            if (element.cache && !isNumber(element.cache)) {
                throw `acceptable_registries[${i}].cache is not a number.`;
            }
        }

        whoami = credsObject.whoami;
        acceptable_registries = credsObject.acceptable_registries;
        expiry_tolerance = credsObject.expiry_tolerance;
        replay_attack_mitigation = credsObject.replay_attack_mitigation;
    } else {
        throw "You did not specify a credentials object, you did Regions() instead of Regions(creds)";
    }

    return {
        getCreds: getCreds,
        sign: sign,
        verify: verify
    };
}

export default Regions;
export { getCreds };