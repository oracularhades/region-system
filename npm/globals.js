import { SignJWT, importPKCS8 } from "jose";
import dns from "dns";

async function signJWT(data, privateKeyV, options) {
    const privateKeyPem = '-----BEGIN PRIVATE KEY-----\n' +
`${privateKeyV.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")}\n` +
'-----END PRIVATE KEY-----\n';

    const privateKey = await importPKCS8(privateKeyPem, "ES512");

    const jwt = await new SignJWT(data) // ECDSA with P-521 curve
    .setProtectedHeader({ alg: 'ES512' }) // Optional if you want to specify headers
    .sign(privateKey);
    
    return jwt;
}

// This ISNT using DNSSEC, but that's fine so long as all records are being verified with the region authority public key.
const resolveTxtPromise = (hostname) => {
    return new Promise((resolve, reject) => {
        dns.resolveTxt(hostname, (err, records) => {
            if (err && err.code == "ENODATA") {
                resolve([]);
            }
            if (err) reject(err);
            else resolve(records);
        });
    });
};

function isValidHostname(hostname) {
    try {
        const regex = /^[a-zA-Z0-9.]+$/;
        // Test the input string against the regex
        if (regex.test(hostname) != true) {
            return false;
        }

        const url = new URL(`https://${hostname}`);
        // Check if the URL consists of only scheme and host
        // If it has pathname, search, hash, or credentials, it's not just a hostname
        return url.pathname === "/" && url.search === "" && url.hash === "" && url.username === "" && url.password === "";
    } catch (error) {
        // If an error is thrown, it's probably not a valid hostname
        console.log(error);
        return false;
    }
}

function isNullOrWhiteSpace(str) {
    if (str == null) {
        return true;
    }
    if (str == false) {
        // false is also classified as actually not having anything in it lol. why javascript.
        return true;
    }
    if (str == true) {
        return false;
    }
    if (str == "null" || str == "undefined") {
        return true;
    }
    if (str == null) {
        return true;
    }
    if (str.trim().length == 0) {
        return true;
    }
    return false;
}

function isNumber(value) {
    return /[0-9]/g.test(value);
}

function URLSanitize(data) {
    if (data == null) {
      return null;
    }
    data = data.replaceAll(/[^a-zA-Z0-9_-]/g, '');
    return data.toString();
}

export { signJWT, resolveTxtPromise, isValidHostname, isNullOrWhiteSpace, isNumber, URLSanitize };