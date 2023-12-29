import { resolveTxtPromise, isValidHostname, isNullOrWhiteSpace, isNumber, URLSanitize } from "./globals.js"; // This ISNT using DNSSEC, but that's fine so long as all records are being verified with the region authority public key.
import jwt from 'jsonwebtoken';
import { getCreds } from "./index.js";

async function Verify(jwt_string) {
    // Get creds.
    const creds = getCreds();

    const signedObject_what = JSON.stringify(jwt.decode(jwt_string));

    const signedObject = JSON.parse(signedObject_what);
    if (!signedObject) {
        throw "signedObject is null.";
    }

    // Check for regionMeta.
    if (!signedObject.regionmeta) {
        throw "signedObject.regionmeta is null. Invalid request.";
    }
  
    const id = signedObject.regionmeta.id;
    const capability = signedObject.regionmeta.capability;

    // Make sure the registry is authorized. It's important to only valid registries are used...since yk...can't have just anyone issuing keys.
    let isValidRegistry = false;
    let acceptedRegistryItem = null;
    for (let i = 0, strLen = creds.acceptable_registries.length; i < strLen; i++) {
        console.debug("LOOP ONCE");
        const data = creds.acceptable_registries[i];
        // why tf did this not error when it was element instead of data?
        console.debug("CHECK", data.url, signedObject.regionmeta.registry);
        if (data.url == signedObject.regionmeta.registry) {
            console.debug("VALID REGISTRY!");
            isValidRegistry = true;
            acceptedRegistryItem = data;
            break;
        }
    }

    if (!acceptedRegistryItem || isValidRegistry != true) {
        // The provided registry isn't valid.
        throw `"${signedObject.regionmeta.registry}" is not an acceptable registry. If you want to authorize this registry, you must specify it in credsObject.acceptable_registries.`;
    }
  
    let compatabilityRecords = [];
    let regionRecords = [];

    if (signedObject.regionmeta.registry.startsWith("dns://")) {
        // Get compatibility/region data via DNS, since a DNS registry was specified.

        let hostname = signedObject.regionmeta.registry.replace("dns://", "");
        if (isValidHostname(hostname) != true) {
            throw `"${hostname}" is not a valid hostname. Because DNS was used as the registry type for this request, the input should be a valid hostname and only a hostname.`
        }
        compatabilityRecords = await resolveTxtPromise(`${URLSanitize(capability)}.capability.${URLSanitize(id)}.${hostname}`);
        regionRecords = await resolveTxtPromise(hostname);
    } else if (signedObject.regionmeta.registry.startsWith("https://")) {
        // Get compatibility/region data via HTTPS, since a HTTPS registry was specified.

        // TODO: This pathname needs to be updated, and the response json handling needs to be fixed as well.
        let https_registry_url = new URL(signedObject.regionmeta.registry);
        https_registry_url.pathname = `/region/${id}/capability/${capability}`;
        const registryResponse = await fetch(https_registry_url.href, {
            method: 'GET',
            redirect: 'error',
            referrerPolicy: 'no-referrer'
        });

        if (registryResponse.status == 200) {
            try {
                const response = await registryResponse.json();
                if (!response) {
                    throw ""; // This should trigger the same error message as in the catch.
                }
            } catch (error) {
                throw `Could not parse registry response JSON (is the registry server returning valid json? Try making a GET request to the registry server "${signedObject.regionmeta.registry}" and check).`;
            }

            const registryResponseData = await registryResponse.json();
            if (!registryResponseData.compatabilityRecords) {
                throw "response.compatabilityRecords is null. The registry server is required to specify this.";
            }
            if (!registryResponseData.regionRecords) {
                throw "response.regionRecords is null. The registry server is required to specify this.";
            }

            compatabilityRecords = registryResponseData.compatabilityRecords;
            regionRecords = registryResponseData.regionRecords;
        } else {
            // Registry server was not able to complete the request.
            throw `Registry server returned ${registryResponse.status} instead of 200.`;
        }

    } else {
        // Client failed to specify a valid registry type.
        throw `Invalid registry type. Registry URL should start with something like dns:// or https://, instead the URL is "${signedObject.regionmeta.registry}"`;
    }

    if (compatabilityRecords.length == 0) {
        throw "No compatability records.";
    }
    if (regionRecords.length == 0) {
        throw "No region records.";
    }
  
    let regionData = null;
    for (let i = 0, strLen = regionRecords.length; i < strLen; i++) {
        const data = regionRecords[i].join("");
        console.debug("ID matches", data);
    
        await jwt.verify(data, acceptedRegistryItem.publickey, (err, decoded) => {
            if (err) {
                console.error('JWT verification failed!', err);
            } else {
                console.log('JWT matches provided token and publickey.', decoded);
        
                if (decoded && decoded.id.toLowerCase() == id.toLowerCase()) {
                    regionData = decoded;
                }
            }
        });
    }
  
    const compatabilityData_jwt = compatabilityRecords[0].join("");
    if (!compatabilityData_jwt) {
        throw "Compatability data after parse not found.";
    }
  
    let compatabilityData = null;
    await jwt.verify(compatabilityData_jwt, acceptedRegistryItem.publickey, (err, decoded) => {
        if (err) {
            console.error('JWT verification failed!', err);
        } else {
            console.log('JWT matches provided token and publickey.', decoded);
            compatabilityData = decoded;
        }
    });
  
    if (!compatabilityData) {
        throw "Compatability data is not valid.";
    }

    if (!regionData) {
        throw "No region data.";
    }
    if (regionData.active != true && regionData.active != "true") {
        throw "Region not active.";
    }

    if (regionData.id != compatabilityData.region_id) {
        throw "region.id does not match compatibility.region_id";
    }
  
    if (isNullOrWhiteSpace(compatabilityData.capability) || compatabilityData.capability != capability) {
        // Ok something is very off here.
        throw `Capability "${capability}" does not match capability "${compatabilityData.capability}"`;
    }

    const publicKeyPem = compatabilityData.publickey.replaceAll("\n\n", "\n");
  
    let decodedData = null; // use this decodedData string to check if JWT verification is successful.
    await jwt.verify(jwt_string, publicKeyPem, (err, decoded) => {
        if (err) {
            console.error('JWT verification failed!', err);
        } else {
            decodedData = decoded;
        }
    });
    if (!decodedData) {
        throw "JWT verification failed.";
    }
    decodedData = null;
  
    return { ok: true, capability: capability, body: signedObject.data };
}

export default Verify;