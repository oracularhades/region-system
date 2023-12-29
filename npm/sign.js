import { getCreds } from "./index.js";
import { signJWT } from "./globals.js";

async function Sign(data) {
    const creds = getCreds();
  
    const signedObject = {
        regionmeta: {
            id: creds.whoami.id,
            capability: creds.whoami.capability,
            registry: creds.whoami.registry,
            expires: new Date().getTime()+60000
        },
        data: data
    }
  
    const options = {
        algorithm: 'ES512',
        compact: true,
        fields: { typ: 'JWT' }
    };
    
    const jwt = await signJWT(signedObject, creds.whoami.privatekey, options);
    
    return jwt;
}

export default Sign;