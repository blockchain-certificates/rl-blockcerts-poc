import revocationCredential from './data/revocationList.json';
import getArg from "./helpers/getArg";

async function revokeCredential () {
  const credentialIndex = getArg('credentialIndex');
  if (credentialIndex == null) {
    throw new Error('please specify credential index to revoke with credentialIndex argument');
  }
  console.log('now revoking credential at index', credentialIndex);
}

revokeCredential();
