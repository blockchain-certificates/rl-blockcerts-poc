import {BlockcertsV3} from "@blockcerts/cert-verifier-js";
const { RevocationList } = require('vc-revocation-list');
import loadFileData from "./helpers/loadFileData";
import {IRevocationList2021VerifiableCredential} from "./models";
import {DEFAULT_REVOCATION_LIST_FILE_NAME} from "./constants";
import retrieveDecodedRevocationList from "./helpers/retrieveDecodedRevocationList";

function verifyProofRevocationCredential (revocationCredential: IRevocationList2021VerifiableCredential) {

}

function getRevocationCredential (credentialStatus): IRevocationList2021VerifiableCredential {
  // const revocationListCredentialUrl = credentialStatus.statusListCredential;
  // const revocationCredential = fetch

  const revocationCredential = loadFileData<IRevocationList2021VerifiableCredential>(DEFAULT_REVOCATION_LIST_FILE_NAME);
  return revocationCredential;
}

async function getStatusList (revocationCredential: IRevocationList2021VerifiableCredential): Promise<typeof RevocationList> {
  const revocationList: typeof RevocationList = await retrieveDecodedRevocationList(revocationCredential);
  return revocationList;
}


async function verifyCredential () {
  const vcData: BlockcertsV3 = loadFileData('issued-vc.json');
  const { credentialStatus } = vcData;
  const credentialIndex = parseInt(credentialStatus.statusListIndex, 10);

  const revocationCredential: IRevocationList2021VerifiableCredential = getRevocationCredential(credentialStatus);
  const revocationList: typeof RevocationList = await getStatusList(revocationCredential);

  if (revocationList.isRevoked(credentialIndex)) {
    console.error('Credential has been revoked');
    return;
  }

  console.log('Credential has not been revoked');
}

verifyCredential();
