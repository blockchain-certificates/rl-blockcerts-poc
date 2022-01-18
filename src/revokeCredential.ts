import getArg from "./helpers/getArg";
import loadFile from "./helpers/loadFile";
import {DEFAULT_REVOCATION_LIST_FILE_NAME} from "./constants";
import {IRevocationList2021VerifiableCredential} from "./models";
const { decodeList, RevocationList } = require('vc-revocation-list');

async function retrieveRevocationList (revocationCredential: IRevocationList2021VerifiableCredential): Promise<typeof RevocationList> {
  const encodedList = revocationCredential.credentialSubject.encodedList;
  console.log('encoded list', encodedList, typeof encodedList);
  return decodeList({ encodedList });
}

async function revokeCredential () {
  let credentialIndex: number;
  try {
    credentialIndex = parseInt(getArg('credentialIndex'), 10);
  } catch (e) {
    throw new Error('Please specify credential index to revoke with credentialIndex argument as number');
  }
  console.log('Revoking credential at index', credentialIndex);

  const revocationCredential: IRevocationList2021VerifiableCredential = JSON.parse(
    loadFile<string>(DEFAULT_REVOCATION_LIST_FILE_NAME)
  );
  console.log('loaded revocation credential', revocationCredential);

  const revocationList: typeof RevocationList = await retrieveRevocationList(revocationCredential);
  console.log('decoded revocation list', revocationList);

  revocationList.setRevoked(credentialIndex, true);
  if (revocationList.isRevoked(credentialIndex)) {
    console.log('Successfully revoked certificate at index', credentialIndex);
  } else {
    console.error('Something went wrong while revoking.', revocationList, revocationList.isRevoked(credentialIndex));
  }
}

revokeCredential();
