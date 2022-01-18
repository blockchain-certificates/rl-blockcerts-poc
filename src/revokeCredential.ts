import getArg from "./helpers/getArg";
import loadFile from "./helpers/loadFile";
import {DEFAULT_REVOCATION_LIST_FILE_NAME} from "./constants";
import {IRevocationList2021VerifiableCredential} from "./models";
const { decodeList } = require('vc-revocation-list');

async function retrieveRevocationList (revocationCredential: IRevocationList2021VerifiableCredential): Promise<string> {
  const encodedList = revocationCredential.credentialSubject.encodedList;
  console.log('encoded list', encodedList, typeof encodedList);
  return decodeList({ encodedList });
}

async function revokeCredential () {
  const credentialIndex = getArg('credentialIndex');
  if (credentialIndex == null) {
    throw new Error('please specify credential index to revoke with credentialIndex argument');
  }
  console.log('now revoking credential at index', credentialIndex);
  const revocationCredential: IRevocationList2021VerifiableCredential = JSON.parse(
    loadFile<string>(DEFAULT_REVOCATION_LIST_FILE_NAME)
  );
  console.log('loaded revocation credential', revocationCredential);
  const revocationList: string = await retrieveRevocationList(revocationCredential);
  console.log('decoded revocation list', revocationList);
}

revokeCredential();
