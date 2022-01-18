import writeFile from "./helpers/writeFile";

const { decodeList, RevocationList } = require('vc-revocation-list');
const { Ed25519VerificationKey2020 } = require('@digitalbazaar/ed25519-verification-key-2020');
import getArg from "./helpers/getArg";
import loadFileData from "./helpers/loadFileData";
import {DEFAULT_KEY_PAIR_FILE_NAME, DEFAULT_REVOCATION_LIST_FILE_NAME} from "./constants";
import {IEd25519VerificationKey2020, IRevocationList2021VerifiableCredential} from "./models";
import signCredential from "./helpers/signCredential";

async function retrieveRevocationList (revocationCredential: IRevocationList2021VerifiableCredential): Promise<typeof RevocationList> {
  const encodedList = revocationCredential.credentialSubject.encodedList;
  console.log('encoded list', encodedList, typeof encodedList);
  return decodeList({ encodedList });
}

async function updateCredentialFile (revocationCredential: IRevocationList2021VerifiableCredential, revocationList: typeof RevocationList) {
  const encodedList = await revocationList.encode();
  revocationCredential.credentialSubject.encodedList = encodedList;
  const keyPairData = loadFileData<IEd25519VerificationKey2020>(DEFAULT_KEY_PAIR_FILE_NAME);
  if (!keyPairData) {
    throw new Error('No key pair file retrieved, it is expected to sign the document with the same initial key pair');
  }
  const keyPair = await Ed25519VerificationKey2020.from(keyPairData);
  const signedCredential = await signCredential(revocationCredential, keyPair);
  await writeFile(signedCredential, DEFAULT_REVOCATION_LIST_FILE_NAME);
}

async function revokeCredential () {
  let credentialIndex: number;
  try {
    credentialIndex = parseInt(getArg('credentialIndex'), 10);
  } catch (e) {
    throw new Error('Please specify credential index to revoke with credentialIndex argument as number');
  }
  console.log('Revoking credential at index', credentialIndex);

  const revocationCredential = loadFileData<IRevocationList2021VerifiableCredential>(DEFAULT_REVOCATION_LIST_FILE_NAME)
  console.log('loaded revocation credential', revocationCredential);

  const revocationList: typeof RevocationList = await retrieveRevocationList(revocationCredential);
  console.log('decoded revocation list', revocationList);

  if (revocationList.isRevoked(credentialIndex)) {
    console.log('credential is already revoked, aborting');
    return;
  }

  revocationList.setRevoked(credentialIndex, true);
  if (!revocationList.isRevoked(credentialIndex)) {
    console.error('Something went wrong while revoking.', revocationList, revocationList.isRevoked(credentialIndex));
    return;
  }

  console.log('list successfully updated', revocationList);

  updateCredentialFile(revocationCredential, revocationList);
  console.log('credential successfully updated after revocation of index', credentialIndex);
}

revokeCredential();
