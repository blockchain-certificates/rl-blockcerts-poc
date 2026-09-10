import writeFile from "./helpers/writeFile";
import getArg from "./helpers/getArg";
import loadFileData from "./helpers/loadFileData";
import { DEFAULT_KEY_PAIR_FILE_NAME } from "./constants";
import { TRevocationListVerifiableCredential } from "./models";
import retrieveDecodedRevocationList from "./helpers/retrieveDecodedRevocationList";
import { getStatus, setStatus } from "./helpers/statusListAdapter";
import { getRevocationListFileName, getStatusListType } from "./helpers/statusListNaming";
import signSecp256k1 from "./helpers/signSecp256k1";
import { EcdsaSecp256k1VerificationKey2019 } from "@blockcerts/ecdsa-secp256k1-verification-key-2019";

async function updateCredentialFile (revocationCredential: TRevocationListVerifiableCredential, statusList: any, fileName: string) {
  const encodedList = await statusList.encode();
  revocationCredential.credentialSubject.encodedList = encodedList;
  const keyPairData = loadFileData<any>(DEFAULT_KEY_PAIR_FILE_NAME);
  if (!keyPairData) {
    throw new Error('No key pair file retrieved, it is expected to sign the document with the same initial key pair');
  }
  const updatedRevocationCredential = JSON.parse(JSON.stringify(revocationCredential));
  delete updatedRevocationCredential.proof;
  const keyPair = await EcdsaSecp256k1VerificationKey2019.from(keyPairData as any);
  const signedCredential = await signSecp256k1(updatedRevocationCredential, keyPair);
  await writeFile(signedCredential, fileName);
}

async function revokeCredential () {
  let credentialIndex: number;
  try {
    credentialIndex = parseInt(getArg('credentialIndex'), 10);
  } catch (e) {
    throw new Error('Please specify credential index to revoke with credentialIndex argument as number');
  }

  const type = getStatusListType();
  const fileName = getArg('file') ?? getRevocationListFileName('revocation', type);
  console.log('Revoking credential at index', credentialIndex, 'in', fileName);

  const revocationCredential = loadFileData<TRevocationListVerifiableCredential>(fileName);
  console.log('loaded revocation credential', revocationCredential);

  const statusList = await retrieveDecodedRevocationList(revocationCredential);
  console.log('decoded revocation list', statusList);

  if (getStatus(revocationCredential, statusList, credentialIndex)) {
    console.log('credential is already revoked, aborting');
    return;
  }

  setStatus(revocationCredential, statusList, credentialIndex, true);
  if (!getStatus(revocationCredential, statusList, credentialIndex)) {
    console.error('Something went wrong while revoking.', statusList);
    return;
  }

  console.log('list successfully updated', statusList);

  await updateCredentialFile(revocationCredential, statusList, fileName);
  console.log('credential successfully updated after revocation of index', credentialIndex);
}

revokeCredential();
