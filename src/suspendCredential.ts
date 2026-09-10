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

async function updateCredentialFile (suspensionCredential: TRevocationListVerifiableCredential, statusList: any, fileName: string) {
  const encodedList = await statusList.encode();
  suspensionCredential.credentialSubject.encodedList = encodedList;
  const keyPairData = loadFileData<any>(DEFAULT_KEY_PAIR_FILE_NAME);
  if (!keyPairData) {
    throw new Error('No key pair file retrieved, it is expected to sign the document with the same initial key pair');
  }
  const updatedSuspensionCredential = JSON.parse(JSON.stringify(suspensionCredential));
  delete updatedSuspensionCredential.proof;
  const keyPair = await EcdsaSecp256k1VerificationKey2019.from(keyPairData as any);
  const signedCredential = await signSecp256k1(updatedSuspensionCredential, keyPair);
  await writeFile(signedCredential, fileName);
}

async function suspendCredential () {
  let credentialIndex: number;
  try {
    credentialIndex = parseInt(getArg('credentialIndex'), 10);
  } catch (e) {
    throw new Error('Please specify credential index to revoke with credentialIndex argument as number');
  }

  const type = getStatusListType();
  const fileName = getArg('file') ?? getRevocationListFileName('suspension', type);
  console.log('Suspending credential at index', credentialIndex, 'in', fileName);

  const suspensionCredential = loadFileData<TRevocationListVerifiableCredential>(fileName);
  console.log('loaded suspension credential', suspensionCredential);

  const statusList = await retrieveDecodedRevocationList(suspensionCredential);
  console.log('decoded suspension list', statusList);

  if (getStatus(suspensionCredential, statusList, credentialIndex)) {
    console.log('credential is already suspended, aborting');
    return;
  }

  setStatus(suspensionCredential, statusList, credentialIndex, true);
  if (!getStatus(suspensionCredential, statusList, credentialIndex)) {
    console.error('Something went wrong while suspending.', statusList);
    return;
  }

  console.log('list successfully updated', statusList);

  await updateCredentialFile(suspensionCredential, statusList, fileName);
  console.log('credential successfully updated after suspension of index', credentialIndex);
}

suspendCredential();
