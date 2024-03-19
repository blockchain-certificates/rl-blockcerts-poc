import writeFile from "./helpers/writeFile";

const { RevocationList } = require('@digitalbazaar/vc-revocation-list');
const { Ed25519VerificationKey2020 } = require('@digitalbazaar/ed25519-verification-key-2020');
const { EcdsaSecp256k1VerificationKey2019 } = require('@blockcerts/ecdsa-secp256k1-verification-key-2019');
import getArg from "./helpers/getArg";
import loadFileData from "./helpers/loadFileData";
import {DEFAULT_KEY_PAIR_FILE_NAME, DEFAULT_REVOCATION_LIST_FILE_NAME} from "./constants";
import {IEd25519VerificationKey2020, IRevocationList2021VerifiableCredential} from "./models";
// import signCredential from "./helpers/signCredential";
import retrieveDecodedRevocationList from "./helpers/retrieveDecodedRevocationList";
import signSecp256k1 from "./helpers/signSecp256k1";

async function updateCredentialFile (revocationCredential: IRevocationList2021VerifiableCredential, revocationList: typeof RevocationList) {
  const encodedList = await revocationList.encode();
  revocationCredential.credentialSubject.encodedList = encodedList;
  const keyPairData = loadFileData<any>(DEFAULT_KEY_PAIR_FILE_NAME);
  if (!keyPairData) {
    throw new Error('No key pair file retrieved, it is expected to sign the document with the same initial key pair');
  }
  const updatedRevocationCredential = JSON.parse(JSON.stringify(revocationCredential));
  delete updatedRevocationCredential.proof;
  const keyPair = await EcdsaSecp256k1VerificationKey2019.from(keyPairData as any);
  const signedCredential = await signSecp256k1(updatedRevocationCredential, keyPair);
  await writeFile(signedCredential, 'revocationList-suspension.json');
}

async function suspendCredential () {
  let credentialIndex: number;
  try {
    credentialIndex = parseInt(getArg('credentialIndex'), 10);
  } catch (e) {
    throw new Error('Please specify credential index to revoke with credentialIndex argument as number');
  }
  console.log('Suspending credential at index', credentialIndex);

  const revocationCredential = loadFileData<IRevocationList2021VerifiableCredential>('revocationList-suspension.json');
  console.log('loaded suspension credential', revocationCredential);

  const revocationList: typeof RevocationList = await retrieveDecodedRevocationList(revocationCredential);
  console.log('decoded revocation list', revocationList);

  if (revocationList.isRevoked(credentialIndex)) {
    console.log('credential is already suspended, aborting');
    return;
  }

  revocationList.setRevoked(credentialIndex, true);
  if (!revocationList.isRevoked(credentialIndex)) {
    console.error('Something went wrong while suspending.', revocationList, revocationList.isRevoked(credentialIndex));
    return;
  }

  console.log('list successfully updated', revocationList);

  updateCredentialFile(revocationCredential, revocationList);
  console.log('credential successfully updated after suspension of index', credentialIndex);
}

suspendCredential();
