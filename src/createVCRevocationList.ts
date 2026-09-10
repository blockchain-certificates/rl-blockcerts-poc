import { TRevocationListVerifiableCredential } from "./models";
import { DEFAULT_KEY_PAIR_FILE_NAME } from "./constants";
import writeFile from "./helpers/writeFile";
import currentTime from "./helpers/currentTime";
import signSecp256k1 from "./helpers/signSecp256k1";
import loadFileData from "./helpers/loadFileData";
import getArg from "./helpers/getArg";
import { createStatusList, createStatusListCredential } from "./helpers/statusListAdapter";
import { getRevocationListFileName, getRevocationListId, getStatusListType } from "./helpers/statusListNaming";
import { EcdsaSecp256k1VerificationKey2019 } from "@blockcerts/ecdsa-secp256k1-verification-key-2019";

async function generateCredential (purpose: string): Promise<TRevocationListVerifiableCredential> {
  const type = getStatusListType();
  const statusList = await createStatusList(type);
  const id = getRevocationListId(purpose, type);
  const statusPurpose = purpose === 'suspension' ? 'suspension' : 'revocation';
  return createStatusListCredential({ type, id, statusList, statusPurpose });
}

async function createVCRevocationList () {
  let purpose: string = getArg('purpose');
  if (purpose == null) {
    console.log('Purpose was not defined as parameter, defaulting to revocation');
    purpose = 'revocation';
  }
  const type = getStatusListType();
  const credential = await generateCredential(purpose);
  credential.validFrom = currentTime();
  const keyPairData = loadFileData<any>(DEFAULT_KEY_PAIR_FILE_NAME);
  const keyPair = await EcdsaSecp256k1VerificationKey2019.from(keyPairData as any);
  credential.issuer = (keyPair as any).controller;
  const signedCredential = await signSecp256k1(credential, keyPair);
  await writeFile(signedCredential, getRevocationListFileName(purpose, type));
}
createVCRevocationList();
