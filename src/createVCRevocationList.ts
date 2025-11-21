import { generateEncodedList } from './helpers/generateList';

import { IRevocationList2021VerifiableCredential } from './models';
import {DEFAULT_KEY_PAIR_FILE_NAME, DEFAULT_REVOCATION_LIST_FILE_NAME} from "./constants";
import writeFile from "./helpers/writeFile";
// import signCredential from "./helpers/signCredential";
import currentTime from "./helpers/currentTime";
import signSecp256k1 from "./helpers/signSecp256k1";
import {v4 as uuidv4} from 'uuid';
import loadFileData from "./helpers/loadFileData";
import getArg from "./helpers/getArg";
import {EcdsaSecp256k1VerificationKey2019} from "@blockcerts/ecdsa-secp256k1-verification-key-2019";


function generateUuid () {
  return uuidv4();
}
function getVCTemplate ({
  encodedList,
  id = generateUuid()
                        }: {
  encodedList: string,
  id?: string
}): IRevocationList2021VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id,
    issuer: '',
    validFrom: '',
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    credentialSubject: {
      id: `${id}#list`,
      type: 'BitstringStatusList',
      encodedList,
    }
  };
}

function getListId (purpose: string) {
  if (purpose === 'revocation') {
    return 'https://www.blockcerts.org/samples/3.0/status-list-2021.json';
  }

  return `https://www.blockcerts.org/samples/3.0/status-list-2021-${purpose}.json`
}

function getFileName (purpose: string) {
  if (purpose === 'revocation') {
    return 'revocationList.json';
  }

  return `revocationList-${purpose}.json`
}

async function generateCredential (purpose: string): Promise<IRevocationList2021VerifiableCredential> {
  const encodedBitStringList = await generateEncodedList();
  const credential = getVCTemplate({
    encodedList: encodedBitStringList,
    id: getListId(purpose)
  });
  return credential;
}

async function createVCRevocationList () {
  let purpose: string = getArg('purpose');
  if (purpose == null) {
    console.log('Purpose was not defined as parameter, defaulting to revocation');
    purpose = 'revocation';
  }
  const credential = await generateCredential(purpose);
  credential.validFrom = currentTime();
  const keyPairData = loadFileData<any>(DEFAULT_KEY_PAIR_FILE_NAME);
  const keyPair = await EcdsaSecp256k1VerificationKey2019.from(keyPairData as any);
  credential.issuer = (keyPair as any).controller;
  const signedCredential = await signSecp256k1(credential, keyPair);
  await writeFile(signedCredential, getFileName(purpose));
}
createVCRevocationList();
