import { generateEncodedList } from './helpers/generateList';

import { IRevocationList2021VerifiableCredential } from './models';
import {DEFAULT_REVOCATION_LIST_FILE_NAME} from "./constants";
import writeFile from "./helpers/writeFile";
// import signCredential from "./helpers/signCredential";
import currentTime from "./helpers/currentTime";
import signSecp256k1 from "./helpers/signSecp256k1";
import {v4 as uuidv4} from 'uuid';


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
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
    id,
    issuer: '',
    issuanceDate: '',
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    credentialSubject: {
      id: `${id}#list`,
      type: 'StatusList2021',
      encodedList,
    }
  };
}

async function generateCredential (): Promise<IRevocationList2021VerifiableCredential> {
  const encodedBitStringList = await generateEncodedList();
  const credential = getVCTemplate({
    encodedList: encodedBitStringList,
    id: 'https://www.blockcerts.org/samples/3.0/status-list-2021.json'
  });
  return credential;
}

async function createVCRevocationList () {
  const credential = await generateCredential();
  credential.issuanceDate = currentTime();
  const signedCredential = await signSecp256k1(credential);
  await writeFile(signedCredential, DEFAULT_REVOCATION_LIST_FILE_NAME);
}
createVCRevocationList();
