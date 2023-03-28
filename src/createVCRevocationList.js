import { generateEncodedList } from './helpers/generateList.js';
import {DEFAULT_REVOCATION_LIST_FILE_NAME} from "./constants/index.js";
import writeFile from "./helpers/writeFile.js";
import signCredential from "./helpers/signCredential.js";
import currentTime from "./helpers/currentTime.js";
import SegfaultHandler from 'segfault-handler';
SegfaultHandler.registerHandler('crash.log');
function getVCTemplate ({
  encodedList,
  id = ''
}) {
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

async function generateCredential () {
  const encodedBitStringList = await generateEncodedList();
  const credential = getVCTemplate({
    encodedList: encodedBitStringList
  });
  return credential;
}

async function createVCRevocationList () {
  const credential = await generateCredential();
  credential.issuanceDate = currentTime();
  const signedCredential = await signCredential(credential);
  await writeFile(signedCredential, DEFAULT_REVOCATION_LIST_FILE_NAME);
}
createVCRevocationList();
