import { generateEncodedList } from './helpers/generateList';

import { IRevocationList2021VerifiableCredential } from './models';
import {DEFAULT_REVOCATION_LIST_FILE_NAME} from "./constants";
import writeFile from "./helpers/writeFile";
import signCredential from "./helpers/signCredential";
import currentTime from "./helpers/currentTime";

function getVCTemplate ({
  encodedList,
  id = ''
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
