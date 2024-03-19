const { decodeList, RevocationList } = require('@digitalbazaar/vc-revocation-list');
import {IRevocationList2021VerifiableCredential} from "../models";

export default async function retrieveDecodedRevocationList (revocationCredential: IRevocationList2021VerifiableCredential): Promise<typeof RevocationList> {
  const encodedList = revocationCredential.credentialSubject.encodedList;
  return decodeList({ encodedList });
}
