const { decodeList } = require('vc-revocation-list');

export default async function retrieveDecodedRevocationList (revocationCredential) {
  const encodedList = revocationCredential.credentialSubject.encodedList;
  return decodeList({ encodedList });
}
