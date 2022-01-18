export interface IRevocationList2021VerifiableCredential {
  '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc-revocation-list-2020/v1'], // TODO: update with 2021
  id: string;
  issuer: string; // or Issuer Object
  issuanceDate: string;
  type: ['VerifiableCredential', 'RevocationList2021Credential'],
  credentialSubject: {
    id: string;
    type: 'RevocationList2021',
    encodedList: string;
  }
}

export interface IEd25519VerificationKey2020 {
  id?: string,
  controller?: string,
  revoked?: string,
  type: 'Ed25519VerificationKey2020',
  publicKeyMultibase: string,
  privateKeyMultibase: string
}
