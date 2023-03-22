import { MerkleProof2019 as VCProof } from "@blockcerts/cert-verifier-js";

export interface IRevocationList2021VerifiableCredential {
  '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'], // TODO: update with 2021
  id: string;
  issuer: string; // or Issuer Object
  issuanceDate: string;
  type: ['VerifiableCredential', 'StatusList2021Credential'],
  credentialSubject: {
    id: string;
    type: 'StatusList2021',
    encodedList: string;
  }
  proof?: VCProof
}

export interface IEd25519VerificationKey2020 {
  id?: string,
  controller?: string,
  revoked?: string,
  type: 'Ed25519VerificationKey2020',
  publicKeyMultibase: string,
  privateKeyMultibase: string
}
