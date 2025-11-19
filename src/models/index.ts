import { MerkleProof2019 as VCProof } from "@blockcerts/cert-verifier-js";

export interface IRevocationList2021VerifiableCredential {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: string;
  issuer: string; // or Issuer Object
  validFrom: string;
  type: ['VerifiableCredential', 'BitstringStatusListCredential'],
  credentialSubject: {
    id: string;
    type: 'BitstringStatusList',
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
