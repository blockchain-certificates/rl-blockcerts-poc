import { MerkleProof2019 as VCProof } from "@blockcerts/cert-verifier-js";

export type TStatusListType = 'statusList2021' | 'bitstring';

export interface IStatusList2021VerifiableCredential {
  '@context': string[],
  id: string;
  issuer: string; // or Issuer Object
  validFrom: string;
  type: ['VerifiableCredential', 'StatusList2021Credential'],
  credentialSubject: {
    id: string;
    type: 'StatusList2021',
    encodedList: string;
  }
  proof?: VCProof
}

export interface IBitstringStatusListVerifiableCredential {
  '@context': string[],
  id: string;
  issuer: string; // or Issuer Object
  validFrom: string;
  type: ['VerifiableCredential', 'BitstringStatusListCredential'],
  credentialSubject: {
    id: string;
    type: 'BitstringStatusList',
    encodedList: string;
    statusPurpose: string;
  }
  proof?: VCProof
}

export type TRevocationListVerifiableCredential = IStatusList2021VerifiableCredential | IBitstringStatusListVerifiableCredential;

// retained for backwards compatibility with existing call sites
export type IRevocationList2021VerifiableCredential = TRevocationListVerifiableCredential;

export interface IEd25519VerificationKey2020 {
  id?: string,
  controller?: string,
  revoked?: string,
  type: 'Ed25519VerificationKey2020',
  publicKeyMultibase: string,
  privateKeyMultibase: string
}
