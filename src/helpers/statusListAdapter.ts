const { createList: createRevocationList, decodeList: decodeRevocationList } = require('@digitalbazaar/vc-revocation-list');
const {
  createList: createBitstringList,
  decodeList: decodeBitstringList,
  createCredential: createBitstringCredential
} = require('@digitalbazaar/vc-bitstring-status-list');

import { TRevocationListVerifiableCredential, TStatusListType } from "../models";

const DEFAULT_LIST_LENGTH = 131072;

export function isBitstringCredential (credential: TRevocationListVerifiableCredential): boolean {
  return (credential.type as string[]).includes('BitstringStatusListCredential');
}

export function getListTypeFromCredential (credential: TRevocationListVerifiableCredential): TStatusListType {
  return isBitstringCredential(credential) ? 'bitstring' : 'statusList2021';
}

export async function createStatusList (type: TStatusListType): Promise<any> {
  if (type === 'bitstring') {
    return createBitstringList({ length: DEFAULT_LIST_LENGTH });
  }
  return createRevocationList({ length: DEFAULT_LIST_LENGTH });
}

export async function decodeStatusList (credential: TRevocationListVerifiableCredential): Promise<any> {
  const { encodedList } = credential.credentialSubject;
  if (isBitstringCredential(credential)) {
    return decodeBitstringList({ encodedList });
  }
  return decodeRevocationList({ encodedList });
}

export function getStatus (credential: TRevocationListVerifiableCredential, statusList: any, index: number): boolean {
  return isBitstringCredential(credential) ? statusList.getStatus(index) : statusList.isRevoked(index);
}

export function setStatus (credential: TRevocationListVerifiableCredential, statusList: any, index: number, value: boolean): void {
  if (isBitstringCredential(credential)) {
    statusList.setStatus(index, value);
  } else {
    statusList.setRevoked(index, value);
  }
}

export async function createStatusListCredential ({
  type,
  id,
  statusList,
  statusPurpose
}: {
  type: TStatusListType,
  id: string,
  statusList: any,
  statusPurpose: string
}): Promise<TRevocationListVerifiableCredential> {
  if (type === 'bitstring') {
    return createBitstringCredential({ id, list: statusList, statusPurpose }) as any;
  }

  const encodedList = await statusList.encode();
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
    id,
    issuer: '',
    validFrom: '',
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    credentialSubject: {
      id: `${id}#list`,
      type: 'StatusList2021',
      encodedList
    }
  } as any;
}
