import { TStatusListType } from "../models";
import getArg from "./getArg";

export function getRevocationListFileName (purpose: string, type: TStatusListType): string {
  const suffix = type === 'bitstring' ? '-bitstring' : '';
  if (purpose === 'revocation') {
    return `revocationList${suffix}.json`;
  }
  return `revocationList${suffix}-${purpose}.json`;
}

export function getRevocationListId (purpose: string, type: TStatusListType): string {
  const base = type === 'bitstring' ? 'bitstring-status-list' : 'status-list-2021';
  if (purpose === 'revocation') {
    return `https://www.blockcerts.org/samples/3.0/${base}.json`;
  }
  return `https://www.blockcerts.org/samples/3.0/${base}-${purpose}.json`;
}

export function getStatusListType (): TStatusListType {
  const type = getArg('type');
  if (type === 'bitstring') {
    return 'bitstring';
  }
  return 'statusList2021';
}
