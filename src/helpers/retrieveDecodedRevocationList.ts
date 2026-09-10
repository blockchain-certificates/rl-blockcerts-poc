import { TRevocationListVerifiableCredential } from "../models";
import { decodeStatusList } from "./statusListAdapter";

export default async function retrieveDecodedRevocationList (revocationCredential: TRevocationListVerifiableCredential): Promise<any> {
  return decodeStatusList(revocationCredential);
}
