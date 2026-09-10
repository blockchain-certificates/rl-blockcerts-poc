import {IEd25519VerificationKey2020} from "../models";

import { EcdsaSecp256k1Signature2019 } from '@blockcerts/ecdsa-secp256k1-signature-2019';
import { EcdsaSecp256k1VerificationKey2019 } from '@blockcerts/ecdsa-secp256k1-verification-key-2019';
import jsigs from 'jsonld-signatures';
import crypto from 'crypto';
import didKeySecp256k1 from '@transmute/did-key-secp256k1';
const {purposes: {AssertionProofPurpose}} = jsigs;
import currentTime from './currentTime';
import writeFile from "./writeFile";
import {IDidDocument} from "@blockcerts/cert-verifier-js";
import generateDocumentLoader from "./generateDocumentLoader";
import {DEFAULT_KEY_PAIR_FILE_NAME} from "../constants";

async function generateSignerData (): Promise<{
  keyPair: any;
  didDocument: IDidDocument
}>  {
  const seed = crypto.randomBytes(32);
  const keyPair = await EcdsaSecp256k1VerificationKey2019.generate({
    seed
  })
  const didKey = await didKeySecp256k1.generate({
    secureRandom: () => seed
  });
  const didDocument = didKey.didDocument;
  keyPair.controller = didDocument.id;
  keyPair.id = didDocument.verificationMethod[0].id;
  await writeFile(keyPair, DEFAULT_KEY_PAIR_FILE_NAME + 'secp256k1');
  console.log('key pair generated:', keyPair);
  await writeFile(didDocument,  'did-secp256k1.json');
  console.log('did document generated:', didDocument);
  return { keyPair, didDocument };
}
export default async function signSecp256k1 (credential, keyPair = null, didDocument = null, documentLoader = generateDocumentLoader()) {
  if (!keyPair) {
    console.log('no keyPair provided, generating a new one');
    const signerData = await generateSignerData();
    keyPair = signerData.keyPair;
    console.log('before sign', keyPair);
    didDocument = signerData.didDocument;
    credential.issuer = didDocument.id;
  }
  const suite = new EcdsaSecp256k1Signature2019({ key: keyPair });
  suite.date = currentTime();

  const signedCredential = await jsigs.sign(credential, {
    suite,
    purpose: new AssertionProofPurpose({ controller: didDocument }),
    documentLoader
  });
  console.log('credential signed', signedCredential.proof);
  return signedCredential;
}
