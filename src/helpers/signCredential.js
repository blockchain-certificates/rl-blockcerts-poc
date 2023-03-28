import {DEFAULT_KEY_PAIR_FILE_NAME} from "../constants/index.js";

import jsigs from 'jsonld-signatures';
import didMethodKey from '@digitalbazaar/did-method-key';
const { driver: didKeyDriver } = didMethodKey;
const {purposes: {AssertionProofPurpose}} = jsigs;
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { securityLoader } from '@digitalbazaar/security-document-loader';
import currentTime from "./currentTime.js";
import writeFile from "./writeFile.js";
import statusList2021Context from '../contexts/status-list-2021.json' assert { type: "json" };

async function generateSignerData () {
  const keyPair = await Ed25519VerificationKey2020.generate();
  const {didDocument} = await didKeyDriver.publicKeyToDidDoc({publicKeyDescription: keyPair});
  keyPair.controller = didDocument.id;
  keyPair.id = keyPair.controller + '#' + keyPair.publicKeyMultibase;
  await writeFile(keyPair, DEFAULT_KEY_PAIR_FILE_NAME);
  console.log('key pair generated:', keyPair);
  await writeFile(didDocument, 'did.json');
  console.log('did document generated:', didDocument);
  return { keyPair, didDocument };
}

export function generateDocumentLoader () {
  const documentLoader = securityLoader();
  documentLoader.addStatic('https://w3id.org/vc/status-list/2021/v1', statusList2021Context);
  return documentLoader.build();
}

export default async function signCredential (credential, keyPair = null, didDocument = null) {
  if (!keyPair) {
    console.log('no keyPair provided, generating a new one');
    const signerData = await generateSignerData();
    keyPair = signerData.keyPair;
    didDocument = signerData.didDocument;
    credential.issuer = didDocument.id;
  }
  const suite = new Ed25519Signature2020({ key: keyPair });
  suite.date = currentTime();

  const signedCredential = await jsigs.sign(credential, {
    suite,
    purpose: new AssertionProofPurpose({ controller: didDocument }),
    documentLoader: generateDocumentLoader()
  });
  console.log('Signed credential', signedCredential);
  return signedCredential;
}
