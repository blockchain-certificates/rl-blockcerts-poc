import {DEFAULT_KEY_PAIR_FILE_NAME} from "../constants";

const jsigs = require('jsonld-signatures');
const didKeyDriver = require('@digitalbazaar/did-method-key').driver();
const {purposes: {AssertionProofPurpose}} = jsigs;
const { Ed25519VerificationKey2020 } = require('@digitalbazaar/ed25519-verification-key-2020');
const { Ed25519Signature2020 } = require('@digitalbazaar/ed25519-signature-2020');
import {IDidDocument} from "@blockcerts/cert-verifier-js";
import currentTime from "./currentTime";
import {IEd25519VerificationKey2020} from "../models";
import writeFile from "./writeFile";
import generateDocumentLoader from "./generateDocumentLoader";

async function generateSignerData (): Promise<{
  keyPair: IEd25519VerificationKey2020;
  didDocument: IDidDocument
}> {
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

export default async function signCredential (credential, keyPair: IEd25519VerificationKey2020 = null, didDocument: IDidDocument = null) {
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
