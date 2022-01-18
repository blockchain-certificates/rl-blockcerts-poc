import {DEFAULT_KEY_PAIR_FILE_NAME} from "../constants";

const jsigs = require('jsonld-signatures');
const {purposes: {AssertionProofPurpose}} = jsigs;
const { Ed25519VerificationKey2020 } = require('@digitalbazaar/ed25519-verification-key-2020');
const { Ed25519Signature2020 } = require('@digitalbazaar/ed25519-signature-2020');
import { securityLoader } from '@digitalbazaar/security-document-loader';
import currentTime from "./currentTime";
import {IEd25519VerificationKey2020} from "../models";
import writeFile from "./writeFile";
import revocationList2020Context from '../contexts/revocation-list-2020.json';

async function generateKeyPair (): Promise<IEd25519VerificationKey2020> {
  const keyPair = await Ed25519VerificationKey2020.generate();
  await writeFile(keyPair, DEFAULT_KEY_PAIR_FILE_NAME);
  return keyPair;
}

function generateDocumentLoader () {
  const documentLoader = securityLoader();
  documentLoader.addStatic('https://w3id.org/vc-revocation-list-2020/v1', revocationList2020Context);
  return documentLoader.build();
}

export default async function signCredential (credential, keyPair = null) {
  if (!keyPair) {
    console.log('no keyPair provided, generating a new one');
    keyPair = await generateKeyPair();
  }
  const suite = new Ed25519Signature2020({ key: keyPair });
  suite.date = currentTime();

  const signedCredential = await jsigs.sign(credential, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader: generateDocumentLoader()
  });
  console.log('Signed credential', signedCredential);
  return signedCredential;
}
