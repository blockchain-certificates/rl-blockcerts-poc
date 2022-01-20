import {BlockcertsV3, IDidDocument} from "@blockcerts/cert-verifier-js";
const { RevocationList } = require('vc-revocation-list');
const jsigs = require('jsonld-signatures');
const {purposes: {AssertionProofPurpose}} = jsigs;
const didKeyDriver = require('@digitalbazaar/did-method-key').driver();
const { Ed25519VerificationKey2020 } = require('@digitalbazaar/ed25519-verification-key-2020');
const { Ed25519Signature2020 } = require('@digitalbazaar/ed25519-signature-2020');
import loadFileData from "./helpers/loadFileData";
import {IRevocationList2021VerifiableCredential} from "./models";
import {DEFAULT_REVOCATION_LIST_FILE_NAME} from "./constants";
import retrieveDecodedRevocationList from "./helpers/retrieveDecodedRevocationList";
import {generateDocumentLoader} from "./helpers/signCredential";
import currentTime from "./helpers/currentTime";

async function verifyProofRevocationCredential (revocationCredential: IRevocationList2021VerifiableCredential) {
  const didDocument: IDidDocument = await didKeyDriver.get({ did: revocationCredential.issuer });
  if (!didDocument) {
    throw new Error('Only did key issuers are supported at this moment');
  }

  const verificationMethod = didDocument.verificationMethod
    .find(verificationMethod => verificationMethod.id === revocationCredential.proof.verificationMethod);

  if (!verificationMethod) {
    throw new Error('The revocation method of the document does not match the provided issuer.');
  }

  const verificationKey = await Ed25519VerificationKey2020.from({
    ...verificationMethod
  });

  if (verificationKey.revoked) {
    throw new Error('The verification key has been revoked');
  }

  const suite = new Ed25519Signature2020({ key: verificationKey });
  suite.date = currentTime();

  const verificationStatus = await jsigs.verify(revocationCredential, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader: generateDocumentLoader()
  });

  if (!verificationStatus.verified) {
    throw new Error('Error validating the revocation list credential proof');
  }
}

async function getRevocationCredential (credentialStatus): Promise<IRevocationList2021VerifiableCredential> {
  // const revocationListCredentialUrl = credentialStatus.statusListCredential;
  // const revocationCredential = fetch

  const revocationCredential = loadFileData<IRevocationList2021VerifiableCredential>(DEFAULT_REVOCATION_LIST_FILE_NAME);
  await verifyProofRevocationCredential(revocationCredential);
  return revocationCredential;
}

async function getStatusList (revocationCredential: IRevocationList2021VerifiableCredential): Promise<typeof RevocationList> {
  const revocationList: typeof RevocationList = await retrieveDecodedRevocationList(revocationCredential);
  return revocationList;
}


async function verifyCredential () {
  const vcData: BlockcertsV3 = loadFileData('issued-vc.json');
  const { credentialStatus } = vcData;
  const credentialIndex = parseInt(credentialStatus.statusListIndex, 10);

  const revocationCredential: IRevocationList2021VerifiableCredential = await getRevocationCredential(credentialStatus);
  const revocationList: typeof RevocationList = await getStatusList(revocationCredential);

  if (revocationList.isRevoked(credentialIndex)) {
    console.error('Credential has been revoked');
    return;
  }

  console.log('Credential has not been revoked');
}

verifyCredential();
