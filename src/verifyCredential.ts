import {BlockcertsV3, IDidDocument} from "@blockcerts/cert-verifier-js";
const { RevocationList } = require('@digitalbazaar/vc-revocation-list');
const jsigs = require('jsonld-signatures');
const {purposes: {AssertionProofPurpose}} = jsigs;
const didKeySecp256k1 = require('@transmute/did-key-secp256k1');
const { EcdsaSecp256k1VerificationKey2019 } = require('@blockcerts/ecdsa-secp256k1-verification-key-2019');
const { EcdsaSecp256k1Signature2019 } = require('@blockcerts/ecdsa-secp256k1-signature-2019');
import loadFileData from "./helpers/loadFileData";
import {IRevocationList2021VerifiableCredential} from "./models";
import {DEFAULT_REVOCATION_LIST_FILE_NAME} from "./constants";
import retrieveDecodedRevocationList from "./helpers/retrieveDecodedRevocationList";
import generateDocumentLoader from "./helpers/generateDocumentLoader";
import currentTime from "./helpers/currentTime";

async function verifyProofRevocationCredential (revocationCredential: IRevocationList2021VerifiableCredential) {
  let didDocument: IDidDocument;

  console.log('verify revocation list credential', revocationCredential);

  // if (revocationCredential.proof.type === 'Ed25519Signature2020') {
  //   didDocument = await didKeyDriver.get({ did: revocationCredential.issuer });
  // }

  if (revocationCredential.proof.type === 'EcdsaSecp256k1Signature2019') {
    console.log('signature is EcdsaSecp256k1Signature2019');
    console.log('issuer is', revocationCredential.issuer);
    try {
      const output = await didKeySecp256k1.resolve(revocationCredential.issuer);
      didDocument = output.didDocument as IDidDocument;
      console.log(didDocument);
    } catch (e) {
      console.error(e);
    }
  }


  if (!didDocument) {
    throw new Error('Only did key issuers are supported at this moment');
  }

  const verificationMethod = didDocument.verificationMethod
    .find(verificationMethod => verificationMethod.id === revocationCredential.proof.verificationMethod);

  if (!verificationMethod) {
    throw new Error('The revocation method of the document does not match the provided issuer.');
  }

  let suite;

  // if (revocationCredential.proof.type === 'Ed25519Signature2020') {
  //   const verificationKey = await Ed25519VerificationKey2020.from({
  //     ...verificationMethod
  //   });
  //
  //   if (verificationKey.revoked) {
  //     throw new Error('The verification key has been revoked');
  //   }
  //
  //   suite = new Ed25519Signature2020({ key: verificationKey });
  // }

  if (revocationCredential.proof.type === 'EcdsaSecp256k1Signature2019') {
    const verificationKey = await EcdsaSecp256k1VerificationKey2019.from({
      ...verificationMethod
    } as any);

    console.log('verification key', JSON.stringify(verificationKey, null, 2));

    if (verificationKey.revoked) {
      throw new Error('The verification key has been revoked');
    }

    suite = new EcdsaSecp256k1Signature2019({ key: verificationKey });
  }


  suite.date = currentTime();

  const verificationStatus = await jsigs.verify(revocationCredential, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader: generateDocumentLoader([{
      [verificationMethod.controller]: loadFileData('did-secp256k1.json')
    }])
  });

  if (!verificationStatus.verified) {
    console.log(verificationStatus);
    throw new Error('Error validating the revocation list credential proof');
  }

  console.log('Revocation list credential successfully verified');
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
  const credentialIndex = parseInt((credentialStatus as any).statusListIndex, 10);

  const revocationCredential: IRevocationList2021VerifiableCredential = await getRevocationCredential(credentialStatus);
  const revocationList: typeof RevocationList = await getStatusList(revocationCredential);

  if (revocationList.isRevoked(credentialIndex)) {
    console.error('Credential has been revoked');
    return;
  }

  console.log('Credential has not been revoked');
}

verifyCredential();
