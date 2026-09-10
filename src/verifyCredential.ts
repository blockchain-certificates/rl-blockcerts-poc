import {BlockcertsV3, IDidDocument} from "@blockcerts/cert-verifier-js";
const jsigs = require('jsonld-signatures');
const {purposes: {AssertionProofPurpose}} = jsigs;
const didKeySecp256k1 = require('@transmute/did-key-secp256k1');
const { EcdsaSecp256k1VerificationKey2019 } = require('@blockcerts/ecdsa-secp256k1-verification-key-2019');
const { EcdsaSecp256k1Signature2019 } = require('@blockcerts/ecdsa-secp256k1-signature-2019');
import loadFileData from "./helpers/loadFileData";
import {TRevocationListVerifiableCredential} from "./models";
import retrieveDecodedRevocationList from "./helpers/retrieveDecodedRevocationList";
import { getStatus } from "./helpers/statusListAdapter";
import { getRevocationListFileName, getStatusListType } from "./helpers/statusListNaming";
import generateDocumentLoader from "./helpers/generateDocumentLoader";
import currentTime from "./helpers/currentTime";

async function verifyProofRevocationCredential (revocationCredential: TRevocationListVerifiableCredential) {
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

async function getRevocationCredential (credentialStatus): Promise<TRevocationListVerifiableCredential> {
  // const revocationListCredentialUrl = credentialStatus.statusListCredential;
  // const revocationCredential = fetch

  const type = getStatusListType();
  const fileName = getRevocationListFileName('revocation', type);
  const revocationCredential = loadFileData<TRevocationListVerifiableCredential>(fileName);
  await verifyProofRevocationCredential(revocationCredential);
  return revocationCredential;
}

async function getStatusList (revocationCredential: TRevocationListVerifiableCredential): Promise<any> {
  return retrieveDecodedRevocationList(revocationCredential);
}


async function verifyCredential () {
  const vcData: BlockcertsV3 = loadFileData('issued-vc.json');
  const { credentialStatus } = vcData;
  const credentialIndex = parseInt((credentialStatus as any).statusListIndex, 10);

  const revocationCredential: TRevocationListVerifiableCredential = await getRevocationCredential(credentialStatus);
  const statusList = await getStatusList(revocationCredential);

  if (getStatus(revocationCredential, statusList, credentialIndex)) {
    console.error('Credential has been revoked');
    return;
  }

  console.log('Credential has not been revoked');
}

verifyCredential();
