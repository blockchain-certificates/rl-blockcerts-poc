import { securityLoader } from '@digitalbazaar/security-document-loader';
import revocationListContext from "../contexts/verifiable-credentials-v2.json";
import verifiableCredentialsV1Context from "../contexts/verifiable-credentials-v1.json";
import secp256k12019Context from "../contexts/secp256k1-2019.json";
import statusList2021Context from "../contexts/status-list-2021.json";

interface DocumentsToPreloadMap {
  [url: string]: any; // any being a context document or did document
}

export default function generateDocumentLoader (documentsToPreload: DocumentsToPreloadMap[] = []) {
  const documentLoader = securityLoader();
  documentLoader.addStatic('https://www.w3.org/ns/credentials/v2', revocationListContext);
  documentLoader.addStatic('https://www.w3.org/2018/credentials/v1', verifiableCredentialsV1Context);
  documentLoader.addStatic('https://ns.did.ai/suites/secp256k1-2019/v1', secp256k12019Context);
  documentLoader.addStatic('https://w3id.org/vc/status-list/2021/v1', statusList2021Context);
  documentsToPreload.forEach(document => {
    const key = Object.keys(document)[0];
    documentLoader.addStatic(key, document[key]);
  })
  return documentLoader.build();
}
