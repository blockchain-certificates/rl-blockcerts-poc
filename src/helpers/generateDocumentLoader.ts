import { securityLoader } from '@digitalbazaar/security-document-loader';
import revocationList2020Context from "../contexts/status-list-2021.json";

interface DocumentsToPreloadMap {
  [url: string]: any; // any being a context document or did document
}

export default function generateDocumentLoader (documentsToPreload: DocumentsToPreloadMap[] = []) {
  const documentLoader = securityLoader();
  documentLoader.addStatic('https://w3id.org/vc/status-list/2021/v1', revocationList2020Context);
  documentsToPreload.forEach(document => {
    const key = Object.keys(document)[0];
    documentLoader.addStatic(key, document[key]);
  })
  return documentLoader.build();
}
