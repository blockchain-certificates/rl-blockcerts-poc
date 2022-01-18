const fs = require('fs');
import {getDefaultFilePath} from "../constants/revocationListFilePath";

export default function loadFileData<T> (fileName: string): T {
  const fileData = fs.readFileSync(getDefaultFilePath(fileName), 'utf8');
  return JSON.parse(fileData);
}
