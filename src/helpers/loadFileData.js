const fs = require('fs');
import {getDefaultFilePath} from "../constants/revocationListFilePath.js";

export default function loadFileData (fileName) {
  const fileData = fs.readFileSync(getDefaultFilePath(fileName), 'utf8');
  return JSON.parse(fileData);
}
