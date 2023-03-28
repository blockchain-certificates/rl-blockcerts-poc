import fs from 'fs';
import {getDefaultFilePath} from "../constants/revocationListFilePath.js";
import prettyFormat from "./prettyFormat.js";

export default async function writeFile (fileContent, fileName) {
  const outputPath = getDefaultFilePath(fileName);
  await fs.writeFile(outputPath, prettyFormat(fileContent), (err) => {
    if (err) {
      console.error(err);
      return;
    }
    console.log(`file saved to file ${outputPath}`);
  });
}
