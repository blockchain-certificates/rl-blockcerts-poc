const fs = require('fs');
import {getDefaultFilePath} from "../constants/revocationListFilePath";
import prettyFormat from "./prettyFormat";

export default async function writeFile (fileContent: any, fileName: string) {
  const outputPath: string = getDefaultFilePath(fileName);
  await fs.writeFile(outputPath, prettyFormat(fileContent), (err) => {
    if (err) {
      console.error(err);
      return;
    }
    console.log(`file saved to file ${outputPath}`);
  });
}
