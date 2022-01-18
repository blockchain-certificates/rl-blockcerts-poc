const path = require('path');

export function getDefaultFilePath (fileName: string): string {
  return path.join(process.cwd(), 'src', 'data', `${fileName}.json`)
}
