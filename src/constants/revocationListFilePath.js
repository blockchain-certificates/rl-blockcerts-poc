import path from 'path';

export function getDefaultFilePath (fileName) {
  return path.join(process.cwd(), 'src', 'data', fileName)
}
