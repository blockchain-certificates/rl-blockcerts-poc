export default function prettyFormat (jsonObject): string {
  return JSON.stringify(jsonObject, null, 2);
}
