const { createList } = require('vc-revocation-list');

async function generateList () {
  const list = await createList({ length: 131072 });
  return list;
}

export async function generateEncodedList (): Promise<string> {
  const list = await generateList();
  const encodedList = await list.encode();
  return encodedList;
}

generateEncodedList();
