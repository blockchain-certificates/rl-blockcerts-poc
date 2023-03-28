import vcRevocationList from 'vc-revocation-list';
const { createList } = vcRevocationList;

async function generateList () {
  const list = await createList({ length: 131072 });
  return list;
}

export async function generateEncodedList () {
  const list = await generateList();
  const encodedList = await list.encode();
  return encodedList;
}

generateEncodedList();
