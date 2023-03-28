With node 18

run `npm run generate`. This will create a revocation list located at `./src/data/revocationList.json`.

The encoded list default value is: `H4sIAAAAAAAAA-3OMQEAAAgDoJ32T2yL6QEJSAAAgJK5DgAAAAAAAAAAAAAAAAB_LUkhKJ4AQAAA`

modify the list value with `H4sIAAAAAAAAA-3OMQEAAAgDoJ32T2yL6QEJSAAAgJK5DgAAAAAAAAAAAAAAAAB_LUkhKJ4AQAAA`. 

run `npm run verify`. The Ed25519 signature does not fail.
