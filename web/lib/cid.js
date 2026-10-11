// Work out the CID (content address) of some bytes ourselves, with the same settings the gateway asks IPFS to use.
// If storage ever returns different bytes, the CID will not match and we refuse to use them.
import { MemoryBlockstore } from "blockstore-core/memory";
import { importBytes } from "ipfs-unixfs-importer";

export async function computeCid(bytes) {
  const { cid } = await importBytes(bytes, new MemoryBlockstore(), { cidVersion: 1, rawLeaves: true });
  return cid.toString();
}
