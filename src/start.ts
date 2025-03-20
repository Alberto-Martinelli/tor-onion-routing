import { launchNetwork } from ".";
import { GetNodeRegistryBody } from "./registry/registry";
import { REGISTRY_PORT } from "./config";


async function main() {
  await launchNetwork(10, 2);
}

main();
