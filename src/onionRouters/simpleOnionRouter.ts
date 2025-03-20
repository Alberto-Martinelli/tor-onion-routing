import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey } from "../crypto";
import { webcrypto } from "node:crypto";


export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());
  let lastMessageEncrypted: string | null = null;
  let lastMessageDecrypted: string | null = null;
  let lastPort: number | null = null;
  let pubKey: webcrypto.CryptoKey;
  let prvKey: webcrypto.CryptoKey;
  let pubKeyStr: string;
  let prvKeyStr: string | null;


  // Registers itself on the nodeRegistry
  try {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    pubKey = publicKey;
    prvKey = privateKey;
    pubKeyStr = await exportPubKey(pubKey);
    prvKeyStr = await exportPrvKey(prvKey);
    
    const response = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        nodeId, 
        pubKey: pubKeyStr  // Send public key to the registry
      }),
    });
    
    if (response.ok) {
      console.log(`Node ${nodeId} successfully registered.`);
    } else {
      console.error(`Failed to register node ${nodeId}`);
    }
  } catch (error) {
    console.error("Error during node registration:", error);
  }


  // Implemented the status route
  onionRouter.get("/status", (req, res) => {
    res.send('live');
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({
      result: lastMessageEncrypted // encrypted message
    });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({
      result: lastMessageDecrypted // decrypted message
    });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({
      result: lastPort // destination (port) of the last received message
    });
  });

  onionRouter.get("/getPrivateKey", async (req, res) => {
    const prvKeyStr = await exportPrvKey(prvKey);
    res.json({
      result: prvKeyStr
    });
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, async () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
