import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, rsaDecrypt, importSymKey, symDecrypt, exportSymKey } from "../crypto";
import { webcrypto } from "node:crypto";


export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastPort: number | null = null;
  let lastCircuit: number[] = [];

  let pubKey: webcrypto.CryptoKey;
  let prvKey: webcrypto.CryptoKey;
  let pubKeyStr: string;
  let prvKeyStr: string | null;

  let lastMessageDestination: number | null = null;


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
      result: lastReceivedEncryptedMessage // encrypted message
    });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({
      result: lastReceivedDecryptedMessage // decrypted message
    });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => res.json({ result: lastMessageDestination }));

  onionRouter.get("/getPrivateKey", async (req, res) => {
    const prvKeyStr = await exportPrvKey(prvKey);
    res.json({
      result: prvKeyStr
    });
  });

  onionRouter.get("/getLastCircuit", (req, res) => res.json({ result: lastCircuit }));

  onionRouter.post("/message", async (req, res) => {
    try {
      const { message, circuit = [] } = req.body;
      console.log(`Node ${nodeId} received message:`, message);
  
      if (!message) return res.status(400).json({ error: "Message required" });
  
      lastReceivedEncryptedMessage = message;
      console.log(`Last received encrypted message on Node ${nodeId}:`, lastReceivedEncryptedMessage);

      const encryptedSymKey = message.slice(0, 344);
      const encryptedPayload = message.slice(344);

      let symKey;
      try {
        const symKeyStr = await rsaDecrypt(encryptedSymKey, prvKey);
        symKey = await importSymKey(symKeyStr);
      } catch (error) {
        console.error(`Node ${nodeId} failed to decrypt symmetric key:`, error);
        return res.status(500).json({ error: "Symmetric key decryption failed" });
      }

      let decryptedPayload;
      try {
        decryptedPayload = await symDecrypt(await exportSymKey(symKey), encryptedPayload);
      } catch (error) {
        console.error(`Node ${nodeId} failed to decrypt payload:`, error);
        return res.status(500).json({ error: "Payload decryption failed" });
      }

      const destination = parseInt(decryptedPayload.slice(0, 10), 10);
      const remainingMessage = decryptedPayload.length > 10 ? decryptedPayload.substring(10) : "";

      lastReceivedDecryptedMessage = remainingMessage;
      lastMessageDestination = destination;
      lastCircuit = [...circuit, nodeId];

      await fetch(`http://localhost:${destination}/message`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: remainingMessage, circuit: lastCircuit }),
      });

      return res.json({ success: true });
    } catch (error) {
      console.error("Error processing message:", error);
      return res.status(500).json({ error: "Failed to process message" });
    }
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
