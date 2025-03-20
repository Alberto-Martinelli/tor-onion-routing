import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { createRandomSymmetricKey, exportSymKey, importPubKey, rsaEncrypt, exportPubKey, symEncrypt } from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

interface RegistryResponse {
  nodes: Array<{ nodeId: number; pubKey: string }>;
}

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());
  let lastCircuit: number[] = [];

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;

  // Implemented the status route
  _user.get("/status", (req, res) => {
    res.send('live');
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({
      result: lastReceivedMessage
    });
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.json({
      result: lastSentMessage
    });
  });
  
  _user.get("/getLastCircuit", (req, res) => res.json({ result: lastCircuit }));

  _user.post("/message", (req, res) => {
    const { message, circuit } = req.body;

    if (!message) {
      return res.status(400).json({ error: "Message is required" });
    }

    lastReceivedMessage = message;
    if (circuit) lastCircuit = circuit;
    return res.send("success")
  });

  _user.post("/sendMessage", async (req, res)=>{
    // Sends a message to another user
    const { message, destinationUserId }: SendMessageBody = req.body;

    if (!message || !destinationUserId) {
      return res.status(400).json({ error: "Message and destinationUserId are required" });
    }

    try{
      // Create a random circuit of 3 distinct nodes
      const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const { nodes } = await registryResponse.json() as RegistryResponse;
      if (nodes.length < 3) return res.status(500).json({ error: "Not enough nodes available" });
      const selectedNodes = selectRandomNodes(nodes, 3);
      const circuit = selectedNodes.map(node => node.nodeId);

      let finalDestination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");

      // Create each layer of encryption
      let encryptedMessage = message;
      for (let i = circuit.length - 1; i >= 0; i--) {
        const symKey = await createRandomSymmetricKey();
        const symKeyStr = await exportSymKey(symKey);
        const nodePublicKey = await importPubKey(selectedNodes[i].pubKey);

        const encryptedSymKey = await rsaEncrypt(symKeyStr, await exportPubKey(nodePublicKey));
        const payload = finalDestination + encryptedMessage;
        const encryptedPayload = await symEncrypt(symKey, payload);

        encryptedMessage = encryptedSymKey + encryptedPayload;
        finalDestination = `${BASE_ONION_ROUTER_PORT + circuit[i]}`.padStart(10, "0");
      }

      // Forward the encrypted message to the entry node
      await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0]}/message`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: encryptedMessage, circuit: [] }),
      }).then(response => response.text()).then(data => console.log("Message sent response:", data));
      

      lastSentMessage = message;
      lastCircuit = circuit;
      return res.json({ success: true });

    }catch (error) {
      console.error("Error sending message:", error);
      return res.status(500).json({ error: "Failed to send message" });
    }
    
    // lastSentMessage = message; // Simulate sending a message to another user

    return res.status(200).json({ result: "Message sent successfully" });
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}

function selectRandomNodes(nodes: Array<{ nodeId: number; pubKey: string }>, count: number) {
  return nodes.sort(() => Math.random() - 0.5).slice(0, count);
}