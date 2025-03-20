import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey } from "../crypto";
import { webcrypto } from "crypto";

export type Node = {
  nodeId: number;
  pubKey: string
};

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export const nodeRegistry: Node[] = [];

export async function registerNode(nodeID: number, pubKeyStr: string){
  // Check if the node already exists
  const existingNode = nodeRegistry.find((n) => n.nodeId === nodeID);
  if (existingNode) {
    existingNode.pubKey = pubKeyStr;
  } else {
    const newNode: Node = { nodeId: nodeID, pubKey: pubKeyStr };
    nodeRegistry.push(newNode);
  }
  
}

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // Implemented the status route
  _registry.get("/status", (req, res) => {
    res.send('live');
  });

  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey } = req.body as RegisterNodeBody;
    // little check
    if (typeof nodeId !== "number" || typeof pubKey !== "string") {
      return res.status(400).json({ error: "Invalid request body" });
    }
    registerNode(nodeId, pubKey);
    res.status(201).send({
      message: "Node registered successfully"
    });
    return res.status(201).send({
      message: "Node registered successfully"
    });
  });

  _registry.get("/getNodeRegistry", (req, res) => {
    nodeRegistry.sort((a, b) => a.nodeId - b.nodeId);
    console.log("Current Node Registry:", nodeRegistry);
    const payload: GetNodeRegistryBody = {
      nodes: nodeRegistry
    };
    res.json(payload);
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
