// Preload (node --import) that makes every outbound network primitive throw
// and records the attempt. Used to show the verifier works with no network.
import { syncBuiltinESMExports } from "node:module";
import { appendFileSync } from "node:fs";
import net from "node:net";
import dns from "node:dns";
import dgram from "node:dgram";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";

const log = process.env.NETWORK_ATTEMPT_LOG;
const block = (what) => () => {
  if (log) appendFileSync(log, what + "\n");
  throw new Error(`network access blocked: ${what}`);
};
net.connect = net.createConnection = block("net.connect");
net.Socket.prototype.connect = block("net.Socket.connect");
tls.connect = block("tls.connect");
http.request = http.get = block("http.request");
https.request = https.get = block("https.request");
dgram.createSocket = block("dgram.createSocket");
for (const k of ["lookup", "resolve", "resolve4", "resolve6"]) dns[k] = block(`dns.${k}`);
for (const k of ["lookup", "resolve", "resolve4", "resolve6"]) dns.promises[k] = block(`dns.promises.${k}`);
globalThis.fetch = block("fetch");
syncBuiltinESMExports();
