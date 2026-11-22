import assert from "node:assert/strict";
import {readFileSync, mkdtempSync, rmSync, realpathSync} from "node:fs";
import {createServer} from "node:http";
import {tmpdir} from "node:os";
import {join, resolve, sep} from "node:path";
import {spawn, execFileSync} from "node:child_process";
import {randomBytes, pbkdf2Sync, createCipheriv, createHash} from "node:crypto";
import {setTimeout as sleep} from "node:timers/promises";

const root=resolve(import.meta.dirname,"..");
const password="local-test-key-1234567890";
const plain=Buffer.from("dummy android payload for browser key test");
const salt=randomBytes(16),iv=randomBytes(12);
const cipher=createCipheriv("aes-256-gcm",pbkdf2Sync(password,salt,250000,32,"sha256"),iv);
const encrypted=Buffer.concat([Buffer.from("FAE1"),salt,iv,cipher.update(plain),cipher.final(),cipher.getAuthTag()]);
const manifest={android:{versionCode:11,versionName:"0.2.6",sha256:createHash("sha256").update(plain).digest("hex"),sizeBytes:plain.length,url:"FitnessAgent.enc",fileName:"test.apk",mime:"application/vnd.android.package-archive"},pc:{versionName:"0.2.6"}};
const server=createServer((request,response)=>{
  const pathname=new URL(request.url,"http://localhost").pathname;
  const table={"/": ["text/html",readFileSync(join(root,"docs/index.html"))],"/app.js":["application/javascript",readFileSync(join(root,"docs/app.js"))],"/downloads.json":["application/json",Buffer.from(JSON.stringify(manifest))],"/FitnessAgent.enc":["application/octet-stream",encrypted]};
  const file=table[pathname];if(!file){response.writeHead(404).end();return;}response.writeHead(200,{"Content-Type":file[0]});response.end(file[1]);
});
await new Promise(resolve=>server.listen(9254,"127.0.0.1",resolve));
const profile=mkdtempSync(join(tmpdir(),"fitness-key-ui-"));
const chrome=spawn("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",["--headless=new","--disable-gpu","--no-first-run","--no-default-browser-check","--remote-allow-origins=*","--remote-debugging-port=9255",`--user-data-dir=${profile}`,"http://127.0.0.1:9254/?platform=android"],{windowsHide:true,stdio:"ignore"});
let ws;
try{
  let tabs;
  for(let i=0;i<60;i++){try{tabs=await(await fetch("http://127.0.0.1:9255/json/list")).json();break;}catch{await sleep(250);}}
  const page=tabs?.find(tab=>tab.type==="page" && tab.url.includes("9254"));if(!page)throw Error("Browser tab missing");
  ws=new WebSocket(page.webSocketDebuggerUrl);await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
  let id=0;const pending=new Map();
  ws.onmessage=event=>{const packet=JSON.parse(event.data);if(!packet.id)return;const item=pending.get(packet.id);pending.delete(packet.id);packet.error?item.reject(Error(packet.error.message)):item.resolve(packet.result);};
  function command(method,params={}){const token=++id;return new Promise((resolve,reject)=>{pending.set(token,{resolve,reject});ws.send(JSON.stringify({id:token,method,params}));});}
  async function evaluate(expression){const packet=await command("Runtime.evaluate",{expression,returnByValue:true,awaitPromise:true});if(packet.exceptionDetails)throw Error(packet.exceptionDetails.exception?.description||packet.exceptionDetails.text);return packet.result.value;}
  async function until(expression){for(let i=0;i<80;i++){if(await evaluate(expression))return;await sleep(250);}throw Error("Timed out: "+expression);}
  await until('document.getElementById("access-key-row") && !document.getElementById("access-key-row").hidden');
  await evaluate(`(()=>{const input=document.getElementById("access-key");input.value=${JSON.stringify(password)};document.getElementById("download-form").requestSubmit();})()`);
  await until('!document.getElementById("manual-download").hidden');
  assert(await evaluate('document.getElementById("access-key-row").hidden && !document.getElementById("activate-updates").hidden'));
  await evaluate('location.reload()');
  await until('document.getElementById("saved-key-row") && !document.getElementById("saved-key-row").hidden');
  await evaluate('document.getElementById("download-form").requestSubmit()');
  await until('!document.getElementById("manual-download").hidden');
  await evaluate('document.getElementById("forget-key").click()');
  assert(await evaluate('!document.getElementById("access-key-row").hidden && document.getElementById("saved-key-row").hidden'));
  console.log("Download key UI smoke passed: remembered after reload, reused, and forgotten");
}finally{
  ws?.close();
  try {execFileSync("taskkill",["/PID",String(chrome.pid),"/T","/F"],{stdio:"ignore"});} catch (_) {chrome.kill();}
  await new Promise(resolve=>server.close(resolve));
  const target=realpathSync(profile);const parent=realpathSync(tmpdir());
  if(target.startsWith(parent+sep))rmSync(target,{recursive:true,force:true,maxRetries:15,retryDelay:200});
}
