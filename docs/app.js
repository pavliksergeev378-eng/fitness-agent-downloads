const MAGIC = [70, 65, 69, 49];

export async function decryptPayload(data, password) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  if (bytes.length < 49 || MAGIC.some((value, index) => bytes[index] !== value)) {
    throw new Error("Invalid encrypted file");
  }
  const salt = bytes.slice(4, 20);
  const iv = bytes.slice(20, 32);
  const ciphertext = bytes.subarray(32);
  const material = await globalThis.crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
  );
  const key = await globalThis.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  return globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
}

if (typeof document !== "undefined") {
  const form=document.getElementById("download-form"),field=document.getElementById("access-key");
  const button=document.getElementById("download-button"),status=document.getElementById("status"),manual=document.getElementById("manual-download");
  const note=document.getElementById("platform-note");
  let currentUrl=null,prepared=null,busy=false;
  const selected=()=>form.querySelector('[name="platform"]:checked').value;
  const initial=new URL(location.href).searchParams.get("platform") || (/Android/i.test(navigator.userAgent)?"android":"pc");
  if(["android","pc"].includes(initial))form.querySelector('[name="platform"][value="'+initial+'"]').checked=true;
  const descriptions={android:"Android: APK устанавливается поверх прежней версии. Данные сохраняются.",pc:"ПК: один файл FitnessAgent-PC.html открывается в Chrome или Edge. Установка и архиватор не нужны. Картинки внутри, данные хранятся в браузере. Для переноса используйте резервную копию. При обновлении заменяйте файл в той же папке и открывайте тем же браузером."};
  function reset(){
    if(busy)return;
    prepared=null;manual.hidden=true;document.getElementById("fallback-download").hidden=true;status.textContent="";note.textContent=descriptions[selected()];
    button.textContent=selected()==="android"?"Подготовить Android APK":"Подготовить версию для ПК";
    if(currentUrl){URL.revokeObjectURL(currentUrl);currentUrl=null;}
  }
  form.querySelectorAll('[name="platform"]').forEach(r=>r.addEventListener("change",reset));reset();
  manual.addEventListener("click",async event=>{
    if(!prepared)return;
    // A second explicit click keeps saving inside a browser user gesture.
    if(selected()==="pc" && typeof window.showSaveFilePicker==="function") {
      event.preventDefault();
      try {
        const handle=await window.showSaveFilePicker({suggestedName:prepared.fileName,types:[{description:"Фитнес-тренер для ПК",accept:{"text/html":[".html"]}}]});
        const writable=await handle.createWritable();await writable.write(prepared.blob);await writable.close();
        status.textContent="Файл сохранён. Откройте его в Chrome или Edge.";
      } catch(error){status.textContent=error.name==="AbortError"?"Сохранение отменено. Можно нажать Скачать ещё раз.":"Браузер не смог сохранить файл. Нажмите Запасная ссылка ниже.";document.getElementById("fallback-download").hidden=false;}
    }
  });
  form.addEventListener("submit",async event=>{
    event.preventDefault();const password=field.value.trim();if(!password)return;
    busy=true;button.disabled=true;form.querySelectorAll('[name="platform"]').forEach(r=>r.disabled=true);
    manual.hidden=true;document.getElementById("fallback-download").hidden=true;prepared=null;
    status.textContent="Получаю сведения о версии…";
    try {
      if(!globalThis.crypto?.subtle)throw Error("secure_browser_required");
      const manifestResponse=await fetch("./downloads.json",{cache:"no-store"});if(!manifestResponse.ok)throw Error("manifest_failed");
      const manifest=await manifestResponse.json();const target=manifest[selected()];
      if(!target || !/^[A-Za-z0-9.-]+\.enc$/.test(target.url) || !/^[a-f0-9]{64}$/i.test(target.sha256))throw Error("invalid_manifest");
      status.textContent="Загружаю защищённую версию "+target.versionName+" (около "+Math.ceil(target.sizeBytes/1000000)+" МБ)…";
      const response=await fetch("./"+target.url,{cache:"no-store"});if(!response.ok)throw Error("download_failed");
      status.textContent="Проверяю ключ и готовлю файл…";
      const payload=await decryptPayload(await response.arrayBuffer(),password);
      const hash=[...new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256",payload))].map(b=>b.toString(16).padStart(2,"0")).join("");
      if(hash!==target.sha256.toLowerCase() || payload.byteLength!==target.sizeBytes)throw Error("integrity_failed");
      if(currentUrl)URL.revokeObjectURL(currentUrl);
      const blob=new Blob([payload],{type:target.mime});currentUrl=URL.createObjectURL(blob);
      prepared={blob,fileName:target.fileName};manual.href=currentUrl;manual.download=target.fileName;
      manual.textContent=selected()==="android" ? "Скачать Android APK" : "Скачать файл для ПК";
      const fallback=document.getElementById("fallback-download");fallback.href=currentUrl;fallback.download=target.fileName;
      manual.hidden=false;field.value="";status.textContent="Файл готов. Нажмите кнопку Скачать ниже, чтобы сохранить его.";
    } catch(error) {
      status.textContent=error.name==="OperationError" ? "Ключ не подошёл или файл повреждён. Проверьте ключ и повторите."
        : error.message==="secure_browser_required" ? "Откройте эту страницу в актуальном Chrome или Edge по адресу https://pavliksergeev378-eng.github.io/fitness-agent-downloads/."
        : "Не удалось подготовить файл. Проверьте подключение и повторите.";
    } finally {busy=false;button.disabled=false;form.querySelectorAll('[name="platform"]').forEach(r=>r.disabled=false);}
  });
}
