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
  const form = document.getElementById("download-form");
  const field = document.getElementById("access-key");
  const button = document.getElementById("download-button");
  const status = document.getElementById("status");
  const manual = document.getElementById("manual-download");
  let currentUrl = null;

  form.addEventListener("submit", async event => {
    event.preventDefault();
    const password = field.value.trim();
    if (!password) return;
    button.disabled = true;
    manual.hidden = true;
    status.textContent = "Загружаю защищённый файл. Подождите — это около 29 МБ.";
    try {
      const response = await fetch("./FitnessAgent.enc", { cache: "no-store" });
      if (!response.ok) throw new Error("Download failed");
      status.textContent = "Проверяю ключ и готовлю APK...";
      const apk = await decryptPayload(await response.arrayBuffer(), password);
      if (currentUrl) URL.revokeObjectURL(currentUrl);
      currentUrl = URL.createObjectURL(new Blob([apk], { type: "application/vnd.android.package-archive" }));
      manual.href = currentUrl;
      let version = "0.2.1";
      try {
        const manifestResponse = await fetch("./version.json", { cache: "no-store" });
        if (manifestResponse.ok) {
          const manifest = await manifestResponse.json();
          if (/^[0-9]+(?:\.[0-9]+)*$/.test(String(manifest.versionName))) version = manifest.versionName;
        }
      } catch (_) {}
      manual.download = "FitnessAgent-v" + version + ".apk";
      manual.hidden = false;
      field.value = "";
      status.textContent = "APK готов. Если скачивание не началось, нажмите ссылку ниже.";
      manual.click();
    } catch (error) {
      status.textContent = error.name === "OperationError"
        ? "Ключ не подошёл или файл повреждён. Проверьте ключ и повторите."
        : "Не удалось подготовить APK. Проверьте подключение и повторите.";
    } finally {
      button.disabled = false;
    }
  });
}