const TRANSPORT_FIELD_NAME = "__enc_payload";
const TRANSPORT_KEY_PREFIX = "eventify:";
const TRANSPORT_IV_LENGTH = 12;
const TRANSPORT_AAD = "eventify-panel-v1";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const transportAdditionalData = textEncoder.encode(TRANSPORT_AAD);

const isCryptoAvailable = () => Boolean(window.crypto && window.crypto.subtle);

const toBase64Url = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });

  return window
    .btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
};

const fromBase64Url = (encodedValue) => {
  const base64 = String(encodedValue).replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = window.atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
};

const deriveTransportKey = async (csrfToken) => {
  const digest = await window.crypto.subtle.digest(
    "SHA-256",
    textEncoder.encode(`${TRANSPORT_KEY_PREFIX}${csrfToken}`)
  );

  return window.crypto.subtle.importKey("raw", digest, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
};

const encryptTransportPayload = async (payload, csrfToken) => {
  const key = await deriveTransportKey(csrfToken);
  const iv = window.crypto.getRandomValues(new Uint8Array(TRANSPORT_IV_LENGTH));
  const plaintext = textEncoder.encode(JSON.stringify(payload));
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: transportAdditionalData },
    key,
    plaintext
  );

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return toBase64Url(combined.buffer);
};

const decryptTransportPayload = async (encryptedPayload, csrfToken) => {
  const key = await deriveTransportKey(csrfToken);
  const combined = fromBase64Url(encryptedPayload);

  if (combined.length < TRANSPORT_IV_LENGTH + 1) {
    throw new Error("Encrypted payload is too short.");
  }

  const iv = combined.slice(0, TRANSPORT_IV_LENGTH);
  const ciphertext = combined.slice(TRANSPORT_IV_LENGTH);
  const plaintext = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: transportAdditionalData },
    key,
    ciphertext
  );

  return JSON.parse(textDecoder.decode(plaintext));
};

const appendPayloadValue = (payload, key, value) => {
  if (!Object.prototype.hasOwnProperty.call(payload, key)) {
    payload[key] = value;
    return;
  }

  if (Array.isArray(payload[key])) {
    payload[key].push(value);
    return;
  }

  payload[key] = [payload[key], value];
};

const collectEncryptableFormData = (formData) => {
  const payload = {};

  for (const [name, value] of formData.entries()) {
    if (name === "csrfmiddlewaretoken" || name === TRANSPORT_FIELD_NAME) {
      continue;
    }

    if (value instanceof File) {
      continue;
    }

    appendPayloadValue(payload, name, String(value));
  }

  return payload;
};

const disablePlainFieldsBeforeSubmit = (form) => {
  Array.from(form.elements).forEach((element) => {
    if (!element || !element.name || element.disabled) {
      return;
    }

    if (
      element.name === "csrfmiddlewaretoken" ||
      element.name === TRANSPORT_FIELD_NAME
    ) {
      return;
    }

    if (element.type === "file") {
      return;
    }

    element.disabled = true;
  });
};

const securePostFormSubmission = (form) => {
  form.addEventListener("submit", async (event) => {
    if (form.dataset.transportEncrypted === "1") {
      return;
    }

    const csrfField = form.querySelector("input[name='csrfmiddlewaretoken']");
    const csrfToken = (csrfField && csrfField.value) || "";
    if (!csrfToken) {
      return;
    }

    event.preventDefault();

    const submitter = event.submitter;
    if (submitter && "disabled" in submitter) {
      submitter.disabled = true;
    }

    try {
      const formData = new FormData(form);
      const payload = collectEncryptableFormData(formData);
      if (submitter && submitter.name) {
        appendPayloadValue(payload, submitter.name, submitter.value || "1");
      }

      if (!Object.keys(payload).length) {
        form.dataset.transportEncrypted = "1";
        form.submit();
        return;
      }

      const encryptedPayload = await encryptTransportPayload(payload, csrfToken);
      let encryptedField = form.querySelector(
        `input[name='${TRANSPORT_FIELD_NAME}']`
      );

      if (!encryptedField) {
        encryptedField = document.createElement("input");
        encryptedField.type = "hidden";
        encryptedField.name = TRANSPORT_FIELD_NAME;
        form.appendChild(encryptedField);
      }

      encryptedField.value = encryptedPayload;
      disablePlainFieldsBeforeSubmit(form);

      form.dataset.transportEncrypted = "1";
      form.submit();
    } catch (error) {
      console.error(
        "Panel transport encryption failed. Falling back to plain form submit.",
        error
      );

      if (submitter && "disabled" in submitter) {
        submitter.disabled = false;
      }

      form.dataset.transportEncrypted = "1";
      form.submit();
    }
  });
};

const enableTransportEncryptionForPostForms = () => {
  if (!isCryptoAvailable()) {
    return;
  }

  const forms = document.querySelectorAll("form");
  forms.forEach((form) => {
    if ((form.method || "").toUpperCase() !== "POST") {
      return;
    }

    if (form.dataset.noTransportEncryption === "true") {
      return;
    }

    securePostFormSubmission(form);
  });
};

window.EventifyTransport = {
  fieldName: TRANSPORT_FIELD_NAME,
  encryptPayload: encryptTransportPayload,
  decryptPayload: decryptTransportPayload,
};

const extractTicketTokenFromValue = (rawValue) => {
  const candidate = String(rawValue || "").trim();
  if (!candidate) {
    return "";
  }

  const compactValue = candidate.replace(/\s+/g, "");
  if (normalizeTicketReference(compactValue)) {
    return "";
  }
  const ticketPathPattern = /\/ticket-scan\/([^/?#]+)\/?/i;
  const directMatch = compactValue.match(ticketPathPattern);

  if (directMatch && directMatch[1]) {
    try {
      return decodeURIComponent(directMatch[1]);
    } catch (error) {
      return directMatch[1];
    }
  }

  try {
    const parsedUrl = new URL(candidate, window.location.origin);
    const parsedMatch = parsedUrl.pathname.match(ticketPathPattern);
    if (parsedMatch && parsedMatch[1]) {
      try {
        return decodeURIComponent(parsedMatch[1]);
      } catch (error) {
        return parsedMatch[1];
      }
    }
  } catch (error) {
    // Ignore parse failures and continue with token fallback.
  }

  if (/^[A-Za-z0-9._:-]+$/.test(compactValue)) {
    if (normalizeTicketReference(compactValue)) {
      return "";
    }
    return compactValue;
  }

  return "";
};

const ADMIN_RESET_UNLOCK_KEY = "eventify:admin-reset-unlock";
const ADMIN_RESET_CLICK_KEY = "eventify:admin-reset-clicks";
const ADMIN_RESET_CLICK_TARGET = 10;

const initializeAdminResetUnlock = () => {
  const authRoot = document.querySelector(".auth-page");
  if (!authRoot) {
    return;
  }

  const brand = authRoot.querySelector(".auth-brand");
  if (brand) {
    brand.addEventListener("click", () => {
      try {
        const current = Number.parseInt(
          window.localStorage.getItem(ADMIN_RESET_CLICK_KEY) || "0",
          10
        );
        const next = Number.isNaN(current) ? 1 : current + 1;
        if (next >= ADMIN_RESET_CLICK_TARGET) {
          const unlocked =
            window.localStorage.getItem(ADMIN_RESET_UNLOCK_KEY) === "1";
          if (unlocked) {
            window.localStorage.removeItem(ADMIN_RESET_UNLOCK_KEY);
          } else {
            window.localStorage.setItem(ADMIN_RESET_UNLOCK_KEY, "1");
          }
          window.localStorage.removeItem(ADMIN_RESET_CLICK_KEY);
        } else {
          window.localStorage.setItem(ADMIN_RESET_CLICK_KEY, String(next));
        }
      } catch (error) {
        // Silent fail for locked storage environments.
      }
    });
  }

  const roleSelect = document.querySelector("[data-forgot-password-role]");
  if (roleSelect) {
    try {
      const isUnlocked =
        window.localStorage.getItem(ADMIN_RESET_UNLOCK_KEY) === "1";
      const existing = Array.from(roleSelect.options).find(
        (option) => option.value === "admin"
      );
      if (isUnlocked && !existing) {
        const option = document.createElement("option");
        option.value = "admin";
        option.textContent = "Admin";
        roleSelect.appendChild(option);
      } else if (!isUnlocked && existing) {
        existing.remove();
      }
    } catch (error) {
      // Ignore storage errors.
    }
  }
};


const normalizeTicketReference = (rawValue) => {
  const candidate = String(rawValue || "").trim().toUpperCase();
  const isNewFormat = /^TKT-E[A-Z0-9]+-B[A-Z0-9]+$/.test(candidate);
  const isLegacyFormat = /^TKT-\d+-\d+$/.test(candidate);
  if (!isNewFormat && !isLegacyFormat) {
    return "";
  }
  return candidate;
};

const extractTicketReferenceFromValue = (rawValue) => {
  const candidate = String(rawValue || "").trim();
  if (!candidate) {
    return "";
  }

  const compactValue = candidate.replace(/\s+/g, "");
  const directReference = normalizeTicketReference(compactValue);
  if (directReference) {
    return directReference;
  }

  const embeddedReferenceMatch = candidate.match(
    /TKT-E[A-Z0-9]+-B[A-Z0-9]+|TKT-\d+-\d+/i
  );
  if (embeddedReferenceMatch && embeddedReferenceMatch[0]) {
    const embeddedReference = normalizeTicketReference(embeddedReferenceMatch[0]);
    if (embeddedReference) {
      return embeddedReference;
    }
  }

  try {
    const parsedUrl = new URL(candidate, window.location.origin);
    const queryReference = normalizeTicketReference(parsedUrl.searchParams.get("ticket_id"));
    if (queryReference) {
      return queryReference;
    }
  } catch (error) {
    // Ignore parse failures and continue with regex fallback.
  }

  const queryMatch = compactValue.match(/[?&]ticket_id=([^&#]+)/i);
  if (queryMatch && queryMatch[1]) {
    try {
      const decoded = decodeURIComponent(queryMatch[1]);
      return normalizeTicketReference(decoded);
    } catch (error) {
      return normalizeTicketReference(queryMatch[1]);
    }
  }

  return "";
};

let ticketQrDetector = null;
let jsQrLibraryPromise = null;

const JSQR_LIBRARY_URL = "/static/js/vendor/jsQR.min.js";
const JSQR_CDN_FALLBACK_URL = "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js";
const LIVE_SCAN_INTERVAL_MS = 140;
const LIVE_SCAN_MAX_FRAME_SIZE = 1280;
const IMAGE_SCAN_MAX_FRAME_SIZE = 1800;

const buildTicketScanUrl = (scanTemplate, scanMarker, token) => {
  const relativePath = scanTemplate.replace(scanMarker, encodeURIComponent(token));
  return new URL(relativePath, window.location.origin).toString();
};

const buildTicketLookupUrl = (lookupBaseUrl, ticketReference) => {
  const lookupUrl = new URL(lookupBaseUrl, window.location.origin);
  lookupUrl.searchParams.set("ticket_id", ticketReference);
  return lookupUrl.toString();
};

const resolveTicketScanRedirectUrl = (
  rawValue,
  scanTemplate,
  scanMarker,
  ticketLookupBaseUrl
) => {
  const ticketReference = extractTicketReferenceFromValue(rawValue);
  if (ticketReference && ticketLookupBaseUrl) {
    return buildTicketLookupUrl(ticketLookupBaseUrl, ticketReference);
  }

  const token = extractTicketTokenFromValue(rawValue);
  if (token) {
    return buildTicketScanUrl(scanTemplate, scanMarker, token);
  }

  return "";
};

const getTicketQrDetector = () => {
  if (!window.BarcodeDetector) {
    return null;
  }

  if (ticketQrDetector) {
    return ticketQrDetector;
  }

  try {
    ticketQrDetector = new window.BarcodeDetector({ formats: ["qr_code"] });
    return ticketQrDetector;
  } catch (error) {
    return null;
  }
};

const getBarcodePayloadText = (barcode) =>
  String(
    (barcode && (barcode.rawValue || barcode.displayValue || barcode.value)) || ""
  ).trim();

const detectQrValueWithDetector = async (detector, source) => {
  if (!detector || !source) {
    return "";
  }

  try {
    const barcodes = await detector.detect(source);
    if (!barcodes || !barcodes.length) {
      return "";
    }

    const targetBarcode = barcodes.find((item) => getBarcodePayloadText(item)) || barcodes[0];
    return getBarcodePayloadText(targetBarcode);
  } catch (error) {
    return "";
  }
};

const loadJsQrLibrary = () => {
  if (typeof window.jsQR === "function") {
    return Promise.resolve(window.jsQR);
  }

  if (jsQrLibraryPromise) {
    return jsQrLibraryPromise;
  }

  const loadScriptUrl = (url, loaderKey) =>
    new Promise((resolve) => {
      const selector = `script[data-jsqr-loader='${loaderKey}']`;
      const existingScript = document.querySelector(selector);
      if (existingScript) {
        if (typeof window.jsQR === "function") {
          resolve(window.jsQR);
          return;
        }

        existingScript.addEventListener("load", () =>
          resolve(typeof window.jsQR === "function" ? window.jsQR : null)
        );
        existingScript.addEventListener("error", () => resolve(null));
        return;
      }

      const script = document.createElement("script");
      script.src = url;
      script.async = true;
      script.defer = true;
      script.dataset.jsqrLoader = loaderKey;
      script.onload = () => resolve(typeof window.jsQR === "function" ? window.jsQR : null);
      script.onerror = () => resolve(null);
      document.head.appendChild(script);
    });

  jsQrLibraryPromise = (async () => {
    const localResult = await loadScriptUrl(JSQR_LIBRARY_URL, "local");
    if (typeof localResult === "function") {
      return localResult;
    }

    const fallbackResult = await loadScriptUrl(JSQR_CDN_FALLBACK_URL, "cdn");
    if (typeof fallbackResult === "function") {
      return fallbackResult;
    }

    return null;
  })().finally(() => {
    if (typeof window.jsQR !== "function") {
      jsQrLibraryPromise = null;
    }
  });

  return jsQrLibraryPromise;
};

const readFileAsDataUrl = (file) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(new Error("File could not be read."));
    reader.readAsDataURL(file);
  });

const loadImageElementFromFile = async (file) => {
  const dataUrl = await readFileAsDataUrl(file);

  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("Image could not be loaded."));
    image.src = dataUrl;
  });
};

const decodeQrWithJsQr = async (imageFile) => {
  const jsQr = await loadJsQrLibrary();
  if (typeof jsQr !== "function") {
    return "";
  }

  const imageElement = await loadImageElementFromFile(imageFile);
  const width = imageElement.naturalWidth || imageElement.width || 0;
  const height = imageElement.naturalHeight || imageElement.height || 0;
  if (!width || !height) {
    return "";
  }

  const decodeFromCrop = (crop) => {
    const sourceX = Math.max(0, Math.floor((crop && crop.x) || 0));
    const sourceY = Math.max(0, Math.floor((crop && crop.y) || 0));
    const sourceWidth = Math.max(
      2,
      Math.min(width - sourceX, Math.floor((crop && crop.width) || (width - sourceX)))
    );
    const sourceHeight = Math.max(
      2,
      Math.min(height - sourceY, Math.floor((crop && crop.height) || (height - sourceY)))
    );

    const scale = Math.min(
      1,
      IMAGE_SCAN_MAX_FRAME_SIZE / Math.max(sourceWidth, sourceHeight)
    );
    const frameWidth = Math.max(2, Math.floor(sourceWidth * scale));
    const frameHeight = Math.max(2, Math.floor(sourceHeight * scale));

    const canvas = document.createElement("canvas");
    canvas.width = frameWidth;
    canvas.height = frameHeight;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) {
      return "";
    }

    context.drawImage(
      imageElement,
      sourceX,
      sourceY,
      sourceWidth,
      sourceHeight,
      0,
      0,
      frameWidth,
      frameHeight
    );
    const imageData = context.getImageData(0, 0, frameWidth, frameHeight);
    const result = jsQr(imageData.data, frameWidth, frameHeight, {
      inversionAttempts: "attemptBoth",
    });
    if (!result || !result.data) {
      return "";
    }
    return String(result.data);
  };

  const crops = [
    null,
    { x: width * 0.06, y: height * 0.06, width: width * 0.88, height: height * 0.88 },
    { x: width * 0.12, y: height * 0.12, width: width * 0.76, height: height * 0.76 },
    { x: width * 0.2, y: height * 0.2, width: width * 0.6, height: height * 0.6 },
  ];

  for (const crop of crops) {
    const decodedValue = decodeFromCrop(crop);
    if (decodedValue) {
      return decodedValue;
    }
  }

  return "";
};

const drawVideoFrameToCanvas = (videoElement, canvasElement, crop, mirror = false) => {
  if (!canvasElement || !videoElement) {
    return null;
  }

  const videoWidth = videoElement.videoWidth || 0;
  const videoHeight = videoElement.videoHeight || 0;
  if (!videoWidth || !videoHeight) {
    return null;
  }

  const sourceX = Math.max(0, Math.floor((crop && crop.x) || 0));
  const sourceY = Math.max(0, Math.floor((crop && crop.y) || 0));
  const sourceWidth = Math.max(
    2,
    Math.min(videoWidth - sourceX, Math.floor((crop && crop.width) || (videoWidth - sourceX)))
  );
  const sourceHeight = Math.max(
    2,
    Math.min(
      videoHeight - sourceY,
      Math.floor((crop && crop.height) || (videoHeight - sourceY))
    )
  );

  const scale = Math.min(
    1,
    LIVE_SCAN_MAX_FRAME_SIZE / Math.max(sourceWidth, sourceHeight)
  );
  const frameWidth = Math.max(2, Math.floor(sourceWidth * scale));
  const frameHeight = Math.max(2, Math.floor(sourceHeight * scale));

  canvasElement.width = frameWidth;
  canvasElement.height = frameHeight;
  const context = canvasElement.getContext("2d", { willReadFrequently: true });
  if (!context) {
    return null;
  }

  context.save();
  context.clearRect(0, 0, frameWidth, frameHeight);
  if (mirror) {
    context.translate(frameWidth, 0);
    context.scale(-1, 1);
  }
  context.drawImage(
    videoElement,
    sourceX,
    sourceY,
    sourceWidth,
    sourceHeight,
    0,
    0,
    frameWidth,
    frameHeight
  );
  context.restore();

  return { frameWidth, frameHeight, context };
};

const decodeQrFromVideoFrame = (
  videoElement,
  canvasElement,
  jsQrFn,
  crop,
  mirror = false
) => {
  if (typeof jsQrFn !== "function" || !canvasElement || !videoElement) {
    return "";
  }

  const frameMeta = drawVideoFrameToCanvas(videoElement, canvasElement, crop, mirror);
  if (!frameMeta) {
    return "";
  }
  const imageData = frameMeta.context.getImageData(0, 0, frameMeta.frameWidth, frameMeta.frameHeight);
  const qrResult = jsQrFn(imageData.data, frameMeta.frameWidth, frameMeta.frameHeight, {
    inversionAttempts: "attemptBoth",
  });

  if (!qrResult || !qrResult.data) {
    return "";
  }

  return String(qrResult.data);
};

const detectQrRawValueFromImage = async (imageFile) => {
  const detector = getTicketQrDetector();

  if (detector) {
    try {
      if (typeof window.createImageBitmap === "function") {
        const imageBitmap = await window.createImageBitmap(imageFile);
        try {
          const barcodes = await detector.detect(imageBitmap);
          if (barcodes && barcodes.length) {
            const targetBarcode =
              barcodes.find((item) => getBarcodePayloadText(item)) || barcodes[0];
            const barcodeValue = getBarcodePayloadText(targetBarcode);
            if (barcodeValue) {
              return barcodeValue;
            }
          }
        } finally {
          if (typeof imageBitmap.close === "function") {
            imageBitmap.close();
          }
        }
      } else {
        const imageElement = await loadImageElementFromFile(imageFile);
        const barcodes = await detector.detect(imageElement);
        if (barcodes && barcodes.length) {
          const targetBarcode =
            barcodes.find((item) => getBarcodePayloadText(item)) || barcodes[0];
          const barcodeValue = getBarcodePayloadText(targetBarcode);
          if (barcodeValue) {
            return barcodeValue;
          }
        }
      }
    } catch (error) {
      console.error("BarcodeDetector scan failed", error);
    }
  }

  try {
    return await decodeQrWithJsQr(imageFile);
  } catch (error) {
    console.error("jsQR scan failed", error);
    return "";
  }
};

const detectQrRawValueFromVideo = async (videoElement, canvasElement, jsQrFn) => {
  if (!videoElement) {
    return "";
  }

  const videoWidth = videoElement.videoWidth || 0;
  const videoHeight = videoElement.videoHeight || 0;
  if (!videoWidth || !videoHeight) {
    return "";
  }

  const centerCrop = {
    x: videoWidth * 0.12,
    y: videoHeight * 0.12,
    width: videoWidth * 0.76,
    height: videoHeight * 0.76,
  };
  const tightCenterCrop = {
    x: videoWidth * 0.2,
    y: videoHeight * 0.2,
    width: videoWidth * 0.6,
    height: videoHeight * 0.6,
  };

  const decodeAttempts = [
    { crop: null, mirror: false },
    { crop: centerCrop, mirror: false },
    { crop: tightCenterCrop, mirror: false },
    { crop: null, mirror: true },
    { crop: centerCrop, mirror: true },
    { crop: tightCenterCrop, mirror: true },
  ];

  const detector = getTicketQrDetector();
  if (detector) {
    const directDetectorValue = await detectQrValueWithDetector(detector, videoElement);
    if (directDetectorValue) {
      return directDetectorValue;
    }

    if (canvasElement) {
      for (const attempt of decodeAttempts) {
        const frameMeta = drawVideoFrameToCanvas(
          videoElement,
          canvasElement,
          attempt.crop,
          attempt.mirror
        );
        if (!frameMeta) {
          continue;
        }

        const frameDetectorValue = await detectQrValueWithDetector(detector, canvasElement);
        if (frameDetectorValue) {
          return frameDetectorValue;
        }
      }
    }
  }

  for (const attempt of decodeAttempts) {
    const scanResult = decodeQrFromVideoFrame(
      videoElement,
      canvasElement,
      jsQrFn,
      attempt.crop,
      attempt.mirror
    );
    if (scanResult) {
      return scanResult;
    }
  }

  return "";
};

const createMobileQrScannerModal = () => {
  const existing = document.querySelector("[data-mobile-qr-modal]");
  if (existing) {
    return {
      root: existing,
      video: existing.querySelector("[data-mobile-qr-video]"),
      status: existing.querySelector("[data-mobile-qr-status]"),
      close: existing.querySelector("[data-mobile-qr-close]"),
      fallback: existing.querySelector("[data-mobile-qr-fallback]"),
    };
  }

  const modalRoot = document.createElement("div");
  modalRoot.className = "mobile-qr-modal";
  modalRoot.hidden = true;
  modalRoot.setAttribute("data-mobile-qr-modal", "1");
  modalRoot.innerHTML = `
    <div class="mobile-qr-modal-card" role="dialog" aria-modal="true" aria-label="Ticket scanner">
      <div class="mobile-qr-modal-head">
        <h3>Ticket Scanner</h3>
        <button type="button" class="small-btn mobile-qr-close-btn" data-mobile-qr-close>Close</button>
      </div>
      <div class="mobile-qr-video-wrap">
        <video data-mobile-qr-video autoplay playsinline muted webkit-playsinline></video>
        <div class="mobile-qr-target" aria-hidden="true"></div>
      </div>
      <p class="mobile-qr-status" data-mobile-qr-status>Starting camera...</p>
      <button type="button" class="small-btn mobile-qr-fallback-btn" data-mobile-qr-fallback>Use Photo Mode</button>
    </div>
  `;

  document.body.appendChild(modalRoot);
  return {
    root: modalRoot,
    video: modalRoot.querySelector("[data-mobile-qr-video]"),
    status: modalRoot.querySelector("[data-mobile-qr-status]"),
    close: modalRoot.querySelector("[data-mobile-qr-close]"),
    fallback: modalRoot.querySelector("[data-mobile-qr-fallback]"),
  };
};

const showMobileQrScanFailure = () => {
  window.alert(
    "QR scan failed. Please take a clear QR photo or use the dashboard scanner input."
  );
};

const initializeMobileQrQuickScanner = () => {
  const qrLaunchButtons = Array.from(
    document.querySelectorAll("[data-mobile-qr-launch], [data-mobile-qr-panel-open]")
  );
  const qrLaunchButton =
    qrLaunchButtons.find((button) => button.hasAttribute("data-mobile-qr-launch")) ||
    qrLaunchButtons[0];
  const qrCaptureInput = document.querySelector("[data-mobile-qr-capture]");

  if (!qrLaunchButton || !qrCaptureInput || !qrLaunchButtons.length) {
    return;
  }

  const isMobileUserAgent = /Android|iPhone|iPad|iPod|webOS|BlackBerry|IEMobile|Opera Mini/i.test(
    navigator.userAgent || ""
  );
  const hasCoarsePointer = window.matchMedia
    ? window.matchMedia("(pointer: coarse)").matches
    : false;
  const isTouchDevice =
    ("ontouchstart" in window) ||
    (navigator.maxTouchPoints && navigator.maxTouchPoints > 0);
  const isMobileViewport = window.matchMedia
    ? window.matchMedia("(max-width: 992px)").matches
    : window.innerWidth <= 992;
  const isLikelyMobileClient =
    Boolean(
      isMobileUserAgent ||
        hasCoarsePointer ||
        isTouchDevice ||
        isMobileViewport
    );

  if (!isLikelyMobileClient) {
    qrLaunchButtons.forEach((button) => {
      button.style.display = "none";
    });
    qrCaptureInput.remove();
    return;
  }

  const scanTemplate = qrLaunchButton.dataset.ticketScanTemplate || "";
  const scanMarker = qrLaunchButton.dataset.ticketScanMarker || "__ticket_token__";
  const ticketLookupBaseUrl = qrLaunchButton.dataset.ticketLookupUrl || "/ticket-lookup/";
  const fallbackHref = qrLaunchButton.getAttribute("href") || "/dashboard/#ticket-scanner";

  if (!scanTemplate) {
    return;
  }

  const scannerModal = createMobileQrScannerModal();
  const scannerCanvas = document.createElement("canvas");
  let scannerStream = null;
  let scannerTimerId = null;
  let scannerActive = false;
  let scannerBusy = false;
  let jsQrFn = null;
  let isProcessingCapture = false;
  let ignoreLaunchUntil = 0;
  let isOpeningScanner = false;
  let scannerSessionToken = 0;
  let isNavigatingFromLiveScan = false;

  const canUseLiveScanner = () =>
    Boolean(
      window.isSecureContext &&
        navigator.mediaDevices &&
        navigator.mediaDevices.getUserMedia
    );

  const requestBestCameraStream = async () => {
    const hdVideoPreference = {
      width: { ideal: 1920 },
      height: { ideal: 1080 },
    };
    const constraintsList = [
      { video: { facingMode: { exact: "environment" }, ...hdVideoPreference }, audio: false },
      { video: { facingMode: "environment", ...hdVideoPreference }, audio: false },
      { video: { facingMode: { ideal: "environment" }, ...hdVideoPreference }, audio: false },
      { video: true, audio: false },
    ];

    let lastError = null;
    for (const constraints of constraintsList) {
      try {
        return await navigator.mediaDevices.getUserMedia(constraints);
      } catch (error) {
        lastError = error;
      }
    }

    throw lastError || new Error("No camera stream available.");
  };

  const attachStreamToVideo = async (videoElement, stream) => {
    if (!videoElement) {
      throw new Error("Scanner video element missing.");
    }

    videoElement.srcObject = stream;
    videoElement.muted = true;
    videoElement.autoplay = true;
    videoElement.setAttribute("playsinline", "");
    videoElement.setAttribute("webkit-playsinline", "");

    await new Promise((resolve) => {
      let settled = false;
      const finish = () => {
        if (settled) {
          return;
        }
        settled = true;
        resolve();
      };

      const timeoutId = window.setTimeout(finish, 1200);
      videoElement.onloadedmetadata = () => {
        window.clearTimeout(timeoutId);
        finish();
      };
    });

    await videoElement.play();
    await new Promise((resolve) => window.setTimeout(resolve, 300));
  };

  const updateScannerStatus = (message, isError = false) => {
    if (!scannerModal.status) {
      return;
    }

    scannerModal.status.textContent = message;
    scannerModal.status.classList.toggle("error", Boolean(isError));
  };

  const stopLiveScanner = () => {
    scannerActive = false;
    isOpeningScanner = false;
    isNavigatingFromLiveScan = false;
    if (scannerTimerId) {
      window.clearTimeout(scannerTimerId);
      scannerTimerId = null;
    }

    if (scannerStream) {
      scannerStream.getTracks().forEach((track) => track.stop());
      scannerStream = null;
    }

    if (scannerModal.video && scannerModal.video.srcObject) {
      scannerModal.video.pause();
      scannerModal.video.srcObject = null;
    }
  };

  const closeLiveScanner = () => {
    scannerSessionToken += 1;
    stopLiveScanner();
    if (scannerModal.root) {
      scannerModal.root.hidden = true;
      scannerModal.root.style.display = "none";
      scannerModal.root.style.pointerEvents = "none";
    }
    document.body.classList.remove("mobile-qr-modal-open");
  };

  const closeScannerFromAction = (event) => {
    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }
    ignoreLaunchUntil = Date.now() + 700;
    closeLiveScanner();
  };

  const scheduleLiveScan = () => {
    if (!scannerActive || isNavigatingFromLiveScan) {
      return;
    }

    scannerTimerId = window.setTimeout(async () => {
      if (!scannerActive || scannerBusy || isNavigatingFromLiveScan) {
        scheduleLiveScan();
        return;
      }

      if (
        !scannerModal.video ||
        scannerModal.video.readyState < HTMLMediaElement.HAVE_CURRENT_DATA
      ) {
        scheduleLiveScan();
        return;
      }

      scannerBusy = true;
      try {
        const rawValue = await detectQrRawValueFromVideo(
          scannerModal.video,
          scannerCanvas,
          jsQrFn
        );
        const redirectUrl = resolveTicketScanRedirectUrl(
          rawValue,
          scanTemplate,
          scanMarker,
          ticketLookupBaseUrl
        );
        if (redirectUrl) {
          isNavigatingFromLiveScan = true;
          updateScannerStatus("QR detected. Opening ticket...");
          closeLiveScanner();
          window.location.assign(redirectUrl);
          return;
        }
      } catch (error) {
        console.error("Live mobile QR scan failed", error);
      } finally {
        scannerBusy = false;
      }

      scheduleLiveScan();
    }, LIVE_SCAN_INTERVAL_MS);
  };

  const openLiveScanner = async () => {
    if (scannerActive || isProcessingCapture || isOpeningScanner) {
      return;
    }
    isOpeningScanner = true;
    const sessionToken = scannerSessionToken + 1;
    scannerSessionToken = sessionToken;

    if (!canUseLiveScanner()) {
      updateScannerStatus(
        "Live scanner unavailable. Switching to photo mode.",
        true
      );
      window.alert(
        "Live camera scan is unavailable on this device/network. Allow camera permission and open the site on HTTPS for live scanning."
      );
      isOpeningScanner = false;
      qrCaptureInput.click();
      return;
    }

    if (scannerModal.root) {
      scannerModal.root.hidden = false;
      scannerModal.root.style.display = "grid";
      scannerModal.root.style.pointerEvents = "auto";
    }
    document.body.classList.add("mobile-qr-modal-open");
    updateScannerStatus("Starting camera...");

    try {
      scannerStream = await requestBestCameraStream();
      if (sessionToken !== scannerSessionToken) {
        if (scannerStream) {
          scannerStream.getTracks().forEach((track) => track.stop());
        }
        return;
      }
      await attachStreamToVideo(scannerModal.video, scannerStream);
      if (sessionToken !== scannerSessionToken) {
        closeLiveScanner();
        return;
      }

      const hasPreview =
        scannerModal.video &&
        scannerModal.video.videoWidth > 0 &&
        scannerModal.video.videoHeight > 0;
      if (!hasPreview) {
        throw new Error("Camera preview could not start.");
      }

      jsQrFn = await loadJsQrLibrary();
      if (sessionToken !== scannerSessionToken) {
        closeLiveScanner();
        return;
      }
      if (!jsQrFn && !getTicketQrDetector()) {
        throw new Error("No QR decoding engine available.");
      }
      scannerActive = true;
      isOpeningScanner = false;
      updateScannerStatus("Point the QR code inside the frame.");
      scheduleLiveScan();
    } catch (error) {
      console.error("Unable to start live scanner", error);
      closeLiveScanner();
      window.alert(
        "Camera permission blocked or unavailable. Using photo mode instead."
      );
      qrCaptureInput.click();
    }
  };

  const launchScannerFromAction = (event) => {
    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }

    if (Date.now() < ignoreLaunchUntil) {
      return;
    }
    if (isProcessingCapture || scannerActive || isOpeningScanner) {
      return;
    }
    openLiveScanner();
  };

  qrLaunchButtons.forEach((launchButton) => {
    ["click", "touchend", "pointerup"].forEach((eventName) => {
      launchButton.addEventListener(eventName, launchScannerFromAction, {
        passive: false,
      });
    });
  });

  if (scannerModal.close) {
    ["click", "touchend", "pointerup"].forEach((eventName) => {
      scannerModal.close.addEventListener(eventName, closeScannerFromAction, {
        passive: false,
        capture: true,
      });
    });
  }

  if (scannerModal.fallback) {
    scannerModal.fallback.addEventListener("click", () => {
      closeLiveScanner();
      qrCaptureInput.click();
    });
  }

  if (scannerModal.root) {
    ["click", "touchend", "pointerup"].forEach((eventName) => {
      scannerModal.root.addEventListener(
        eventName,
        (event) => {
          if (
            event.target === scannerModal.root ||
            (event.target && event.target.closest("[data-mobile-qr-close]"))
          ) {
            closeScannerFromAction(event);
          }
        },
        { passive: false, capture: true }
      );
    });
  }

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && scannerModal.root && !scannerModal.root.hidden) {
      closeLiveScanner();
    }
  });

  qrCaptureInput.addEventListener("change", async () => {
    if (isProcessingCapture) {
      return;
    }

    const selectedFile =
      qrCaptureInput.files && qrCaptureInput.files[0] ? qrCaptureInput.files[0] : null;
    qrCaptureInput.value = "";

    if (!selectedFile) {
      return;
    }

    isProcessingCapture = true;
    try {
      const rawValue = await detectQrRawValueFromImage(selectedFile);
      const redirectUrl = resolveTicketScanRedirectUrl(
        rawValue,
        scanTemplate,
        scanMarker,
        ticketLookupBaseUrl
      );
      if (redirectUrl) {
        window.location.assign(redirectUrl);
        return;
      }
    } catch (error) {
      console.error("Mobile QR quick scan failed", error);
    } finally {
      isProcessingCapture = false;
    }

    showMobileQrScanFailure();
    window.location.assign(fallbackHref);
  });

  window.addEventListener("pagehide", closeLiveScanner);
};

const initializeDashboardTicketScanner = () => {
  const scannerRoot = document.querySelector("[data-ticket-scanner]");
  if (!scannerRoot) {
    return;
  }

  const lookupBaseUrl = scannerRoot.dataset.ticketLookupUrl || "";
  if (!lookupBaseUrl) {
    return;
  }

  const controlGroups = Array.from(
    scannerRoot.querySelectorAll("[data-ticket-scan-controls]")
  );
  if (!controlGroups.length) {
    controlGroups.push(scannerRoot);
  }

  const bindPressEvents = (target, handler) => {
    if (!target) {
      return;
    }

    let lastInvokeAt = 0;
    const INVOKE_GUARD_MS = 300;

    ["click", "touchend", "pointerup"].forEach((eventName) => {
      target.addEventListener(eventName, (event) => {
        const now = Date.now();
        if (now - lastInvokeAt < INVOKE_GUARD_MS) {
          if (eventName !== "click") {
            event.preventDefault();
            event.stopPropagation();
          }
          return;
        }
        lastInvokeAt = now;

        if (eventName !== "click") {
          event.preventDefault();
          event.stopPropagation();
        }
        handler(event);
      });
    });
  };

  controlGroups.forEach((group) => {
    const manualInput = group.querySelector("[data-ticket-scan-manual]");
    const openButton = group.querySelector("[data-ticket-scan-open]");
    const statusElement = group.querySelector("[data-ticket-scan-status]");

    if (!manualInput || !openButton || !statusElement) {
      return;
    }

    const setStatus = (message, tone = "info") => {
      statusElement.textContent = message;
      statusElement.classList.remove("success", "error");

      if (tone === "success") {
        statusElement.classList.add("success");
      } else if (tone === "error") {
        statusElement.classList.add("error");
      }
    };

    const openManualValue = () => {
      const ticketReference = normalizeTicketReference(manualInput.value || "");
      if (!ticketReference) {
        setStatus("Enter valid Ticket ID like TKT-E0001-B000001.", "error");
        return;
      }

      setStatus("Checking ticket ID...", "success");
      window.location.assign(
        `${lookupBaseUrl}?ticket_id=${encodeURIComponent(ticketReference)}`
      );
    };

    bindPressEvents(openButton, openManualValue);
    manualInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        openManualValue();
      }
    });

    setStatus("Enter Ticket ID and tap Open.");
  });
};

const initializeEventParticipantsToggle = () => {
  const toggleButtons = document.querySelectorAll("[data-participants-toggle]");
  if (!toggleButtons.length) {
    return;
  }

  toggleButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const targetId = button.getAttribute("data-target");
      if (!targetId) {
        return;
      }

      const targetRow = document.getElementById(targetId);
      if (!targetRow) {
        return;
      }

      const isOpen = targetRow.classList.toggle("show");
      button.setAttribute("aria-expanded", isOpen ? "true" : "false");
      button.textContent = isOpen ? "Hide" : "View";
      if (isOpen) {
        targetRow.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    });
  });
};

const initializeSupportAI = () => {
  const root = document.querySelector("[data-support-ai-root]");
  if (!root) {
    return;
  }

  const stateNode = document.getElementById("support-ai-state");
  let conversation = null;
  if (stateNode && stateNode.textContent) {
    try {
      conversation = JSON.parse(stateNode.textContent);
    } catch (error) {
      console.error("Failed to parse support AI state.", error);
    }
  }

  const startUrl = root.dataset.startUrl || "";
  const messageUrlTemplate = root.dataset.messageUrlTemplate || "";
  const handoffUrlTemplate = root.dataset.handoffUrlTemplate || "";
  const transcript = root.querySelector("[data-support-ai-messages]");
  const alertBox = root.querySelector("[data-support-ai-alert]");
  const startButton = root.querySelector("[data-support-ai-start]");
  const handoffButton = root.querySelector("[data-support-ai-handoff]");
  const composeForm = root.querySelector("[data-support-ai-form]");
  const textarea = composeForm
    ? composeForm.querySelector("textarea[name='message']")
    : null;
  const sendButton = composeForm
    ? composeForm.querySelector("[data-support-ai-send]")
    : null;

  const getCsrfToken = () => {
    const csrfField = composeForm
      ? composeForm.querySelector("input[name='csrfmiddlewaretoken']")
      : null;
    return (csrfField && csrfField.value) || "";
  };

  const buildConversationUrl = (template, conversationId) =>
    template.replace("/0/", `/${conversationId}/`);

  const setBusy = (isBusy) => {
    if (startButton) {
      startButton.disabled = Boolean(isBusy);
    }
    if (sendButton) {
      sendButton.disabled =
        Boolean(isBusy) || !conversation || conversation.status !== "active";
    }
    if (handoffButton) {
      handoffButton.disabled =
        Boolean(isBusy) || !conversation || conversation.status !== "active";
    }
    if (textarea) {
      textarea.disabled = Boolean(isBusy) || !conversation || conversation.status !== "active";
    }
  };

  const setAlert = (message, type = "error") => {
    if (!alertBox) {
      return;
    }

    if (!message) {
      alertBox.hidden = true;
      alertBox.textContent = "";
      alertBox.className = "flash flash-error support-ai-alert";
      return;
    }

    alertBox.hidden = false;
    alertBox.textContent = message;
    alertBox.className =
      type === "success"
        ? "flash flash-success support-ai-alert"
        : "flash flash-error support-ai-alert";
  };

  const renderConversation = () => {
    if (!transcript) {
      return;
    }

    transcript.innerHTML = "";
    if (!conversation || !Array.isArray(conversation.messages) || !conversation.messages.length) {
      const empty = document.createElement("div");
      empty.className = "support-ai-empty";
      empty.textContent =
        "Start a chat to get quick help with bookings, payments, tickets, or your account.";
      transcript.appendChild(empty);
    } else {
      conversation.messages.forEach((item) => {
        const article = document.createElement("article");
        article.className = `support-ai-message support-ai-message-${item.sender_type}`;

        const role = document.createElement("span");
        role.className = "support-ai-role";
        role.textContent = item.sender_type;

        const content = document.createElement("p");
        content.textContent = item.content || "";

        const meta = document.createElement("small");
        meta.textContent = item.created_at || "";

        article.appendChild(role);
        article.appendChild(content);
        article.appendChild(meta);
        transcript.appendChild(article);
      });
      transcript.scrollTop = transcript.scrollHeight;
    }

    if (startButton) {
      startButton.textContent =
        conversation && conversation.status === "active" ? "Resume Chat" : "Start AI Chat";
    }
    setBusy(false);
  };

  const postForm = async (url, formData = new FormData()) => {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "X-CSRFToken": getCsrfToken(),
        "X-Requested-With": "XMLHttpRequest",
      },
      body: formData,
      credentials: "same-origin",
    });
    let payload = {};
    try {
      payload = await response.json();
    } catch (error) {
      payload = { ok: false, error: "Unexpected response from support assistant." };
    }
    if (!response.ok || payload.ok === false) {
      throw new Error(
        (payload && payload.error) ||
          "AI assistant is unavailable right now. You can still submit a support ticket."
      );
    }
    return payload;
  };

  const ensureConversation = async () => {
    if (conversation && conversation.status === "active") {
      return conversation;
    }

    const payload = await postForm(startUrl);
    conversation = payload.conversation || null;
    renderConversation();
    return conversation;
  };

  if (startButton) {
    startButton.addEventListener("click", async () => {
      setAlert("");
      setBusy(true);
      try {
        await ensureConversation();
      } catch (error) {
        setAlert(error.message || "Unable to start AI chat right now.");
        setBusy(false);
      }
    });
  }

  if (composeForm) {
    composeForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      setAlert("");

      const message = textarea ? textarea.value.trim() : "";
      if (!message) {
        setAlert("Please enter a message.");
        return;
      }

      setBusy(true);
      try {
        const activeConversation = await ensureConversation();
        const formData = new FormData();
        formData.append("message", message);
        const payload = await postForm(
          buildConversationUrl(messageUrlTemplate, activeConversation.id),
          formData
        );
        conversation = payload.conversation || activeConversation;
        if (textarea) {
          textarea.value = "";
        }
        renderConversation();
      } catch (error) {
        setAlert(error.message || "Unable to send your message right now.");
        setBusy(false);
      }
    });
  }

  if (handoffButton) {
    handoffButton.addEventListener("click", async () => {
      setAlert("");
      if (!conversation || conversation.status !== "active") {
        setAlert("Start a chat before handing it off.");
        return;
      }

      setBusy(true);
      try {
        const payload = await postForm(
          buildConversationUrl(handoffUrlTemplate, conversation.id)
        );
        setAlert(
          `Conversation handed off successfully as ticket #${payload.ticket_id}.`,
          "success"
        );
        window.setTimeout(() => {
          window.location.assign(payload.redirect_url || root.dataset.supportUrl || window.location.href);
        }, 700);
      } catch (error) {
        setAlert(error.message || "Unable to hand off this conversation right now.");
        setBusy(false);
      }
    });
  }

  renderConversation();
};

document.addEventListener("DOMContentLoaded", () => {
  enableTransportEncryptionForPostForms();
  initializeMobileQrQuickScanner();
  initializeDashboardTicketScanner();
  initializeEventParticipantsToggle();
  initializeSupportAI();
  initializeAdminResetUnlock();

  const sidebar = document.getElementById("sidebar");
  const toggle = document.querySelector("[data-toggle-sidebar]");
  const sidebarBackdrop = document.querySelector("[data-sidebar-backdrop]");

  if (toggle && sidebar) {
    const setSidebarState = (isOpen) => {
      sidebar.classList.toggle("show", Boolean(isOpen));
      document.body.classList.toggle("sidebar-open", Boolean(isOpen));
      if (sidebarBackdrop) {
        sidebarBackdrop.hidden = !isOpen;
      }
    };

    toggle.addEventListener("click", () => {
      setSidebarState(!sidebar.classList.contains("show"));
    });

    if (sidebarBackdrop) {
      sidebarBackdrop.addEventListener("click", () => {
        setSidebarState(false);
      });
    }

    sidebar.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        if (window.innerWidth <= 992) {
          setSidebarState(false);
        }
      });
    });

    window.addEventListener("resize", () => {
      if (window.innerWidth > 992) {
        setSidebarState(false);
      }
    });
  }

  const flash = document.querySelector("[data-auto-dismiss='true']");
  if (flash) {
    window.setTimeout(() => {
      flash.remove();
    }, 3500);
  }

  document.querySelectorAll("[data-confirm]").forEach((btn) => {
    btn.addEventListener("click", (event) => {
      const message = btn.getAttribute("data-confirm") || "Are you sure?";
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });

  const upcomingSwiperElement = document.querySelector(".upcoming-swiper");

  // Initialize Swiper only when the section exists and library is loaded.
  if (upcomingSwiperElement && typeof window.Swiper !== "undefined") {
    new window.Swiper(upcomingSwiperElement, {
      loop: true,
      centeredSlides: true,
      slidesPerView: 1.5,
      spaceBetween: 20,
      speed: 700,
      grabCursor: true,
      watchSlidesProgress: true,
      keyboard: {
        enabled: true,
      },
      autoplay: {
        delay: 2500,
        disableOnInteraction: false,
        pauseOnMouseEnter: true,
      },
      breakpoints: {
        0: {
          slidesPerView: 1,
          spaceBetween: 20,
        },
        768: {
          slidesPerView: 1.3,
          spaceBetween: 20,
        },
        1200: {
          slidesPerView: 1.5,
          spaceBetween: 20,
        },
      },
    });
  }

  const albumModal = document.querySelector("[data-album-modal]");
  const albumTriggers = document.querySelectorAll("[data-album-trigger='true']");

  if (albumModal && albumTriggers.length) {
    const albumMedia = albumModal.querySelector("[data-album-media]");
    const albumFields = {
      title: albumModal.querySelector("[data-album-field='title']"),
      category: albumModal.querySelector("[data-album-field='category']"),
      date: albumModal.querySelector("[data-album-field='date']"),
      time: albumModal.querySelector("[data-album-field='time']"),
      location: albumModal.querySelector("[data-album-field='location']"),
      organizer: albumModal.querySelector("[data-album-field='organizer']"),
      contact: albumModal.querySelector("[data-album-field='contact']"),
      price: albumModal.querySelector("[data-album-field='price']"),
      description: albumModal.querySelector("[data-album-field='description']"),
    };

    const closeAlbumModal = () => {
      albumModal.hidden = true;
      document.body.classList.remove("modal-open");
    };

    const setField = (fieldName, value) => {
      const target = albumFields[fieldName];
      if (target) {
        target.textContent = (value || "").trim() || "-";
      }
    };

    const openAlbumModal = (trigger) => {
      const imageUrl = (trigger.dataset.albumImage || "").trim();
      if (albumMedia) {
        albumMedia.style.backgroundImage = imageUrl
          ? `url("${imageUrl.replace(/"/g, '\\"')}")`
          : "none";
      }

      setField("title", trigger.dataset.albumTitle);
      setField("category", trigger.dataset.albumCategory);
      setField("date", trigger.dataset.albumDate);
      setField("time", trigger.dataset.albumTime);
      setField("location", trigger.dataset.albumLocation);
      setField("organizer", trigger.dataset.albumOrganizer);
      setField("contact", trigger.dataset.albumContact);
      setField("price", trigger.dataset.albumPrice);
      setField("description", trigger.dataset.albumDescription);

      albumModal.hidden = false;
      document.body.classList.add("modal-open");
    };

    albumTriggers.forEach((trigger) => {
      trigger.addEventListener("click", (event) => {
        if (
          event.defaultPrevented ||
          event.button !== 0 ||
          event.metaKey ||
          event.ctrlKey ||
          event.shiftKey ||
          event.altKey
        ) {
          return;
        }
        event.preventDefault();
        openAlbumModal(trigger);
      });
    });

    albumModal
      .querySelectorAll("[data-album-close]")
      .forEach((closeButton) => {
        closeButton.addEventListener("click", closeAlbumModal);
      });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && !albumModal.hidden) {
        closeAlbumModal();
      }
    });
  }
});
