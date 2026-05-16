import express from "express";
import crypto from "crypto";
import { randomUUID } from "crypto";

const app = express();
app.use(express.json());

// ─── CONFIGURACIÓN ───────────────────────────────────────────────────────────
// SHA-256 de tu firma oficial (Play Store / keystore)
// Obtenla con: keytool -printcert -jarfile app-release.apk | grep SHA256
const VALID_SIGNATURES = new Set([
    "PEGA_AQUI_TU_SHA256_DE_PLAY_STORE",
]);

// Debe coincidir byte a byte con SECRET[] en native-lib.cpp
const HMAC_SECRET = Buffer.from([
    0x4b, 0x39, 0x21, 0x7f, 0x4e, 0x2a, 0x55, 0x68,
    0x3c, 0x91, 0xb2, 0x0d, 0x6e, 0x47, 0xc8, 0x13,
    0x9a, 0xf1, 0x5e, 0x72, 0x04, 0x88, 0xd3, 0x60,
    0xab, 0x1c, 0x57, 0xe9, 0x30, 0x76, 0xfd, 0x2b,
]);

const JWT_SECRET = process.env.JWT_SECRET ?? "change-me-in-production";
const MAX_CLOCK_SKEW_SECONDS = 60;
const PORT = process.env.PORT ?? 3000;
// ─────────────────────────────────────────────────────────────────────────────

function verifyHmac(signatureHash, timestamp, receivedHmac) {
    const payload = `${signatureHash}:${timestamp}`;
    const expected = crypto
        .createHmac("sha256", HMAC_SECRET)
        .update(payload, "utf8")
        .digest("hex");

    const expectedBuf = Buffer.from(expected, "hex");
    const receivedBuf = Buffer.from(receivedHmac, "hex");

    if (expectedBuf.length !== receivedBuf.length) return false;
    return crypto.timingSafeEqual(expectedBuf, receivedBuf);
}

function generateSessionToken(packageName) {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({
        sub: packageName,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        jti: randomUUID(),
    })).toString("base64url");
    const sig = crypto
        .createHmac("sha256", JWT_SECRET)
        .update(`${header}.${payload}`)
        .digest("base64url");
    return `${header}.${payload}.${sig}`;
}

app.post("/api/validate-signature", (req, res) => {
    const { signatureHash, timestamp, hmac, packageName } = req.body;

    if (!signatureHash || !timestamp || !hmac || !packageName) {
        return res.status(400).json({ valid: false, reason: "Missing fields" });
    }

    // 1. Anti-replay: ventana de tiempo de 60 segundos
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > MAX_CLOCK_SKEW_SECONDS) {
        return res.status(401).json({ valid: false, reason: "Request expired" });
    }

    // 2. Validar HMAC — prueba que viene del código nativo
    let hmacValid = false;
    try {
        hmacValid = verifyHmac(signatureHash, timestamp, hmac);
    } catch {
        return res.status(401).json({ valid: false, reason: "Invalid HMAC" });
    }

    if (!hmacValid) {
        return res.status(401).json({ valid: false, reason: "Invalid HMAC" });
    }

    // 3. Comparar firma APK vs firma oficial registrada
    if (!VALID_SIGNATURES.has(signatureHash)) {
        return res.status(403).json({ valid: false, reason: "Unauthorized build" });
    }

    // 4. Todo OK → emitir token de sesión JWT
    const sessionToken = generateSessionToken(packageName);
    return res.json({ valid: true, sessionToken });
});

app.listen(PORT, () => {
    console.log(`Signature validation server running on :${PORT}`);
});
