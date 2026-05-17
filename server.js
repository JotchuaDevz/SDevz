/* By JotchuaDevz */

import express from "express";
import crypto from "crypto";
import { randomUUID } from "crypto";

const app = express();

app.use(express.json());

const VALID_SIGNATURES = new Set([
    "24:9E:53:32:29:6B:3A:7F:A0:DB:17:F3:D2:8D:28:C1:78:B8:81:C4:AC:CC:12:E2:F5:39:BD:6B:A8:07:EC:91"
        .replace(/:/g, "")
        .toLowerCase(),
]);

const HMAC_SECRET = Buffer.from([
    0x4b, 0x39, 0x21, 0x7f,
    0x4e, 0x2a, 0x55, 0x68,
    0x3c, 0x91, 0xb2, 0x0d,
    0x6e, 0x47, 0xc8, 0x13,
    0x9a, 0xf1, 0x5e, 0x72,
    0x04, 0x88, 0xd3, 0x60,
    0xab, 0x1c, 0x57, 0xe9,
    0x30, 0x76, 0xfd, 0x2b,
]);

const JWT_SECRET =
    process.env.JWT_SECRET ??
    "change-me-in-production";

const MAX_CLOCK_SKEW_SECONDS = 60;

const PORT =
    process.env.PORT ?? 3000;

function verifyHmac(
    signatureHash,
    timestamp,
    receivedHmac
) {

    const payload =
        `${signatureHash}:${timestamp}`;

    const expected = crypto
        .createHmac(
            "sha256",
            HMAC_SECRET
        )
        .update(payload, "utf8")
        .digest("hex");

    const expectedBuf =
        Buffer.from(expected, "hex");

    const receivedBuf =
        Buffer.from(receivedHmac, "hex");

    if (
        expectedBuf.length !==
        receivedBuf.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        expectedBuf,
        receivedBuf
    );
}

function generateSessionToken(
    packageName
) {

    const now =
        Math.floor(Date.now() / 1000);

    const header = Buffer
        .from(JSON.stringify({
            alg: "HS256",
            typ: "JWT"
        }))
        .toString("base64url");

    const payload = Buffer
        .from(JSON.stringify({
            sub: packageName,
            iat: now,
            exp: now + 3600,
            jti: randomUUID(),
        }))
        .toString("base64url");

    const sig = crypto
        .createHmac(
            "sha256",
            JWT_SECRET
        )
        .update(
            `${header}.${payload}`
        )
        .digest("base64url");

    return `${header}.${payload}.${sig}`;
}

app.post(
    "/api/validate-signature",
    (req, res) => {

        const {
            signatureHash,
            timestamp,
            hmac,
            packageName
        } = req.body;

        /*
         * Campos faltantes
         */
        if (
            !signatureHash ||
            !timestamp ||
            !hmac ||
            !packageName
        ) {

            return res
                .status(400)
                .json({
                    valid: false,
                    reason:
                        "Campos faltantes"
                });
        }

        /*
         * Tiempo expirado
         */
        const now =
            Math.floor(
                Date.now() / 1000
            );

        if (
            Math.abs(
                now - timestamp
            ) >
            MAX_CLOCK_SKEW_SECONDS
        ) {

            return res
                .status(401)
                .json({
                    valid: false,
                    reason:
                        "Solicitud expirada"
                });
        }

        /*
         * Verificar HMAC
         */
        let hmacValid = false;

        try {

            hmacValid = verifyHmac(
                signatureHash,
                timestamp,
                hmac
            );

        } catch {

            return res
                .status(401)
                .json({
                    valid: false,
                    reason:
                        "HMAC inválido"
                });
        }

        if (!hmacValid) {

            return res
                .status(401)
                .json({
                    valid: false,
                    reason:
                        "HMAC inválido"
                });
        }

        /*
         * Detectar MT Manager /
         * Signature Killer /
         * Manifest modificado
         */
        if (

            signatureHash ===
            "mt_manager_killerApplication_detected"

            ||

            signatureHash ===
            "manifest_application_modified"

        ) {

            console.log(
                "[SECURITY] Modificación detectada:",
                {
                    packageName,
                    signatureHash
                }
            );

            return res
                .status(403)
                .json({
                    valid: false,
                    reason:
                        "Acceso denegado"
                });
        }

        /*
         * Normalizar hash
         */
        const normalizedHash =
            signatureHash
                .replace(/:/g, "")
                .toLowerCase();

        /*
         * Firma inválida
         */
        if (
            !VALID_SIGNATURES.has(
                normalizedHash
            )
        ) {

            console.log(
                "[SECURITY] Firma inválida:",
                {
                    packageName,
                    hash: normalizedHash
                }
            );

            return res
                .status(403)
                .json({
                    valid: false,
                    reason:
                        "Acceso denegado"
                });
        }

        /*
         * Build válida
         */
        return res.json({
            valid: true,
            sessionToken:
                generateSessionToken(
                    packageName
                )
        });
    }
);

app.listen(PORT, () => {

    console.log(
        `Signature validation server running on :${PORT}`
    );
});
