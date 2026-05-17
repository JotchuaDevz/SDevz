app.post("/api/validate-signature", (req, res) => {

    const {
        signatureHash,
        timestamp,
        hmac,
        packageName
    } = req.body;

    if (
        !signatureHash ||
        !timestamp ||
        !hmac ||
        !packageName
    ) {
        return res.status(400).json({
            valid: false,
            reason: "Campos faltantes"
        });
    }

    // VALIDAR MANIFEST NO MODIFICADO
    if (signatureHash.includes("MANIFEST_MODIFIED_ERROR")) {
        console.log(
            "[SECURITY] Manifest modificado:",
            packageName
        );
        return res.status(403).json({
            valid: false,
            reason: "Manifest ha sido modificado"
        });
    }

    // VALIDAR PACKAGE CORRECTO
    const VALID_PACKAGE = "com.hex.tunnel.jotchuast";
    if (packageName !== VALID_PACKAGE) {
        console.log(
            "[SECURITY] Package inválido:",
            packageName
        );
        return res.status(403).json({
            valid: false,
            reason: "Package no autorizado"
        });
    }

    const now = Math.floor(Date.now() / 1000);

    if (
        Math.abs(now - timestamp) >
        MAX_CLOCK_SKEW_SECONDS
    ) {
        return res.status(401).json({
            valid: false,
            reason: "Solicitud expirada"
        });
    }

    let hmacValid = false;

    try {
        hmacValid = verifyHmac(
            signatureHash,
            timestamp,
            hmac
        );
    } catch {
        return res.status(401).json({
            valid: false,
            reason: "HMAC inválido"
        });
    }

    if (!hmacValid) {
        return res.status(401).json({
            valid: false,
            reason: "HMAC inválido"
        });
    }

    const normalizedHash = signatureHash
        .replace(/:/g, "")
        .toLowerCase();
    
    if (
        normalizedHash.includes("mt_manager") ||
        normalizedHash.includes("killerapplication")
    ) {
        console.log(
            "[SECURITY] MT Manager detectado:",
            packageName
        );
        return res.status(403).json({
            valid: false,
            reason: "Acceso denegado"
        });
    }

    if (!VALID_SIGNATURES.has(normalizedHash)) {
        console.log(
            "[SECURITY] Firma inválida:",
            normalizedHash
        );
        return res.status(403).json({
            valid: false,
            reason: "Acceso denegado"
        });
    }
    
    return res.json({
        valid: true,
        sessionToken: generateSessionToken(packageName)
    });
});
