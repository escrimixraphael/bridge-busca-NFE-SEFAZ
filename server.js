import 'dotenv/config';
import express from 'express';
import https from 'node:https';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

const app = express();
const PORT = Number(process.env.PORT || 3000);

// ================================
// CONFIGURAÇÃO DE CHAVES E LOG INICIAL
// ================================
const AUTH_KEY = process.env.AUTH_KEY;
const XML_KEY = process.env.XML_KEY;

console.log("====================================");
console.log("BRIDGE SEFAZ INICIANDO");
console.log("AUTH_KEY carregada:", !!AUTH_KEY);
console.log("XML_KEY carregada:", !!XML_KEY);
console.log("NODE_ENV:", process.env.NODE_ENV || "development");
console.log("====================================");

// ================================
// MIDDLEWARES GERAIS
// ================================
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: "*" }));
app.use(compression());
app.use(express.json({ limit: "20mb" }));
app.use(morgan("combined"));

// ================================
// RATE LIMIT
// ================================
const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    message: {
        success: false,
        error: "Muitas requisições"
    }
});
app.use("/api", limiter);

// ================================
// HEALTH CHECK
// ================================
app.get("/health", (req, res) => {
    res.json({
        status: "online",
        service: "Bridge SEFAZ",
        node: process.version,
        timestamp: new Date()
    });
});

// ================================
// TESTE DE AUTENTICAÇÃO
// ================================
app.get("/api/test-auth", validarAPI, (req, res) => {
    res.json({
        success: true,
        message: "Autenticação OK",
        node: process.version,
        timestamp: new Date().toISOString()
    });
});

// ================================
// VALIDAÇÃO API KEY E XML KEY
// ================================
function validarAPI(req, res, next) {
    const apiKey = req.headers["x-api-key"];
    const xmlKey = req.headers["x-xml-key"];

    console.log("========== NOVA REQUISIÇÃO ==========");
    console.log("IP:", req.ip);
    console.log("Método:", req.method);
    console.log("URL:", req.originalUrl);
    console.log("API KEY recebida:", !!apiKey);
    console.log("XML KEY recebida:", !!xmlKey);
    console.log("AUTH_KEY configurada:", !!AUTH_KEY);
    console.log("XML_KEY configurada:", !!XML_KEY);

    if (!AUTH_KEY) {
        console.error("AUTH_KEY não configurada.");
        return res.status(500).json({
            success: false,
            error: "AUTH_KEY não configurada no servidor"
        });
    }

    if (apiKey !== AUTH_KEY) {
        console.error("API KEY inválida.");
        return res.status(403).json({
            success: false,
            error: "API Key inválida"
        });
    }

    if (XML_KEY && xmlKey !== XML_KEY) {
        console.error("XML KEY inválida.");
        return res.status(403).json({
            success: false,
            error: "XML Key inválida"
        });
    }

    console.log("Autenticação OK");
    console.log("====================================");
    next();
}

// ================================
// TESTE DE CERTIFICADO
// ================================
app.post("/api/sefaz/test-cert", validarAPI, async (req, res) => {
    try {
        const { pfxBase64, password } = req.body;

        if (!pfxBase64 || !password) {
            return res.status(400).json({
                success: false,
                error: "PFX ou senha não informados."
            });
        }

        const certificado = Buffer.from(pfxBase64, "base64");
        
        // Testa a criação do contexto seguro para validar o certificado e a senha
        const contexto = crypto.createSecureContext({
            pfx: certificado,
            passphrase: password
        });

        return res.json({
            success: true,
            message: "Certificado carregado com sucesso."
        });

    } catch (error) {
        return res.status(400).json({
            success: false,
            error: error.message
        });
    }
});

// ================================
// CONSULTA SEFAZ MTLS
// ================================
app.post("/api/sefaz/consultar", validarAPI, async (req, res) => {
    let finalizado = false;

    try {
        const {
            pfxBase64,
            password,
            endpoint,
            soapAction,
            soapEnvelope,
            empresaId
        } = req.body;

        if (!pfxBase64 || !password || !endpoint || !soapEnvelope) {
            return res.status(400).json({
                success: false,
                error: "Campos obrigatórios ausentes"
            });
        }

        const url = new URL(endpoint);

        if (url.protocol !== "https:") {
            return res.status(400).json({
                success: false,
                error: "Somente HTTPS permitido"
            });
        }

        const certificado = Buffer.from(pfxBase64, "base64");

        if (!certificado.length) {
            return res.status(400).json({
                success: false,
                error: "Certificado inválido"
            });
        }

        console.log(`
================================
CONSULTA SEFAZ
Empresa: ${empresaId || "N/A"}
Servidor: ${url.hostname}
Data: ${new Date()}
================================
        `);

        const options = {
            hostname: url.hostname,
            port: url.port || 443,
            path: url.pathname + url.search,
            method: "POST",
            pfx: certificado,
            passphrase: password,
            // mTLS
            rejectUnauthorized: false,
            secureOptions: crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1,
            headers: {
                "Content-Type": 'application/soap+xml; charset=utf-8',
                SOAPAction: soapAction || "",
                Accept: "text/xml",
                "Content-Length": Buffer.byteLength(soapEnvelope)
            }
        };

        const sefazRequest = https.request(options, (sefazResponse) => {
            let body = "";
            sefazResponse.setEncoding("utf8");

            console.log(`SEFAZ STATUS ${sefazResponse.statusCode}`);

            sefazResponse.on("data", (chunk) => {
                body += chunk;
            });

            sefazResponse.on("end", () => {
                if (finalizado) return;
                finalizado = true;

                res.status(sefazResponse.statusCode || 502).json({
                    success: sefazResponse.statusCode === 200,
                    statusCode: sefazResponse.statusCode,
                    xmlResponse: body,
                    empresaId
                });
            });
        });

        sefazRequest.setTimeout(60000, () => {
            console.error("Timeout SEFAZ");
            sefazRequest.destroy();

            if (!finalizado) {
                finalizado = true;
                res.status(504).json({
                    success: false,
                    error: "Timeout SEFAZ"
                });
            }
        });

        sefazRequest.on("error", (error) => {
            console.error("Erro HTTPS:", error.message);

            if (!finalizado) {
                finalizado = true;
                res.status(502).json({
                    success: false,
                    error: error.message
                });
            }
        });

        sefazRequest.write(soapEnvelope, "utf8");
        sefazRequest.end();

    } catch (error) {
        console.error("Erro Bridge", error);

        if (!res.headersSent) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }
});

// ================================
// 404 - ENDPOINT INEXISTENTE
// ================================
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: "Endpoint inexistente"
    });
});

// ================================
// ERRO GLOBAL
// ================================
app.use((error, req, res, next) => {
    console.error(error);
    res.status(500).json({
        success: false,
        error: "Erro interno"
    });
});

// ================================
// START
// ================================
app.listen(PORT, "0.0.0.0", () => {
    console.log(`
====================================
BRIDGE SEFAZ ONLINE
Porta: ${PORT}

Health: /health
Teste Auth: /api/test-auth
Teste Cert: /api/sefaz/test-cert
Consulta: /api/sefaz/consultar
====================================
    `);
});
