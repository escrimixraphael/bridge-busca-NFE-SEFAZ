import 'dotenv/config';
import express from 'express';
import tls from 'node:tls';
import https from 'node:https';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { Buffer } from 'node:buffer';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import forge from 'node-forge';
import { SignedXml } from 'xml-crypto';
import PDFDocument from 'pdfkit';

// IMPORTAR BIBLIOTECA DE PDF AQUI (Descomente após instalar com npm install danfe)
// import Danfe from 'danfe'; 

const app = express();
const PORT = Number(process.env.PORT || 3000);

// Tratamento global para evitar crash silencioso
process.on('uncaughtException', (err) => {
    console.error('ERRO NÃO TRATADO (CRASH):', err);
});
process.on('unhandledRejection', (reason) => {
    console.error('PROMISE REJEITADA:', reason);
});

app.set('trust proxy', 1);

const AUTH_KEY = process.env.AUTH_KEY;
const XML_KEY = process.env.XML_KEY;

console.log("====================================");
console.log("BRIDGE SEFAZ INICIANDO");
console.log("AUTH_KEY carregada:", !!AUTH_KEY);
console.log("XML_KEY carregada:", !!XML_KEY);
console.log("NODE_ENV:", process.env.NODE_ENV || "development");
console.log("====================================");

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: "*" }));
app.use(compression());
app.use(express.json({ limit: "20mb" }));
app.use(morgan("combined"));

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    message: { success: false, error: "Muitas requisições" }
});

app.use("/api", limiter);
app.use("/backend", limiter);
app.use("/rpa", limiter);

function sanitizarBase64(b64) {
    if (typeof b64 !== 'string') return '';
    return b64.replace(/^data:.*;base64,/, '').replace(/\s+/g, '');
}

// ============================================================
// 1. MÓDULO: DISTRIBUIÇÃO DF-E E PDF
// ============================================================
function processarRespostaSefaz(soapXml) {
    const retorno = { cStat: '', ultNSU: '', maxNSU: '', docs: [] };
    if (typeof soapXml !== 'string') return retorno;

    const cStatMatch = soapXml.match(/<cStat[^>]*>(.*?)<\/cStat>/);
    if (cStatMatch) retorno.cStat = cStatMatch[1];

    const ultNSUMatch = soapXml.match(/<ultNSU[^>]*>(.*?)<\/ultNSU>/);
    if (ultNSUMatch) retorno.ultNSU = ultNSUMatch[1];

    const maxNSUMatch = soapXml.match(/<maxNSU[^>]*>(.*?)<\/maxNSU>/);
    if (maxNSUMatch) retorno.maxNSU = maxNSUMatch[1];

    const docRegex = /<docZip[^>]*NSU="([^"]+)"[^>]*schema="([^"]+)"[^>]*>(.*?)<\/docZip>/g;
    let match;

    while ((match = docRegex.exec(soapXml)) !== null) {
        const nsu = match[1];
        const schema = match[2];
        const b64Zipped = match[3];

        try {
            const bufferZip = Buffer.from(b64Zipped, 'base64');
            const unzipped = zlib.gunzipSync(bufferZip).toString('utf8');
            retorno.docs.push({ nsu, schema, xml: unzipped });
        } catch (e) {
            console.error(`Erro ao descompactar documento NSU ${nsu}:`, e.message);
        }
    }
    return retorno;
}

app.get("/health", (req, res) => res.json({ status: "online", node: process.version, timestamp: new Date() }));
app.get("/api/info", (req, res) => res.json({ success: true, service: "Bridge SEFAZ", version: "1.3.0", authKeyConfigured: !!AUTH_KEY }));
app.get("/version", (req, res) => res.json({ service: "Bridge SEFAZ", version: "1.3.0", node: process.version }));

function validarAPI(req, res, next) {
    const apiKey = req.headers["x-api-key"] || req.headers["x-xml-key"];
    if (!AUTH_KEY) return res.status(500).json({ success: false, error: "AUTH_KEY não configurada" });
    if (apiKey !== AUTH_KEY) return res.status(403).json({ success: false, error: "API Key inválida" });
    next();
}

app.get("/api/test-auth", validarAPI, (req, res) => res.json({ success: true, message: "Autenticação OK" }));

const consultarSefaz = async (req, res, dadosCustom = null) => {
    let finalizado = false;
    const requestId = crypto.randomUUID();

    try {
        const payload = dadosCustom || req.body;
        const { pfxBase64, password, endpoint, soapEnvelope } = payload;
        const soapAction = payload.soapAction || "http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse";

        if (!pfxBase64 || !password || !endpoint || !soapEnvelope) {
            return res.status(400).json({ success: false, requestId, error: "Campos obrigatórios ausentes" });
        }

        const url = new URL(endpoint);
        const certificado = Buffer.from(sanitizarBase64(pfxBase64), "base64");

        try {
            tls.createSecureContext({ pfx: certificado, passphrase: password });
        } catch (err) {
            return res.status(400).json({ success: false, requestId, error: "Erro PFX: " + err.message });
        }

        const options = {
            hostname: url.hostname,
            port: url.port || 443,
            path: url.pathname + url.search,
            method: "POST",
            pfx: certificado,
            passphrase: password,
            minVersion: "TLSv1.2",
            rejectUnauthorized: true,
            secureOptions: crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1,
            headers: {
                "Content-Type": `application/soap+xml; charset=utf-8; action="${soapAction}"`,
                SOAPAction: soapAction,
                "User-Agent": "Bridge-SEFAZ/1.3",
                "Content-Length": Buffer.byteLength(soapEnvelope)
            }
        };

        const sefazRequest = https.request(options, (sefazResponse) => {
            let body = "";
            sefazResponse.setEncoding("utf8");
            sefazResponse.on("data", (chunk) => body += chunk);
            sefazResponse.on("end", () => {
                if (finalizado) return;
                finalizado = true;

                const processado = processarRespostaSefaz(body);
                const isSuccess = sefazResponse.statusCode === 200;

                res.status(isSuccess ? 200 : 422).json({
                    success: isSuccess,
                    statusCode: sefazResponse.statusCode,
                    cStat: processado.cStat,
                    ultNSU: processado.ultNSU,
                    maxNSU: processado.maxNSU,
                    docs: processado.docs,
                    soapResponse: body
                });
            });
        });

        sefazRequest.setTimeout(60000, () => {
            sefazRequest.destroy();
            if (!finalizado) {
                finalizado = true;
                res.status(504).json({ success: false, error: "Timeout SEFAZ" });
            }
        });

        sefazRequest.on("error", (error) => {
            if (!finalizado) {
                finalizado = true;
                res.status(502).json({ success: false, error: error.message });
            }
        });

        sefazRequest.write(soapEnvelope, "utf8");
        sefazRequest.end();

    } catch (error) {
        if (!res.headersSent) res.status(500).json({ success: false, error: error.message });
    }
};

app.post("/api/sefaz/distribuicao", validarAPI, (req, res) => consultarSefaz(req, res));
app.post("/api/sefaz/consultar", validarAPI, (req, res) => consultarSefaz(req, res));
app.post("/backend/v1/xml/sync", validarAPI, (req, res) => consultarSefaz(req, res));

// ============================================================
// NOVO ENDPOINT: GERAÇÃO DE PDF (DANFE) ON DEMAND COM PDFKIT
// ============================================================
app.post("/api/xml/render-pdf", async (req, res) => {
    try {
        const { xmlBase64, tipo } = req.body;
        
        if (!xmlBase64) {
            return res.status(400).json({ success: false, error: "XML Base64 não fornecido" });
        }

        const xmlString = Buffer.from(xmlBase64, 'base64').toString('utf8');

        // Extração rápida de dados essenciais via Regex do XML
        const extractTag = (xml, tag) => {
            const match = xml.match(new RegExp(`<${tag}[^>]*>(.*?)<\/${tag}>`));
            return match ? match[1] : '';
        };

        const chave = extractTag(xmlString, 'chNFe') || extractTag(xmlString, 'Id')?.replace('NFe', '') || 'N/D';
        const cnpjEmit = extractTag(xmlString, 'CNPJ');
        const xNomeEmit = extractTag(xmlString, 'xNome');
        const vNF = extractTag(xmlString, 'vNF');
        const dhEmi = extractTag(xmlString, 'dhEmi') || extractTag(xmlString, 'dEmi');
        const nNF = extractTag(xmlString, 'nNF');

        // Criação do PDF em memória usando PDFKit
        const doc = new PDFDocument({ size: 'A4', margin: 40 });
        const buffers = [];

        doc.on('data', chunk => buffers.push(chunk));
        
        doc.on('end', () => {
            const pdfBuffer = Buffer.concat(buffers);
            return res.json({
                success: true,
                pdfBase64: pdfBuffer.toString('base64')
            });
        });

        // Desenho do layout do DANFE Simplificado
        doc.fontSize(14).font('Helvetica-Bold').text('DANFE Simplificado (Visualização)', { align: 'center' });
        doc.moveDown(1);

        doc.fontSize(10).font('Helvetica-Bold').text('DADOS DA NOTA FISCAL');
        doc.moveTo(40, doc.y).lineTo(555, doc.y).stroke();
        doc.moveDown(0.5);

        doc.font('Helvetica').text(`Chave de Acesso: ${chave}`);
        doc.text(`Número da NF: ${nNF || 'N/D'}   |   Data Emissão: ${dhEmi || 'N/D'}`);
        doc.text(`Emitente: ${xNomeEmit || 'Não identificado'} (CNPJ: ${cnpjEmit})`);
        doc.text(`Valor Total da Nota: R$ ${vNF || '0,00'}`);
        
        doc.moveDown(2);
        doc.fontSize(8).fillColor('gray').text('Documento gerado automaticamente pelo Bridge SEFAZ / ERP.', { align: 'center' });

        doc.end();

    } catch (error) {
        console.error("Erro ao gerar PDF:", error);
        return res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================
// 2. MÓDULO: MANIFESTAÇÃO DO DESTINATÁRIO NF-e
// Ambiente Nacional - RecepcaoEvento 4.00
// ============================================================
const NFE_NAMESPACE = "http://www.portalfiscal.inf.br/nfe";
const NFE_EVENTO_WSDL_NAMESPACE = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4";
const NFE_EVENTO_SOAP_ACTION = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento";

function obterAmbienteNFe() {
    return process.env.NFE_AMBIENTE === "2" ? "2" : "1";
}

function obterEndpointManifestacao(endpointFornecido = null) {
    if (endpointFornecido) {
        try {
            const url = new URL(endpointFornecido);
            if (url.protocol !== "https:") {
                throw new Error("Endpoint precisa utilizar HTTPS.");
            }
            return endpointFornecido;
        } catch (error) {
            throw new Error("Endpoint SEFAZ inválido: " + error.message);
        }
    }

    const tpAmb = obterAmbienteNFe();

    if (tpAmb === "1") {
        return "https://www.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx";
    }

    return "https://hom.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx";
}

function escapeXml(valor) {
    return String(valor ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
}

function normalizarCNPJ(cnpj) {
    const valor = String(cnpj || "").replace(/\D/g, "");
    if (valor.length !== 14) {
        throw new Error("CNPJ inválido. Esperado CNPJ com 14 dígitos.");
    }
    return valor;
}

function normalizarChaveNFe(chave) {
    const valor = String(chave || "").replace(/\D/g, "");
    if (valor.length !== 44) {
        throw new Error("Chave NF-e inválida. Esperados 44 dígitos.");
    }
    return valor;
}

function gerarDhEvento() {
    const agora = new Date();
    const offsetMinutos = -agora.getTimezoneOffset();
    const sinal = offsetMinutos >= 0 ? "+" : "-";
    const absoluto = Math.abs(offsetMinutos);
    const horasOffset = Math.floor(absoluto / 60);
    const minutosOffset = absoluto % 60;
    const pad = (numero) => String(numero).padStart(2, "0");

    return (
        agora.getFullYear() +
        "-" +
        pad(agora.getMonth() + 1) +
        "-" +
        pad(agora.getDate()) +
        "T" +
        pad(agora.getHours()) +
        ":" +
        pad(agora.getMinutes()) +
        ":" +
        pad(agora.getSeconds()) +
        sinal +
        pad(horasOffset) +
        ":" +
        pad(minutosOffset)
    );
}

function gerarIdLote() {
    return String(Date.now()).slice(-15);
}

const TIPOS_MANIFESTACAO = {
    confirmada: { codigo: "210200", descricao: "Confirmacao da Operacao" },
    ciencia: { codigo: "210210", descricao: "Ciencia da Operacao" },
    desconhecida: { codigo: "210220", descricao: "Desconhecimento da Operacao" },
    nao_realizada: { codigo: "210240", descricao: "Operacao nao Realizada" }
};

function extrairCertificadoA1(pfxBase64, password) {
    if (!pfxBase64) throw new Error("Certificado PFX não informado.");
    if (!password) throw new Error("Senha do certificado não informada.");

    try {
        const base64 = sanitizarBase64(pfxBase64);
        const pfxDer = forge.util.decode64(base64);
        const p12Asn1 = forge.asn1.fromDer(pfxDer);
        const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

        let privateKey = null;
        let certificate = null;

        for (const safeContents of p12.safeContents) {
            for (const safeBag of safeContents.safeBags) {
                if (safeBag.type === forge.pki.oids.keyBag || safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
                    if (safeBag.key) privateKey = safeBag.key;
                }
                if (safeBag.type === forge.pki.oids.certBag && safeBag.cert) {
                    if (!certificate) certificate = safeBag.cert;
                }
            }
        }

        if (!privateKey) throw new Error("Chave privada não encontrada no certificado.");
        if (!certificate) throw new Error("Certificado X509 não encontrado no PFX.");

        const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
        const certPem = forge.pki.certificateToPem(certificate);
        const certBase64 = certPem
            .replace(/-----BEGIN CERTIFICATE-----/g, "")
            .replace(/-----END CERTIFICATE-----/g, "")
            .replace(/\r?\n/g, "")
            .trim();

        return { privateKeyPem, certBase64 };
    } catch (error) {
        throw new Error("Erro ao abrir certificado A1: " + error.message);
    }
}

function gerarEventoManifestacaoAssinado(cnpj, chave, tipoManifestacao, pfxBase64, password) {
    const evento = TIPOS_MANIFESTACAO[tipoManifestacao];
    if (!evento) throw new Error("Tipo de manifestação inválido: " + tipoManifestacao);

    const cnpjLimpo = normalizarCNPJ(cnpj);
    const chaveLimpa = normalizarChaveNFe(chave);
    const tpAmb = obterAmbienteNFe();
    const dhEvento = gerarDhEvento();
    const cOrgao = "91";
    const nSeqEvento = "1";

    const idEvento = "ID" + evento.codigo + chaveLimpa + nSeqEvento.padStart(2, "0");

    let detalheExtra = "";
    if (evento.codigo === "210240") {
        detalheExtra = "<xJust>" + escapeXml("Operacao nao realizada pelo destinatario") + "</xJust>";
    }

    const infEvento =
        `<infEvento Id="${idEvento}">` +
            `<cOrgao>${cOrgao}</cOrgao>` +
            `<tpAmb>${tpAmb}</tpAmb>` +
            `<CNPJ>${cnpjLimpo}</CNPJ>` +
            `<chNFe>${chaveLimpa}</chNFe>` +
            `<dhEvento>${dhEvento}</dhEvento>` +
            `<tpEvento>${evento.codigo}</tpEvento>` +
            `<nSeqEvento>${nSeqEvento}</nSeqEvento>` +
            `<verEvento>1.00</verEvento>` +
            `<detEvento versao="1.00">` +
                `<descEvento>${evento.descricao}</descEvento>` +
                detalheExtra +
            `</detEvento>` +
        `</infEvento>`;

    const eventoXml = `<evento xmlns="${NFE_NAMESPACE}" versao="1.00">${infEvento}</evento>`;

    const { privateKeyPem, certBase64 } = extrairCertificadoA1(pfxBase64, password);

    const sig = new SignedXml();
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    sig.addReference({
        xpath: `//*[local-name(.)='infEvento' and @Id='${idEvento}']`,
        transforms: [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        ],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1"
    });

    sig.privateKey = privateKeyPem;

    sig.getKeyInfoContent = () =>
        `<X509Data><X509Certificate>${certBase64}</X509Certificate></X509Data>`;

    sig.keyInfoProvider = {
        getKeyInfo: () => `<X509Data><X509Certificate>${certBase64}</X509Certificate></X509Data>`
    };

    sig.computeSignature(eventoXml, {
        location: {
            reference: `//*[local-name(.)='infEvento' and @Id='${idEvento}']`,
            action: "after"
        }
    });

    const eventoAssinado = sig.getSignedXml();

    if (!eventoAssinado || !eventoAssinado.includes("<Signature")) {
        throw new Error("Falha ao gerar assinatura XML do evento.");
    }

    return eventoAssinado;
}

function gerarManifestacaoXML(cnpj, chave, tipoManifestacao, pfxBase64, password) {
    const eventoAssinado = gerarEventoManifestacaoAssinado(cnpj, chave, tipoManifestacao, pfxBase64, password);
    const idLote = gerarIdLote();

    return (
        `<?xml version="1.0" encoding="utf-8"?>` +
        `<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">` +
        `<soap12:Body>` +
            `<nfeDadosMsg xmlns="${NFE_EVENTO_WSDL_NAMESPACE}">` +
                `<envEvento xmlns="${NFE_NAMESPACE}" versao="1.00">` +
                    `<idLote>${idLote}</idLote>` +
                    eventoAssinado +
                `</envEvento>` +
            `</nfeDadosMsg>` +
        `</soap12:Body>` +
        `</soap12:Envelope>`
    );
}

function extrairTagXml(xml, tag) {
    if (!xml) return null;
    const regex = new RegExp(`<(?:\\w+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:\\w+:)?${tag}>`, "i");
    const match = xml.match(regex);
    return match ? match[1].trim() : null;
}

function extrairTodasTags(xml, tag) {
    if (!xml) return [];
    const regex = new RegExp(`<(?:\\w+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:\\w+:)?${tag}>`, "gi");
    const valores = [];
    let match;
    while ((match = regex.exec(xml)) !== null) {
        valores.push(match[1].trim());
    }
    return valores;
}

function interpretarRespostaManifestacao(body, statusCode) {
    const cStats = extrairTodasTags(body, "cStat");
    const motivos = extrairTodasTags(body, "xMotivo");

    const cStatLote = cStats.length > 0 ? cStats[0] : null;
    const cStatEvento = cStats.length > 1 ? cStats[cStats.length - 1] : cStatLote;
    const motivo = motivos.length > 0 ? motivos[motivos.length - 1] : null;
    const protocolo = extrairTagXml(body, "nProt");
    const dhRegEvento = extrairTagXml(body, "dhRegEvento");

    const sucesso = statusCode === 200 && (cStatEvento === "135" || cStatEvento === "136");

    return { sucesso, cStatLote, cStatEvento, motivo, protocolo, dhRegEvento };
}

app.post("/rpa/xml/manifest", validarAPI, async (req, res) => {
    let finalizado = false;
    const requestId = crypto.randomUUID();

    try {
        const { pfxBase64, password, cnpj, chave, tipoManifestacao, endpoint } = req.body;

        if (!pfxBase64) return res.status(400).json({ success: false, requestId, error: "Certificado PFX não informado." });
        if (!password) return res.status(400).json({ success: false, requestId, error: "Senha do certificado não informada." });
        if (!cnpj) return res.status(400).json({ success: false, requestId, error: "CNPJ não informado." });
        if (!chave) return res.status(400).json({ success: false, requestId, error: "Chave NF-e não informada." });
        if (!tipoManifestacao) return res.status(400).json({ success: false, requestId, error: "Tipo de manifestação não informado." });

        const cnpjLimpo = normalizarCNPJ(cnpj);
        const chaveLimpa = normalizarChaveNFe(chave);

        if (!TIPOS_MANIFESTACAO[tipoManifestacao]) {
            return res.status(400).json({ success: false, requestId, error: "Manifestação inválida." });
        }

        const certificado = Buffer.from(sanitizarBase64(pfxBase64), "base64");

        try {
            tls.createSecureContext({ pfx: certificado, passphrase: password });
        } catch (error) {
            return res.status(400).json({ success: false, requestId, error: "Certificado PFX inválido ou senha incorreta: " + error.message });
        }

        const soapEnvelope = gerarManifestacaoXML(cnpjLimpo, chaveLimpa, tipoManifestacao, pfxBase64, password);

        const urlDestino = obterEndpointManifestacao(endpoint);
        const endpointUrl = new URL(urlDestino);
        const soapBuffer = Buffer.from(soapEnvelope, "utf8");

        const options = {
            hostname: endpointUrl.hostname,
            port: endpointUrl.port || 443,
            path: endpointUrl.pathname + endpointUrl.search,
            method: "POST",
            pfx: certificado,
            passphrase: password,
            minVersion: "TLSv1.2",
            rejectUnauthorized: true,
            headers: {
                "Content-Type": `application/soap+xml; charset=utf-8; action="${NFE_EVENTO_SOAP_ACTION}"`,
                "Accept": "application/soap+xml, text/xml, */*",
                "User-Agent": "Bridge-SEFAZ/1.3",
                "Cache-Control": "no-cache",
                "Content-Length": soapBuffer.length
            }
        };

        const sefazReq = https.request(options, (sefazRes) => {
            let body = "";
            sefazRes.setEncoding("utf8");
            sefazRes.on("data", (chunk) => { body += chunk; });
            sefazRes.on("end", () => {
                if (finalizado) return;
                finalizado = true;

                const retorno = interpretarRespostaManifestacao(body, sefazRes.statusCode);

                if (retorno.sucesso) {
                    return res.json({
                        success: true,
                        requestId,
                        cStat: retorno.cStatEvento,
                        message: retorno.motivo || "Manifestação registrada com sucesso.",
                        protocolo: retorno.protocolo,
                        dhRegEvento: retorno.dhRegEvento
                    });
                }

                let mensagemErro = retorno.motivo;
                if (!mensagemErro) {
                    const fault = extrairTagXml(body, "faultstring") || extrairTagXml(body, "Text") || extrairTagXml(body, "Reason");
                    mensagemErro = fault || `HTTP ${sefazRes.statusCode} retornado pela SEFAZ`;
                }

                return res.status(400).json({
                    success: false,
                    requestId,
                    statusCode: sefazRes.statusCode,
                    cStat: retorno.cStatEvento,
                    error: mensagemErro
                });
            });
        });

        sefazReq.setTimeout(60000, () => {
            sefazReq.destroy();
            if (!finalizado) {
                finalizado = true;
                return res.status(504).json({ success: false, requestId, error: "Timeout ao conectar com a SEFAZ." });
            }
        });

        sefazReq.on("error", (error) => {
            if (!finalizado) {
                finalizado = true;
                return res.status(502).json({ success: false, requestId, error: "Erro de comunicação: " + error.message });
            }
        });

        sefazReq.write(soapBuffer);
        sefazReq.end();

    } catch (error) {
        if (!res.headersSent) {
            return res.status(500).json({ success: false, requestId, error: error.message });
        }
    }
});

app.use((req, res) => res.status(404).json({ success: false, error: "Endpoint inexistente" }));

app.listen(PORT, "0.0.0.0", () => {
    console.log(`BRIDGE SEFAZ ONLINE (GZIP Ativo) - Porta: ${PORT}`);
});
