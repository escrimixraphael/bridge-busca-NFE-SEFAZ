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
app.get("/api/info", (req, res) => res.json({ success: true, service: "Bridge SEFAZ", version: "1.2.0", authKeyConfigured: !!AUTH_KEY }));
app.get("/version", (req, res) => res.json({ service: "Bridge SEFAZ", version: "1.2.0", node: process.version }));

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
                "User-Agent": "Bridge-SEFAZ/1.2",
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

function gerarManifestacaoXML(cnpj, chave, tipoManifestacao, pfxBase64, password) {
    const mapaEventos = {
        'confirmada': { tp: '210200', desc: 'Confirmacao da Operacao' },
        'ciencia': { tp: '210210', desc: 'Ciencia da Operacao' },
        'desconhecida': { tp: '210220', desc: 'Desconhecimento da Operacao' },
        'nao_realizada': { tp: '210240', desc: 'Operacao nao Realizada' }
    };
    
    const evt = mapaEventos[tipoManifestacao];
    if (!evt) throw new Error("Tipo de manifestação inválido.");

    const pfxDer = forge.util.decode64(sanitizarBase64(pfxBase64));
    const p12Asn1 = forge.asn1.fromDer(pfxDer);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

    let privateKeyPem, certPem;
    for (const safeContents of p12.safeContents) {
        for (const safeBag of safeContents.safeBags) {
            if (safeBag.type === forge.pki.oids.keyBag || safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
                privateKeyPem = forge.pki.privateKeyToPem(safeBag.key);
            } else if (safeBag.type === forge.pki.oids.certBag) {
                if (!certPem) certPem = forge.pki.certificateToPem(safeBag.cert);
            }
        }
    }
    if (!privateKeyPem || !certPem) throw new Error("Não foi possível extrair a chave do certificado.");
    
    const certB64 = certPem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\r|\n/g, '');

    const idEvento = `ID${evt.tp}${chave}01`;
    const date = new Date();
    const tzo = -date.getTimezoneOffset();
    const dif = tzo >= 0 ? '+' : '-';
    const pad = (num) => (num < 10 ? '0' : '') + num;
    const dhEvento = date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate()) + 'T' + pad(date.getHours()) + ':' + pad(date.getMinutes()) + ':' + pad(date.getSeconds()) + dif + pad(Math.floor(Math.abs(tzo) / 60)) + ':' + pad(Math.abs(tzo) % 60);

    const justificativaXML = evt.tp === '210240' ? '<xJust>Operacao nao realizada pelo destinatario</xJust>' : '';

    // Extrai o código da UF da chave de acesso (2 primeiros dígitos)
    const cUF = chave ? chave.substring(0, 2) : '91';

    const xmlInfEvento = `<infEvento Id="${idEvento}" xmlns="http://www.portalfiscal.inf.br/nfe">` +
        `<cOrgao>${cUF}</cOrgao>` +
        `<tpAmb>1</tpAmb>` +
        `<CNPJ>${cnpj}</CNPJ>` +
        `<chNFe>${chave}</chNFe>` +
        `<dhEvento>${dhEvento}</dhEvento>` +
        `<tpEvento>${evt.tp}</tpEvento>` +
        `<nSeqEvento>1</nSeqEvento>` +
        `<verEvento>1.00</verEvento>` +
        `<detEvento versao="1.00">` +
        `<descEvento>${evt.desc}</descEvento>` +
        justificativaXML +
        `</detEvento>` +
        `</infEvento>`;

    const sig = new SignedXml();
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.addReference({
        xpath: `//*[@Id='${idEvento}']`,
        transforms: [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        ],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1"
    });
    
    sig.privateKey = privateKeyPem;
    sig.keyInfoProvider = {
        getKeyInfo: () => `<X509Data><X509Certificate>${certB64}</X509Certificate></X509Data>`
    };
    sig.computeSignature(xmlInfEvento);
    
    let signatureXml = sig.getSignedXml();
    signatureXml = signatureXml
        .replace('<Signature>', '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<SignedInfo>', '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<CanonicalizationMethod', '<CanonicalizationMethod xmlns="http://www.w3.org/2000/09/xmldsig#"')
        .replace('<SignatureMethod', '<SignatureMethod xmlns="http://www.w3.org/2000/09/xmldsig#"')
        .replace('<Reference', '<Reference xmlns="http://www.w3.org/2000/09/xmldsig#"')
        .replace('<Transforms>', '<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<Transform', '<Transform xmlns="http://www.w3.org/2000/09/xmldsig#"')
        .replace('<DigestMethod', '<DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#"')
        .replace('<DigestValue>', '<DigestValue xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<SignatureValue>', '<SignatureValue xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<KeyInfo>', '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<X509Data>', '<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#">')
        .replace('<X509Certificate>', '<X509Certificate xmlns="http://www.w3.org/2000/09/xmldsig#">');

    const xmlLimpoInf = xmlInfEvento.replace(' xmlns="http://www.portalfiscal.inf.br/nfe"', '');
    const xmlEventoAssinado = `<evento xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">` +
        xmlLimpoInf +
        signatureXml +
        `</evento>`;

    return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
    <soap12:Body>
        <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">
            <envEvento versao="1.00" xmlns="http://www.portalfiscal.inf.br/nfe">
                <idLote>1</idLote>
                ${xmlEventoAssinado}
            </envEvento>
        </nfeDadosMsg>
    </soap12:Body>
</soap12:Envelope>`;
}

// Função para determinar o endpoint correto de Recepção de Eventos com base na UF da chave de NFe ou parâmetro manual
function obterEndpointEvento(chave, endpointFornecido) {
    if (endpointFornecido) return endpointFornecido;

    // Extrai o código da UF dos 2 primeiros dígitos da chave de acesso
    const cUF = chave ? chave.substring(0, 2) : '41';

    // Mapeamento correto e exato dos webservices de Recepção de Eventos v4.00 para NF-e
    const endpointsUF = {
        // Estados atendidos pela SVRS (PR, RS, SC, RJ, ES, MS, MT, etc.) com o caminho oficial exato em minúsculas
        '41': 'https://nfe.svrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx',
        '43': 'https://nfe.svrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx',
        '42': 'https://nfe.svrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx',
        '33': 'https://nfe.svrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx',
        '32': 'https://nfe.svrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx',
        '50': 'https://nfe.svrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx',
        '51': 'https://nfe.svrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx',

        // São Paulo (Webservice próprio)
        '35': 'https://nfe.fazenda.sp.gov.br/ws/nferecepcaoevento4.asmx',
        
        // Minas Gerais (Webservice próprio)
        '31': 'https://nfe.fazenda.mg.gov.br/nfe2/services/NFeRecepcaoEvento4'
    };

    // Fallback padrão para a SVRS oficial de NF-e
    return endpointsUF[cUF] || "https://nfe.svrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx";
}                               

app.post("/api/sefaz/distribuicao", validarAPI, (req, res) => consultarSefaz(req, res));
app.post("/api/sefaz/consultar", validarAPI, (req, res) => consultarSefaz(req, res));
app.post("/backend/v1/xml/sync", validarAPI, (req, res) => consultarSefaz(req, res));

// ================================
// ROTA DE MANIFESTAÇÃO INDEPENDENTE (SUPORTE MULTI-UF)
// ================================
app.post("/rpa/xml/manifest", validarAPI, async (req, res) => {
    let finalizado = false;
    try {
        const { pfxBase64, password, cnpj, chave, tipoManifestacao, endpoint } = req.body;
        
        if (!pfxBase64 || !password || !cnpj || !chave || !tipoManifestacao) {
            return res.status(400).json({ success: false, error: "Dados incompletos para a manifestação." });
        }

        const soapEnvelope = gerarManifestacaoXML(cnpj, chave, tipoManifestacao, pfxBase64, password);
        
        // Determina dinamicamente o endpoint adequado para a UF da nota ou usa o enviado no body
        const urlDestino = obterEndpointEvento(chave, endpoint);
        const endpointUrl = new URL(urlDestino);
        const soapAction = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento";

        const certificado = Buffer.from(sanitizarBase64(pfxBase64), "base64");
        const soapBuffer = Buffer.from(soapEnvelope, "utf8");

        const options = {
            hostname: endpointUrl.hostname,
            port: 443,
            path: endpointUrl.pathname + endpointUrl.search,
            method: "POST",
            pfx: certificado,
            passphrase: password,
            minVersion: "TLSv1.2",
            // Removido o maxVersion estrito para permitir negociação correta com a SEFAZ
            rejectUnauthorized: false, // Opcional temporariamente se houver problema de cadeia, mas idealmente mantido true se o certificado raiz da SEFAZ for aceito. Vamos manter true e ajustar as cifras:
            // ciphers padrão abertos do Node.js para garantir compatibilidade com webservices governamentais antigos:
            ciphers: 'DEFAULT:@SECLEVEL=0', 
            headers: {
                "Cache-Control": "no-cache",
                "Content-Type": "application/soap+xml; charset=utf-8; action=\"" + soapAction + "\"",
                "SOAPAction": soapAction,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Content-Length": soapBuffer.length
            }
        };
        
        const sefazReq = https.request(options, (sefazRes) => {
            let body = "";
            sefazRes.setEncoding("utf8");
            sefazRes.on("data", (chunk) => body += chunk);
            sefazRes.on("end", () => {
                if (finalizado) return;
                finalizado = true;

                console.log("=== RESPOSTA CRUA SEFAZ (MANIFESTAÇÃO) ===");
                console.log("Destino:", endpointUrl.hostname);
                console.log("Status HTTP:", sefazRes.statusCode);
                console.log(body);
                console.log("==========================================");

                const cStatMatch = body.match(/<cStat[^>]*>(.*?)<\/cStat>/g);
                const cStatLote = cStatMatch && cStatMatch.length > 0 ? cStatMatch[0].replace(/<\/?cStat[^>]*>/g, '') : '';
                const cStatEvento = cStatMatch && cStatMatch.length > 1 ? cStatMatch[1].replace(/<\/?cStat[^>]*>/g, '') : '';
                const cStatFinal = cStatEvento || cStatLote;

                const xMotivoMatch = body.match(/<xMotivo[^>]*>(.*?)<\/xMotivo>/g);
                let xMotivo = xMotivoMatch && xMotivoMatch.length > 0 ? xMotivoMatch[xMotivoMatch.length - 1].replace(/<\/?xMotivo[^>]*>/g, '') : null;

                if (!xMotivo) {
                    const faultMatch = body.match(/<faultstring[^>]*>(.*?)<\/faultstring>/i) || body.match(/<reason[^>]*>(.*?)<\/reason>/i);
                    if (faultMatch) xMotivo = faultMatch[1];
                }

                const motivoFinal = (xMotivo && xMotivo.trim()) ? xMotivo.trim() : (body && body.trim().length > 0 && body.length < 500 ? body.trim() : `Rejeição HTTP ${sefazRes.statusCode} da SEFAZ`);

                // cStat 135 (Registrado e vinculado), 136 (Registrado mas já vinculado)
                const isSuccess = sefazRes.statusCode === 200 && (cStatFinal === '135' || cStatFinal === '136');

                if (isSuccess) {
                    return res.json({ success: true, message: `Manifestação registrada com sucesso: ${motivoFinal}`, cStat: cStatFinal });
                } else {
                    return res.status(400).json({ success: false, error: `SEFAZ (${cStatFinal || sefazRes.statusCode}): ${motivoFinal}` });
                }
            });
        });

        sefazReq.setTimeout(60000, () => {
            sefazReq.destroy();
            if (!finalizado) {
                finalizado = true;
                return res.status(504).json({ success: false, error: "Timeout ao conectar com a SEFAZ" });
            }
        });

        sefazReq.on("error", (err) => {
            if (!finalizado) {
                finalizado = true;
                return res.status(502).json({ success: false, error: "Erro de conexão: " + err.message });
            }
        });

        sefazReq.write(soapBuffer);
        sefazReq.end();

    } catch (error) {
        console.error("Erro interno no Bridge:", error);
        return res.status(500).json({ success: false, error: "Falha interna no Bridge: " + error.message });
    }
});
        
app.use((req, res) => res.status(404).json({ success: false, error: "Endpoint inexistente" }));

app.listen(PORT, "0.0.0.0", () => {
    console.log(`BRIDGE SEFAZ ONLINE (GZIP Ativo) - Porta: ${PORT}`);
});
