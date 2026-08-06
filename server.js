import "dotenv/config";

import express from "express";
import tls from "node:tls";
import https from "node:https";
import crypto from "node:crypto";
import zlib from "node:zlib";
import { Buffer } from "node:buffer";

import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import forge from "node-forge";
import { SignedXml } from "xml-crypto";
import PDFDocument from "pdfkit";

const app = express();
const PORT = Number(process.env.PORT || 3000);

const AUTH_KEY = process.env.AUTH_KEY;
const XML_KEY = process.env.XML_KEY;

const NFE_NAMESPACE = "http://www.portalfiscal.inf.br/nfe";
const NFE_EVENTO_WSDL_NAMESPACE =
    "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4";

const NFE_EVENTO_SOAP_ACTION =
    "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento";

process.on("uncaughtException", (error) => {
    console.error("ERRO NÃO TRATADO:", error);
});

process.on("unhandledRejection", (reason) => {
    console.error("PROMISE REJEITADA:", reason);
});

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(cors({ origin: "*" }));
app.use(compression());
app.use(express.json({ limit: "20mb" }));
app.use(morgan("combined"));

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: "Muitas requisições. Tente novamente mais tarde."
    }
});

app.use("/api", limiter);
app.use("/backend", limiter);
app.use("/rpa", limiter);

console.log("====================================");
console.log("BRIDGE SEFAZ INICIANDO");
console.log("AUTH_KEY carregada:", Boolean(AUTH_KEY));
console.log("XML_KEY carregada:", Boolean(XML_KEY));
console.log("NODE_ENV:", process.env.NODE_ENV || "development");
console.log("====================================");

/* ============================================================
   FUNÇÕES GERAIS
============================================================ */

function sanitizarBase64(valor) {
    if (typeof valor !== "string") return "";

    return valor
        .replace(/^data:.*?;base64,/i, "")
        .replace(/\s+/g, "")
        .trim();
}

function escapeXml(valor) {
    return String(valor ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
}

function decodeXml(valor) {
    if (!valor) return "";

    return String(valor)
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&#(\d+);/g, (_, code) =>
            String.fromCharCode(Number(code))
        )
        .replace(/&#x([0-9a-f]+);/gi, (_, code) =>
            String.fromCharCode(parseInt(code, 16))
        )
        .trim();
}

function extrairTagXml(xml, tag, origem = null) {
    if (!xml) return "";

    const conteudo = origem || xml;

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        "i"
    );

    const match = conteudo.match(regex);
    return match ? decodeXml(match[1]) : "";
}

function extrairTagsXml(xml, tag) {
    if (!xml) return [];

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        "gi"
    );

    const valores = [];
    let match;

    while ((match = regex.exec(xml)) !== null) {
        valores.push(decodeXml(match[1]));
    }

    return valores;
}

function extrairBlocoXml(xml, tag) {
    if (!xml) return "";

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>[\\s\\S]*?<\\/(?:[\\w.-]+:)?${tag}>`,
        "i"
    );

    const match = xml.match(regex);
    return match ? match[0] : "";
}

function extrairTodosBlocosXml(xml, tag) {
    if (!xml) return [];

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>[\\s\\S]*?<\\/(?:[\\w.-]+:)?${tag}>`,
        "gi"
    );

    return xml.match(regex) || [];
}

function formatarMoeda(valor) {
    const numero = Number(String(valor || "0").replace(",", "."));

    if (!Number.isFinite(numero)) {
        return "R$ 0,00";
    }

    return numero.toLocaleString("pt-BR", {
        style: "currency",
        currency: "BRL"
    });
}

function formatarNumero(valor, casas = 2) {
    const numero = Number(String(valor || "0").replace(",", "."));

    if (!Number.isFinite(numero)) return "0,00";

    return numero.toLocaleString("pt-BR", {
        minimumFractionDigits: casas,
        maximumFractionDigits: casas
    });
}

function formatarData(valor) {
    if (!valor) return "";

    const data = new Date(valor);

    if (Number.isNaN(data.getTime())) {
        return valor;
    }

    return data.toLocaleString("pt-BR");
}

function somenteDigitos(valor) {
    return String(valor || "").replace(/\D/g, "");
}

function quebrarTexto(valor, tamanho = 90) {
    const texto = String(valor || "").trim();

    if (!texto) return "";

    const partes = [];

    for (let i = 0; i < texto.length; i += tamanho) {
        partes.push(texto.substring(i, i + tamanho));
    }

    return partes.join("\n");
}

/* ============================================================
   AUTENTICAÇÃO
============================================================ */

function validarAPI(req, res, next) {
    const apiKey = req.headers["x-api-key"] || req.headers["x-xml-key"];

    if (!AUTH_KEY) {
        return res.status(500).json({
            success: false,
            error: "AUTH_KEY não configurada no ambiente."
        });
    }

    if (!apiKey || apiKey !== AUTH_KEY) {
        return res.status(403).json({
            success: false,
            error: "API Key inválida."
        });
    }

    next();
}

/* ============================================================
   HEALTHCHECK
============================================================ */

app.get("/health", (req, res) => {
    res.json({
        status: "online",
        node: process.version,
        timestamp: new Date().toISOString()
    });
});

app.get("/api/info", (req, res) => {
    res.json({
        success: true,
        service: "Bridge SEFAZ",
        version: "1.4.0",
        authKeyConfigured: Boolean(AUTH_KEY),
        xmlKeyConfigured: Boolean(XML_KEY)
    });
});

app.get("/version", (req, res) => {
    res.json({
        service: "Bridge SEFAZ",
        version: "1.4.0",
        node: process.version
    });
});

app.get("/api/test-auth", validarAPI, (req, res) => {
    res.json({
        success: true,
        message: "Autenticação OK"
    });
});

/* ============================================================
   DISTRIBUIÇÃO DF-E
============================================================ */

function processarRespostaSefaz(soapXml) {
    const retorno = {
        cStat: "",
        xMotivo: "",
        ultNSU: "",
        maxNSU: "",
        docs: []
    };

    if (typeof soapXml !== "string") {
        return retorno;
    }

    retorno.cStat = extrairTagXml(soapXml, "cStat");
    retorno.xMotivo = extrairTagXml(soapXml, "xMotivo");
    retorno.ultNSU = extrairTagXml(soapXml, "ultNSU");
    retorno.maxNSU = extrairTagXml(soapXml, "maxNSU");

    const docRegex =
        /<docZip\b[^>]*NSU="([^"]+)"[^>]*schema="([^"]+)"[^>]*>([\s\S]*?)<\/docZip>/gi;

    let match;

    while ((match = docRegex.exec(soapXml)) !== null) {
        const nsu = match[1];
        const schema = match[2];
        const conteudoBase64 = match[3].replace(/\s+/g, "");

        try {
            const zipBuffer = Buffer.from(conteudoBase64, "base64");
            const xmlDescompactado = zlib.gunzipSync(zipBuffer).toString("utf8");

            retorno.docs.push({
                nsu,
                schema,
                xml: xmlDescompactado
            });
        } catch (error) {
            console.error(
                `Erro ao descompactar documento NSU ${nsu}:`,
                error.message
            );
        }
    }

    return retorno;
}

async function consultarSefaz(req, res, dadosCustom = null) {
    let finalizado = false;
    const requestId = crypto.randomUUID();

    try {
        const payload = dadosCustom || req.body;

        const {
            pfxBase64,
            password,
            endpoint,
            soapEnvelope
        } = payload;

        const soapAction =
            payload.soapAction ||
            "http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse";

        if (!pfxBase64 || !password || !endpoint || !soapEnvelope) {
            return res.status(400).json({
                success: false,
                requestId,
                error: "pfxBase64, password, endpoint e soapEnvelope são obrigatórios."
            });
        }

        const endpointUrl = new URL(endpoint);

        if (endpointUrl.protocol !== "https:") {
            return res.status(400).json({
                success: false,
                requestId,
                error: "O endpoint SEFAZ precisa utilizar HTTPS."
            });
        }

        const certificado = Buffer.from(
            sanitizarBase64(pfxBase64),
            "base64"
        );

        try {
            tls.createSecureContext({
                pfx: certificado,
                passphrase: password
            });
        } catch (error) {
            return res.status(400).json({
                success: false,
                requestId,
                error: "Erro no certificado PFX: " + error.message
            });
        }

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
                "Content-Type": `application/soap+xml; charset=utf-8; action="${soapAction}"`,
                SOAPAction: soapAction,
                Accept: "application/soap+xml, text/xml, */*",
                "User-Agent": "Bridge-SEFAZ/1.4",
                "Content-Length": soapBuffer.length
            }
        };

        const sefazRequest = https.request(options, (sefazResponse) => {
            let body = "";

            sefazResponse.setEncoding("utf8");

            sefazResponse.on("data", (chunk) => {
                body += chunk;
            });

            sefazResponse.on("end", () => {
                if (finalizado) return;

                finalizado = true;

                const processado = processarRespostaSefaz(body);
                const sucesso = sefazResponse.statusCode === 200;

                return res.status(sucesso ? 200 : 422).json({
                    success: sucesso,
                    requestId,
                    statusCode: sefazResponse.statusCode,
                    cStat: processado.cStat,
                    xMotivo: processado.xMotivo,
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

                return res.status(504).json({
                    success: false,
                    requestId,
                    error: "Timeout na comunicação com a SEFAZ."
                });
            }
        });

        sefazRequest.on("error", (error) => {
            if (!finalizado) {
                finalizado = true;

                return res.status(502).json({
                    success: false,
                    requestId,
                    error: "Erro de comunicação com a SEFAZ: " + error.message
                });
            }
        });

        sefazRequest.write(soapBuffer);
        sefazRequest.end();
    } catch (error) {
        if (!res.headersSent) {
            return res.status(500).json({
                success: false,
                requestId,
                error: error.message
            });
        }
    }
}

app.post(
    "/api/sefaz/distribuicao",
    validarAPI,
    (req, res) => consultarSefaz(req, res)
);

app.post(
    "/api/sefaz/consultar",
    validarAPI,
    (req, res) => consultarSefaz(req, res)
);

app.post(
    "/backend/v1/xml/sync",
    validarAPI,
    (req, res) => consultarSefaz(req, res)
);

/* ============================================================
   GERAÇÃO DO DANFE EM PDF
============================================================ */

function obterDadosNFe(xml) {
    const blocoNFe = extrairBlocoXml(xml, "infNFe") || xml;
    const blocoIde = extrairBlocoXml(blocoNFe, "ide");
    const blocoEmit = extrairBlocoXml(blocoNFe, "emit");
    const blocoDest = extrairBlocoXml(blocoNFe, "dest");
    const blocoTotal = extrairBlocoXml(blocoNFe, "ICMSTot");
    const blocoTransp = extrairBlocoXml(blocoNFe, "transp");
    const blocoInfAdic = extrairBlocoXml(blocoNFe, "infAdic");

    const idNFe =
        blocoNFe.match(/\bId\s*=\s*["']([^"']+)["']/i)?.[1] || "";

    const chave =
        extrairTagXml(xml, "chNFe") ||
        idNFe.replace(/^NFe/i, "") ||
        "";

    const produtos = extrairTodosBlocosXml(blocoNFe, "det").map((blocoDet) => {
        const blocoProd = extrairBlocoXml(blocoDet, "prod");

        return {
            numero: blocoDet.match(/\bnItem\s*=\s*["']([^"']+)["']/i)?.[1] || "",
            codigo: extrairTagXml(blocoProd, "cProd"),
            descricao: extrairTagXml(blocoProd, "xProd"),
            ncm: extrairTagXml(blocoProd, "NCM"),
            cfop: extrairTagXml(blocoProd, "CFOP"),
            unidade: extrairTagXml(blocoProd, "uCom"),
            quantidade: extrairTagXml(blocoProd, "qCom"),
            valorUnitario: extrairTagXml(blocoProd, "vUnCom"),
            valorTotal: extrairTagXml(blocoProd, "vProd"),
            cest: extrairTagXml(blocoProd, "CEST")
        };
    });

    const chaveNumerica = somenteDigitos(chave);

    return {
        chave: chaveNumerica || chave || "NÃO INFORMADA",
        protocolo:
            extrairTagXml(xml, "nProt") ||
            extrairTagXml(xml, "nRec") ||
            "",
        emitente: {
            cnpj:
                extrairTagXml(blocoEmit, "CNPJ") ||
                extrairTagXml(blocoEmit, "CPF"),
            nome: extrairTagXml(blocoEmit, "xNome"),
            fantasia: extrairTagXml(blocoEmit, "xFant"),
            ie: extrairTagXml(blocoEmit, "IE"),
            logradouro: extrairTagXml(blocoEmit, "xLgr"),
            numero: extrairTagXml(blocoEmit, "nro"),
            complemento: extrairTagXml(blocoEmit, "xCpl"),
            bairro: extrairTagXml(blocoEmit, "xBairro"),
            municipio: extrairTagXml(blocoEmit, "xMun"),
            uf: extrairTagXml(blocoEmit, "UF"),
            cep: extrairTagXml(blocoEmit, "CEP"),
            telefone: extrairTagXml(blocoEmit, "fone")
        },
        destinatario: {
            cnpj:
                extrairTagXml(blocoDest, "CNPJ") ||
                extrairTagXml(blocoDest, "CPF"),
            nome: extrairTagXml(blocoDest, "xNome"),
            ie: extrairTagXml(blocoDest, "IE"),
            logradouro: extrairTagXml(blocoDest, "xLgr"),
            numero: extrairTagXml(blocoDest, "nro"),
            complemento: extrairTagXml(blocoDest, "xCpl"),
            bairro: extrairTagXml(blocoDest, "xBairro"),
            municipio: extrairTagXml(blocoDest, "xMun"),
            uf: extrairTagXml(blocoDest, "UF"),
            cep: extrairTagXml(blocoDest, "CEP"),
            telefone: extrairTagXml(blocoDest, "fone")
        },
        identificacao: {
            numero: extrairTagXml(blocoIde, "nNF"),
            serie: extrairTagXml(blocoIde, "serie"),
            modelo: extrairTagXml(blocoIde, "mod"),
            natureza: extrairTagXml(blocoIde, "natOp"),
            emissao:
                extrairTagXml(blocoIde, "dhEmi") ||
                extrairTagXml(blocoIde, "dEmi"),
            entradaSaida:
                extrairTagXml(blocoIde, "dhSaiEnt") ||
                extrairTagXml(blocoIde, "dSaiEnt")
        },
        totais: {
            produtos: extrairTagXml(blocoTotal, "vProd"),
            frete: extrairTagXml(blocoTotal, "vFrete"),
            seguro: extrairTagXml(blocoTotal, "vSeg"),
            desconto: extrairTagXml(blocoTotal, "vDesc"),
            outras: extrairTagXml(blocoTotal, "vOutro"),
            icms: extrairTagXml(blocoTotal, "vICMS"),
            ipi: extrairTagXml(blocoTotal, "vIPI"),
            pis: extrairTagXml(blocoTotal, "vPIS"),
            cofins: extrairTagXml(blocoTotal, "vCOFINS"),
            valorNota: extrairTagXml(blocoTotal, "vNF")
        },
        transporte: {
            modalidade: extrairTagXml(blocoTransp, "modFrete"),
            nome: extrairTagXml(blocoTransp, "xNome"),
            cnpj: extrairTagXml(blocoTransp, "CNPJ"),
            placa: extrairTagXml(blocoTransp, "placa"),
            uf: extrairTagXml(blocoTransp, "UF"),
            quantidade: extrairTagXml(blocoTransp, "qVol"),
            especie: extrairTagXml(blocoTransp, "esp"),
            pesoBruto: extrairTagXml(blocoTransp, "pesoB"),
            pesoLiquido: extrairTagXml(blocoTransp, "pesoL")
        },
        informacoesAdicionais:
            extrairTagXml(blocoInfAdic, "infCpl") ||
            extrairTagXml(blocoInfAdic, "infAdFisco"),
        produtos
    };
}

function desenharCaixa(doc, x, y, largura, altura, titulo, valor = "") {
    doc.rect(x, y, largura, altura).stroke();

    if (titulo) {
        doc.font("Helvetica-Bold")
            .fontSize(6)
            .fillColor("#333333")
            .text(titulo.toUpperCase(), x + 4, y + 3, {
                width: largura - 8,
                lineBreak: false
            });
    }

    if (valor) {
        doc.font("Helvetica")
            .fontSize(8)
            .fillColor("#000000")
            .text(String(valor), x + 4, y + 14, {
                width: largura - 8,
                height: altura - 15,
                ellipsis: true
            });
    }

    return y + altura;
}

function desenharCabecalhoDanfe(doc, dados) {
    const margem = 32;
    const larguraPagina = 595;
    const larguraUtil = larguraPagina - margem * 2;
    const yInicial = 30;

    doc.lineWidth(0.7);
    doc.fillColor("#000000");

    doc.rect(margem, yInicial, 190, 82).stroke();

    doc.font("Helvetica-Bold")
        .fontSize(14)
        .text("DANFE", margem + 8, yInicial + 10);

    doc.font("Helvetica")
        .fontSize(7)
        .text("Documento Auxiliar da Nota Fiscal Eletrônica", margem + 8, yInicial + 31, {
            width: 174
        });

    doc.font("Helvetica-Bold")
        .fontSize(8)
        .text(`NF-e nº ${dados.identificacao.numero || "N/D"}`, margem + 8, yInicial + 53);

    doc.font("Helvetica")
        .fontSize(7)
        .text(`Série: ${dados.identificacao.serie || "N/D"}`, margem + 8, yInicial + 66);

    doc.rect(margem + 190, yInicial, larguraUtil - 190, 82).stroke();

    doc.font("Helvetica-Bold")
        .fontSize(9)
        .text("IDENTIFICAÇÃO DA NOTA FISCAL", margem + 198, yInicial + 8);

    doc.font("Helvetica")
        .fontSize(7)
        .text(
            `Modelo: ${dados.identificacao.modelo || "55"}   Série: ${
                dados.identificacao.serie || "N/D"
            }`,
            margem + 198,
            yInicial + 25
        );

    doc.text(
        `Número: ${dados.identificacao.numero || "N/D"}`,
        margem + 198,
        yInicial + 39
    );

    doc.text(
        `Emissão: ${formatarData(dados.identificacao.emissao) || "N/D"}`,
        margem + 198,
        yInicial + 53
    );

    doc.text(
        `Protocolo: ${dados.protocolo || "NÃO INFORMADO"}`,
        margem + 198,
        yInicial + 67
    );

    let y = yInicial + 94;

    doc.font("Helvetica-Bold")
        .fontSize(7)
        .text("CHAVE DE ACESSO", margem, y);

    y += 12;

    doc.rect(margem, y, larguraUtil, 31).stroke();

    doc.font("Helvetica-Bold")
        .fontSize(10)
        .text(
            dados.chave.replace(/(.{4})/g, "$1 ").trim(),
            margem + 8,
            y + 10,
            {
                width: larguraUtil - 16,
                align: "center",
                characterSpacing: 0.8
            }
        );

    y += 43;

    doc.font("Helvetica")
        .fontSize(7)
        .text(
            "Consulta de autenticidade no portal nacional da NF-e",
            margem,
            y
        );

    return y + 18;
}

function desenharEmitente(doc, dados, y) {
    const margem = 32;
    const largura = 531;
    const altura = 82;

    doc.font("Helvetica-Bold")
        .fontSize(8)
        .text("EMITENTE", margem, y);

    y += 12;

    doc.rect(margem, y, largura, altura).stroke();

    doc.font("Helvetica-Bold")
        .fontSize(9)
        .text(
            dados.emitente.nome || "NOME DO EMITENTE NÃO INFORMADO",
            margem + 7,
            y + 7,
            {
                width: 330
            }
        );

    doc.font("Helvetica")
        .fontSize(7)
        .text(
            dados.emitente.fantasia
                ? `Nome fantasia: ${dados.emitente.fantasia}`
                : "",
            margem + 7,
            y + 22,
            {
                width: 330
            }
        );

    doc.text(
        `CNPJ/CPF: ${dados.emitente.cnpj || "N/D"}`,
        margem + 7,
        y + 38
    );

    doc.text(
        `IE: ${dados.emitente.ie || "N/D"}`,
        margem + 7,
        y + 52
    );

    const endereco = [
        dados.emitente.logradouro,
        dados.emitente.numero,
        dados.emitente.complemento,
        dados.emitente.bairro,
        dados.emitente.municipio,
        dados.emitente.uf
    ]
        .filter(Boolean)
        .join(", ");

    doc.text(quebrarTexto(endereco, 70), margem + 220, y + 8, {
        width: 300,
        height: 38
    });

    doc.text(
        `CEP: ${dados.emitente.cep || "N/D"}  Tel.: ${
            dados.emitente.telefone || "N/D"
        }`,
        margem + 220,
        y + 53,
        {
            width: 300
        }
    );

    return y + altura + 16;
}

function desenharDestinatario(doc, dados, y) {
    const margem = 32;
    const largura = 531;
    const altura = 82;

    doc.font("Helvetica-Bold")
        .fontSize(8)
        .text("DESTINATÁRIO / REMETENTE", margem, y);

    y += 12;

    doc.rect(margem, y, largura, altura).stroke();

    doc.font("Helvetica-Bold")
        .fontSize(9)
        .text(
            dados.destinatario.nome || "DESTINATÁRIO NÃO INFORMADO",
            margem + 7,
            y + 7,
            {
                width: 330
            }
        );

    doc.font("Helvetica")
        .fontSize(7)
        .text(
            `CNPJ/CPF: ${dados.destinatario.cnpj || "N/D"}`,
            margem + 7,
            y + 25
        );

    doc.text(
        `IE: ${dados.destinatario.ie || "N/D"}`,
        margem + 7,
        y + 40
    );

    const endereco = [
        dados.destinatario.logradouro,
        dados.destinatario.numero,
        dados.destinatario.complemento,
        dados.destinatario.bairro,
        dados.destinatario.municipio,
        dados.destinatario.uf
    ]
        .filter(Boolean)
        .join(", ");

    doc.text(quebrarTexto(endereco, 70), margem + 220, y + 8, {
        width: 300,
        height: 38
    });

    doc.text(
        `CEP: ${dados.destinatario.cep || "N/D"}  Tel.: ${
            dados.destinatario.telefone || "N/D"
        }`,
        margem + 220,
        y + 53,
        {
            width: 300
        }
    );

    return y + altura + 16;
}

function desenharTabelaProdutos(doc, produtos, y) {
    const margem = 32;
    const largura = 531;
    const alturaCabecalho = 22;
    const alturaLinha = 35;

    doc.font("Helvetica-Bold")
        .fontSize(8)
        .text("DADOS DOS PRODUTOS / SERVIÇOS", margem, y);

    y += 12;

    const colunas = [
        { titulo: "ITEM", x: margem, largura: 32 },
        { titulo: "CÓDIGO", x: margem + 32, largura: 58 },
        { titulo: "DESCRIÇÃO", x: margem + 90, largura: 185 },
        { titulo: "NCM", x: margem + 275, largura: 48 },
        { titulo: "CFOP", x: margem + 323, largura: 40 },
        { titulo: "QTD.", x: margem + 363, largura: 42 },
        { titulo: "V. UNIT.", x: margem + 405, largura: 60 },
        { titulo: "V. TOTAL", x: margem + 465, largura: 66 }
    ];

    doc.rect(margem, y, largura, alturaCabecalho).stroke();

    doc.font("Helvetica-Bold").fontSize(6);

    for (const coluna of colunas) {
        doc.text(coluna.titulo, coluna.x + 2, y + 7, {
            width: coluna.largura - 4,
            align: "center"
        });

        doc
            .moveTo(coluna.x, y)
            .lineTo(coluna.x, y + alturaCabecalho)
            .stroke();
    }

    doc.moveTo(margem + largura, y)
        .lineTo(margem + largura, y + alturaCabecalho)
        .stroke();

    y += alturaCabecalho;

    if (!produtos.length) {
        doc.rect(margem, y, largura, alturaLinha).stroke();
        doc.font("Helvetica")
            .fontSize(7)
            .text("Nenhum item encontrado no XML.", margem + 5, y + 13);
        return y + alturaLinha;
    }

    for (const produto of produtos) {
        if (y > 700) {
            doc.addPage();
            y = 35;

            doc.font("Helvetica-Bold")
                .fontSize(8)
                .text("DADOS DOS PRODUTOS / SERVIÇOS - CONTINUAÇÃO", margem, y);

            y += 12;
        }

        doc.rect(margem, y, largura, alturaLinha).stroke();

        for (const coluna of colunas) {
            doc
                .moveTo(coluna.x, y)
                .lineTo(coluna.x, y + alturaLinha)
                .stroke();
        }

        const valores = [
            produto.numero,
            produto.codigo,
            produto.descricao,
            produto.ncm,
            produto.cfop,
            produto.quantidade
                ? formatarNumero(produto.quantidade, 3)
                : "",
            produto.valorUnitario
                ? formatarMoeda(produto.valorUnitario)
                : "",
            produto.valorTotal
                ? formatarMoeda(produto.valorTotal)
                : ""
        ];

        doc.font("Helvetica").fontSize(6);

        valores.forEach((valor, index) => {
            const coluna = colunas[index];

            doc.text(String(valor || ""), coluna.x + 2, y + 8, {
                width: coluna.largura - 4,
                height: alturaLinha - 10,
                align: index === 2 ? "left" : "center",
                ellipsis: true
            });
        });

        y += alturaLinha;
    }

    return y;
}

function desenharTotais(doc, dados, y) {
    const margem = 32;
    const largura = 531;
    const altura = 96;

    if (y > 665) {
        doc.addPage();
        y = 35;
    }

    doc.font("Helvetica-Bold")
        .fontSize(8)
        .text("CÁLCULO DO IMPOSTO", margem, y);

    y += 12;

    doc.rect(margem, y, largura, altura).stroke();

    const totais = [
        ["Valor dos produtos", formatarMoeda(dados.totais.produtos)],
        ["Frete", formatarMoeda(dados.totais.frete)],
        ["Seguro", formatarMoeda(dados.totais.seguro)],
        ["Desconto", formatarMoeda(dados.totais.desconto)],
        ["ICMS", formatarMoeda(dados.totais.icms)],
        ["IPI", formatarMoeda(dados.totais.ipi)],
        ["PIS", formatarMoeda(dados.totais.pis)],
        ["COFINS", formatarMoeda(dados.totais.cofins)]
    ];

    const larguraColuna = largura / 4;

    totais.forEach(([titulo, valor], index) => {
        const coluna = index % 4;
        const linha = Math.floor(index / 4);
        const x = margem + coluna * larguraColuna;
        const linhaY = y + linha * 45;

        doc.rect(x, linhaY, larguraColuna, 45).stroke();

        doc.font("Helvetica-Bold")
            .fontSize(6)
            .text(titulo.toUpperCase(), x + 4, linhaY + 6, {
                width: larguraColuna - 8,
                align: "center"
            });

        doc.font("Helvetica")
            .fontSize(8)
            .text(valor, x + 4, linhaY + 22, {
                width: larguraColuna - 8,
                align: "center"
            });
    });

    doc.font("Helvetica-Bold")
        .fontSize(9)
        .text(
            `VALOR TOTAL DA NOTA: ${formatarMoeda(dados.totais.valorNota)}`,
            margem + 7,
            y + 76
        );

    return y + altura + 16;
}

function desenharTransporte(doc, dados, y) {
    const margem = 32;
    const largura = 531;
    const altura = 72;

    if (y > 700) {
        doc.addPage();
        y = 35;
    }

    doc.font("Helvetica-Bold")
        .fontSize(8)
        .text("TRANSPORTADOR / VOLUMES TRANSPORTADOS", margem, y);

    y += 12;

    doc.rect(margem, y, largura, altura).stroke();

    doc.font("Helvetica")
        .fontSize(7)
        .text(
            `Transportadora: ${dados.transporte.nome || "NÃO INFORMADA"}`,
            margem + 7,
            y + 8,
            {
                width: 360
            }
        );

    doc.text(
        `CNPJ: ${dados.transporte.cnpj || "N/D"}`,
        margem + 7,
        y + 24
    );

    doc.text(
        `Modalidade frete: ${dados.transporte.modalidade || "N/D"}`,
        margem + 7,
        y + 40
    );

    doc.text(
        `Placa: ${dados.transporte.placa || "N/D"}  UF: ${
            dados.transporte.uf || "N/D"
        }`,
        margem + 280,
        y + 8
    );

    doc.text(
        `Volumes: ${dados.transporte.quantidade || "N/D"}  Espécie: ${
            dados.transporte.especie || "N/D"
        }`,
        margem + 280,
        y + 24
    );

    doc.text(
        `Peso bruto: ${dados.transporte.pesoBruto || "N/D"}  Peso líquido: ${
            dados.transporte.pesoLiquido || "N/D"
        }`,
        margem + 280,
        y + 40
    );

    return y + altura + 16;
}

function desenharInformacoesAdicionais(doc, dados, y) {
    const margem = 32;
    const largura = 531;

    if (!dados.informacoesAdicionais) {
        return y;
    }

    if (y > 680) {
        doc.addPage();
        y = 35;
    }

    const texto = quebrarTexto(dados.informacoesAdicionais, 120);
    const altura = Math.max(60, texto.split("\n").length * 11 + 28);

    doc.font("Helvetica-Bold")
        .fontSize(8)
        .text("INFORMAÇÕES ADICIONAIS", margem, y);

    y += 12;

    doc.rect(margem, y, largura, altura).stroke();

    doc.font("Helvetica")
        .fontSize(7)
        .text(texto, margem + 7, y + 8, {
            width: largura - 14,
            height: altura - 14
        });

    return y + altura + 12;
}

function gerarPdfDanfe(xmlString) {
    return new Promise((resolve, reject) => {
        try {
            const dados = obterDadosNFe(xmlString);

            const doc = new PDFDocument({
                size: "A4",
                margins: {
                    top: 28,
                    bottom: 28,
                    left: 32,
                    right: 32
                },
                bufferPages: true,
                info: {
                    Title: `DANFE NF-e ${dados.identificacao.numero || ""}`,
                    Author: "Bridge SEFAZ",
                    Subject: "Documento Auxiliar da Nota Fiscal Eletrônica"
                }
            });

            const buffers = [];

            doc.on("data", (chunk) => buffers.push(chunk));

            doc.on("error", reject);

            doc.on("end", () => {
                resolve(Buffer.concat(buffers));
            });

            let y = desenharCabecalhoDanfe(doc, dados);

            y = desenharEmitente(doc, dados, y);
            y = desenharDestinatario(doc, dados, y);
            y = desenharTabelaProdutos(doc, dados.produtos, y);
            y += 16;
            y = desenharTotais(doc, dados, y);
            y = desenharTransporte(doc, dados, y);
            y = desenharInformacoesAdicionais(doc, dados, y);

            const paginas = doc.bufferedPageRange();

            for (
                let pagina = 0;
                pagina < paginas.count;
                pagina++
            ) {
                doc.switchToPage(pagina);

                doc.font("Helvetica")
                    .fontSize(6)
                    .fillColor("#555555")
                    .text(
                        `Bridge SEFAZ - DANFE | Página ${pagina + 1} de ${paginas.count}`,
                        32,
                        805,
                        {
                            width: 531,
                            align: "center"
                        }
                    );
            }

            doc.end();
        } catch (error) {
            reject(error);
        }
    });
}

app.post("/api/xml/render-pdf", validarAPI, async (req, res) => {
    try {
        const { xmlBase64, tipo } = req.body;

        if (!xmlBase64) {
            return res.status(400).json({
                success: false,
                error: "XML Base64 não fornecido."
            });
        }

        const xmlLimpo = sanitizarBase64(xmlBase64);

        if (!xmlLimpo) {
            return res.status(400).json({
                success: false,
                error: "XML Base64 vazio."
            });
        }

        let xmlString;

        try {
            xmlString = Buffer.from(xmlLimpo, "base64").toString("utf8");
        } catch (error) {
            return res.status(400).json({
                success: false,
                error: "XML Base64 inválido."
            });
        }

        if (!xmlString.includes("<")) {
            return res.status(400).json({
                success: false,
                error: "O conteúdo informado não parece ser um XML válido."
            });
        }

        const pdfBuffer = await gerarPdfDanfe(xmlString);

        return res.json({
            success: true,
            tipo: tipo || "danfe",
            filename: "danfe-nfe.pdf",
            mimeType: "application/pdf",
            size: pdfBuffer.length,
            pdfBase64: pdfBuffer.toString("base64")
        });
    } catch (error) {
        console.error("Erro ao gerar PDF DANFE:", error);

        if (!res.headersSent) {
            return res.status(500).json({
                success: false,
                error: "Erro ao gerar DANFE: " + error.message
            });
        }
    }
});

/* ============================================================
   MANIFESTAÇÃO DO DESTINATÁRIO
============================================================ */

function obterAmbienteNFe() {
    return process.env.NFE_AMBIENTE === "2" ? "2" : "1";
}

function obterEndpointManifestacao(endpointFornecido = null) {
    if (endpointFornecido) {
        const url = new URL(endpointFornecido);

        if (url.protocol !== "https:") {
            throw new Error("Endpoint precisa utilizar HTTPS.");
        }

        return endpointFornecido;
    }

    if (obterAmbienteNFe() === "1") {
        return "https://www.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx";
    }

    return "https://hom.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx";
}

function normalizarCNPJ(cnpj) {
    const valor = somenteDigitos(cnpj);

    if (valor.length !== 14) {
        throw new Error("CNPJ inválido. Esperados 14 dígitos.");
    }

    return valor;
}

function normalizarChaveNFe(chave) {
    const valor = somenteDigitos(chave);

    if (valor.length !== 44) {
        throw new Error("Chave NF-e inválida. Esperados 44 dígitos.");
    }

    return valor;
}

function gerarDhEvento() {
    const agora = new Date();
    const offset = -agora.getTimezoneOffset();
    const sinal = offset >= 0 ? "+" : "-";
    const absoluto = Math.abs(offset);

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
        pad(Math.floor(absoluto / 60)) +
        ":" +
        pad(absoluto % 60)
    );
}

function gerarIdLote() {
    return String(Date.now()).slice(-15);
}

const TIPOS_MANIFESTACAO = {
    confirmada: {
        codigo: "210200",
        descricao: "Confirmacao da Operacao"
    },
    ciencia: {
        codigo: "210210",
        descricao: "Ciencia da Operacao"
    },
    desconhecida: {
        codigo: "210220",
        descricao: "Desconhecimento da Operacao"
    },
    nao_realizada: {
        codigo: "210240",
        descricao: "Operacao nao Realizada"
    }
};

function extrairCertificadoA1(pfxBase64, password) {
    if (!pfxBase64) {
        throw new Error("Certificado PFX não informado.");
    }

    if (!password) {
        throw new Error("Senha do certificado não informada.");
    }

    try {
        const pfxDer = forge.util.decode64(sanitizarBase64(pfxBase64));
        const pfxAsn1 = forge.asn1.fromDer(pfxDer);
        const p12 = forge.pkcs12.pkcs12FromAsn1(
            pfxAsn1,
            false,
            password
        );

        let privateKey = null;
        let certificate = null;

        for (const safeContents of p12.safeContents) {
            for (const safeBag of safeContents.safeBags) {
                if (
                    safeBag.type === forge.pki.oids.keyBag ||
                    safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag
                ) {
                    if (safeBag.key) {
                        privateKey = safeBag.key;
                    }
                }

                if (
                    safeBag.type === forge.pki.oids.certBag &&
                    safeBag.cert &&
                    !certificate
                ) {
                    certificate = safeBag.cert;
                }
            }
        }

        if (!privateKey) {
            throw new Error("Chave privada não encontrada.");
        }

        if (!certificate) {
            throw new Error("Certificado X509 não encontrado.");
        }

        const privateKeyPem = forge.pki.privateKeyToPem(privateKey);

        const certPem = forge.pki.certificateToPem(certificate);

        const certBase64 = certPem
            .replace(/-----BEGIN CERTIFICATE-----/g, "")
            .replace(/-----END CERTIFICATE-----/g, "")
            .replace(/\r?\n/g, "")
            .trim();

        return {
            privateKeyPem,
            certBase64
        };
    } catch (error) {
        throw new Error("Erro ao abrir certificado A1: " + error.message);
    }
}

function gerarEventoManifestacaoAssinado(
    cnpj,
    chave,
    tipoManifestacao,
    pfxBase64,
    password
) {
    const evento = TIPOS_MANIFESTACAO[tipoManifestacao];

    if (!evento) {
        throw new Error(
            "Tipo de manifestação inválido: " + tipoManifestacao
        );
    }

    const cnpjLimpo = normalizarCNPJ(cnpj);
    const chaveLimpa = normalizarChaveNFe(chave);
    const idEvento =
        "ID" + evento.codigo + chaveLimpa + "01";

    let detalheExtra = "";

    if (evento.codigo === "210240") {
        detalheExtra =
            "<xJust>Operacao nao realizada pelo destinatario</xJust>";
    }

    const infEvento =
        `<infEvento Id="${idEvento}">` +
        `<cOrgao>91</cOrgao>` +
        `<tpAmb>${obterAmbienteNFe()}</tpAmb>` +
        `<CNPJ>${cnpjLimpo}</CNPJ>` +
        `<chNFe>${chaveLimpa}</chNFe>` +
        `<dhEvento>${gerarDhEvento()}</dhEvento>` +
        `<tpEvento>${evento.codigo}</tpEvento>` +
        `<nSeqEvento>1</nSeqEvento>` +
        `<verEvento>1.00</verEvento>` +
        `<detEvento versao="1.00">` +
        `<descEvento>${evento.descricao}</descEvento>` +
        detalheExtra +
        `</detEvento>` +
        `</infEvento>`;

    const eventoXml =
        `<evento xmlns="${NFE_NAMESPACE}" versao="1.00">` +
        infEvento +
        `</evento>`;

    const { privateKeyPem, certBase64 } =
        extrairCertificadoA1(pfxBase64, password);

    const assinatura = new SignedXml();

    assinatura.canonicalizationAlgorithm =
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    assinatura.signatureAlgorithm =
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    assinatura.addReference({
        xpath: `//*[local-name(.)='infEvento' and @Id='${idEvento}']`,
        transforms: [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        ],
        digestAlgorithm:
            "http://www.w3.org/2000/09/xmldsig#sha1"
    });

    assinatura.privateKey = privateKeyPem;

    assinatura.getKeyInfoContent = () =>
        `<X509Data><X509Certificate>${certBase64}</X509Certificate></X509Data>`;

    assinatura.keyInfoProvider = {
        getKeyInfo: () =>
            `<X509Data><X509Certificate>${certBase64}</X509Certificate></X509Data>`
    };

    assinatura.computeSignature(eventoXml, {
        location: {
            reference: `//*[local-name(.)='infEvento' and @Id='${idEvento}']`,
            action: "after"
        }
    });

    const xmlAssinado = assinatura.getSignedXml();

    if (!xmlAssinado.includes("<Signature")) {
        throw new Error("Falha ao gerar assinatura XML.");
    }

    return xmlAssinado;
}

function gerarManifestacaoXML(
    cnpj,
    chave,
    tipoManifestacao,
    pfxBase64,
    password
) {
    const eventoAssinado = gerarEventoManifestacaoAssinado(
        cnpj,
        chave,
        tipoManifestacao,
        pfxBase64,
        password
    );

    return (
        `<?xml version="1.0" encoding="utf-8"?>` +
        `<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
        `xmlns:xsd="http://www.w3.org/2001/XMLSchema" ` +
        `xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">` +
        `<soap12:Body>` +
        `<nfeDadosMsg xmlns="${NFE_EVENTO_WSDL_NAMESPACE}">` +
        `<envEvento xmlns="${NFE_NAMESPACE}" versao="1.00">` +
        `<idLote>${gerarIdLote()}</idLote>` +
        eventoAssinado +
        `</envEvento>` +
        `</nfeDadosMsg>` +
        `</soap12:Body>` +
        `</soap12:Envelope>`
    );
}

function interpretarRespostaManifestacao(body, statusCode) {
    const cStats = extrairTagsXml(body, "cStat");
    const motivos = extrairTagsXml(body, "xMotivo");

    const cStatLote = cStats[0] || null;
    const cStatEvento =
        cStats.length > 1
            ? cStats[cStats.length - 1]
            : cStatLote;

    const sucesso =
        statusCode === 200 &&
        ["135", "136"].includes(cStatEvento);

    return {
        sucesso,
        cStatLote,
        cStatEvento,
        motivo: motivos[motivos.length - 1] || null,
        protocolo: extrairTagXml(body, "nProt"),
        dhRegEvento: extrairTagXml(body, "dhRegEvento")
    };
}

app.post("/rpa/xml/manifest", validarAPI, async (req, res) => {
    let finalizado = false;
    const requestId = crypto.randomUUID();

    try {
        const {
            pfxBase64,
            password,
            cnpj,
            chave,
            tipoManifestacao,
            endpoint
        } = req.body;

        if (
            !pfxBase64 ||
            !password ||
            !cnpj ||
            !chave ||
            !tipoManifestacao
        ) {
            return res.status(400).json({
                success: false,
                requestId,
                error:
                    "pfxBase64, password, cnpj, chave e tipoManifestacao são obrigatórios."
            });
        }

        if (!TIPOS_MANIFESTACAO[tipoManifestacao]) {
            return res.status(400).json({
                success: false,
                requestId,
                error: "Tipo de manifestação inválido."
            });
        }

        const cnpjLimpo = normalizarCNPJ(cnpj);
        const chaveLimpa = normalizarChaveNFe(chave);
        const certificado = Buffer.from(
            sanitizarBase64(pfxBase64),
            "base64"
        );

        tls.createSecureContext({
            pfx: certificado,
            passphrase: password
        });

        const soapEnvelope = gerarManifestacaoXML(
            cnpjLimpo,
            chaveLimpa,
            tipoManifestacao,
            pfxBase64,
            password
        );

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
                Accept: "application/soap+xml, text/xml, */*",
                "User-Agent": "Bridge-SEFAZ/1.4",
                "Content-Length": soapBuffer.length
            }
        };

        const requisicao = https.request(options, (resposta) => {
            let body = "";

            resposta.setEncoding("utf8");

            resposta.on("data", (chunk) => {
                body += chunk;
            });

            resposta.on("end", () => {
                if (finalizado) return;

                finalizado = true;

                const retorno = interpretarRespostaManifestacao(
                    body,
                    resposta.statusCode
                );

                if (retorno.sucesso) {
                    return res.json({
                        success: true,
                        requestId,
                        cStat: retorno.cStatEvento,
                        message:
                            retorno.motivo ||
                            "Manifestação registrada com sucesso.",
                        protocolo: retorno.protocolo,
                        dhRegEvento: retorno.dhRegEvento
                    });
                }

                const erro =
                    retorno.motivo ||
                    extrairTagXml(body, "faultstring") ||
                    extrairTagXml(body, "Text") ||
                    `HTTP ${resposta.statusCode} retornado pela SEFAZ.`;

                return res.status(400).json({
                    success: false,
                    requestId,
                    statusCode: resposta.statusCode,
                    cStat: retorno.cStatEvento,
                    error: erro
                });
            });
        });

        requisicao.setTimeout(60000, () => {
            requisicao.destroy();

            if (!finalizado) {
                finalizado = true;

                return res.status(504).json({
                    success: false,
                    requestId,
                    error: "Timeout ao conectar com a SEFAZ."
                });
            }
        });

        requisicao.on("error", (error) => {
            if (!finalizado) {
                finalizado = true;

                return res.status(502).json({
                    success: false,
                    requestId,
                    error: "Erro de comunicação: " + error.message
                });
            }
        });

        requisicao.write(soapBuffer);
        requisicao.end();
    } catch (error) {
        if (!res.headersSent) {
            return res.status(500).json({
                success: false,
                requestId,
                error: error.message
            });
        }
    }
});

/* ============================================================
   TRATAMENTO DE ROTAS
============================================================ */

app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: "Endpoint inexistente."
    });
});

app.use((error, req, res, next) => {
    console.error("ERRO INTERNO:", error);

    if (res.headersSent) {
        return next(error);
    }

    return res.status(500).json({
        success: false,
        error: "Erro interno do servidor."
    });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(
        `BRIDGE SEFAZ ONLINE - Porta: ${PORT} - Ambiente: ${
            process.env.NODE_ENV || "development"
        }`
    );
});
