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
import bwipjs from "bwip-js";

const app = express();

const PORT = Number(process.env.PORT || 3000);
const AUTH_KEY = process.env.AUTH_KEY;
const XML_KEY = process.env.XML_KEY;

const NFE_NAMESPACE = "http://www.portalfiscal.inf.br/nfe";

const NFE_EVENTO_WSDL_NAMESPACE =
    "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4";

const NFE_EVENTO_SOAP_ACTION =
    "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento";

const VERSAO = "2.0.0";

process.on("uncaughtException", (error) => {
    console.error("ERRO NÃO TRATADO:", error);
});

process.on("unhandledRejection", (reason) => {
    console.error("PROMISE NÃO TRATADA:", reason);
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

/* ============================================================
   FUNÇÕES GERAIS
============================================================ */

function sanitizarBase64(valor) {
    if (typeof valor !== "string") {
        return "";
    }

    return valor
        .replace(/^data:.*?;base64,/i, "")
        .replace(/\s+/g, "")
        .trim();
}

function somenteDigitos(valor) {
    return String(valor || "").replace(/\D/g, "");
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
    if (!valor) {
        return "";
    }

    return String(valor)
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&#(\d+);/g, (_, codigo) =>
            String.fromCharCode(Number(codigo))
        )
        .replace(/&#x([0-9a-f]+);/gi, (_, codigo) =>
            String.fromCharCode(parseInt(codigo, 16))
        )
        .trim();
}

function extrairTagXml(xml, tag, origem = null) {
    if (!xml) {
        return "";
    }

    const conteudo = origem || xml;

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        "i"
    );

    const resultado = conteudo.match(regex);

    return resultado ? decodeXml(resultado[1]) : "";
}

function extrairTagsXml(xml, tag) {
    if (!xml) {
        return [];
    }

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        "gi"
    );

    const valores = [];
    let resultado;

    while ((resultado = regex.exec(xml)) !== null) {
        valores.push(decodeXml(resultado[1]));
    }

    return valores;
}

function extrairBlocoXml(xml, tag) {
    if (!xml) {
        return "";
    }

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>[\\s\\S]*?<\\/(?:[\\w.-]+:)?${tag}>`,
        "i"
    );

    const resultado = xml.match(regex);

    return resultado ? resultado[0] : "";
}

function extrairTodosBlocosXml(xml, tag) {
    if (!xml) {
        return [];
    }

    const regex = new RegExp(
        `<(?:[\\w.-]+:)?${tag}\\b[^>]*>[\\s\\S]*?<\\/(?:[\\w.-]+:)?${tag}>`,
        "gi"
    );

    return xml.match(regex) || [];
}

function extrairAtributoXml(bloco, atributo) {
    if (!bloco) {
        return "";
    }

    const regex = new RegExp(
        `${atributo}\\s*=\\s*["']([^"']*)["']`,
        "i"
    );

    const resultado = bloco.match(regex);

    return resultado ? decodeXml(resultado[1]) : "";
}

function converterNumero(valor) {
    if (valor === null || valor === undefined || valor === "") {
        return 0;
    }

    const texto = String(valor).trim();

    const numero = Number(texto);

    if (Number.isFinite(numero)) {
        return numero;
    }

    const brasileiro = Number(
        texto.replace(/\./g, "").replace(",", ".")
    );

    return Number.isFinite(brasileiro) ? brasileiro : 0;
}

function formatarMoeda(valor) {
    return converterNumero(valor).toLocaleString("pt-BR", {
        style: "currency",
        currency: "BRL"
    });
}

function formatarNumero(valor, casas = 2) {
    return converterNumero(valor).toLocaleString("pt-BR", {
        minimumFractionDigits: casas,
        maximumFractionDigits: casas
    });
}

function formatarCnpjCpf(valor) {
    const digitos = somenteDigitos(valor);

    if (digitos.length === 14) {
        return digitos.replace(
            /^(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})$/,
            "$1.$2.$3/$4-$5"
        );
    }

    if (digitos.length === 11) {
        return digitos.replace(
            /^(\d{3})(\d{3})(\d{3})(\d{2})$/,
            "$1.$2.$3-$4"
        );
    }

    return valor || "";
}

function formatarCep(valor) {
    const digitos = somenteDigitos(valor);

    if (digitos.length === 8) {
        return digitos.replace(/^(\d{5})(\d{3})$/, "$1-$2");
    }

    return valor || "";
}

function formatarChave(chave) {
    const digitos = somenteDigitos(chave);

    return digitos.replace(/(.{4})/g, "$1 ").trim();
}

function formatarData(valor) {
    if (!valor) {
        return "N/D";
    }

    const texto = String(valor)
        .replace("T", " ")
        .replace(/[+-]\d{2}:\d{2}$/, "");

    const data = new Date(valor);

    if (Number.isNaN(data.getTime())) {
        return texto;
    }

    return data.toLocaleString("pt-BR");
}

function obterChaveNFe(xml) {
    const chaveDireta =
        extrairTagXml(xml, "chNFe") ||
        extrairTagXml(xml, "chCTe") ||
        extrairTagXml(xml, "chMDFe");

    if (chaveDireta) {
        return somenteDigitos(chaveDireta);
    }

    const id = xml.match(
        /Id=["'](?:NFe|CTe|MDFe)?([0-9]{44})["']/i
    );

    return id ? id[1] : "";
}

function limitarTexto(valor, tamanho = 100) {
    const texto = String(valor || "").trim();

    if (texto.length <= tamanho) {
        return texto;
    }

    return `${texto.substring(0, tamanho - 3)}...`;
}

function textoSeguro(valor, padrao = "N/D") {
    const texto = String(valor || "").trim();

    return texto || padrao;
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
   ROTAS BÁSICAS
============================================================ */

app.get("/health", (req, res) => {
    res.json({
        status: "online",
        service: "Bridge SEFAZ",
        version: VERSAO,
        node: process.version,
        timestamp: new Date().toISOString()
    });
});

app.get("/version", (req, res) => {
    res.json({
        service: "Bridge SEFAZ",
        version: VERSAO,
        node: process.version
    });
});

app.get("/api/info", (req, res) => {
    res.json({
        success: true,
        service: "Bridge SEFAZ",
        version: VERSAO,
        authKeyConfigured: Boolean(AUTH_KEY),
        xmlKeyConfigured: Boolean(XML_KEY)
    });
});

app.get("/api/test-auth", validarAPI, (req, res) => {
    res.json({
        success: true,
        message: "Autenticação OK"
    });
});

/* ============================================================
   COMUNICAÇÃO HTTPS COM A SEFAZ
============================================================ */

function executarRequisicaoHttps({
    endpoint,
    certificado,
    password,
    body,
    soapAction
}) {
    return new Promise((resolve, reject) => {
        const endpointUrl = new URL(endpoint);

        if (endpointUrl.protocol !== "https:") {
            reject(new Error("O endpoint da SEFAZ precisa utilizar HTTPS."));
            return;
        }

        const bodyBuffer = Buffer.from(body, "utf8");

        const opcoes = {
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
                "User-Agent": "Bridge-SEFAZ/2.0",
                "Content-Length": bodyBuffer.length
            }
        };

        const requisicao = https.request(opcoes, (resposta) => {
            let respostaBody = "";

            resposta.setEncoding("utf8");

            resposta.on("data", (chunk) => {
                respostaBody += chunk;
            });

            resposta.on("end", () => {
                resolve({
                    statusCode: resposta.statusCode,
                    body: respostaBody
                });
            });
        });

        requisicao.setTimeout(60000, () => {
            requisicao.destroy(
                new Error("Timeout na comunicação com a SEFAZ.")
            );
        });

        requisicao.on("error", reject);

        requisicao.write(bodyBuffer);
        requisicao.end();
    });
}

/* ============================================================
   DISTRIBUIÇÃO DF-E
============================================================ */

function processarRespostaSefaz(soapXml) {
    const retorno = {
        cStat: extrairTagXml(soapXml, "cStat"),
        xMotivo: extrairTagXml(soapXml, "xMotivo"),
        ultNSU: extrairTagXml(soapXml, "ultNSU"),
        maxNSU: extrairTagXml(soapXml, "maxNSU"),
        docs: []
    };

    const regex =
        /<docZip\b[^>]*NSU="([^"]+)"[^>]*schema="([^"]+)"[^>]*>([\s\S]*?)<\/docZip>/gi;

    let resultado;

    while ((resultado = regex.exec(soapXml)) !== null) {
        const nsu = resultado[1];
        const schema = resultado[2];
        const conteudo = resultado[3].replace(/\s+/g, "");

        try {
            const xml = zlib
                .gunzipSync(Buffer.from(conteudo, "base64"))
                .toString("utf8");

            retorno.docs.push({
                nsu,
                schema,
                xml
            });
        } catch (error) {
            console.error(
                `Erro ao descompactar NSU ${nsu}:`,
                error.message
            );
        }
    }

    return retorno;
}

async function consultarSefaz(req, res) {
    const requestId = crypto.randomUUID();

    try {
        const {
            pfxBase64,
            password,
            endpoint,
            soapEnvelope,
            soapAction
        } = req.body || {};

        if (!pfxBase64 || !password || !endpoint || !soapEnvelope) {
            return res.status(400).json({
                success: false,
                requestId,
                error:
                    "pfxBase64, password, endpoint e soapEnvelope são obrigatórios."
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
                error: `Erro no certificado PFX: ${error.message}`
            });
        }

        const action =
            soapAction ||
            "http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse";

        const resposta = await executarRequisicaoHttps({
            endpoint,
            certificado,
            password,
            body: soapEnvelope,
            soapAction: action
        });

        const processado = processarRespostaSefaz(resposta.body);
        const sucesso = resposta.statusCode === 200;

        return res.status(sucesso ? 200 : 422).json({
            success: sucesso,
            requestId,
            statusCode: resposta.statusCode,
            cStat: processado.cStat,
            xMotivo: processado.xMotivo,
            ultNSU: processado.ultNSU,
            maxNSU: processado.maxNSU,
            docs: processado.docs,
            soapResponse: resposta.body
        });
    } catch (error) {
        console.error("Erro na consulta SEFAZ:", error);

        return res.status(502).json({
            success: false,
            requestId,
            error: error.message || "Erro de comunicação com a SEFAZ."
        });
    }
}

app.post(
    "/api/sefaz/distribuicao",
    validarAPI,
    consultarSefaz
);

app.post(
    "/api/sefaz/consultar",
    validarAPI,
    consultarSefaz
);

app.post(
    "/backend/v1/xml/sync",
    validarAPI,
    consultarSefaz
);

/* ============================================================
   EXTRAÇÃO DOS DADOS DA NF-E
============================================================ */

function extrairDadosNfe(xml, tipo = "NFe") {
    const blocoInfNFe =
        extrairBlocoXml(xml, "infNFe") || xml;

    const blocoEmit =
        extrairBlocoXml(blocoInfNFe, "emit");

    const blocoDest =
        extrairBlocoXml(blocoInfNFe, "dest");

    const blocoIde =
        extrairBlocoXml(blocoInfNFe, "ide");

    const blocoTotal =
        extrairBlocoXml(blocoInfNFe, "total");

    const blocoIcmsTot =
        extrairBlocoXml(blocoTotal, "ICMSTot");

    const blocoTransp =
        extrairBlocoXml(blocoInfNFe, "transp");

    const blocoInfAdic =
        extrairBlocoXml(blocoInfNFe, "infAdic");

    const blocoProt =
        extrairBlocoXml(xml, "infProt");

    const emitEndereco = [
        extrairTagXml(blocoEmit, "xLgr"),
        extrairTagXml(blocoEmit, "nro")
    ]
        .filter(Boolean)
        .join(", ");

    const emitCidade = [
        extrairTagXml(blocoEmit, "xBairro"),
        extrairTagXml(blocoEmit, "xMun"),
        extrairTagXml(blocoEmit, "UF")
    ]
        .filter(Boolean)
        .join(" - ")
        .replace(/ - ([A-Z]{2})$/, "/$1");

    const destEndereco = [
        extrairTagXml(blocoDest, "xLgr"),
        extrairTagXml(blocoDest, "nro")
    ]
        .filter(Boolean)
        .join(", ");

    const destinatarioDocumento =
        extrairTagXml(blocoDest, "CNPJ") ||
        extrairTagXml(blocoDest, "CPF");

    const produtos = extrairTodosBlocosXml(
        blocoInfNFe,
        "det"
    ).map((det, indice) => {
        const blocoProduto = extrairBlocoXml(det, "prod");

        const blocoImposto = extrairBlocoXml(det, "imposto");

        return {
            numero: indice + 1,
            codigo: extrairTagXml(blocoProduto, "cProd"),
            descricao: extrairTagXml(blocoProduto, "xProd"),
            ncm: extrairTagXml(blocoProduto, "NCM"),
            cfop: extrairTagXml(blocoProduto, "CFOP"),
            unidade: extrairTagXml(blocoProduto, "uCom"),
            quantidade: extrairTagXml(blocoProduto, "qCom"),
            valorUnitario: extrairTagXml(blocoProduto, "vUnCom"),
            valorTotal: extrairTagXml(blocoProduto, "vProd"),
            valorDesconto: extrairTagXml(blocoProduto, "vDesc"),
            imposto: blocoImposto
        };
    });

    const informacoesAdicionais =
        extrairTagXml(blocoInfAdic, "infCpl") ||
        extrairTagXml(blocoInfAdic, "infAdFisco");

    return {
        tipo,

        chave: obterChaveNFe(xml),

        numero: extrairTagXml(blocoIde, "nNF"),
        serie: extrairTagXml(blocoIde, "serie"),
        modelo: extrairTagXml(blocoIde, "mod"),
        naturezaOperacao: extrairTagXml(blocoIde, "natOp"),
        tipoOperacao: extrairTagXml(blocoIde, "tpNF"),
        dataEmissao:
            extrairTagXml(blocoIde, "dhEmi") ||
            extrairTagXml(blocoIde, "dEmi"),

        emitente: {
            nome: extrairTagXml(blocoEmit, "xNome"),
            fantasia: extrairTagXml(blocoEmit, "xFant"),
            cnpj: extrairTagXml(blocoEmit, "CNPJ"),
            ie: extrairTagXml(blocoEmit, "IE"),
            endereco: emitEndereco,
            bairro: extrairTagXml(blocoEmit, "xBairro"),
            cidade: emitCidade,
            cep: extrairTagXml(blocoEmit, "CEP"),
            uf: extrairTagXml(blocoEmit, "UF")
        },

        destinatario: {
            nome: extrairTagXml(blocoDest, "xNome"),
            documento: destinatarioDocumento,
            ie: extrairTagXml(blocoDest, "IE"),
            endereco: destEndereco,
            bairro: extrairTagXml(blocoDest, "xBairro"),
            cidade: extrairTagXml(blocoDest, "xMun"),
            uf: extrairTagXml(blocoDest, "UF"),
            cep: extrairTagXml(blocoDest, "CEP")
        },

        protocolo:
            extrairTagXml(blocoProt, "nProt") ||
            extrairTagXml(xml, "nProt"),

        produtos,

        transporte: {
            modalidade: extrairTagXml(blocoTransp, "modFrete"),
            transportadora: extrairTagXml(blocoTransp, "xNome"),
            cnpj: extrairTagXml(blocoTransp, "CNPJ"),
            placa: extrairTagXml(blocoTransp, "placa"),
            uf: extrairTagXml(blocoTransp, "UF")
        },

        totais: {
            produtos: extrairTagXml(blocoIcmsTot, "vProd"),
            frete: extrairTagXml(blocoIcmsTot, "vFrete"),
            seguro: extrairTagXml(blocoIcmsTot, "vSeg"),
            desconto: extrairTagXml(blocoIcmsTot, "vDesc"),
            outrasDespesas: extrairTagXml(blocoIcmsTot, "vOutro"),
            ipi: extrairTagXml(blocoIcmsTot, "vIPI"),
            icms: extrairTagXml(blocoIcmsTot, "vICMS"),
            valorNota: extrairTagXml(blocoIcmsTot, "vNF")
        },

        informacoesAdicionais
    };
}

/* ============================================================
   COMPONENTES DO DANFE
============================================================ */

function criarCodigoBarras(chave) {
    return bwipjs.toBuffer({
        bcid: "code128",
        text: chave,
        scale: 2,
        height: 12,
        includetext: false,
        backgroundcolor: "FFFFFF"
    });
}

function desenharBorda(doc, x, y, largura, altura, espessura = 0.6) {
    doc
        .lineWidth(espessura)
        .strokeColor("#000000")
        .rect(x, y, largura, altura)
        .stroke();
}

function desenharTituloCaixa(doc, titulo, x, y, largura) {
    doc
        .font("Helvetica-Bold")
        .fontSize(6.5)
        .fillColor("#000000")
        .text(titulo, x + 4, y + 3, {
            width: largura - 8,
            lineBreak: false
        });
}

function desenharCampo(
    doc,
    titulo,
    valor,
    x,
    y,
    largura,
    altura = 28,
    tamanho = 7
) {
    desenharBorda(doc, x, y, largura, altura);

    doc
        .font("Helvetica-Bold")
        .fontSize(5.5)
        .fillColor("#333333")
        .text(titulo, x + 4, y + 3, {
            width: largura - 8,
            lineBreak: false
        });

    doc
        .font("Helvetica")
        .fontSize(tamanho)
        .fillColor("#000000")
        .text(textoSeguro(valor), x + 4, y + 12, {
            width: largura - 8,
            height: altura - 13,
            ellipsis: true,
            lineBreak: false
        });
}

function desenharCabecalhoDanfe(doc, dados, margem, largura) {
    const altura = 82;
    const y = 28;

    desenharBorda(doc, margem, y, largura, altura);

    const larguraEsquerda = 150;
    const larguraDireita = 155;
    const xCentro = margem + larguraEsquerda;
    const xDireita = margem + largura - larguraDireita;

    doc
        .font("Helvetica-Bold")
        .fontSize(16)
        .text("DANFE", margem + 8, y + 10, {
            width: 70,
            align: "center"
        });

    doc
        .font("Helvetica")
        .fontSize(6.5)
        .text("Documento Auxiliar da Nota Fiscal Eletrônica", margem + 4, y + 31, {
            width: 78,
            align: "center"
        });

    doc
        .font("Helvetica-Bold")
        .fontSize(8)
        .text("0 - ENTRADA", margem + 88, y + 13, {
            width: 58,
            align: "center"
        });

    doc
        .font("Helvetica-Bold")
        .fontSize(8)
        .text("1 - SAÍDA", margem + 88, y + 30, {
            width: 58,
            align: "center"
        });

    doc
        .font("Helvetica")
        .fontSize(6.5)
        .text(
            dados.tipoOperacao === "0"
                ? "Entrada marcada no XML"
                : "Saída marcada no XML",
            margem + 82,
            y + 51,
            {
                width: 68,
                align: "center"
            }
        );

    doc
        .moveTo(xCentro, y)
        .lineTo(xCentro, y + altura)
        .stroke();

    doc
        .moveTo(xDireita, y)
        .lineTo(xDireita, y + altura)
        .stroke();

    doc
        .font("Helvetica-Bold")
        .fontSize(8)
        .text("NF-e", xDireita + 8, y + 10, {
            width: larguraDireita - 16,
            align: "center"
        });

    doc
        .font("Helvetica-Bold")
        .fontSize(10)
        .text(`Nº ${textoSeguro(dados.numero)}`, xDireita + 8, y + 28, {
            width: larguraDireita - 16,
            align: "center"
        });

    doc
        .font("Helvetica")
        .fontSize(8)
        .text(`Série ${textoSeguro(dados.serie)}`, xDireita + 8, y + 48, {
            width: larguraDireita - 16,
            align: "center"
        });

    doc
        .font("Helvetica-Bold")
        .fontSize(9)
        .text("DANFE", xCentro + 10, y + 10, {
            width: 115,
            align: "center"
        });

    doc
        .font("Helvetica")
        .fontSize(7)
        .text("Documento Auxiliar da Nota Fiscal Eletrônica", xCentro + 10, y + 26, {
            width: 115,
            align: "center"
        });

    if (dados.chave) {
        doc
            .font("Helvetica-Bold")
            .fontSize(6.5)
            .text("CHAVE DE ACESSO", xCentro + 10, y + 47, {
                width: 115,
                align: "center"
            });

        doc
            .font("Helvetica")
            .fontSize(7)
            .text(formatarChave(dados.chave), xCentro + 10, y + 59, {
                width: 115,
                align: "center"
            });
    }
}

function desenharEmitente(doc, dados, margem, largura, y) {
    const altura = 72;

    desenharBorda(doc, margem, y, largura, altura);
    desenharTituloCaixa(doc, "IDENTIFICAÇÃO DO EMITENTE", margem, y, largura);

    const divisor = margem + 300;

    doc
        .moveTo(divisor, y)
        .lineTo(divisor, y + altura)
        .stroke();

    doc
        .font("Helvetica-Bold")
        .fontSize(9)
        .text(
            limitarTexto(dados.emitente.nome, 65),
            margem + 8,
            y + 18,
            {
                width: 275
            }
        );

    doc
        .font("Helvetica")
        .fontSize(7)
        .text(
            dados.emitente.fantasia
                ? `Nome fantasia: ${dados.emitente.fantasia}`
                : "",
            margem + 8,
            y + 33,
            {
                width: 275
            }
        );

    doc
        .font("Helvetica")
        .fontSize(7)
        .text(
            `CNPJ: ${formatarCnpjCpf(dados.emitente.cnpj)}   IE: ${textoSeguro(dados.emitente.ie, "")}`,
            margem + 8,
            y + 48,
            {
                width: 275
            }
        );

    doc
        .font("Helvetica")
        .fontSize(7)
        .text(
            `${dados.emitente.endereco} - ${dados.emitente.bairro}`,
            divisor + 8,
            y + 19,
            {
                width: largura - 316,
                ellipsis: true
            }
        );

    doc
        .font("Helvetica")
        .fontSize(7)
        .text(
            `${dados.emitente.cidade}/${dados.emitente.uf}`,
            divisor + 8,
            y + 35,
            {
                width: largura - 316
            }
        );

    doc
        .font("Helvetica")
        .fontSize(7)
        .text(
            `CEP: ${formatarCep(dados.emitente.cep)}`,
            divisor + 8,
            y + 51,
            {
                width: largura - 316
            }
        );

    return y + altura;
}

function desenharDestinatario(doc, dados, margem, largura, y) {
    const altura = 68;

    desenharBorda(doc, margem, y, largura, altura);
    desenharTituloCaixa(doc, "DESTINATÁRIO / REMETENTE", margem, y, largura);

    desenharCampo(
        doc,
        "NOME / RAZÃO SOCIAL",
        dados.destinatario.nome,
        margem + 4,
        y + 15,
        250,
        25,
        7
    );

    desenharCampo(
        doc,
        "CNPJ / CPF",
        formatarCnpjCpf(dados.destinatario.documento),
        margem + 258,
        y + 15,
        125,
        25,
        7
    );

    desenharCampo(
        doc,
        "DATA DE EMISSÃO",
        formatarData(dados.dataEmissao),
        margem + 387,
        y + 15,
        largura - 391,
        25,
        7
    );

    desenharCampo(
        doc,
        "ENDEREÇO",
        `${dados.destinatario.endereco} - ${dados.destinatario.bairro}`,
        margem + 4,
        y + 42,
        310,
        22,
        7
    );

    desenharCampo(
        doc,
        "MUNICÍPIO",
        dados.destinatario.cidade,
        margem + 318,
        y + 42,
        130,
        22,
        7
    );

    desenharCampo(
        doc,
        "UF",
        dados.destinatario.uf,
        margem + 452,
        y + 42,
        largura - 456,
        22,
        7
    );

    return y + altura;
}

function desenharProdutos(doc, dados, margem, largura, y) {
    const alturaCabecalho = 22;
    const alturaLinha = 22;
    const quantidade = Math.max(dados.produtos.length, 1);
    const altura = alturaCabecalho + quantidade * alturaLinha + 16;

    desenharBorda(doc, margem, y, largura, altura);
    desenharTituloCaixa(doc, "DADOS DOS PRODUTOS / SERVIÇOS", margem, y, largura);

    const inicio = y + 16;

    const colunas = [
        { titulo: "#", largura: 22 },
        { titulo: "CÓDIGO", largura: 55 },
        { titulo: "DESCRIÇÃO", largura: 190 },
        { titulo: "NCM", largura: 55 },
        { titulo: "CFOP", largura: 38 },
        { titulo: "UN", largura: 25 },
        { titulo: "QTD.", largura: 48 },
        { titulo: "V. UNIT.", largura: 58 },
        { titulo: "V. TOTAL", largura: largura - 491 }
    ];

    let x = margem;

    for (const coluna of colunas) {
        desenharBorda(doc, x, inicio, coluna.largura, alturaCabecalho);

        doc
            .font("Helvetica-Bold")
            .fontSize(5.5)
            .text(coluna.titulo, x + 2, inicio + 7, {
                width: coluna.largura - 4,
                align: "center",
                lineBreak: false
            });

        x += coluna.largura;
    }

    const linhas = dados.produtos.length
        ? dados.produtos
        : [
              {
                  numero: "",
                  codigo: "",
                  descricao: "Nenhum produto informado no XML",
                  ncm: "",
                  cfop: "",
                  unidade: "",
                  quantidade: "",
                  valorUnitario: "",
                  valorTotal: ""
              }
          ];

    linhas.forEach((produto, indice) => {
        const linhaY = inicio + alturaCabecalho + indice * alturaLinha;
        let colunaX = margem;

        const valores = [
            produto.numero || indice + 1,
            produto.codigo,
            produto.descricao,
            produto.ncm,
            produto.cfop,
            produto.unidade,
            produto.quantidade
                ? formatarNumero(produto.quantidade, 4)
                : "",
            produto.valorUnitario
                ? formatarMoeda(produto.valorUnitario)
                : "",
            produto.valorTotal
                ? formatarMoeda(produto.valorTotal)
                : ""
        ];

        colunas.forEach((coluna, colunaIndice) => {
            desenharBorda(
                doc,
                colunaX,
                linhaY,
                coluna.largura,
                alturaLinha
            );

            doc
                .font("Helvetica")
                .fontSize(5.5)
                .text(
                    limitarTexto(valores[colunaIndice], colunaIndice === 2 ? 48 : 20),
                    colunaX + 2,
                    linhaY + 7,
                    {
                        width: coluna.largura - 4,
                        align: colunaIndice >= 6 ? "right" : "left",
                        ellipsis: true,
                        lineBreak: false
                    }
                );

            colunaX += coluna.largura;
        });
    });

    return y + altura;
}

function desenharTotais(doc, dados, margem, largura, y) {
    const altura = 65;

    desenharBorda(doc, margem, y, largura, altura);
    desenharTituloCaixa(doc, "CÁLCULO DO IMPOSTO", margem, y, largura);

    const campos = [
        ["BASE ICMS", formatarMoeda(dados.totais.icms)],
        ["VALOR ICMS", formatarMoeda(dados.totais.icms)],
        ["VALOR IPI", formatarMoeda(dados.totais.ipi)],
        ["VALOR PRODUTOS", formatarMoeda(dados.totais.produtos)],
        ["FRETE", formatarMoeda(dados.totais.frete)],
        ["SEGURO", formatarMoeda(dados.totais.seguro)],
        ["DESCONTO", formatarMoeda(dados.totais.desconto)],
        ["VALOR TOTAL NF", formatarMoeda(dados.totais.valorNota)]
    ];

    const larguraCampo = largura / campos.length;

    campos.forEach(([titulo, valor], indice) => {
        desenharCampo(
            doc,
            titulo,
            valor,
            margem + indice * larguraCampo,
            y + 15,
            larguraCampo,
            45,
            indice === campos.length - 1 ? 8 : 6.5
        );
    });

    return y + altura;
}

function desenharTransporte(doc, dados, margem, largura, y) {
    const altura = 53;

    desenharBorda(doc, margem, y, largura, altura);
    desenharTituloCaixa(doc, "TRANSPORTADOR / VOLUMES TRANSPORTADOS", margem, y, largura);

    desenharCampo(
        doc,
        "MODALIDADE DO FRETE",
        dados.transporte.modalidade,
        margem + 4,
        y + 15,
        125,
        30,
        6.5
    );

    desenharCampo(
        doc,
        "TRANSPORTADORA",
        dados.transporte.transportadora,
        margem + 133,
        y + 15,
        220,
        30,
        6.5
    );

    desenharCampo(
        doc,
        "CNPJ",
        formatarCnpjCpf(dados.transporte.cnpj),
        margem + 357,
        y + 15,
        100,
        30,
        6.5
    );

    desenharCampo(
        doc,
        "PLACA / UF",
        `${dados.transporte.placa || ""} ${dados.transporte.uf || ""}`,
        margem + 461,
        y + 15,
        largura - 465,
        30,
        6.5
    );

    return y + altura;
}

function desenharInformacoesAdicionais(doc, dados, margem, largura, y) {
    const altura = 72;

    desenharBorda(doc, margem, y, largura, altura);
    desenharTituloCaixa(doc, "DADOS ADICIONAIS", margem, y, largura);

    const texto = [
        dados.informacoesAdicionais,
        dados.protocolo
            ? `Protocolo de autorização: ${dados.protocolo}`
            : ""
    ]
        .filter(Boolean)
        .join("\n");

    doc
        .font("Helvetica")
        .fontSize(7)
        .text(
            textoSeguro(texto, "Nenhuma informação adicional informada."),
            margem + 7,
            y + 18,
            {
                width: largura - 14,
                height: altura - 24,
                ellipsis: true
            }
        );

    return y + altura;
}

async function gerarDanfePdf(xml, tipo) {
    const dados = extrairDadosNfe(xml, tipo);

    if (!dados.chave || dados.chave.length !== 44) {
        throw new Error(
            "Não foi possível identificar a chave de acesso de 44 dígitos."
        );
    }

    const doc = new PDFDocument({
        size: "A4",
        margin: 0,
        autoFirstPage: true,
        bufferPages: true
    });

    const paginas = [];

    doc.on("data", (chunk) => paginas.push(chunk));

    const margem = 24;
    const larguraPagina = 595;
    const alturaPagina = 842;
    const largura = larguraPagina - margem * 2;

    desenharCabecalhoDanfe(doc, dados, margem, largura);

    let y = 120;

    y = desenharEmitente(doc, dados, margem, largura, y) + 8;
    y = desenharDestinatario(doc, dados, margem, largura, y) + 8;
    y = desenharProdutos(doc, dados, margem, largura, y) + 8;
    y = desenharTotais(doc, dados, margem, largura, y) + 8;
    y = desenharTransporte(doc, dados, margem, largura, y) + 8;
    y = desenharInformacoesAdicionais(
        doc,
        dados,
        margem,
        largura,
        y
    ) + 12;

    if (dados.chave) {
        try {
            const codigoBarras = await criarCodigoBarras(dados.chave);

            doc
                .font("Helvetica-Bold")
                .fontSize(6.5)
                .text(
                    "CHAVE DE ACESSO",
                    margem,
                    y,
                    {
                        width: 180
                    }
                );

            doc
                .font("Helvetica")
                .fontSize(7)
                .text(
                    formatarChave(dados.chave),
                    margem,
                    y + 10,
                    {
                        width: 180
                    }
                );

            doc.image(codigoBarras, margem + 205, y - 2, {
                width: 330,
                height: 35
            });
        } catch (error) {
            console.error(
                "Não foi possível gerar o código de barras:",
                error.message
            );
        }
    }

    doc
        .moveTo(margem, alturaPagina - 45)
        .lineTo(larguraPagina - margem, alturaPagina - 45)
        .lineWidth(0.6)
        .stroke();

    doc
        .font("Helvetica")
        .fontSize(6.5)
        .text(
            "DANFE gerado automaticamente a partir do XML autorizado.",
            margem,
            alturaPagina - 35,
            {
                width: largura,
                align: "center"
            }
        );

    doc.end();

    return new Promise((resolve, reject) => {
        doc.on("end", () => {
            resolve({
                pdf: Buffer.concat(paginas),
                chave: dados.chave,
                numero: dados.numero,
                serie: dados.serie
            });
        });

        doc.on("error", reject);
    });
}

/* ============================================================
   ROTA DE GERAÇÃO DO DANFE
============================================================ */

app.post("/api/xml/render-pdf", async (req, res) => {
    try {
        const { xmlBase64, tipo } = req.body || {};

        if (!xmlBase64 || typeof xmlBase64 !== "string") {
            return res.status(400).json({
                success: false,
                error: "xmlBase64 não fornecido."
            });
        }

        const xmlString = Buffer
            .from(sanitizarBase64(xmlBase64), "base64")
            .toString("utf8")
            .replace(/^\uFEFF/, "")
            .trim();

        const pareceXml =
            xmlString.startsWith("<?xml") ||
            xmlString.includes("<nfeProc") ||
            xmlString.includes("<NFe") ||
            xmlString.includes("<infNFe");

        if (!pareceXml) {
            return res.status(400).json({
                success: false,
                error: "O conteúdo enviado não parece ser um XML NF-e válido."
            });
        }

        const resultado = await gerarDanfePdf(
            xmlString,
            tipo || "NFe"
        );

        return res.status(200).json({
            success: true,
            tipo: tipo || "NFe",
            chave: resultado.chave,
            numero: resultado.numero,
            serie: resultado.serie,
            pdfBase64: resultado.pdf.toString("base64")
        });
    } catch (error) {
        console.error("Erro ao gerar DANFE:", error);

        return res.status(500).json({
            success: false,
            error: error.message || "Erro interno ao gerar o DANFE."
        });
    }
});

/* ============================================================
   MANIFESTAÇÃO DO DESTINATÁRIO
============================================================ */

function obterAmbienteNFe() {
    return process.env.NFE_AMBIENTE === "2" ? "2" : "1";
}

function obterEndpointManifestacao(endpointFornecido) {
    if (endpointFornecido) {
        const url = new URL(endpointFornecido);

        if (url.protocol !== "https:") {
            throw new Error("O endpoint precisa utilizar HTTPS.");
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
        throw new Error("CNPJ inválido. Informe 14 dígitos.");
    }

    return valor;
}

function normalizarChaveNFe(chave) {
    const valor = somenteDigitos(chave);

    if (valor.length !== 44) {
        throw new Error("Chave NF-e inválida. Informe 44 dígitos.");
    }

    return valor;
}

function gerarDhEvento() {
    const agora = new Date();
    const offset = -agora.getTimezoneOffset();
    const sinal = offset >= 0 ? "+" : "-";
    const absoluto = Math.abs(offset);

    const pad = (valor) =>
        String(valor).padStart(2, "0");

    return (
        `${agora.getFullYear()}-` +
        `${pad(agora.getMonth() + 1)}-` +
        `${pad(agora.getDate())}T` +
        `${pad(agora.getHours())}:` +
        `${pad(agora.getMinutes())}:` +
        `${pad(agora.getSeconds())}` +
        `${sinal}${pad(Math.floor(absoluto / 60))}:` +
        `${pad(absoluto % 60)}`
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
    if (!pfxBase64 || !password) {
        throw new Error("Certificado e senha são obrigatórios.");
    }

    try {
        const pfxDer = forge.util.decode64(
            sanitizarBase64(pfxBase64)
        );

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
            throw new Error("Chave privada não encontrada no certificado.");
        }

        if (!certificate) {
            throw new Error("Certificado X509 não encontrado.");
        }

        const privateKeyPem =
            forge.pki.privateKeyToPem(privateKey);

        const certPem =
            forge.pki.certificateToPem(certificate);

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
        throw new Error(
            `Erro ao abrir certificado A1: ${error.message}`
        );
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
        throw new Error("Tipo de manifestação inválido.");
    }

    const cnpjLimpo = normalizarCNPJ(cnpj);
    const chaveLimpa = normalizarChaveNFe(chave);

    const idEvento =
        `ID${evento.codigo}${chaveLimpa}01`;

    const justificativa =
        evento.codigo === "210240"
            ? "<xJust>Operacao nao realizada pelo destinatario</xJust>"
            : "";

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
        justificativa +
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
        xpath:
            `//*[local-name(.)='infEvento' and @Id='${idEvento}']`,
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
            reference:
                `//*[local-name(.)='infEvento' and @Id='${idEvento}']`,
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
    const eventoAssinado =
        gerarEventoManifestacaoAssinado(
            cnpj,
            chave,
            tipoManifestacao,
            pfxBase64,
            password
        );

    return (
        `<?xml version="1.0" encoding="utf-8"?>` +
        `<soap12:Envelope ` +
        `xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
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

app.post(
    "/rpa/xml/manifest",
    validarAPI,
    async (req, res) => {
        const requestId = crypto.randomUUID();

        try {
            const {
                pfxBase64,
                password,
                cnpj,
                chave,
                tipoManifestacao,
                endpoint
            } = req.body || {};

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

            const soapEnvelope =
                gerarManifestacaoXML(
                    cnpjLimpo,
                    chaveLimpa,
                    tipoManifestacao,
                    pfxBase64,
                    password
                );

            const endpointFinal =
                obterEndpointManifestacao(endpoint);

            const resposta =
                await executarRequisicaoHttps({
                    endpoint: endpointFinal,
                    certificado,
                    password,
                    body: soapEnvelope,
                    soapAction: NFE_EVENTO_SOAP_ACTION
                });

            const retorno =
                interpretarRespostaManifestacao(
                    resposta.body,
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
                extrairTagXml(resposta.body, "faultstring") ||
                extrairTagXml(resposta.body, "Text") ||
                `HTTP ${resposta.statusCode} retornado pela SEFAZ.`;

            return res.status(400).json({
                success: false,
                requestId,
                statusCode: resposta.statusCode,
                cStat: retorno.cStatEvento,
                error: erro
            });
        } catch (error) {
            console.error("Erro na manifestação:", error);

            return res.status(500).json({
                success: false,
                requestId,
                error: error.message || "Erro na manifestação."
            });
        }
    }
);

/* ============================================================
   TRATAMENTO DE ERROS
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
    console.log("====================================");
    console.log("BRIDGE SEFAZ ONLINE");
    console.log(`Porta: ${PORT}`);
    console.log(`Versão: ${VERSAO}`);
    console.log(`Ambiente: ${process.env.NODE_ENV || "development"}`);
    console.log("AUTH_KEY carregada:", Boolean(AUTH_KEY));
    console.log("XML_KEY carregada:", Boolean(XML_KEY));
    console.log("====================================");
});
