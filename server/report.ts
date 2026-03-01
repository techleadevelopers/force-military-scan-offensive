import PDFDocument from "pdfkit";

export type Severity = "critical" | "high" | "medium" | "low";

export interface EnterpriseFinding {
  titulo: string;
  impacto: string;
  evidencia?: string;
  recomendacao?: string;
  severidade?: Severity;
}

export interface KillChainStage {
  fase: string;
  descricao?: string;
  metrica?: string;
  status?: string;
}

export interface EnterpriseReportPayload {
  metadata: {
    cliente?: string;
    alvo: string;
    data: string;
    id?: string;
    duracaoSeg?: number;
    score: number;
    criticidade: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    riscoFinanceiro?: number;
  };
  panorama: {
    total: number;
    criticos: number;
    altos: number;
    medios: number;
    baixos: number;
  };
  kill_chain: KillChainStage[];
  descobertas: EnterpriseFinding[];
  recomendacoes: {
    prazo24h?: string[];
    prazo7d?: string[];
    prazo30d?: string[];
  };
  impacto: {
    riscoFinanceiro?: number;
    registros?: string;
    conformidade?: string;
    mttr?: string;
  };
  anexos?: string[];
  logoUrl?: string;
}

const colors = {
  bg: "#0F1115",
  card: "#161A21",
  text: "#E8ECF2",
  mute: "#9CA3AF",
  critical: "#D32F2F",
  high: "#F59E0B",
  medium: "#FFB020",
  low: "#1E88E5",
  accent: "#7C3AED",
};

async function fetchLogo(logoUrl?: string): Promise<Buffer | null> {
  if (!logoUrl) return null;
  try {
    const res = await fetch(logoUrl);
    if (!res.ok) return null;
    const arrayBuffer = await res.arrayBuffer();
    return Buffer.from(arrayBuffer);
  } catch {
    return null;
  }
}

function currencyBRL(value?: number): string {
  if (value === undefined || value === null) return "-";
  return new Intl.NumberFormat("pt-BR", {
    style: "currency",
    currency: "BRL",
    maximumFractionDigits: 0,
  }).format(value);
}

function addSectionTitle(doc: PDFDocument, title: string) {
  doc.moveDown(0.6);
  doc
    .fillColor(colors.text)
    .fontSize(13)
    .font("Helvetica-Bold")
    .text(title.toUpperCase(), { underline: false });
  doc.moveDown(0.25);
}

function addCard(doc: PDFDocument, label: string, value: string, width = 260) {
  const y = doc.y;
  doc
    .rect(doc.x, y, width, 40)
    .fill(colors.card)
    .stroke(colors.accent);
  doc.fillColor(colors.mute).font("Helvetica").fontSize(9).text(label, doc.x + 10, y + 8);
  doc.fillColor(colors.text).font("Helvetica-Bold").fontSize(12).text(value, doc.x + 10, y + 22);
  doc.moveDown(1.2);
}

export async function generateEnterprisePdf(payload: EnterpriseReportPayload): Promise<Buffer> {
  const doc = new PDFDocument({ margin: 36, size: "A4" });
  const chunks: Buffer[] = [];
  const logoBuffer = await fetchLogo(
    payload.logoUrl || "https://res.cloudinary.com/limpeja/image/upload/v1772170000/Shieldscan_1_hggjsm.png"
  );

  doc.on("data", (c) => chunks.push(c));

  // Header
  if (logoBuffer) {
    doc.image(logoBuffer, (doc.page.width - 100) / 2, doc.y, { width: 100 }).moveDown(0.5);
  }
  doc
    .font("Helvetica-Bold")
    .fontSize(16)
    .fillColor(colors.text)
    .text("FORCE SCAN ENTERPRISE", { align: "center" });
  doc
    .font("Helvetica")
    .fontSize(11)
    .fillColor(colors.mute)
    .text("Relatório Executivo de Segurança Ofensiva", { align: "center" });

  doc.moveDown(1);

  // Metadata cards
  addSectionTitle(doc, "Dados do Assessment");
  const meta = payload.metadata;
  const cardWidth = (doc.page.width - doc.page.margins.left - doc.page.margins.right - 12) / 2;
  const startX = doc.x;
  const startY = doc.y;

  // Left column
  doc.save();
  addCard(doc, "Alvo", meta.alvo, cardWidth);
  addCard(doc, "ID / Data", `${meta.id || "--"} | ${meta.data}`, cardWidth);
  doc.restore();

  // Right column
  doc.x = startX + cardWidth + 12;
  doc.y = startY;
  addCard(doc, "Score", `${meta.score.toFixed(1)}/10 (${meta.criticidade})`, cardWidth);
  addCard(doc, "Duração / Risco", `${meta.duracaoSeg || "--"}s | ${currencyBRL(meta.riscoFinanceiro)}`, cardWidth);
  doc.x = startX;

  // Score gauge (simplified bar)
  addSectionTitle(doc, "Score de Risco");
  doc
    .rect(doc.x, doc.y, doc.page.width - doc.page.margins.left - doc.page.margins.right, 14)
    .fill(colors.card);
  const barWidth =
    ((meta.score || 0) / 10) *
    (doc.page.width - doc.page.margins.left - doc.page.margins.right);
  doc.rect(doc.x, doc.y, Math.max(barWidth, 4), 14).fill(colors.critical);
  doc
    .fillColor(colors.text)
    .font("Helvetica-Bold")
    .fontSize(11)
    .text(`Score ${meta.score.toFixed(1)} • ${meta.criticidade}`, doc.x + 6, doc.y + 2);
  doc.moveDown(1.5);

  // Panorama table
  addSectionTitle(doc, "Panorama de Vulnerabilidades");
  const pano = payload.panorama;
  const rows: Array<[string, number, number, string]> = [
    ["CRITICAL", pano.criticos, Math.round((pano.criticos / pano.total) * 100), colors.critical],
    ["HIGH", pano.altos, Math.round((pano.altos / pano.total) * 100), colors.high],
    ["MEDIUM", pano.medios, Math.round((pano.medios / pano.total) * 100), colors.medium],
    ["LOW", pano.baixos, Math.round((pano.baixos / pano.total) * 100), colors.low],
  ];
  rows.forEach(([label, qtd, perc, color]) => {
    doc
      .fillColor(color)
      .font("Helvetica-Bold")
      .fontSize(11)
      .text(label, { continued: true })
      .fillColor(colors.text)
      .text(`  ${qtd}  (${perc}%)`, { continued: true })
      .moveDown(0.3);
  });
  doc.moveDown(0.8);

  // Kill chain
  addSectionTitle(doc, "Kill Chain Executada");
  payload.kill_chain.slice(0, 8).forEach((stage, idx) => {
    doc
      .font("Helvetica-Bold")
      .fillColor(colors.text)
      .fontSize(11)
      .text(`${idx + 1}. ${stage.fase}`);
    if (stage.descricao) {
      doc
        .font("Helvetica")
        .fillColor(colors.mute)
        .fontSize(10)
        .text(stage.descricao);
    }
    if (stage.metrica || stage.status) {
      doc
        .font("Helvetica")
        .fillColor(colors.text)
        .fontSize(9)
        .text([stage.metrica, stage.status].filter(Boolean).join(" • "));
    }
    doc.moveDown(0.6);
  });

  // Findings
  addSectionTitle(doc, "Descobertas Críticas");
  payload.descobertas.slice(0, 6).forEach((f) => {
    const color =
      f.severidade === "critical"
        ? colors.critical
        : f.severidade === "high"
        ? colors.high
        : f.severidade === "medium"
        ? colors.medium
        : colors.low;
    doc.font("Helvetica-Bold").fillColor(color).fontSize(11).text(`• ${f.titulo}`);
    doc.font("Helvetica").fillColor(colors.text).fontSize(10).text(f.impacto);
    if (f.evidencia) doc.fillColor(colors.mute).fontSize(9).text(`Evidência: ${f.evidencia}`);
    if (f.recomendacao)
      doc.fillColor(colors.high).fontSize(9).text(`Recomendação: ${f.recomendacao}`);
    doc.moveDown(0.6);
  });

  // Recommendations
  addSectionTitle(doc, "Recomendações");
  const rec = payload.recomendacoes;
  const recBlock = (label: string, items?: string[]) => {
    if (!items || items.length === 0) return;
    doc.font("Helvetica-Bold").fillColor(colors.text).fontSize(11).text(label);
    items.slice(0, 6).forEach((item) => {
      doc.font("Helvetica").fillColor(colors.mute).fontSize(10).text(`- ${item}`);
    });
    doc.moveDown(0.4);
  };
  recBlock("⏳ 24 HORAS", rec.prazo24h);
  recBlock("📅 7 DIAS", rec.prazo7d);
  recBlock("🗓️ 30 DIAS", rec.prazo30d);

  // Business impact
  addSectionTitle(doc, "Impacto no Negócio");
  const imp = payload.impacto;
  doc
    .font("Helvetica")
    .fillColor(colors.text)
    .fontSize(10)
    .text(`Risco financeiro: ${currencyBRL(imp.riscoFinanceiro || payload.metadata.riscoFinanceiro)}`);
  if (imp.registros) doc.text(`Registros expostos: ${imp.registros}`);
  if (imp.conformidade) doc.text(`Conformidade: ${imp.conformidade}`);
  if (imp.mttr) doc.text(`Tempo médio de reparo: ${imp.mttr}`);

  // Attachments list
  if (payload.anexos && payload.anexos.length) {
    addSectionTitle(doc, "Anexos Técnicos");
    payload.anexos.slice(0, 8).forEach((a) => {
      doc.font("Helvetica").fillColor(colors.mute).fontSize(10).text(`• ${a}`);
    });
  }

  doc.end();

  return await new Promise<Buffer>((resolve) => {
    doc.on("end", () => resolve(Buffer.concat(chunks)));
  });
}

