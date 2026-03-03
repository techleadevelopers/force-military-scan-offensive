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
    score?: number;
    criticidade?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    riscoFinanceiro?: number;
  };
  panorama: {
    total: number;
    criticos: number;
    altos: number;
    medios: number;
    baixos: number;
  };
  metodologia?: {
    escopo?: string;
    fases?: string[];
    motor11?: string;
  };
  motor11?: {
    topAcoes?: string[];
    autoExecutadas?: string[];
    planoAtaque?: string[];
  };
  kill_chain: KillChainStage[];
  descobertas: EnterpriseFinding[];
  recomendacoes: {
    prazo24h?: string[];
    prazo7d?: string[];
    prazo30d?: string[];
  };
  recomendacoesEstrategicas?: string[];
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
  bg: "#FFFFFF",
  card: "#F5F7FB",
  text: "#1A2E1A",
  mute: "#5A6B5A",
  critical: "#D32F2F",
  high: "#B45F06",
  medium: "#D4A017",
  low: "#2D5A27",
  accent: "#2D5A27",
};

async function fetchLogo(logoUrl?: string): Promise<Buffer | null> {
  if (!logoUrl) return null;
  try {
    const res = await fetch(logoUrl);
    if (!res.ok) throw new Error(`http ${res.status}`);
    const arrayBuffer = await res.arrayBuffer();
    return Buffer.from(arrayBuffer);
  } catch {
    // Fallback: try https.get (Ãºtil caso fetch falhe por polÃ­tica de TLS)
    try {
      const https = await import("https");
      return await new Promise<Buffer | null>((resolve) => {
        https.get(logoUrl, (resp) => {
          const chunks: Buffer[] = [];
          resp.on("data", (d) => chunks.push(d));
          resp.on("end", () => resolve(Buffer.concat(chunks)));
        }).on("error", () => resolve(null));
      });
    } catch {
      return null;
    }
  }
}

function currencyBRL(value?: number): string {
  if (value === undefined || value === null) return "-";
  if (!Number.isFinite(value)) return "-";
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
    .stroke("#E0E6E0");
  doc.fillColor(colors.mute).font("Helvetica").fontSize(9).text(label, doc.x + 10, y + 8);
  doc.fillColor(colors.text).font("Helvetica-Bold").fontSize(12).text(value, doc.x + 10, y + 22);
  doc.moveDown(1.2);
}

function addBulletList(doc: PDFDocument, items?: string[], max = 8, color = colors.text) {
  if (!items || items.length === 0) return;
  items.slice(0, max).forEach((item) => {
    doc
      .font("Helvetica")
      .fillColor(color)
      .fontSize(10)
      .text(`• ${item}`);
  });
  doc.moveDown(0.4);
}

function addSeverityBars(
  doc: PDFDocument,
  pano: { total: number; criticos: number; altos: number; medios: number; baixos: number }
) {
  const entries: Array<[string, number, string]> = [
    ["CRITICAL", pano.criticos, colors.critical],
    ["HIGH", pano.altos, colors.high],
    ["MEDIUM", pano.medios, colors.medium],
    ["LOW", pano.baixos, colors.low],
  ];
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  entries.forEach(([label, value, color]) => {
    const perc = pano.total ? Math.round((value / pano.total) * 100) : 0;
    const bar = Math.max((perc / 100) * width, 4);
    const y = doc.y;
    doc.rect(doc.x, y, width, 12).fill(colors.card);
    doc.rect(doc.x, y, bar, 12).fill(color);
    doc
      .fillColor(colors.text)
      .font("Helvetica-Bold")
      .fontSize(9)
      .text(`${label}  ${value} (${perc}%)`, doc.x + 6, y + 2);
    doc.moveDown(0.5);
  });
  doc.moveDown(0.6);
}

export async function generateEnterprisePdf(payload: EnterpriseReportPayload): Promise<Buffer> {
  const doc = new PDFDocument({ margin: 36, size: "A4" });
  const chunks: Buffer[] = [];
  const logoBuffer = await fetchLogo(
    payload.logoUrl || "https://res.cloudinary.com/limpeja/image/upload/v1772399086/Shieldscan_7_uexn2r.png"
  );

  doc.on("data", (c) => chunks.push(c));

  // Header (black bar, centered logo)
  const headerHeight = 100;
  doc.save();
  doc
    .rect(0, 0, doc.page.width, headerHeight)
    .fill("#F8F9FA");
  if (logoBuffer) {
    // centraliza a logo; se falhar silenciosamente, continua com o tÃ­tulo
    try {
      doc.image(logoBuffer, (doc.page.width - 140) / 2, 18, { width: 140 });
    } catch {}
  }
  doc
    .fillColor(colors.text)
    .font("Helvetica-Bold")
    .fontSize(18)
    .text("RELATÓRIO ESTRATÉGICO DE SEGURANÇA", 0, headerHeight - 32, { align: "center" });
  doc
    .font("Helvetica")
    .fontSize(11)
    .fillColor(colors.mute)
    .text("Military Scan Enterprise v2.1", { align: "center" });
  doc
    .font("Helvetica")
    .fontSize(10)
    .fillColor(colors.mute)
    .text(payload.metadata.cliente ? `Confidencial — ${payload.metadata.cliente}` : "Confidencial — Cliente", { align: "center" });
  doc.restore();

  doc.moveDown(1.6);

  // Contexto & Metodologia
  addSectionTitle(doc, "Contexto e Metodologia");
  doc
    .font("Helvetica-Bold")
    .fillColor(colors.text)
    .fontSize(11)
    .text("FORCESCAN — Sniper Mode + Motor 11");
  doc
    .font("Helvetica")
    .fillColor(colors.mute)
    .fontSize(10)
    .text(
      payload.metodologia?.escopo ||
        "Avaliação ofensiva autorizada: reconhecimento, exploração assistida (Sniper Mode 10+ fases) e consolidação autônoma pelo Motor 11."
    );
  const fases = payload.metodologia?.fases?.filter(Boolean);
  if (fases && fases.length > 0) {
    addBulletList(doc, fases.slice(0, 8), 8, colors.text);
  } else if (payload.kill_chain && payload.kill_chain.length > 0) {
    addBulletList(
      doc,
      payload.kill_chain.slice(0, 8).map((k) => `\u2713 ${k.fase}`),
      8,
      colors.text
    );
  } else {
    doc
      .font("Helvetica")
      .fillColor(colors.text)
      .fontSize(10)
      .text("Fases executadas: N/D");
    doc.moveDown(0.4);
  }
  if (payload.metodologia?.motor11) {
    doc
      .font("Helvetica")
      .fillColor(colors.mute)
      .fontSize(10)
      .text(payload.metodologia.motor11);
  }
  doc.moveDown(0.8);

  // Metadata cards
  addSectionTitle(doc, "Dados do Assessment");
  const meta = payload.metadata;
  const cardWidth = (doc.page.width - doc.page.margins.left - doc.page.margins.right - 12) / 2;
  const startX = doc.x;
  const startY = doc.y;
  const panoScore = (() => {
    const total = payload.panorama.total || 0;
    if (total === 0) return null;
    const weights = { criticos: 10, altos: 7, medios: 4, baixos: 1 };
    const weighted =
      (payload.panorama.criticos || 0) * weights.criticos +
      (payload.panorama.altos || 0) * weights.altos +
      (payload.panorama.medios || 0) * weights.medios +
      (payload.panorama.baixos || 0) * weights.baixos;
    const max = total * 10;
    return max > 0 ? Number(((weighted / max) * 10).toFixed(1)) : null;
  })();
  const metaScore = Number.isFinite(meta.score) ? (meta.score as number) : null;
  // Prefer computed panorama score; fallback to provided meta score only if it isn't the default 10.0 placeholder
  const score =
    panoScore !== null
      ? panoScore
      : metaScore !== null && metaScore < 9.9
        ? metaScore
        : null;
  const criticidade =
    score === null
      ? "LOW"
      : score >= 8
      ? "CRITICAL"
      : score >= 5
      ? "HIGH"
      : score >= 2
      ? "MEDIUM"
      : "LOW";
  const duracao = Number.isFinite(meta.duracaoSeg) ? `${meta.duracaoSeg}s` : "N/D";
  const riscoFin = Number.isFinite(meta.riscoFinanceiro || 0) ? currencyBRL(meta.riscoFinanceiro) : "N/D";

  // Left column
  doc.save();
  addCard(doc, "Alvo", meta.alvo, cardWidth);
  addCard(doc, "ID / Data", `${meta.id || "N/D"} | ${meta.data || "N/D"}`, cardWidth);
  doc.restore();

  // Right column
  doc.x = startX + cardWidth + 12;
  doc.y = startY;
  addCard(doc, "Score", score !== null ? `${score.toFixed(1)}/10 (${criticidade})` : "N/D", cardWidth);
  addCard(
    doc,
    "DuraÃ§Ã£o / Risco",
    `${duracao} | ${riscoFin}`,
    cardWidth
  );
  doc.x = startX;

  // Score gauge (simplified bar)
  addSectionTitle(doc, "Score de Risco");
  if (score !== null) {
    const barColor =
      criticidade === "CRITICAL"
        ? colors.critical
        : criticidade === "HIGH"
        ? colors.high
        : criticidade === "MEDIUM"
        ? colors.medium
        : colors.low;
    doc
      .rect(doc.x, doc.y, doc.page.width - doc.page.margins.left - doc.page.margins.right, 14)
      .fill(colors.card);
    const barWidth =
      (score / 10) *
      (doc.page.width - doc.page.margins.left - doc.page.margins.right);
    doc.rect(doc.x, doc.y, Math.max(barWidth, 4), 14).fill(barColor);
    doc
      .fillColor(colors.text)
      .font("Helvetica-Bold")
      .fontSize(11)
      .text(`Score ${score.toFixed(1)} • ${criticidade} (${Math.round((score / 10) * 100)}%)`, doc.x + 6, doc.y + 2);
    doc.moveDown(1.5);
  } else {
    doc
      .fillColor(colors.mute)
      .font("Helvetica")
      .fontSize(10)
      .text("Score nÃ£o disponÃ­vel (N/D)");
    doc.moveDown(1);
  }

  // Severidade (visual)
  addSectionTitle(doc, "DistribuiÃ§Ã£o por Severidade");
  if (payload.panorama.total > 0) {
    addSeverityBars(doc, payload.panorama);
  } else {
    doc.font("Helvetica").fillColor(colors.mute).fontSize(10).text("Sem vulnerabilidades reportadas.");
    doc.moveDown(0.6);
  }

  // Panorama table
  addSectionTitle(doc, "Panorama de Vulnerabilidades");
  const pano = payload.panorama;
  const totalPano = pano.total || 0;
  const rows: Array<[string, number, number, string]> = [
    ["CRITICAL", pano.criticos, totalPano ? Math.round((pano.criticos / totalPano) * 100) : 0, colors.critical],
    ["HIGH", pano.altos, totalPano ? Math.round((pano.altos / totalPano) * 100) : 0, colors.high],
    ["MEDIUM", pano.medios, totalPano ? Math.round((pano.medios / totalPano) * 100) : 0, colors.medium],
    ["LOW", pano.baixos, totalPano ? Math.round((pano.baixos / totalPano) * 100) : 0, colors.low],
  ];
  if (totalPano === 0) {
    doc
      .font("Helvetica")
      .fillColor(colors.mute)
      .fontSize(10)
      .text("Sem vulnerabilidades reportadas.");
    doc.moveDown(0.8);
  } else {
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
  }

  // Motor 11 â€” DecisÃ£o AutÃ´noma
  if (payload.motor11?.topAcoes || payload.motor11?.autoExecutadas || payload.motor11?.planoAtaque) {
    addSectionTitle(doc, "Motor 11 â€” DecisÃ£o AutÃ´noma");
    if (payload.motor11.planoAtaque?.length) {
      doc.font("Helvetica-Bold").fillColor(colors.text).fontSize(11).text("Plano de ataque (Top 3):");
      addBulletList(doc, payload.motor11.planoAtaque, 5, colors.text);
    }
    if (payload.motor11.autoExecutadas?.length) {
      doc.font("Helvetica-Bold").fillColor(colors.text).fontSize(11).text("AÃ§Ãµes autÃ´nomas executadas:");
      addBulletList(doc, payload.motor11.autoExecutadas, 5, colors.mute);
    }
    if (payload.motor11.topAcoes?.length) {
      doc.font("Helvetica-Bold").fillColor(colors.text).fontSize(11).text("PrÃ³ximas aÃ§Ãµes sugeridas:");
      addBulletList(doc, payload.motor11.topAcoes, 5, colors.high);
    }
    doc.moveDown(0.6);
  } else {
    addSectionTitle(doc, "Motor 11 â€” DecisÃ£o AutÃ´noma");
    doc.font("Helvetica").fillColor(colors.mute).fontSize(10).text("Nenhuma aÃ§Ã£o autÃ´noma registrada.");
    doc.moveDown(0.6);
  }

  // Kill chain
  addSectionTitle(doc, "Kill Chain Executada");
  if (payload.kill_chain && payload.kill_chain.length > 0) {
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
  } else {
    doc.font("Helvetica").fillColor(colors.mute).fontSize(10).text("NÃ£o executado / sem dados.");
    doc.moveDown(0.6);
  }

  // Findings
  addSectionTitle(doc, "Descobertas CrÃ­ticas");
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
    if (f.evidencia) doc.fillColor(colors.mute).fontSize(9).text(`EvidÃªncia: ${f.evidencia}`);
    if (f.recomendacao)
      doc.fillColor(colors.high).fontSize(9).text(`RecomendaÃ§Ã£o: ${f.recomendacao}`);
    doc.moveDown(0.6);
  });

  // Recommendations
  addSectionTitle(doc, "RecomendaÃ§Ãµes");
  const rec = payload.recomendacoes;
  const recBlock = (label: string, items?: string[]) => {
    if (!items || items.length === 0) return;
    doc.font("Helvetica-Bold").fillColor(colors.text).fontSize(11).text(label);
    items.slice(0, 6).forEach((item) => {
      doc.font("Helvetica").fillColor(colors.mute).fontSize(10).text(`- ${item}`);
    });
    doc.moveDown(0.4);
  };
  recBlock("â³ 24 HORAS", rec.prazo24h);
  recBlock("ðŸ“… 7 DIAS", rec.prazo7d);
  recBlock("ðŸ—“ï¸ 30 DIAS", rec.prazo30d);
  if (payload.recomendacoesEstrategicas?.length) {
    doc.font("Helvetica-Bold").fillColor(colors.text).fontSize(11).text("Camada estratÃ©gica (Board/CISO)");
    addBulletList(doc, payload.recomendacoesEstrategicas, 6, colors.text);
  }

  // Business impact
  addSectionTitle(doc, "Impacto no NegÃ³cio");
  const imp = payload.impacto;
  doc
    .font("Helvetica")
    .fillColor(colors.text)
    .fontSize(10)
    .text(`Risco financeiro: ${currencyBRL(imp.riscoFinanceiro || payload.metadata.riscoFinanceiro)}`);
  if (imp.registros) doc.text(`Registros expostos: ${imp.registros}`);
  if (imp.conformidade) doc.text(`Conformidade: ${imp.conformidade}`);
  if (imp.mttr) doc.text(`Tempo mÃ©dio de reparo: ${imp.mttr}`);

  // Attachments list
  if (payload.anexos && payload.anexos.length) {
    addSectionTitle(doc, "Anexos TÃ©cnicos");
    payload.anexos.slice(0, 8).forEach((a) => {
      doc.font("Helvetica").fillColor(colors.mute).fontSize(10).text(`• ${a}`);
    });
  }

  doc.end();

  return await new Promise<Buffer>((resolve) => {
    doc.on("end", () => resolve(Buffer.concat(chunks)));
  });
}

