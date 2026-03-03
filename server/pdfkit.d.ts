declare module "pdfkit" {
  import { Duplex } from "stream";

  class PDFDocument extends Duplex {
    constructor(options?: any);
    // cursor
    x: number;
    y: number;
    page: {
      width: number;
      height: number;
      margins: { left: number; right: number; top?: number; bottom?: number };
    };

    // layout / drawing
    addPage(options?: any): this;
    image(src: Buffer | string, x?: number, y?: number, options?: any): this;
    text(text: string, x?: number, y?: number, options?: any): this;
    rect(x: number, y: number, w: number, h: number): this;
    fill(color: string | number): this;
    fillColor(color: string | number): this;
    stroke(color: string | number): this;
    moveTo(x: number, y: number): this;
    lineTo(x: number, y: number): this;
    lineWidth(w: number): this;
    save(): this;
    restore(): this;
    moveDown(lines?: number): this;

    // typography
    font(name: string): this;
    fontSize(size: number): this;

    end(): void;
  }

  export = PDFDocument;
  export default PDFDocument;
}
