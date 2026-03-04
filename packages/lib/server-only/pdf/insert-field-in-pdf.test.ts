import fontkit from '@pdf-lib/fontkit';
import { PDFDocument } from 'pdf-lib';
import { readFileSync } from 'fs';
import { join } from 'path';
import { describe, expect, it, beforeAll } from 'vitest';
import type { PDFFont } from 'pdf-lib';

import { breakLongString, calculateFontSizeToFit } from './insert-field-in-pdf';
import {
  DEFAULT_STANDARD_FONT_SIZE,
  MIN_STANDARD_FONT_SIZE,
} from '../../constants/pdf';

// Load the actual font used in production for accurate measurements
const FONT_PATH = join(__dirname, '../../../../apps/remix/public/fonts/noto-sans.ttf');

let font: PDFFont;
let pdf: PDFDocument;

beforeAll(async () => {
  const fontBytes = readFileSync(FONT_PATH);
  pdf = await PDFDocument.create();
  pdf.registerFontkit(fontkit);
  font = await pdf.embedFont(fontBytes);
});

describe('breakLongString', () => {
  it('should return empty string for empty input', () => {
    expect(breakLongString('', 100, font, 14)).toBe('');
  });

  it('should not break text that fits on one line', () => {
    const text = 'Hello';
    const width = font.widthOfTextAtSize(text, 14) + 20; // plenty of room
    expect(breakLongString(text, width, font, 14)).toBe(text);
  });

  it('should break long text into multiple lines at word boundaries', () => {
    const text = 'This is a long sentence that should wrap onto multiple lines';
    const width = font.widthOfTextAtSize('This is a long', 14); // narrow width
    const result = breakLongString(text, width, font, 14);

    const lines = result.split('\n');
    expect(lines.length).toBeGreaterThan(1);

    // Every line should fit within the width
    for (const line of lines) {
      expect(font.widthOfTextAtSize(line, 14)).toBeLessThanOrEqual(width + 1); // +1 for float precision
    }
  });

  it('should preserve explicit newlines', () => {
    const text = 'Line 1\nLine 2\nLine 3';
    const width = 500; // wide enough for all lines
    const result = breakLongString(text, width, font, 14);
    expect(result).toBe(text);
  });

  it('should break words that are too long for a single line', () => {
    const text = 'Supercalifragilisticexpialidocious';
    const width = font.widthOfTextAtSize('Super', 14);
    const result = breakLongString(text, width, font, 14);

    const lines = result.split('\n');
    expect(lines.length).toBeGreaterThan(1);

    // Rejoined text should equal original
    expect(lines.join('')).toBe(text);
  });

  it('should handle mixed short and long words', () => {
    const text = 'a Supercalifragilisticexpialidocious b';
    const width = font.widthOfTextAtSize('Supercal', 14);
    const result = breakLongString(text, width, font, 14);
    const lines = result.split('\n');

    expect(lines.length).toBeGreaterThan(1);

    for (const line of lines) {
      expect(font.widthOfTextAtSize(line, 14)).toBeLessThanOrEqual(width + 1);
    }
  });
});

describe('calculateFontSizeToFit', () => {
  const defaults = {
    initialFontSize: DEFAULT_STANDARD_FONT_SIZE,
    minFontSize: MIN_STANDARD_FONT_SIZE,
  };

  describe('single-line text', () => {
    it('should not shrink text that already fits', () => {
      const text = 'Hi';
      const fieldWidth = 200;
      const fieldHeight = 30;

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: false,
        ...defaults,
      });

      expect(result.fontSize).toBe(defaults.initialFontSize);
      expect(result.isMultiline).toBe(false);
    });

    it('should shrink font to fit width', () => {
      const text = 'John Doe';
      const fieldWidth = 50;
      const fieldHeight = 30;

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: false,
        ...defaults,
      });

      expect(result.fontSize).toBeLessThan(defaults.initialFontSize);
      expect(result.fontSize).toBeGreaterThanOrEqual(defaults.minFontSize);

      // Verify it actually fits within render width
      const renderWidth = fieldWidth - 2; // PDF_TEXT_FIELD_PADDING
      expect(font.widthOfTextAtSize(text, result.fontSize)).toBeLessThanOrEqual(renderWidth + 0.5);
    });

    it('should shrink font to fit height', () => {
      const text = 'Hi';
      const fieldWidth = 200;
      const fieldHeight = 10; // very short field

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: false,
        ...defaults,
      });

      expect(result.fontSize).toBeLessThan(defaults.initialFontSize);
      // Single-line available height = min(renderHeight, fontSize * 1.375)
      expect(font.heightAtSize(result.fontSize)).toBeLessThanOrEqual(
        Math.min(fieldHeight - 2, result.fontSize * 1.375),
      );
    });

    it('should never go below absolute minimum font size', () => {
      const text = 'This extremely long text will never fit in a tiny field no matter what';
      const fieldWidth = 20;
      const fieldHeight = 5;

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: false,
        ...defaults,
      });

      // Minimum is max(4, fontSize * 0.15) matching web's useShrinkToFit
      const expectedMin = Math.max(4, defaults.initialFontSize * 0.15);
      expect(result.fontSize).toBeGreaterThanOrEqual(expectedMin - 0.01);
    });

    it('should use custom font size when provided', () => {
      const text = 'Hello';
      const fieldWidth = 200;
      const fieldHeight = 30;
      const customSize = 10;

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        initialFontSize: customSize,
        minFontSize: defaults.minFontSize,
        isTextField: false,
      });

      expect(result.fontSize).toBeLessThanOrEqual(customSize);
    });
  });

  describe('multi-line text', () => {
    it('should detect multiline when text overflows width (isTextField=true)', () => {
      const text = 'This is a long text that should definitely overflow the width of a narrow field';
      const fieldWidth = 80;
      const fieldHeight = 100;

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: true,
        ...defaults,
      });

      expect(result.isMultiline).toBe(true);
      expect(result.wrappedText).toContain('\n');
    });

    it('should detect multiline when text contains newlines (isTextField=true)', () => {
      const text = 'Line 1\nLine 2';
      const fieldWidth = 500;
      const fieldHeight = 100;

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: true,
        ...defaults,
      });

      expect(result.isMultiline).toBe(true);
    });

    it('should NOT detect multiline for non-TEXT fields even with overflow', () => {
      const text = 'This is a long text that should definitely overflow the width of a narrow field';
      const fieldWidth = 80;
      const fieldHeight = 100;

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: false,
        ...defaults,
      });

      expect(result.isMultiline).toBe(false);
    });

    it('should shrink font size when wrapped text exceeds field height', () => {
      const text =
        'This box has long text that should shrink in size so we can see the jj and gg letters properly';
      const fieldWidth = 100;
      const fieldHeight = 80; // forces shrinking but achievable

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: true,
        ...defaults,
      });

      expect(result.fontSize).toBeLessThan(defaults.initialFontSize);
      expect(result.isMultiline).toBe(true);

      // Verify wrapped text height fits within field
      const lineCount = result.wrappedText.split('\n').length;
      const wrappedHeight = font.heightAtSize(result.fontSize) * lineCount * 1.375;
      expect(wrappedHeight).toBeLessThanOrEqual(fieldHeight);
    });

    it('should produce wrapped lines that fit within render width', () => {
      const text = 'Multiple words that need to be wrapped carefully so each line fits';
      const fieldWidth = 120;
      const fieldHeight = 200;

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: true,
        ...defaults,
      });

      const renderWidth = fieldWidth - 2;
      const lines = result.wrappedText.split('\n');

      for (const line of lines) {
        expect(font.widthOfTextAtSize(line, result.fontSize)).toBeLessThanOrEqual(renderWidth + 0.5);
      }
    });
  });

  describe('realistic field sizes', () => {
    // Simulate typical page dimensions (US Letter: 612 x 792 points)
    const pageWidth = 612;
    const pageHeight = 792;

    it('should handle typical 5% width/height field with short text', () => {
      const fieldWidth = pageWidth * 0.05; // ~30pt
      const fieldHeight = pageHeight * 0.05; // ~40pt
      const text = 'John';

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: false,
        ...defaults,
      });

      expect(result.fontSize).toBeGreaterThanOrEqual(defaults.minFontSize);
      expect(font.widthOfTextAtSize(text, result.fontSize)).toBeLessThanOrEqual(fieldWidth);
    });

    it('should handle 15% width field with email text', () => {
      const fieldWidth = pageWidth * 0.15; // ~92pt
      const fieldHeight = pageHeight * 0.05; // ~40pt
      const text = 'john.doe@example.com';

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: false,
        ...defaults,
      });

      const renderWidth = fieldWidth - 2;
      const renderHeight = fieldHeight - 2;
      expect(font.widthOfTextAtSize(text, result.fontSize)).toBeLessThanOrEqual(renderWidth + 0.5);
    });

    // These tests match exact scenarios from user-reported screenshot issues
    it('should fit long address text that was being cut off in PDF', () => {
      // ~38% width field on a letter page, ~3% height
      const fieldWidth = pageWidth * 0.38; // ~232pt
      const fieldHeight = pageHeight * 0.03; // ~24pt
      const text = 'This is a long address that should shrink in size to fit to the text both deimensions';

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: true,
        ...defaults,
      });

      // Text must fit within render area
      const renderWidth = fieldWidth - 2;
      const renderHeight = fieldHeight - 2;

      if (result.isMultiline) {
        const lines = result.wrappedText.split('\n');
        for (const line of lines) {
          expect(font.widthOfTextAtSize(line, result.fontSize)).toBeLessThanOrEqual(renderWidth + 0.5);
        }
        const totalHeight = font.heightAtSize(result.fontSize) * lines.length * 1.375;
        expect(totalHeight).toBeLessThanOrEqual(renderHeight);
      } else {
        expect(font.widthOfTextAtSize(text, result.fontSize)).toBeLessThanOrEqual(renderWidth + 0.5);
        expect(font.heightAtSize(result.fontSize)).toBeLessThanOrEqual(renderHeight);
      }
    });

    it('should fit text with descenders within field dimensions', () => {
      // ~38% width, ~3% height field
      const fieldWidth = pageWidth * 0.38;
      const fieldHeight = pageHeight * 0.03; // ~24pt
      const text = 'This has jj gg';

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: false,
        ...defaults,
      });

      const renderWidth = fieldWidth - 2;
      const renderHeight = fieldHeight - 2;
      expect(font.widthOfTextAtSize(text, result.fontSize)).toBeLessThanOrEqual(renderWidth + 0.5);
    });

    it('should fit "My address ggjj" within field width', () => {
      const fieldWidth = pageWidth * 0.38;
      const fieldHeight = pageHeight * 0.03;
      const text = 'My address ggjj';

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: false,
        ...defaults,
      });

      const renderWidth = fieldWidth - 2;
      expect(font.widthOfTextAtSize(text, result.fontSize)).toBeLessThanOrEqual(renderWidth + 0.5);
    });

    it('should handle multiline text field at 20% width, 10% height', () => {
      const fieldWidth = pageWidth * 0.2; // ~122pt
      const fieldHeight = pageHeight * 0.1; // ~79pt
      const text =
        'This box has long text that should shrink in size so we can see the jj and gg';

      const result = calculateFontSizeToFit({
        text,
        fieldWidth,
        fieldHeight,
        font,
        isTextField: true,
        ...defaults,
      });

      // Should wrap and fit
      const lineCount = result.wrappedText.split('\n').length;
      const totalHeight = font.heightAtSize(result.fontSize) * lineCount * 1.375;
      expect(totalHeight).toBeLessThanOrEqual(fieldHeight);

      // Each line should fit in render width
      const renderWidth = fieldWidth - 2;
      for (const line of result.wrappedText.split('\n')) {
        expect(font.widthOfTextAtSize(line, result.fontSize)).toBeLessThanOrEqual(renderWidth + 0.5);
      }
    });
  });
});
