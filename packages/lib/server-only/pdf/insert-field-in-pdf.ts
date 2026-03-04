// https://github.com/Hopding/pdf-lib/issues/20#issuecomment-412852821
import fontkit from '@pdf-lib/fontkit';
import { FieldType } from '@prisma/client';
import type { PDFDocument, PDFFont, PDFTextField } from 'pdf-lib';
import {
  RotationTypes,
  TextAlignment,
  degrees,
  radiansToDegrees,
  rgb,
  setFontAndSize,
} from 'pdf-lib';
import { P, match } from 'ts-pattern';

import {
  DEFAULT_HANDWRITING_FONT_SIZE,
  DEFAULT_STANDARD_FONT_SIZE,
  MIN_HANDWRITING_FONT_SIZE,
  MIN_STANDARD_FONT_SIZE,
} from '@documenso/lib/constants/pdf';
import { fromCheckboxValue } from '@documenso/lib/universal/field-checkbox';
import { isSignatureFieldType } from '@documenso/prisma/guards/is-signature-field';
import type { FieldWithSignature } from '@documenso/prisma/types/field-with-signature';

import { NEXT_PUBLIC_WEBAPP_URL } from '../../constants/app';
import {
  ZCheckboxFieldMeta,
  ZDateFieldMeta,
  ZEmailFieldMeta,
  ZInitialsFieldMeta,
  ZNameFieldMeta,
  ZNumberFieldMeta,
  ZRadioFieldMeta,
  ZTextFieldMeta,
} from '../../types/field-meta';
import { getPageSize } from './get-page-size';

export const insertFieldInPDF = async (pdf: PDFDocument, field: FieldWithSignature) => {
  const [fontCaveat, fontNoto] = await Promise.all([
    fetch(`${NEXT_PUBLIC_WEBAPP_URL()}/fonts/caveat.ttf`).then(async (res) => res.arrayBuffer()),
    fetch(`${NEXT_PUBLIC_WEBAPP_URL()}/fonts/noto-sans.ttf`).then(async (res) => res.arrayBuffer()),
  ]);

  const isSignatureField = isSignatureFieldType(field.type);

  /**
   * Red box is the original field width, height and position.
   *
   * Blue box is the adjusted field width, height and position. It will represent
   * where the text will overflow into.
   */
  const isDebugMode =
    // eslint-disable-next-line turbo/no-undeclared-env-vars
    process.env.DEBUG_PDF_INSERT === '1' || process.env.DEBUG_PDF_INSERT === 'true';

  pdf.registerFontkit(fontkit);

  const pages = pdf.getPages();

  const minFontSize = isSignatureField ? MIN_HANDWRITING_FONT_SIZE : MIN_STANDARD_FONT_SIZE;
  const maxFontSize = isSignatureField ? DEFAULT_HANDWRITING_FONT_SIZE : DEFAULT_STANDARD_FONT_SIZE;

  const page = pages.at(field.page - 1);

  if (!page) {
    throw new Error(`Page ${field.page} does not exist`);
  }

  const pageRotation = page.getRotation();

  let pageRotationInDegrees = match(pageRotation.type)
    .with(RotationTypes.Degrees, () => pageRotation.angle)
    .with(RotationTypes.Radians, () => radiansToDegrees(pageRotation.angle))
    .exhaustive();

  // Round to the closest multiple of 90 degrees.
  pageRotationInDegrees = Math.round(pageRotationInDegrees / 90) * 90;

  const isPageRotatedToLandscape = pageRotationInDegrees === 90 || pageRotationInDegrees === 270;

  let { width: pageWidth, height: pageHeight } = getPageSize(page);

  // PDFs can have pages that are rotated, which are correctly rendered in the frontend.
  // However when we load the PDF in the backend, the rotation is applied.
  //
  // To account for this, we swap the width and height for pages that are rotated by 90/270
  // degrees. This is so we can calculate the virtual position the field was placed if it
  // was correctly oriented in the frontend.
  //
  // Then when we insert the fields, we apply a transformation to the position of the field
  // so it is rotated correctly.
  if (isPageRotatedToLandscape) {
    [pageWidth, pageHeight] = [pageHeight, pageWidth];
  }

  const fieldWidth = pageWidth * (Number(field.width) / 100);
  const fieldHeight = pageHeight * (Number(field.height) / 100);

  const fieldX = pageWidth * (Number(field.positionX) / 100);
  const fieldY = pageHeight * (Number(field.positionY) / 100);

  // Draw debug box if debug mode is enabled
  if (isDebugMode) {
    let debugX = fieldX;
    let debugY = pageHeight - fieldY - fieldHeight; // Invert Y for PDF coordinates

    if (pageRotationInDegrees !== 0) {
      const adjustedPosition = adjustPositionForRotation(
        pageWidth,
        pageHeight,
        debugX,
        debugY,
        pageRotationInDegrees,
      );

      debugX = adjustedPosition.xPos;
      debugY = adjustedPosition.yPos;
    }

    page.drawRectangle({
      x: debugX,
      y: debugY,
      width: fieldWidth,
      height: fieldHeight,
      borderColor: rgb(1, 0, 0), // Red
      borderWidth: 1,
      rotate: degrees(pageRotationInDegrees),
    });
  }

  const font = await pdf.embedFont(
    isSignatureField ? fontCaveat : fontNoto,
    isSignatureField ? { features: { calt: false } } : undefined,
  );

  if (field.type === FieldType.SIGNATURE || field.type === FieldType.FREE_SIGNATURE) {
    await pdf.embedFont(fontCaveat);
  }

  await match(field)
    .with(
      {
        type: P.union(FieldType.SIGNATURE, FieldType.FREE_SIGNATURE),
      },
      async (field) => {
        if (field.signature?.signatureImageAsBase64) {
          const image = await pdf.embedPng(field.signature?.signatureImageAsBase64 ?? '');

          let imageWidth = image.width;
          let imageHeight = image.height;

          const scalingFactor = Math.min(fieldWidth / imageWidth, fieldHeight / imageHeight, 1);

          imageWidth = imageWidth * scalingFactor;
          imageHeight = imageHeight * scalingFactor;

          let imageX = fieldX + (fieldWidth - imageWidth) / 2;
          let imageY = fieldY + (fieldHeight - imageHeight) / 2;

          // Invert the Y axis since PDFs use a bottom-left coordinate system
          imageY = pageHeight - imageY - imageHeight;

          if (pageRotationInDegrees !== 0) {
            const adjustedPosition = adjustPositionForRotation(
              pageWidth,
              pageHeight,
              imageX,
              imageY,
              pageRotationInDegrees,
            );

            imageX = adjustedPosition.xPos;
            imageY = adjustedPosition.yPos;
          }

          page.drawImage(image, {
            x: imageX,
            y: imageY,
            width: imageWidth,
            height: imageHeight,
            rotate: degrees(pageRotationInDegrees),
          });
        } else {
          const signatureText = field.signature?.typedSignature ?? '';

          const longestLineInTextForWidth = signatureText
            .split('\n')
            .sort((a, b) => b.length - a.length)[0];

          let fontSize = maxFontSize;
          let textWidth = font.widthOfTextAtSize(longestLineInTextForWidth, fontSize);
          let textHeight = font.heightAtSize(fontSize);

          const scalingFactor = Math.min(fieldWidth / textWidth, fieldHeight / textHeight, 1);
          fontSize = Math.max(Math.min(fontSize * scalingFactor, maxFontSize), minFontSize);

          textWidth = font.widthOfTextAtSize(longestLineInTextForWidth, fontSize);
          textHeight = font.heightAtSize(fontSize);

          let textX = fieldX + (fieldWidth - textWidth) / 2;
          let textY = fieldY + (fieldHeight - textHeight) / 2;

          // Invert the Y axis since PDFs use a bottom-left coordinate system
          textY = pageHeight - textY - textHeight;

          if (pageRotationInDegrees !== 0) {
            const adjustedPosition = adjustPositionForRotation(
              pageWidth,
              pageHeight,
              textX,
              textY,
              pageRotationInDegrees,
            );

            textX = adjustedPosition.xPos;
            textY = adjustedPosition.yPos;
          }

          page.drawText(signatureText, {
            x: textX,
            y: textY,
            size: fontSize,
            font,
            rotate: degrees(pageRotationInDegrees),
          });
        }
      },
    )
    .with({ type: FieldType.CHECKBOX }, (field) => {
      const meta = ZCheckboxFieldMeta.safeParse(field.fieldMeta);

      if (!meta.success) {
        console.error(meta.error);

        throw new Error('Invalid checkbox field meta');
      }

      const values = meta.data.values?.map((item) => ({
        ...item,
        value: item.value.length > 0 ? item.value : `empty-value-${item.id}`,
      }));

      const selected: string[] = fromCheckboxValue(field.customText);
      const direction = meta.data.direction ?? 'vertical';

      const topPadding = 12;
      const leftCheckboxPadding = 8;
      const leftCheckboxLabelPadding = 12;
      const checkboxSpaceY = 13;

      if (direction === 'horizontal') {
        // Horizontal layout: arrange checkboxes side by side with wrapping
        let currentX = leftCheckboxPadding;
        let currentY = topPadding;
        const maxWidth = pageWidth - fieldX - leftCheckboxPadding * 2;

        for (const [index, item] of (values ?? []).entries()) {
          const checkbox = pdf.getForm().createCheckBox(`checkbox.${field.secondaryId}.${index}`);

          if (selected.includes(item.value)) {
            checkbox.check();
          }

          const labelText = item.value.includes('empty-value-') ? '' : item.value;
          const labelWidth = font.widthOfTextAtSize(labelText, 12);
          const itemWidth = leftCheckboxLabelPadding + labelWidth + 16; // checkbox + padding + label + margin

          // Check if item fits on current line, if not wrap to next line
          if (currentX + itemWidth > maxWidth && index > 0) {
            currentX = leftCheckboxPadding;
            currentY += checkboxSpaceY;
          }

          page.drawText(labelText, {
            x: fieldX + currentX + leftCheckboxLabelPadding,
            y: pageHeight - (fieldY + currentY),
            size: 12,
            font,
            rotate: degrees(pageRotationInDegrees),
          });

          checkbox.addToPage(page, {
            x: fieldX + currentX,
            y: pageHeight - (fieldY + currentY),
            height: 8,
            width: 8,
          });

          currentX += itemWidth;
        }
      } else {
        // Vertical layout: original behavior
        for (const [index, item] of (values ?? []).entries()) {
          const offsetY = index * checkboxSpaceY + topPadding;

          const checkbox = pdf.getForm().createCheckBox(`checkbox.${field.secondaryId}.${index}`);

          if (selected.includes(item.value)) {
            checkbox.check();
          }

          page.drawText(item.value.includes('empty-value-') ? '' : item.value, {
            x: fieldX + leftCheckboxPadding + leftCheckboxLabelPadding,
            y: pageHeight - (fieldY + offsetY),
            size: 12,
            font,
            rotate: degrees(pageRotationInDegrees),
          });

          checkbox.addToPage(page, {
            x: fieldX + leftCheckboxPadding,
            y: pageHeight - (fieldY + offsetY),
            height: 8,
            width: 8,
          });
        }
      }
    })
    .with({ type: FieldType.RADIO }, (field) => {
      const meta = ZRadioFieldMeta.safeParse(field.fieldMeta);

      if (!meta.success) {
        console.error(meta.error);

        throw new Error('Invalid radio field meta');
      }

      const values = meta?.data.values?.map((item) => ({
        ...item,
        value: item.value.length > 0 ? item.value : `empty-value-${item.id}`,
      }));

      const selected = field.customText.split(',');

      const topPadding = 12;
      const leftRadioPadding = 8;
      const leftRadioLabelPadding = 12;
      const radioSpaceY = 13;

      for (const [index, item] of (values ?? []).entries()) {
        const offsetY = index * radioSpaceY + topPadding;

        const radio = pdf.getForm().createRadioGroup(`radio.${field.secondaryId}.${index}`);

        // Draw label.
        page.drawText(item.value.includes('empty-value-') ? '' : item.value, {
          x: fieldX + leftRadioPadding + leftRadioLabelPadding,
          y: pageHeight - (fieldY + offsetY),
          size: 12,
          font,
          rotate: degrees(pageRotationInDegrees),
        });

        // Draw radio button.
        radio.addOptionToPage(item.value, page, {
          x: fieldX + leftRadioPadding,
          y: pageHeight - (fieldY + offsetY),
          height: 8,
          width: 8,
        });

        if (selected.includes(item.value)) {
          radio.select(item.value);
        }
      }
    })
    .otherwise((field) => {
      const fieldMetaParsers = {
        [FieldType.TEXT]: ZTextFieldMeta,
        [FieldType.NUMBER]: ZNumberFieldMeta,
        [FieldType.DATE]: ZDateFieldMeta,
        [FieldType.EMAIL]: ZEmailFieldMeta,
        [FieldType.NAME]: ZNameFieldMeta,
        [FieldType.INITIALS]: ZInitialsFieldMeta,
      } as const;

      // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
      const fieldMetaParser = fieldMetaParsers[field.type as keyof typeof fieldMetaParsers];
      const meta = fieldMetaParser ? fieldMetaParser.safeParse(field.fieldMeta) : null;

      const customFontSize = meta?.success && meta.data.fontSize ? meta.data.fontSize : null;
      const textAlign = meta?.success && meta.data.textAlign ? meta.data.textAlign : 'left';

      const { fontSize, isMultiline, wrappedText } = calculateFontSizeToFit({
        text: field.customText,
        fieldWidth,
        fieldHeight,
        font,
        initialFontSize: customFontSize || maxFontSize,
        minFontSize,
        isTextField: field.type === FieldType.TEXT,
      });

      const textFieldBoxY = pageHeight - fieldY - fieldHeight;

      const textAlignment = textAlignmentMap[textAlign];
      const textField = pdf.getForm().createTextField(`text.${field.secondaryId}`);
      textField.setAlignment(textAlignment);

      const adjustedFieldWidth = fieldWidth;
      const adjustedFieldHeight = fieldHeight;
      let adjustedFieldX = fieldX;
      let adjustedFieldY = textFieldBoxY;

      const textToInsert = isMultiline ? wrappedText : field.customText;

      if (isMultiline) {
        textField.enableMultiline();
        textField.disableCombing();
        textField.disableScrolling();
      }

      if (pageRotationInDegrees !== 0) {
        const adjustedPosition = adjustPositionForRotation(
          pageWidth,
          pageHeight,
          adjustedFieldX,
          adjustedFieldY,
          pageRotationInDegrees,
        );

        adjustedFieldX = adjustedPosition.xPos;
        adjustedFieldY = adjustedPosition.yPos;
      }

      // Set properties for the text field
      setTextFieldFontSize(textField, font, fontSize);
      textField.setText(textToInsert);

      // Set the position and size of the text field
      textField.addToPage(page, {
        x: adjustedFieldX,
        y: adjustedFieldY,
        width: adjustedFieldWidth,
        height: adjustedFieldHeight,
        rotate: degrees(pageRotationInDegrees),

        font,

        // Hide borders.
        borderWidth: 0,
        borderColor: undefined,
        backgroundColor: undefined,

        ...(isDebugMode ? { borderWidth: 1, borderColor: rgb(0, 0, 1) } : {}),
      });
    });

  return pdf;
};

const adjustPositionForRotation = (
  pageWidth: number,
  pageHeight: number,
  xPos: number,
  yPos: number,
  pageRotationInDegrees: number,
) => {
  if (pageRotationInDegrees === 270) {
    xPos = pageWidth - xPos;
    [xPos, yPos] = [yPos, xPos];
  }

  if (pageRotationInDegrees === 90) {
    yPos = pageHeight - yPos;
    [xPos, yPos] = [yPos, xPos];
  }

  // Invert all the positions since it's rotated by 180 degrees.
  if (pageRotationInDegrees === 180) {
    xPos = pageWidth - xPos;
    yPos = pageHeight - yPos;
  }

  return {
    xPos,
    yPos,
  };
};

/**
 * Calculate the font size that fits text within the given field dimensions.
 * Handles both single-line (scale to fit) and multi-line (word wrap + shrink).
 */
export function calculateFontSizeToFit({
  text,
  fieldWidth,
  fieldHeight,
  font,
  initialFontSize,
  minFontSize,
  isTextField,
}: {
  text: string;
  fieldWidth: number;
  fieldHeight: number;
  font: PDFFont;
  initialFontSize: number;
  minFontSize: number;
  isTextField: boolean;
}): { fontSize: number; isMultiline: boolean; wrappedText: string } {
  // pdf-lib text fields use padding=1 (1pt per side) when borderWidth=0
  // and clip content to: width - (borderWidth/2 + padding) * 2
  const PDF_TEXT_FIELD_PADDING = 2; // 1pt per side
  const LINE_SPACING = 1.375; // Match web's leading-snug
  const renderWidth = fieldWidth - PDF_TEXT_FIELD_PADDING;
  const renderHeight = fieldHeight - PDF_TEXT_FIELD_PADDING;

  let fontSize = initialFontSize;

  const isMultiline =
    isTextField && (font.widthOfTextAtSize(text, fontSize) > renderWidth || text.includes('\n'));

  // Matches the web's useShrinkToFit availableHeight function:
  // - Multiline: uses full container height
  // - Single-line: caps to one line height so wrapping triggers shrinking
  const availableHeight = (size: number) => {
    if (isMultiline) return renderHeight;
    return Math.min(renderHeight, size * LINE_SPACING);
  };

  // Binary search for largest font size that fits (matches web algorithm).
  // The web uses scrollHeight; we simulate with font metrics + word wrapping.
  const absoluteMinFontSize = Math.max(4, fontSize * 0.15);

  const fitsAtSize = (size: number): { fits: boolean; wrapped: string } => {
    const wrapped = isMultiline ? breakLongString(text, renderWidth, font, size) : text;

    if (!isMultiline) {
      // Single-line: text must fit width-wise without wrapping.
      // Use size * LINE_SPACING as the height measurement to match the web's
      // scrollHeight (which is fontSize * lineHeight for a single line).
      const textWidth = font.widthOfTextAtSize(text, size);
      const simulatedScrollHeight = size * LINE_SPACING;
      return {
        fits: textWidth <= renderWidth && simulatedScrollHeight <= availableHeight(size),
        wrapped,
      };
    }

    // Multiline: check wrapped text fits height
    const lineCount = wrapped.split('\n').length;
    const wrappedHeight = font.heightAtSize(size) * lineCount * LINE_SPACING;
    return {
      fits: wrappedHeight <= availableHeight(size),
      wrapped,
    };
  };

  // Check if it already fits at the desired size
  const initialCheck = fitsAtSize(fontSize);
  if (initialCheck.fits) {
    return {
      fontSize,
      isMultiline,
      wrappedText: isMultiline ? initialCheck.wrapped : text,
    };
  }

  // Binary search: 20 iterations matches the web's useShrinkToFit
  let lo = absoluteMinFontSize;
  let hi = fontSize;
  let lastWrapped = initialCheck.wrapped;

  for (let i = 0; i < 20; i++) {
    const mid = (lo + hi) / 2;
    const check = fitsAtSize(mid);
    if (check.fits) {
      lo = mid;
      lastWrapped = check.wrapped;
    } else {
      hi = mid;
    }
  }

  fontSize = lo;
  const finalWrapped = isMultiline ? breakLongString(text, renderWidth, font, fontSize) : text;

  return { fontSize, isMultiline, wrappedText: finalWrapped };
}

const textAlignmentMap = {
  left: TextAlignment.Left,
  center: TextAlignment.Center,
  right: TextAlignment.Right,
} as const;

/**
 * Break a long string into multiple lines so it fits within a given width,
 * using natural word breaking similar to word processors.
 *
 * - Keeps words together when possible
 * - Only breaks words when they're too long to fit on a line
 * - Handles whitespace intelligently
 *
 * @param text - The text to break into lines
 * @param maxWidth - The maximum width of each line in PX
 * @param font - The PDF font object
 * @param fontSize - The font size in points
 * @returns Object containing the result string and line count
 */
export function breakLongString(
  text: string,
  maxWidth: number,
  font: PDFFont,
  fontSize: number,
): string {
  // Handle empty text
  if (!text) {
    return '';
  }

  const lines: string[] = [];

  // Process each original line separately to preserve newlines
  for (const paragraph of text.split('\n')) {
    // If paragraph fits on one line or is empty, add it as-is
    if (paragraph === '' || font.widthOfTextAtSize(paragraph, fontSize) <= maxWidth) {
      lines.push(paragraph);
      continue;
    }

    // Split paragraph into words
    const words = paragraph.split(' ');
    let currentLine = '';

    for (const word of words) {
      // Check if adding word to current line would exceed max width
      const lineWithWord = currentLine.length === 0 ? word : `${currentLine} ${word}`;

      if (font.widthOfTextAtSize(lineWithWord, fontSize) <= maxWidth) {
        // Word fits, add it to current line
        currentLine = lineWithWord;
      } else {
        // Word doesn't fit on current line

        // First, save current line if it's not empty
        if (currentLine.length > 0) {
          lines.push(currentLine);
          currentLine = '';
        }

        // Check if word fits on a line by itself
        if (font.widthOfTextAtSize(word, fontSize) <= maxWidth) {
          // Word fits on its own line
          currentLine = word;
        } else {
          // Word is too long, need to break it character by character
          let charLine = '';

          // Process each character in the word
          for (const char of word) {
            const nextCharLine = charLine + char;

            if (font.widthOfTextAtSize(nextCharLine, fontSize) <= maxWidth) {
              // Character fits, add it
              charLine = nextCharLine;
            } else {
              // Character doesn't fit, push current charLine and start a new one
              lines.push(charLine);
              charLine = char;
            }
          }

          // Add any remaining characters as the current line
          currentLine = charLine;
        }
      }
    }

    // Add the last line if not empty
    if (currentLine.length > 0) {
      lines.push(currentLine);
    }
  }

  return lines.join('\n');
}

const setTextFieldFontSize = (textField: PDFTextField, font: PDFFont, fontSize: number) => {
  textField.defaultUpdateAppearances(font);
  textField.updateAppearances(font);

  try {
    textField.setFontSize(fontSize);
  } catch (err) {
    let da = textField.acroField.getDefaultAppearance() ?? '';

    da += `\n ${setFontAndSize(font.name, fontSize)}`;

    textField.acroField.setDefaultAppearance(da);
  }

  textField.defaultUpdateAppearances(font);
  textField.updateAppearances(font);
};
