import {
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFHexString,
  PDFName,
  PDFNumber,
  PDFString,
  rectangle,
} from 'pdf-lib';

import { BYTE_RANGE_PLACEHOLDER } from '../constants/byte-range';

export type AddSigningPlaceholderOptions = {
  pdf: Buffer;
  /**
   * Certification level for DocMDP (Document Modification Detection and Prevention)
   * - 0 or undefined: Approval signature (no certification, no DocMDP)
   * - 1: No changes allowed after signing (certified, locked)
   * - 2: Form filling allowed
   * - 3: Form filling and annotations allowed
   */
  certificationLevel?: 0 | 1 | 2 | 3;
};

export const addSigningPlaceholder = async ({
  pdf,
  certificationLevel,
}: AddSigningPlaceholderOptions) => {
  const doc = await PDFDocument.load(pdf);
  const [firstPage] = doc.getPages();

  const byteRange = PDFArray.withContext(doc.context);

  byteRange.push(PDFNumber.of(0));
  byteRange.push(PDFName.of(BYTE_RANGE_PLACEHOLDER));
  byteRange.push(PDFName.of(BYTE_RANGE_PLACEHOLDER));
  byteRange.push(PDFName.of(BYTE_RANGE_PLACEHOLDER));

  // Build signature dictionary based on certification level
  const signatureDict: Record<
    string,
    | string
    | PDFName
    | PDFArray
    | PDFHexString
    | PDFString
    | PDFDict
    | ReturnType<typeof doc.context.obj>
  > = {
    Type: 'Sig',
    Filter: 'Adobe.PPKLite',
    SubFilter: 'adbe.pkcs7.detached',
    ByteRange: byteRange,
    Contents: PDFHexString.fromText(' '.repeat(8192)),
    M: PDFString.fromDate(new Date()),
    Prop_Build: doc.context.obj({
      Filter: doc.context.obj({
        Name: 'Documenso',
        R: PDFNumber.of(1.0),
      }),
      App: doc.context.obj({
        Name: 'Documenso',
        R: PDFNumber.of(1.0),
        TrustedMode: true,
      }),
    }),
  };

  // Add DocMDP reference for certification signatures
  if (certificationLevel && certificationLevel > 0) {
    // Create DocMDP transform parameters for certification signature
    const transformParams = doc.context.obj({
      Type: 'TransformParams',
      V: '1.2',
      P: certificationLevel, // Permission level: 1 = no changes, 2 = form fill, 3 = annotations/form fill
    });

    // Create signature reference with DocMDP
    const sigReference = doc.context.obj({
      Type: 'SigRef',
      TransformMethod: 'DocMDP',
      DigestMethod: 'SHA256',
      TransformParams: transformParams,
    });

    const referenceArray = PDFArray.withContext(doc.context);
    referenceArray.push(sigReference);

    signatureDict.Reference = referenceArray;
  }

  const signature = doc.context.register(doc.context.obj(signatureDict));

  const widget = doc.context.register(
    doc.context.obj({
      Type: 'Annot',
      Subtype: 'Widget',
      FT: 'Sig',
      Rect: [0, 0, 0, 0],
      V: signature,
      T: PDFString.of('Signature1'),
      F: 4,
      P: firstPage.ref,
      AP: doc.context.obj({
        N: doc.context.register(doc.context.formXObject([rectangle(0, 0, 0, 0)])),
      }),
    }),
  );

  let widgets: PDFArray;

  try {
    widgets = firstPage.node.lookup(PDFName.of('Annots'), PDFArray);
  } catch {
    widgets = PDFArray.withContext(doc.context);

    firstPage.node.set(PDFName.of('Annots'), widgets);
  }

  widgets.push(widget);

  let arcoForm: PDFDict;

  try {
    arcoForm = doc.catalog.lookup(PDFName.of('AcroForm'), PDFDict);
  } catch {
    arcoForm = doc.context.obj({
      Fields: PDFArray.withContext(doc.context),
    });

    doc.catalog.set(PDFName.of('AcroForm'), arcoForm);
  }

  let fields: PDFArray;

  try {
    fields = arcoForm.lookup(PDFName.of('Fields'), PDFArray);
  } catch {
    fields = PDFArray.withContext(doc.context);

    arcoForm.set(PDFName.of('Fields'), fields);
  }

  fields.push(widget);

  arcoForm.set(PDFName.of('SigFlags'), PDFNumber.of(3));

  // Add Perms (Permissions) dictionary to Catalog for certification signatures
  // This is required for Adobe LTV recognition with DocMDP
  if (certificationLevel && certificationLevel > 0) {
    const perms = doc.context.obj({
      DocMDP: signature,
    });

    doc.catalog.set(PDFName.of('Perms'), perms);
  }

  return Buffer.from(await doc.save({ useObjectStreams: false }));
};
