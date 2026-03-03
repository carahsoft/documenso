import React from 'react';

import { FieldType } from '@prisma/client';
import { Pencil, X } from 'lucide-react';

import { type TRecipientActionAuth } from '@documenso/lib/types/document-auth';
import { ZFieldMetaSchema } from '@documenso/lib/types/field-meta';
import type { FieldWithSignature } from '@documenso/prisma/types/field-with-signature';
import { FieldRootContainer } from '@documenso/ui/components/field/field';
import { RECIPIENT_COLOR_STYLES } from '@documenso/ui/lib/recipient-colors';
import { cn } from '@documenso/ui/lib/utils';

import { useRequiredDocumentSigningAuthContext } from './document-signing-auth-provider';

export type DocumentSigningFieldContainerProps = {
  field: FieldWithSignature;
  loading?: boolean;
  children: React.ReactNode;

  /**
   * A function that is called before the field requires to be signed, or reauthed.
   *
   * Example, you may want to show a dialog prior to signing where they can enter a value.
   *
   * Once that action is complete, you will need to call `executeActionAuthProcedure` to proceed
   * regardless if it requires reauth or not.
   *
   * If the function returns true, we will proceed with the signing process. Otherwise if
   * false is returned we will not proceed.
   */
  onPreSign?: () => Promise<boolean> | boolean;

  /**
   * The function required to be executed to insert the field.
   *
   * The auth values will be passed in if available.
   */
  onSign?: (documentAuthValue?: TRecipientActionAuth) => Promise<void> | void;
  onRemove?: (fieldType?: string) => Promise<void> | void;
  onEdit?: () => void;
  type?:
    | 'Date'
    | 'Initials'
    | 'Email'
    | 'Name'
    | 'Signature'
    | 'Text'
    | 'Radio'
    | 'Dropdown'
    | 'Number'
    | 'Checkbox';
  tooltipText?: string | null;
};

export const DocumentSigningFieldContainer = ({
  field,
  loading,
  onPreSign,
  onSign,
  onRemove,
  onEdit,
  children,
  type,
  tooltipText,
}: DocumentSigningFieldContainerProps) => {
  const { executeActionAuthProcedure, isAuthRedirectRequired } =
    useRequiredDocumentSigningAuthContext();

  const parsedFieldMeta = field.fieldMeta ? ZFieldMetaSchema.parse(field.fieldMeta) : undefined;
  const readOnlyField = parsedFieldMeta?.readOnly || false;

  const handleInsertField = async () => {
    if (field.inserted || !onSign) {
      return;
    }

    // Bypass reauth for non signature fields.
    if (field.type !== FieldType.SIGNATURE) {
      const presignResult = await onPreSign?.();

      if (presignResult === false) {
        return;
      }

      await onSign();
      return;
    }

    if (isAuthRedirectRequired) {
      await executeActionAuthProcedure({
        onReauthFormSubmit: () => {
          // Do nothing since the user should be redirected.
        },
        actionTarget: field.type,
      });

      return;
    }

    // Handle any presign requirements, and halt if required.
    if (onPreSign) {
      const preSignResult = await onPreSign();

      if (preSignResult === false) {
        return;
      }
    }

    await executeActionAuthProcedure({
      onReauthFormSubmit: onSign,
      actionTarget: field.type,
    });
  };

  const onRemoveSignedFieldClick = async () => {
    if (!field.inserted) {
      return;
    }

    await onRemove?.();
  };

  const onClearCheckBoxValues = async (fieldType?: string) => {
    if (!field.inserted) {
      return;
    }

    await onRemove?.(fieldType);
  };

  return (
    <div className={cn('[container-type:size]')}>
      <FieldRootContainer
        color={
          field.fieldMeta?.readOnly ? RECIPIENT_COLOR_STYLES.readOnly : RECIPIENT_COLOR_STYLES.green
        }
        field={field}
      >
        {!field.inserted && !loading && !readOnlyField && (
          <button
            type="submit"
            className="absolute inset-0 z-10 h-full w-full rounded-[2px]"
            onClick={async () => handleInsertField()}
          />
        )}

        {field.inserted && !loading && !readOnlyField && (
          <div className="absolute -bottom-8 left-1/2 z-50 flex -translate-x-1/2 items-center gap-0.5 rounded-md border bg-gray-900 px-0.5 py-0.5 opacity-0 shadow-sm transition-opacity group-hover:opacity-100">
            {onEdit && (
              <button
                className="rounded p-1 text-gray-400 transition-colors hover:bg-white/10 hover:text-gray-100"
                onClick={() => onEdit()}
              >
                <Pencil className="h-3.5 w-3.5" />
              </button>
            )}

            <button
              className="rounded p-1 text-gray-400 transition-colors hover:bg-white/10 hover:text-gray-100"
              onClick={() =>
                type === 'Checkbox'
                  ? void onClearCheckBoxValues(type)
                  : void onRemoveSignedFieldClick()
              }
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        {(field.type === FieldType.RADIO || field.type === FieldType.CHECKBOX) &&
          field.fieldMeta?.label && (
            <div
              className={cn(
                'absolute -top-16 left-0 right-0 rounded-md p-2 text-center text-xs text-gray-700',
                {
                  'bg-foreground/5 border-border border': !field.inserted,
                },
                {
                  'bg-documenso-200 border-primary border': field.inserted,
                },
              )}
            >
              {field.fieldMeta.label}
            </div>
          )}

        {children}
      </FieldRootContainer>
    </div>
  );
};
