import { useRef, useState } from 'react';

import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';
import { Trans } from '@lingui/react/macro';
import { FileUp, Loader } from 'lucide-react';

import { APP_DOCUMENT_UPLOAD_SIZE_LIMIT } from '@documenso/lib/constants/app';
import { megabytesToBytes } from '@documenso/lib/universal/unit-convertions';
import { putPdfFile } from '@documenso/lib/universal/upload/put-file';
import { trpc } from '@documenso/trpc/react';
import { Button } from '@documenso/ui/primitives/button';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@documenso/ui/primitives/dialog';
import { useToast } from '@documenso/ui/primitives/use-toast';

export interface TemplateReplaceDocumentDialogProps {
  templateId: number;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void | Promise<void>;
}

export const TemplateReplaceDocumentDialog = ({
  templateId,
  open,
  onOpenChange,
  onSuccess,
}: TemplateReplaceDocumentDialogProps) => {
  const { _ } = useLingui();
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isLoading, setIsLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const { mutateAsync: replaceTemplateDocument } =
    trpc.template.replaceTemplateDocument.useMutation();

  const handleOpenChange = (value: boolean) => {
    onOpenChange(value);

    if (!value) {
      setSelectedFile(null);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];

    if (!file) {
      return;
    }

    if (file.type !== 'application/pdf') {
      toast({
        title: _(msg`Invalid file`),
        description: _(msg`Only PDF files are allowed.`),
        variant: 'destructive',
      });
      return;
    }

    if (file.size > megabytesToBytes(APP_DOCUMENT_UPLOAD_SIZE_LIMIT)) {
      toast({
        title: _(msg`File too large`),
        description: _(msg`File is larger than ${APP_DOCUMENT_UPLOAD_SIZE_LIMIT}MB.`),
        variant: 'destructive',
      });
      return;
    }

    setSelectedFile(file);
  };

  const handleReplace = async () => {
    if (!selectedFile) {
      return;
    }

    try {
      setIsLoading(true);

      const documentData = await putPdfFile(selectedFile);

      await replaceTemplateDocument({
        templateId,
        documentDataId: documentData.id,
      });

      toast({
        title: _(msg`Document replaced`),
        description: _(msg`The template document has been replaced successfully.`),
        duration: 5000,
      });

      handleOpenChange(false);

      await onSuccess?.();
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : _(msg`An error occurred while replacing the document.`);

      toast({
        title: _(msg`Failed to replace document`),
        description: message,
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            <Trans>Replace Template Document</Trans>
          </DialogTitle>
          <DialogDescription>
            <Trans>
              Upload a new PDF to replace the current document. Existing fields will be kept. The
              new document must have at least as many pages as are needed by existing fields.
            </Trans>
          </DialogDescription>
        </DialogHeader>

        <div className="my-4">
          <input
            ref={fileInputRef}
            type="file"
            accept="application/pdf"
            onChange={handleFileChange}
            className="hidden"
          />

          <Button
            type="button"
            variant="outline"
            className="w-full"
            onClick={() => fileInputRef.current?.click()}
            disabled={isLoading}
          >
            <FileUp className="mr-2 h-4 w-4" />
            {selectedFile ? selectedFile.name : <Trans>Choose PDF file</Trans>}
          </Button>
        </div>

        <DialogFooter>
          <DialogClose asChild>
            <Button variant="secondary" disabled={isLoading}>
              <Trans>Cancel</Trans>
            </Button>
          </DialogClose>

          <Button onClick={handleReplace} disabled={!selectedFile || isLoading}>
            {isLoading ? (
              <>
                <Loader className="mr-2 h-4 w-4 animate-spin" />
                <Trans>Replacing...</Trans>
              </>
            ) : (
              <Trans>Replace</Trans>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
