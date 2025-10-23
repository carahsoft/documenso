import { useState } from 'react';

import { zodResolver } from '@hookform/resolvers/zod';
import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';
import { Trans } from '@lingui/react/macro';
import { File as FileIcon, FolderIcon, HomeIcon, Loader2, Search, Upload, X } from 'lucide-react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';

import { FolderType } from '@documenso/lib/types/folder-type';
import { trpc } from '@documenso/trpc/react';
import { Button } from '@documenso/ui/primitives/button';
import { Checkbox } from '@documenso/ui/primitives/checkbox';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@documenso/ui/primitives/dialog';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
} from '@documenso/ui/primitives/form/form';
import { Input } from '@documenso/ui/primitives/input';
import { useToast } from '@documenso/ui/primitives/use-toast';

import { useCurrentTeam } from '~/providers/team';

const ZBulkSendFormSchema = z.object({
  file: z.instanceof(File),
  sendImmediately: z.boolean().default(false),
  folderId: z.string().nullable().optional(),
});

type TBulkSendFormSchema = z.infer<typeof ZBulkSendFormSchema>;

export type TemplateBulkSendDialogProps = {
  templateId: number;
  recipients: Array<{ email: string; name?: string | null }>;
  trigger?: React.ReactNode;
  onSuccess?: () => void;
};

export const TemplateBulkSendDialog = ({
  templateId,
  recipients,
  trigger,
  onSuccess,
}: TemplateBulkSendDialogProps) => {
  const { _ } = useLingui();
  const { toast } = useToast();

  const team = useCurrentTeam();
  const [searchTerm, setSearchTerm] = useState('');

  const form = useForm<TBulkSendFormSchema>({
    resolver: zodResolver(ZBulkSendFormSchema),
    defaultValues: {
      sendImmediately: false,
      folderId: null,
    },
  });

  const { data: folders, isLoading: isFoldersLoading } = trpc.folder.findFolders.useQuery({
    type: FolderType.DOCUMENT,
  });

  const { mutateAsync: uploadBulkSend } = trpc.template.uploadBulkSend.useMutation();

  const onDownloadTemplate = () => {
    const headers = [
      'external_id',
      ...recipients.flatMap((_, index) => [
        `recipient_${index + 1}_email`,
        `recipient_${index + 1}_name`,
      ]),
    ];

    const exampleRow = [
      '',
      ...recipients.flatMap((recipient) => [recipient.email, recipient.name || '']),
    ];

    const csv = [headers.join(','), exampleRow.join(',')].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);

    const a = Object.assign(document.createElement('a'), {
      href: url,
      download: 'template.csv',
    });

    a.click();

    window.URL.revokeObjectURL(url);
  };

  const onSubmit = async (values: TBulkSendFormSchema) => {
    try {
      const csv = await values.file.text();

      await uploadBulkSend({
        templateId,
        teamId: team?.id,
        csv: csv,
        sendImmediately: values.sendImmediately,
        folderId: values.folderId ?? undefined,
      });

      toast({
        title: _(msg`Success`),
        description: _(
          msg`Your bulk send has been initiated. You will receive an email notification upon completion.`,
        ),
      });

      form.reset();
      onSuccess?.();
    } catch (err) {
      console.error(err);

      toast({
        title: 'Error',
        description: 'Failed to upload CSV. Please check the file format and try again.',
        variant: 'destructive',
      });
    }
  };

  const filteredFolders = folders?.data.filter((folder) =>
    folder.name.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  return (
    <Dialog>
      <DialogTrigger asChild>
        {trigger ?? (
          <Button variant="outline">
            <Upload className="mr-2 h-4 w-4" />
            <Trans>Bulk Send via CSV</Trans>
          </Button>
        )}
      </DialogTrigger>

      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            <Trans>Bulk Send Template via CSV</Trans>
          </DialogTitle>

          <DialogDescription>
            <Trans>
              Upload a CSV file to create multiple documents from this template. Each row represents
              one document with its recipient details.
            </Trans>
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="flex flex-col gap-y-4">
            <div className="bg-muted/70 rounded-lg border p-4">
              <h3 className="text-sm font-medium">
                <Trans>CSV Structure</Trans>
              </h3>

              <p className="text-muted-foreground mt-1 text-sm">
                <Trans>
                  For each recipient, provide their email (required) and name (optional) in separate
                  columns. You can also optionally specify an external_id for each document.
                  Download the template CSV below for the correct format.
                </Trans>
              </p>

              <p className="mt-4 text-sm">
                <Trans>Current recipients:</Trans>
              </p>

              <ul className="text-muted-foreground mt-2 list-inside list-disc text-sm">
                {recipients.map((recipient, index) => (
                  <li key={index}>
                    {recipient.name ? `${recipient.name} (${recipient.email})` : recipient.email}
                  </li>
                ))}
              </ul>
            </div>

            <div className="flex flex-col gap-y-2">
              <Button onClick={onDownloadTemplate} variant="outline" type="button">
                <Trans>Download Template CSV</Trans>
              </Button>

              <p className="text-muted-foreground text-xs">
                <Trans>Pre-formatted CSV template with example data.</Trans>
              </p>
            </div>

            <FormField
              control={form.control}
              name="file"
              render={({ field: { onChange, value }, fieldState: { error } }) => (
                <FormItem>
                  <FormControl>
                    {!value ? (
                      <Button asChild variant="outline" className="w-full">
                        <label className="cursor-pointer">
                          <input
                            type="file"
                            accept=".csv"
                            className="hidden"
                            onChange={(e) => {
                              const file = e.target.files?.[0];
                              if (file) {
                                onChange(file);
                              }
                            }}
                            disabled={form.formState.isSubmitting}
                          />
                          <Upload className="mr-2 h-4 w-4" />
                          <Trans>Upload CSV</Trans>
                        </label>
                      </Button>
                    ) : (
                      <div className="flex h-10 items-center rounded-md border px-3">
                        <div className="flex flex-1 items-center gap-2">
                          <FileIcon className="text-muted-foreground h-4 w-4" />
                          <span className="flex-1 truncate text-sm">{value.name}</span>
                        </div>

                        <Button
                          type="button"
                          variant="link"
                          className="text-destructive hover:text-destructive p-0 text-xs"
                          onClick={() => onChange(null)}
                          disabled={form.formState.isSubmitting}
                        >
                          <X className="h-4 w-4" />
                          <span className="sr-only">
                            <Trans>Remove</Trans>
                          </span>
                        </Button>
                      </div>
                    )}
                  </FormControl>

                  {error && <p className="text-destructive text-sm">{error.message}</p>}

                  <p className="text-muted-foreground text-xs">
                    <Trans>
                      Maximum file size: 4MB. Maximum 100 rows per upload. The external_id column is
                      optional and can be left blank. Blank recipient values will use template
                      defaults.
                    </Trans>
                  </p>
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="folderId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    <Trans>Destination Folder (Optional)</Trans>
                  </FormLabel>

                  <div className="relative mb-2">
                    <Search className="text-muted-foreground absolute left-2 top-3 h-4 w-4" />
                    <Input
                      placeholder={_(msg`Search folders...`)}
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="pl-8"
                    />
                  </div>

                  <FormControl>
                    <div className="max-h-48 space-y-2 overflow-y-auto rounded-md border p-2">
                      {isFoldersLoading ? (
                        <div className="flex h-10 items-center justify-center">
                          <Loader2 className="h-4 w-4 animate-spin" />
                        </div>
                      ) : (
                        <>
                          <Button
                            type="button"
                            variant={field.value === null ? 'default' : 'outline'}
                            className="w-full justify-start"
                            onClick={() => field.onChange(null)}
                          >
                            <HomeIcon className="mr-2 h-4 w-4" />
                            <Trans>Home (No Folder)</Trans>
                          </Button>

                          {filteredFolders?.map((folder) => (
                            <Button
                              key={folder.id}
                              type="button"
                              variant={field.value === folder.id ? 'default' : 'outline'}
                              className="w-full justify-start"
                              onClick={() => field.onChange(folder.id)}
                            >
                              <FolderIcon className="mr-2 h-4 w-4" />
                              {folder.name}
                            </Button>
                          ))}

                          {searchTerm && filteredFolders?.length === 0 && (
                            <div className="text-muted-foreground px-2 py-2 text-center text-sm">
                              <Trans>No folders found</Trans>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  </FormControl>
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="sendImmediately"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2">
                  <FormControl>
                    <div className="flex items-center">
                      <Checkbox
                        id="send-immediately"
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />

                      <label
                        htmlFor="send-immediately"
                        className="text-muted-foreground ml-2 flex items-center text-sm"
                      >
                        <Trans>Send documents to recipients immediately</Trans>
                      </label>
                    </div>
                  </FormControl>
                </FormItem>
              )}
            />

            <DialogFooter className="mt-4">
              <DialogClose asChild>
                <Button variant="secondary" onClick={() => form.reset()} type="button">
                  <Trans>Cancel</Trans>
                </Button>
              </DialogClose>

              <Button type="submit" loading={form.formState.isSubmitting}>
                <Trans>Upload and Process</Trans>
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
};
