import { useEffect, useState } from 'react';

import { zodResolver } from '@hookform/resolvers/zod';
import { msg } from '@lingui/core/macro';
import { Trans } from '@lingui/react/macro';
import type { Document } from '@prisma/client';
import { useForm } from 'react-hook-form';
import { useNavigate } from 'react-router';
import { z } from 'zod';

import { trpc } from '@documenso/trpc/react';
import { Button } from '@documenso/ui/primitives/button';
import {
  Dialog,
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
  FormMessage,
} from '@documenso/ui/primitives/form/form';
import { Input } from '@documenso/ui/primitives/input';
import { useToast } from '@documenso/ui/primitives/use-toast';

const ZReassignDocumentFormSchema = z.object({
  name: z.string().min(1, msg`Name is required`),
  email: z.string().email(msg`Invalid email address`),
});

type TReassignDocumentFormSchema = z.infer<typeof ZReassignDocumentFormSchema>;

export interface DocumentSigningReassignDialogProps {
  document: Pick<Document, 'id'>;
  token: string;
  currentName: string;
  currentEmail: string;
  onReassigned?: (name: string, email: string) => void | Promise<void>;
}

export function DocumentSigningReassignDialog({
  document,
  token,
  currentName,
  currentEmail,
  onReassigned,
}: DocumentSigningReassignDialogProps) {
  const { toast } = useToast();
  const navigate = useNavigate();

  const [isOpen, setIsOpen] = useState(false);

  const { mutateAsync: reassignDocumentWithToken } =
    trpc.recipient.reassignDocumentWithToken.useMutation();

  const form = useForm<TReassignDocumentFormSchema>({
    resolver: zodResolver(ZReassignDocumentFormSchema),
    defaultValues: {
      name: currentName,
      email: currentEmail,
    },
  });

  const onReassignDocument = async ({ name, email }: TReassignDocumentFormSchema) => {
    try {
      await reassignDocumentWithToken({
        documentId: document.id,
        token,
        name,
        email,
      });

      toast({
        title: 'Document reassigned',
        description: 'The signing link has been sent to the new recipient.',
        duration: 5000,
      });

      setIsOpen(false);

      if (onReassigned) {
        await onReassigned(name, email);
      } else {
        await navigate(`/sign/${token}/reassigned`);
      }
    } catch (err) {
      toast({
        title: 'Error',
        description: 'An error occurred while reassigning the document. Please try again.',
        variant: 'destructive',
        duration: 5000,
      });
    }
  };

  useEffect(() => {
    if (!isOpen) {
      form.reset({
        name: currentName,
        email: currentEmail,
      });
    }
  }, [isOpen, currentName, currentEmail]);

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <Trans>Reassign Document</Trans>
        </Button>
      </DialogTrigger>

      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            <Trans>Reassign Document</Trans>
          </DialogTitle>

          <DialogDescription>
            <Trans>
              Update the recipient information and send a new signing link to the updated email
              address.
            </Trans>
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onReassignDocument)} className="space-y-4">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    <Trans>Name</Trans>
                  </FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      placeholder="John Doe"
                      disabled={form.formState.isSubmitting}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    <Trans>Email</Trans>
                  </FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      type="email"
                      placeholder="john@example.com"
                      disabled={form.formState.isSubmitting}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setIsOpen(false)}
                disabled={form.formState.isSubmitting}
              >
                <Trans>Cancel</Trans>
              </Button>

              <Button type="submit" loading={form.formState.isSubmitting}>
                <Trans>Reassign Document</Trans>
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
