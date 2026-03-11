import { useState } from 'react';

import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';
import { Trans } from '@lingui/react/macro';

import { useSession } from '@documenso/lib/client-only/providers/session';
import { trpc as trpcReact } from '@documenso/trpc/react';
import { Button } from '@documenso/ui/primitives/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@documenso/ui/primitives/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@documenso/ui/primitives/select';
import { useToast } from '@documenso/ui/primitives/use-toast';

import { useCurrentTeam } from '~/providers/team';

type TemplateDuplicateDialogProps = {
  id: number;
  open: boolean;
  onOpenChange: (_open: boolean) => void;
};

export const TemplateDuplicateDialog = ({
  id,
  open,
  onOpenChange,
}: TemplateDuplicateDialogProps) => {
  const { _ } = useLingui();
  const { toast } = useToast();

  const currentTeam = useCurrentTeam();
  const { organisations } = useSession();

  const allTeams = organisations.flatMap((org) => org.teams);
  const otherTeams = allTeams.filter((t) => t.id !== currentTeam.id);

  const [targetTeamId, setTargetTeamId] = useState<number | undefined>(undefined);

  const { mutateAsync: duplicateTemplate, isPending } =
    trpcReact.template.duplicateTemplate.useMutation({
      onSuccess: () => {
        const targetTeam = targetTeamId ? allTeams.find((t) => t.id === targetTeamId) : undefined;

        toast({
          title: _(msg`Template duplicated`),
          description: targetTeam
            ? _(msg`Your template has been duplicated to ${targetTeam.name}.`)
            : _(msg`Your template has been duplicated successfully.`),
          duration: 5000,
        });

        onOpenChange(false);
        setTargetTeamId(undefined);
      },
      onError: () => {
        toast({
          title: _(msg`Error`),
          description: _(msg`An error occurred while duplicating template.`),
          variant: 'destructive',
        });
      },
    });

  return (
    <Dialog
      open={open}
      onOpenChange={(value) => {
        if (!isPending) {
          onOpenChange(value);
          if (!value) {
            setTargetTeamId(undefined);
          }
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            <Trans>Do you want to duplicate this template?</Trans>
          </DialogTitle>

          <DialogDescription className="pt-2">
            <Trans>Your template will be duplicated.</Trans>
          </DialogDescription>
        </DialogHeader>

        {otherTeams.length > 0 && (
          <div className="flex flex-col gap-y-2">
            <label className="text-sm font-medium">
              <Trans>Destination team</Trans>
            </label>

            <Select
              value={targetTeamId?.toString() ?? 'current'}
              onValueChange={(value) =>
                setTargetTeamId(value === 'current' ? undefined : Number(value))
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="current">
                  {currentTeam.name} (<Trans>current</Trans>)
                </SelectItem>
                {otherTeams.map((team) => (
                  <SelectItem key={team.id} value={team.id.toString()}>
                    {team.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}

        <DialogFooter>
          <Button
            type="button"
            disabled={isPending}
            variant="secondary"
            onClick={() => onOpenChange(false)}
          >
            <Trans>Cancel</Trans>
          </Button>

          <Button
            type="button"
            loading={isPending}
            onClick={async () =>
              duplicateTemplate({
                templateId: id,
                targetTeamId,
              })
            }
          >
            <Trans>Duplicate</Trans>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
