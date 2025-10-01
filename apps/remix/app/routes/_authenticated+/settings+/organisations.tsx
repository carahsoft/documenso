import { msg } from '@lingui/core/macro';
import { useLingui } from '@lingui/react';

import { useSession } from '@documenso/lib/client-only/providers/session';
import { ADMIN_CREATE_ORGANISATION_ENABLED } from '@documenso/lib/constants/app';
import { isAdmin } from '@documenso/lib/utils/is-admin';

import { OrganisationCreateDialog } from '~/components/dialogs/organisation-create-dialog';
import { OrganisationInvitations } from '~/components/general/organisations/organisation-invitations';
import { SettingsHeader } from '~/components/general/settings-header';
import { UserOrganisationsTable } from '~/components/tables/user-organisations-table';

export default function TeamsSettingsPage() {
  const { _ } = useLingui();
  const { user } = useSession();
  const isUserAdmin = isAdmin(user);
  const canCreateOrganisation = !ADMIN_CREATE_ORGANISATION_ENABLED() || isUserAdmin;

  return (
    <div>
      <SettingsHeader
        title={_(msg`Organisations`)}
        subtitle={_(msg`Manage all organisations you are currently associated with.`)}
      >
        {canCreateOrganisation && <OrganisationCreateDialog />}
      </SettingsHeader>

      <UserOrganisationsTable />

      <div className="mt-8 space-y-8">
        <OrganisationInvitations />
      </div>
    </div>
  );
}
