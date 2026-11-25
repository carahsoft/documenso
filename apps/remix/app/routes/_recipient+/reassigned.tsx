import { Trans } from '@lingui/react/macro';
import { UserCheck } from 'lucide-react';
import { Link } from 'react-router';

import { useOptionalSession } from '@documenso/lib/client-only/providers/session';
import { Button } from '@documenso/ui/primitives/button';

/**
 * Confirmation shown after a signer reassigns their document.
 *
 * Reassigning rotates the signing token, so this page intentionally does not depend on a token
 * (the old link no longer works and the new one is only emailed to the new recipient).
 */
export default function ReassignedPage() {
  const { sessionData } = useOptionalSession();
  const user = sessionData?.user;

  return (
    <div className="flex flex-col items-center pt-24 lg:pt-36 xl:pt-44">
      <div className="flex flex-col items-center">
        <div className="flex items-center gap-x-4">
          <UserCheck className="text-primary h-10 w-10" />

          <h2 className="max-w-[35ch] text-center text-2xl font-semibold leading-normal md:text-3xl lg:text-4xl">
            <Trans>Document Reassigned</Trans>
          </h2>
        </div>

        <div className="text-primary mt-4 flex items-center text-center text-sm">
          <Trans>You have successfully reassigned this document</Trans>
        </div>

        <p className="text-muted-foreground mt-6 max-w-[60ch] text-center text-sm">
          <Trans>
            A signing link has been sent to the new recipient. They will receive an email with
            instructions to access and sign the document.
          </Trans>
        </p>

        <p className="text-muted-foreground mt-2 max-w-[60ch] text-center text-sm">
          <Trans>No further action is required from you at this time.</Trans>
        </p>

        {user && (
          <Button className="mt-6" asChild>
            <Link to={`/`}>Return Home</Link>
          </Button>
        )}
      </div>
    </div>
  );
}
