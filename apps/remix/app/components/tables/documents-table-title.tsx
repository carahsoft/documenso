import { FolderIcon } from 'lucide-react';
import { Link } from 'react-router';
import { match } from 'ts-pattern';

import { useSession } from '@documenso/lib/client-only/providers/session';
import type { TDocumentMany as TDocumentRow } from '@documenso/lib/types/document';
import { formatDocumentsPath } from '@documenso/lib/utils/teams';

export type DataTableTitleProps = {
  row: TDocumentRow;
  teamUrl: string;
};

export const DataTableTitle = ({ row, teamUrl }: DataTableTitleProps) => {
  const { user } = useSession();

  const recipient = row.recipients.find((recipient) => recipient.email === user.email);

  const isOwner = row.user.id === user.id;
  const isRecipient = !!recipient;
  const isCurrentTeamDocument = teamUrl && row.team?.url === teamUrl;

  const documentsPath = formatDocumentsPath(teamUrl);

  const titleLink = match({
    isOwner,
    isRecipient,
    isCurrentTeamDocument,
  })
    .with({ isOwner: true }, { isCurrentTeamDocument: true }, () => (
      <Link
        to={`${documentsPath}/${row.id}`}
        title={row.title}
        className="block max-w-[10rem] truncate font-medium hover:underline md:max-w-[20rem]"
      >
        {row.title}
      </Link>
    ))
    .with({ isRecipient: true }, () => (
      <Link
        to={`/sign/${recipient?.token}`}
        title={row.title}
        className="block max-w-[10rem] truncate font-medium hover:underline md:max-w-[20rem]"
      >
        {row.title}
      </Link>
    ))
    .otherwise(() => (
      <span className="block max-w-[10rem] truncate font-medium hover:underline md:max-w-[20rem]">
        {row.title}
      </span>
    ));

  return (
    <div className="flex flex-col">
      {titleLink}
      {row.folder && (
        <div className="text-muted-foreground flex max-w-[10rem] items-center gap-1 text-xs md:max-w-[20rem]">
          <FolderIcon className="h-3 w-3 flex-shrink-0" />
          <Link
            to={`${documentsPath}?folderId=${row.folder.id}`}
            className="truncate hover:underline"
          >
            {row.folder.name}
          </Link>
        </div>
      )}
    </div>
  );
};
