import { useRef } from 'react';

import { Loader } from 'lucide-react';

import { useShrinkToFit } from '@documenso/ui/lib/use-shrink-to-fit';
import { cn } from '@documenso/ui/lib/utils';

export const DocumentSigningFieldsLoader = () => {
  return (
    <div className="bg-background absolute inset-0 flex items-center justify-center rounded-md">
      <Loader className="text-primary h-5 w-5 animate-spin md:h-8 md:w-8" />
    </div>
  );
};

export const DocumentSigningFieldsUninserted = ({ children }: { children: React.ReactNode }) => {
  return (
    <p className="text-foreground group-hover:text-recipient-green whitespace-pre-wrap text-[clamp(0.425rem,25cqw,0.825rem)] leading-snug duration-200">
      {children}
    </p>
  );
};

type DocumentSigningFieldsInsertedProps = {
  children: React.ReactNode;

  /**
   * The text alignment of the field.
   *
   * Defaults to left.
   */
  textAlign?: 'left' | 'center' | 'right';

  /**
   * Optional font size in pixels. Text starts at this size and shrinks
   * to fit the field if needed.
   */
  fontSize?: number;

  /**
   * Whether text can wrap to multiple lines (TEXT fields).
   * When false, text stays on one line and shrinks to fit width.
   */
  isMultiline?: boolean;
};

export const DocumentSigningFieldsInserted = ({
  children,
  textAlign = 'left',
  fontSize: fontSizeProp,
  isMultiline,
}: DocumentSigningFieldsInsertedProps) => {
  const fontSize = fontSizeProp ?? 14;
  const containerRef = useRef<HTMLDivElement>(null);
  const textRef = useRef<HTMLDivElement>(null);

  useShrinkToFit(containerRef, textRef, fontSize, isMultiline);

  return (
    <div
      ref={containerRef}
      className="pointer-events-none flex h-full w-full items-center overflow-hidden"
    >
      <div ref={textRef} className="w-full">
        <p
          className={cn(
            'text-foreground w-full whitespace-pre-wrap break-words text-left leading-snug duration-200',
            {
              '!text-center': textAlign === 'center',
              '!text-right': textAlign === 'right',
            },
          )}
        >
          {children}
        </p>
      </div>
    </div>
  );
};
