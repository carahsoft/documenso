import type { I18n } from '@lingui/core';
import { I18nProvider } from '@lingui/react';
import * as ReactEmail from '@react-email/render';

import config from '@documenso/tailwind-config';

import { Tailwind } from './components';
import { BrandingProvider, type BrandingSettings } from './providers/branding';

export type RenderOptions = ReactEmail.Options & {
  branding?: BrandingSettings;
  i18n?: I18n;
};

// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
const colors = (config.theme?.extend?.colors || {}) as Record<string, string>;

export const render = async (element: React.ReactNode, options?: RenderOptions) => {
  const { branding, i18n, ...otherOptions } = options ?? {};

  const wrappedElement = (
    <BrandingProvider branding={branding}>
      <Tailwind
        config={{
          theme: {
            extend: {
              colors,
            },
          },
        }}
      >
        {element}
      </Tailwind>
    </BrandingProvider>
  );

  const finalElement = i18n ? (
    <I18nProvider i18n={i18n}>{wrappedElement}</I18nProvider>
  ) : (
    wrappedElement
  );

  return ReactEmail.render(finalElement, otherOptions);
};

export const renderAsync = async (element: React.ReactNode, options?: RenderOptions) => {
  const { branding, i18n, ...otherOptions } = options ?? {};

  const wrappedElement = (
    <BrandingProvider branding={branding}>
      <Tailwind
        config={{
          theme: {
            extend: {
              colors,
            },
          },
        }}
      >
        {element}
      </Tailwind>
    </BrandingProvider>
  );

  const finalElement = i18n ? (
    <I18nProvider i18n={i18n}>{wrappedElement}</I18nProvider>
  ) : (
    wrappedElement
  );

  return await ReactEmail.renderAsync(finalElement, otherOptions);
};
