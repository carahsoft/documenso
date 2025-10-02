import { Img, Section } from '../components';

export interface TemplateDocumentImageProps {
  assetBaseUrl: string;
  className?: string;
}

export const TemplateDocumentImage = ({ assetBaseUrl, className }: TemplateDocumentImageProps) => {
  const getAssetUrl = (path: string) => {
    return new URL(path, assetBaseUrl).toString();
  };

  return (
    <Section className={className} style={{ textAlign: 'center' }}>
      <Img
        src={getAssetUrl('/static/document.png')}
        alt="Documenso"
        style={{ display: 'block', margin: '0 auto', height: '168px', width: 'auto' }}
        height={168}
        align="center"
      />
    </Section>
  );
};

export default TemplateDocumentImage;
