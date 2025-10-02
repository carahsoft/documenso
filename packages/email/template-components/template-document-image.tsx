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
    <Section className={className}>
      <Img
        className="h-42"
        src={getAssetUrl('/static/document.png')}
        alt="Documenso"
        style={{ display: 'block', margin: '0 auto' }}
      />
    </Section>
  );
};

export default TemplateDocumentImage;
