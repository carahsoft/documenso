import { Column, Img, Row, Section } from '../components';

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
      <Row>
        <Column align="center">
          <Img
            className="h-42"
            src={getAssetUrl('/static/document.png')}
            alt="Documenso"
            width="168"
            height="168"
          />
        </Column>
      </Row>
    </Section>
  );
};

export default TemplateDocumentImage;
