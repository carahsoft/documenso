import { Img } from '../components';

export interface TemplateImageProps {
  assetBaseUrl: string;
  className?: string;
  staticAsset: string;
  width?: string | number;
  height?: string | number;
  style?: React.CSSProperties;
}

export const TemplateImage = ({
  assetBaseUrl,
  className,
  staticAsset,
  width,
  height,
  style,
}: TemplateImageProps) => {
  const getAssetUrl = (path: string) => {
    return new URL(path, assetBaseUrl).toString();
  };

  return (
    <Img
      className={className}
      src={getAssetUrl(`/static/${staticAsset}`)}
      width={width}
      height={height}
      style={style}
    />
  );
};

export default TemplateImage;
