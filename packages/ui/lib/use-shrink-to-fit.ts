import { type RefObject, useLayoutEffect } from 'react';

/**
 * Shrinks text fontSize to fit within a container using binary search.
 *
 * - isMultiline: text wraps and shrinks to fit container height.
 * - !isMultiline: caps available height to one line so any wrapping
 *   triggers shrinking, keeping text on a single line.
 *
 * Uses useLayoutEffect to avoid flash of unsized text, and
 * ResizeObserver + MutationObserver to re-run on layout/content changes.
 */
export function useShrinkToFit(
  containerRef: RefObject<HTMLElement | null>,
  textRef: RefObject<HTMLElement | null>,
  fontSize?: number,
  isMultiline?: boolean,
) {
  useLayoutEffect(() => {
    const container = containerRef.current;
    const textEl = textRef.current;
    if (!container || !textEl || !fontSize) return;

    const shrink = () => {
      const containerHeight = container.clientHeight;
      if (containerHeight === 0 || container.clientWidth === 0) return;

      // Disable CSS transitions on textEl and all descendants so
      // measurements reflect the target size, not an animated intermediate.
      textEl.style.transition = 'none';
      const descendants = textEl.querySelectorAll('*');
      descendants.forEach((el) => {
        (el as HTMLElement).style.transition = 'none';
      });

      // Start at the desired size
      textEl.style.fontSize = `${fontSize}px`;

      // Force a reflow so the browser computes layout at the new size
      // eslint-disable-next-line @typescript-eslint/no-unused-expressions
      textEl.scrollHeight;

      const availableHeight = (size: number) => {
        if (isMultiline) return containerHeight;
        // Single-line: cap to one line so any wrapping triggers shrinking
        return Math.min(containerHeight, size * 1.375); // 1.375 = leading-snug
      };

      // Check if it already fits at the desired size
      if (textEl.scrollHeight <= availableHeight(fontSize)) {
        restoreTransitions(textEl, descendants);
        return;
      }

      // Binary search for the largest font size that fits.
      const minSize = Math.max(4, fontSize * 0.15);
      let lo = minSize;
      let hi = fontSize;

      for (let i = 0; i < 20; i++) {
        const mid = (lo + hi) / 2;
        textEl.style.fontSize = `${mid}px`;

        // Force reflow for accurate measurement
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        textEl.scrollHeight;

        if (textEl.scrollHeight <= availableHeight(mid)) {
          lo = mid;
        } else {
          hi = mid;
        }
      }

      // Use the lower bound (largest confirmed fitting size)
      textEl.style.fontSize = `${lo}px`;

      // Restore transitions
      restoreTransitions(textEl, descendants);
    };

    shrink();

    // Re-run when the container resizes (window resize, zoom, etc.)
    const resizeObserver = new ResizeObserver(() => shrink());
    resizeObserver.observe(container);

    // Re-run when text content changes (React children update)
    const mutationObserver = new MutationObserver(() => shrink());
    mutationObserver.observe(textEl, {
      childList: true,
      subtree: true,
      characterData: true,
    });

    return () => {
      resizeObserver.disconnect();
      mutationObserver.disconnect();
    };
  }, [fontSize, isMultiline]);
}

function restoreTransitions(textEl: HTMLElement, descendants: NodeListOf<Element>) {
  requestAnimationFrame(() => {
    textEl.style.transition = '';
    descendants.forEach((el) => {
      (el as HTMLElement).style.transition = '';
    });
  });
}
